package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/montanaflynn/stats"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Build a struct to hold details of each ping destination
type pingDest struct {
	DSTDC    string
	LOCALIP  string
	LPORT    int64
	REMOTEIP string
	RPORT    int64
	PBR      int64
	RPBR     int64
	INTERVAL float64
	SENDCHAN chan int64    //This is the ping send log.
	RECVCHAN chan [2]int64 //This is the ping receive log.

}

// Map type to map a string (hash) to
type pingTuple map[string]*pingDest

// Create channel store to have channel by port work.
type chanStore struct {
	SENDCHAN chan int64
	RECVCHAN chan [2]int64
}

type chanByPort map[string]*chanStore

// Build a struct to hold a pingers pertinent info
type pingerData struct {
	SRCSOCKET net.PacketConn //We'll stick a socket here.  I don't really care that we're opening multiple sockets per pinger because that's the point.
	UDPDEST   *net.UDPAddr   //We'll store the UDP dest.  I'm not sure if it's actually faster to do it this way but it at least seems less wasteful.
}

//type receiverData map[*net.UDPAddr]*chan int64

// Map type to map a string (lport:remoteip:rport) to a source socket and dest address
type pingerDataTuple map[string]*pingerData

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

// Uses strings.Builder for string concat for performance reasons
func join(strs ...string) string {
	var sb strings.Builder
	for _, str := range strs {
		sb.WriteString(str)
	}
	return sb.String()
}

var (
	udpSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "udp_sent_total",
		Help: "UDP sent counter.",
	},
		[]string{"dst_dc", "localip", "target", "lport", "rport", "pbr", "rpbr"},
	)

	udpRecv = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "udp_received_total",
		Help: "UDP received counter.",
	},
		[]string{"dst_dc", "localip", "target", "lport", "rport", "pbr", "rpbr"},
	)

	udpLatency = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "udp_latency_quantile",
		Help: "UDP latency quantiles.",
	},
		[]string{"dst_dc", "localip", "target", "lport", "rport", "pbr", "rpbr", "pct"},
	)

	pingoDump = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pingo_dump_timer",
		Help: "Pingo Dump timers",
	},
		[]string{"dst_dc", "localip", "target", "lport", "rport", "pbr", "rpbr", "timer"},
	)

	pingoScrape = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pingo_scrape_timer",
		Help: "Pingo Scrape timers",
	},
		[]string{"timer"},
	)

	currentPath = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "udp_current_transit_path",
		Help: "UDPyng current outbound transit path.",
	},
		[]string{"dst_dc", "seq", "target"},
	)

	dumpLock sync.RWMutex

	triggeredDump bool
	pingoDebug    bool
	generateMTR   bool
	pingoPort     string
	pingoConfig   string

	lastScrape int64
)

func getASPath(remoteHost string) (asnInt []int, err error) {
	/*
	   Runs a MTR command for a hostname or IP and returns a filtered AS path list.
	*/

	var asnList []string

	cmd := exec.Command("mtr", "-i .1", "-z", "-4", "-c1", "--csv", "-f2", "-oS", "--no-dns", remoteHost)

	//Build a buffer to receive input from stdout
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()

	if err != nil {
		return nil, err
	}

	//Read through the response line by line until we hit EOF.
	for {
		text, err := out.ReadString('\n')
		if text != "" {
			text = strings.TrimSuffix(text, "\n")

			mtrVals := strings.Split(text, ",") //Output should be CSV.  Split it up.

			//We're going to build up a list of valid ASN's that we found in the path list.  No dupes and trimming some stuff that's not helpful.
			if Contains(asnList, mtrVals[6]) == false && mtrVals[6] != "Asn" && mtrVals[6] != "AS???" {
				asnList = append(asnList, mtrVals[6])
			}

		}

		//Break once we reach EOF
		if err == io.EOF {
			break
		}

	}

	//Trim off "AS" from each ASN and convert to int slice.
	for i := 0; i < len(asnList); i++ {
		noAS, err := strconv.Atoi(strings.ReplaceAll(asnList[i], "AS", ""))
		if err != nil {
			continue
		}

		asnInt = append(asnInt, noAS)
	}

	return asnInt, nil

}

func fetchMTR(destMap pingTuple) {
	/*
	   Iterate across all remote DC's and get current AS Path then populate prometheus metric.
	*/

	//Iterate across the destMap and populate a second map with each unique DC and the pertinent info
	uniqueDC := make(map[string]string)

	for _, element := range destMap {
		if _, ok := uniqueDC[element.DSTDC]; ok == false && element.DSTDC != "recv" {
			uniqueDC[element.DSTDC] = element.REMOTEIP
		}
	}

	for {
		for dstDC, remoteIP := range uniqueDC {
			dcASPath, _ := getASPath(remoteIP)

			//Clear all the values first so we don't have cruft hanging around
			for i := 0; i < 32; i++ {
				currentPath.WithLabelValues(dstDC, strconv.FormatInt(int64(i), 10), remoteIP).Set(0.0)
			}

			for i := 0; i < len(dcASPath); i++ {
				currentPath.WithLabelValues(dstDC, strconv.FormatInt(int64(i), 10), remoteIP).Set(float64(dcASPath[i]))
			}

		}
	}
}

func Contains[T comparable](s []T, e T) bool {
	// Contains function to see if a slice contains an object.

	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func getSysIP(ipList []string, getbyhostname bool) []net.IP {
	if getbyhostname == true {
		//Get system hostname
		hostname, err := os.Hostname()
		if err != nil {
			panic(err)
		}

		ips, err := net.LookupIP(hostname)
		if err != nil {
			panic(err)
		}
		return ips

	} else {
		var ips []net.IP
		for i := 0; i < len(ipList); i++ {
			ip := net.ParseIP(ipList[i])
			log.Println(ip)

			ips = append(ips, ip)
		}
		return ips
	}

}

func openPingSocket(portNum int, ipver int, sourceIP string) (net.PacketConn, error) {

	ips := getSysIP([]string{sourceIP}, false)
	ipIndex := 0
	udpVer := "udp4"

	if ipver == 4 {
		for i := 0; i < len(ips); i++ {
			if IsIPv4(ips[i].String()) {
				ipIndex = i
				udpVer = "udp4"
			}
		}
	} else if ipver == 6 {
		for i := 0; i < len(ips); i++ {
			if IsIPv6(ips[i].String()) {
				ipIndex = i
				udpVer = "udp6"
			}
		}
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error

			//Set the reuse port option
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}

			rcvbufsize := 212992 //Linux default UDP buffer size

			if len(os.Getenv("PINGOBUFSIZE")) > 0 { //Lets see if the env variable is set.
				bufsize := os.Getenv("PINGOBUFSIZE")
				log.Println("Buffer size environment variable was set. it is:" + bufsize)

				buf, err := strconv.Atoi(bufsize)

				if err != nil {
					log.Println("Buffer" + bufsize + " size could not be converted from string. Leaving at default")
				} else {
					rcvbufsize = buf
				}

			}

			err = c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbufsize)
			})
			if err != nil {
				return err
			}

			return opErr
		},
	}

	portString := strconv.Itoa(portNum)
	var portToOpen string

	if ipver == 4 {
		portToOpen = join(ips[ipIndex].String(), ":", portString)
	} else if ipver == 6 {
		portToOpen = join("[", ips[ipIndex].String(), "]", ":", portString)
		log.Println(portToOpen)
	}

	lp, err := lc.ListenPacket(context.Background(), udpVer, portToOpen)
	log.Println("Opening" + udpVer + " socket on " + portToOpen)

	return lp, err
}

func pinger(destMap pingTuple, mapEntry string, udpSocket net.PacketConn) {

	/*
	   This actually puts the pings on the wire.  It listens to a flows generator routine and then sends the ping out on the UDP socket

	*/

	remoteUdpTuple := join("[", destMap[mapEntry].REMOTEIP, "]:", strconv.FormatInt(destMap[mapEntry].RPORT, 10))

	//Resolve UDP destination
	udpDest, err := net.ResolveUDPAddr("udp", remoteUdpTuple)
	if err != nil {
		log.Println("Couldnt resolve UDP address on pinger: ", err)
	}

	sleepDuration := time.Duration(destMap[mapEntry].INTERVAL * float64(time.Second))

	time.Sleep(time.Millisecond * time.Duration(rand.Intn(430))) //Randomize startup of pinger to prevent pings from heartbeating.

	// Infinite receive loop.
	for {

		nowTime := time.Now().UnixMilli() // Get the current time in milliseconds

		//Do something with this channel.  This is where we log the send.

		//Actually send the packet via UDP.
		if _, err := udpSocket.WriteTo([]byte(strconv.FormatInt(nowTime, 10)), udpDest); err != nil {
			panic(err)
		} else {

			destMap[mapEntry].SENDCHAN <- nowTime //Log the send in the channel
		}

		time.Sleep(time.Duration(sleepDuration))

	}

}

func receiver(destMap pingTuple, lport int64, mapEntry string) {
	/*
	   This opens a UDP socket on a local port and starts listening for packets. If it gets a response it dumps it into the appropriate response channel.

	   If the received packet doesn't look like a response, it'll compose a response and inject it into the send channel to be sent back.

	*/

	//Open the UDP socket to listen on.
	udpVer := 4

	if IsIPv4(destMap[mapEntry].LOCALIP) {
		udpVer = 4
	}

	if IsIPv6(destMap[mapEntry].LOCALIP) {
		udpVer = 6
		log.Println("This is a udp6 socket")
	}

	udpSocket, err := openPingSocket(int(lport), udpVer, destMap[mapEntry].LOCALIP)
	if err != nil {
		log.Println("Error opening ping socket")
		panic(err)
	}

	if destMap[mapEntry].DSTDC != "recv" {
		go pinger(destMap, mapEntry, udpSocket)
		go dumper(destMap, mapEntry)
	}

	/*
	   Build map of channels by port via: type chanByPort map[string]*chanStore for all channels that have our lport.
	   This lets us use the addr returned by udpSocket.ReadFrom to look up the appropriate send/recieve buffers.
	*/

	remoteByPort := make(chanByPort)

	for _, destDetails := range destMap {
		if destDetails.LPORT == lport {
			if IsIPv6(destDetails.REMOTEIP) {
				remoteByPort[join("[", destDetails.REMOTEIP, "]", ":", strconv.FormatInt(destDetails.RPORT, 10))] = &chanStore{destDetails.SENDCHAN, destDetails.RECVCHAN}
			} else {
				remoteByPort[join(destDetails.REMOTEIP, ":", strconv.FormatInt(destDetails.RPORT, 10))] = &chanStore{destDetails.SENDCHAN, destDetails.RECVCHAN}
			}
		}
	}

	// Start the receive loop.
	for {
		packetBuffer := make([]byte, 128)
		buflen, addr, err := udpSocket.ReadFrom(packetBuffer)
		recvTime := time.Now().UnixMilli()

		if err != nil {
			log.Println("read failed", err)
			continue
		}

		if buflen < 50 { //Let's not get skunked by someone sending a very large packet and trying to cause problems.

			go receiveHelper(buflen, packetBuffer, remoteByPort, udpSocket, lport, addr, recvTime)

		}
	}

}

func receiveHelper(buflen int, packetBuffer []byte, remoteByPort chanByPort, udpSocket net.PacketConn, lport int64, addr net.Addr, recvTime int64) {
	/*
	   This function exists to decouple write attempts of the receive buffer from the big glut of reads that happen during a dump.  This is spawned as a goroutine on packet receive.  The idea being to let this eat the
	   latency incurred by the dump routine and let the receive process get back to the business of receiving packets.
	*/

	packetContent := packetBuffer[:buflen]

	if string(packetContent[:2]) == "r-" {
		//First two characters is a r-.  Let's deal with this as a response.
		responseString := string(packetContent[2:buflen])

		packetDataInt, err := strconv.ParseInt(responseString, 10, 64)
		if err != nil {
			log.Println(join(err.Error(), "Got a bad response sent from ", addr.String(), " to: udp/", strconv.FormatInt(lport, 10), "  Could not convert to int64"))
		} else {
			// Lets see if we expect to receive responses from this host.
			if _, ok := remoteByPort[addr.String()]; ok {
				//Good int from a known remote host.  Lets put it in the appropriate receive buffer.
				recvTuple := [2]int64{packetDataInt, recvTime} //Build packet record to insert in to recv channel.  It's an array of length 2. [0]: Original packet timestamp [1]: When we received it.
				//go receiveHelper(recvTuple, remoteByPort[addr.String()].RECVCHAN)
				remoteByPort[addr.String()].RECVCHAN <- recvTuple
			} else {
				log.Println(join("Got an unsolicited r- from ", addr.String()))
			}

		}
	} else if buflen >= 12 && buflen < 19 {
		//Probably a packet from classic UDPyng
		remoteTimestamp := strings.Replace(string(packetContent), ".", "", -1)
		remoteTimestamp = remoteTimestamp[0 : buflen-1]

		_, err := strconv.ParseInt(remoteTimestamp, 10, 64)
		if err != nil {
			log.Println(join("Got a bad classic UDpyng packet sent from ", addr.String(), " to: udp/", strconv.FormatInt(lport, 10), "  Could not convert to int64. Error: ", err.Error()))
		} else {
			//Actually send the packet via UDP.
			packetByte := bytes.Trim([]byte(join("r-", string(packetContent[:buflen]))), "\x00")

			if _, err := udpSocket.WriteTo(packetByte, addr); err != nil {
				panic(err)
			}

		}

	} else {
		log.Println(join("Got a bad packet sent from ", addr.String(), " to: udp/", strconv.FormatInt(lport, 10), "  Did not look like a ping request or response."))
	}

}

func dumper(destMap pingTuple, mapEntry string) {

	/*
	   This dumps a *single* channel and comiples metrics.
	*/

	var lastDump int64 //Let's log the last time we dumped this flow
	var deltaHoldover []float64

	for {

		//Lock on MUTEX here.
		if triggeredDump == false {
			time.Sleep(time.Second * 15) // Run every 10 seconds
		}

		dumpStart := time.Now().UnixMicro()   // We're going to instrument this to see how long a dump routine usually takes.
		dumpLock.RLock()                      //Institute a read lock.
		dumpLockAcq := time.Now().UnixMicro() // We're going to instrument this to see how long a dump routine usually takes.

		recvChan := destMap[mapEntry].RECVCHAN
		sendChan := destMap[mapEntry].SENDCHAN

		var readTime int64 = 0                     //We update this to stop reading when the time comes.
		var recvUnit [2]int64                      //We update this to stop reading when the time comes.
		sendList := make(map[int64]int64)          //A list of all the sends that were going to try and resolve.
		var deltaList []float64                    //A slice to contain all the latency values we calculate
		statList := [6]int{0, 25, 50, 75, 95, 100} //The list of stats to generate. Kind of a constant.
		statMap := make(map[int]float64)           //A place to contain the stats we generate.
		var currentPBR string
		var currentRPBR string

		for readTime < time.Now().UnixMilli()-2300 { //Dump all the sends up to the stopTime. (usually now - 2.3s)
			readTime = <-sendChan
			sendList[readTime] = 0

		}

		if lastDump > lastScrape {
			//The last dump completed AFTER the last scrape.  We need to read everything out of the deltaHoldover into deltaList
			for i := 0; i < len(deltaHoldover); i++ {
				deltaList = append(deltaList, deltaHoldover[i]) //Read the holdover slice into deltalist.
			}
		}

		deltaHoldover = nil //Empty out deltaHoldover

		//The prometheus label should be "CURRENT" when pbr == 0
		if destMap[mapEntry].PBR > 0 {
			currentPBR = strconv.FormatInt(destMap[mapEntry].PBR, 10)
		} else {
			currentPBR = "CURRENT"
		}
		//Same for RPBR
		if destMap[mapEntry].RPBR > 0 {
			currentRPBR = strconv.FormatInt(destMap[mapEntry].RPBR, 10)
		} else {
			currentRPBR = "CURRENT"
		}

		//How long is the receive channel
		recvLen := len(recvChan)

		for i := 0; i < recvLen; i++ {

			recvUnit = <-recvChan

			if _, ok := sendList[recvUnit[0]]; ok {
				// Yay we found the appropriate key and can resolve this.  Lets append to the delta list with the latency we found.
				deltaList = append(deltaList, float64(recvUnit[1]-recvUnit[0]))         // Do the math and convert to float64.   Since we're using ms as our timecode we shouldnt get into any issuses with generating a float by accident.
				deltaHoldover = append(deltaHoldover, float64(recvUnit[1]-recvUnit[0])) //Copy things into deltaholdover.

			} else if recvUnit[1] > time.Now().UnixMilli()-10000 { //If the timestamp of when it was received is newer than now-10000
				recvChan <- recvUnit // Put it back in the list
			} else { //It's too old to deal with.  We'll just zeroize it and let it expire. It'll go down as lost.
				recvUnit[0] = 0 //zeroize
				recvUnit[1] = 0 //Zeroize
			}

		}

		//Let's collect some stats for future use:
		sendSize := len(sendList)
		recvSize := len(deltaList)

		//We need to record sent packets regardless.
		udpSent.WithLabelValues(
			destMap[mapEntry].DSTDC,
			destMap[mapEntry].LOCALIP,
			destMap[mapEntry].REMOTEIP,
			strconv.FormatInt(destMap[mapEntry].LPORT, 10),
			strconv.FormatInt(destMap[mapEntry].RPORT, 10),
			currentPBR,
			currentRPBR,
		).Add(float64(sendSize))

		if len(deltaList) > 0 {

			sort.Float64s(deltaList)

			for i := 0; i < len(statList); i++ { // Generate all the percentiles and store them in the statMap
				if statList[i] == 0 {
					statMap[statList[i]] = deltaList[0]
				} else {
					statMap[statList[i]], _ = stats.Percentile(deltaList, float64(statList[i]))
				}
			}

			statAvg, _ := stats.Mean(deltaList) // Grab the average

			//Compile prometheus metrics.

			udpRecv.WithLabelValues(
				destMap[mapEntry].DSTDC,
				destMap[mapEntry].LOCALIP,
				destMap[mapEntry].REMOTEIP,
				strconv.FormatInt(destMap[mapEntry].LPORT, 10),
				strconv.FormatInt(destMap[mapEntry].RPORT, 10),
				currentPBR,
				currentRPBR,
			).Add(float64(recvSize))

			for key, statValue := range statMap {
				udpLatency.WithLabelValues(
					destMap[mapEntry].DSTDC,
					destMap[mapEntry].LOCALIP,
					destMap[mapEntry].REMOTEIP,
					strconv.FormatInt(destMap[mapEntry].LPORT, 10),
					strconv.FormatInt(destMap[mapEntry].RPORT, 10),
					currentPBR,
					currentRPBR,
					strconv.FormatInt(int64(key), 10),
				).Set(statValue)
			}

			udpLatency.WithLabelValues(
				destMap[mapEntry].DSTDC,
				destMap[mapEntry].LOCALIP,
				destMap[mapEntry].REMOTEIP,
				strconv.FormatInt(destMap[mapEntry].LPORT, 10),
				strconv.FormatInt(destMap[mapEntry].RPORT, 10),
				currentPBR,
				currentRPBR,
				"avg",
			).Set(statAvg)

		} else {

			// We need to increment by 0 for a timeseries that gets no receives. This prevents the timeseries from stealth not reporting.
			udpRecv.WithLabelValues(
				destMap[mapEntry].DSTDC,
				destMap[mapEntry].LOCALIP,
				destMap[mapEntry].REMOTEIP,
				strconv.FormatInt(destMap[mapEntry].LPORT, 10),
				strconv.FormatInt(destMap[mapEntry].RPORT, 10),
				currentPBR,
				currentRPBR,
			).Add(0.0)
		}

		dumpLock.RUnlock() //Unlock before we begin waiting.

		if triggeredDump {
			time.Sleep(time.Second * 3) //Sleep before beginning next loop.
		}

		lastDump = time.Now().UnixMilli() //We'll log the last time we completed a dump of this flow.

		dumpEnd := time.Now().UnixMicro() // We're going to instrument this to see how long a dump routine usually takes.
		pingoDump.WithLabelValues(
			destMap[mapEntry].DSTDC,
			destMap[mapEntry].LOCALIP,
			destMap[mapEntry].REMOTEIP,
			strconv.FormatInt(destMap[mapEntry].LPORT, 10),
			strconv.FormatInt(destMap[mapEntry].RPORT, 10),
			currentPBR,
			currentRPBR,
			"lock",
		).Set(float64(dumpLockAcq - dumpStart))

		pingoDump.WithLabelValues(
			destMap[mapEntry].DSTDC,
			destMap[mapEntry].LOCALIP,
			destMap[mapEntry].REMOTEIP,
			strconv.FormatInt(destMap[mapEntry].LPORT, 10),
			strconv.FormatInt(destMap[mapEntry].RPORT, 10),
			currentPBR,
			currentRPBR,
			"run",
		).Set(float64(dumpEnd - dumpLockAcq))

	}
}

func containsint64(s []int64, e int64) bool {
	//Just a utility function to decide if a slice contains a given int64
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func debugLog(logString ...string) {
	/*
	   Logs debugging info if the correct env variable is set.
	*/
	if pingoDebug == true {
		var concatString string
		for i := 0; i < len(logString); i++ {
			concatString = join(concatString, logString[i], " ")
		}
		log.Println(concatString)
	}
}

func promScrapeMiddleware(h http.Handler) http.HandlerFunc {
	/*
	   Interceptor middleware function for prometheus scrapes.  This lets us do things like mutex locking and triggering dumps before actually returning metrics.
	*/

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		lastScrape = time.Now().UnixMilli() //Lets set our scrape sentinel to the last scrape time.

		if triggeredDump == false {
			scrapeStart := time.Now().UnixMicro() // We're going to instrument this to see how long a scrape routine usually takes.

			debugLog("Dump start at:", strconv.FormatInt(scrapeStart, 10))

			dumpLock.Lock() //Lock the dumplock mutex when we begin a scrape. We want to pause all the dumpers before they begin their next dump while we let prometheus scrape.

			scrapeLockAcq := time.Now().UnixMicro() // We're going to instrument this to see how long a scrape routine usually takes.
			debugLog("Lock Acquired at:", strconv.FormatInt(scrapeLockAcq, 10))

			pingoScrape.WithLabelValues("lock").Set(float64(scrapeLockAcq - scrapeStart))

			h.ServeHTTP(w, r) // call ServeHTTP on the original handler
			debugLog("Dump Complete:", strconv.FormatInt(time.Now().UnixMilli(), 10))

			dumpLock.Unlock() //Unlock the mutex.
		} else {

			dumpLock.Unlock()                     //Unlock the dumplock.  This will uncork all the read locked dummpers and let them complete.
			time.Sleep(time.Millisecond * 100)    //Sleep a bit while the dumpers get sorted.
			scrapeStart := time.Now().UnixMicro() // We're going to instrument this to see how long a scrape routine usually takes.
			debugLog("Dump start at:", strconv.FormatInt(scrapeStart, 10))
			dumpLock.Lock()                         //Relock the mutex. By this point all the read locks should have started and we'll block here waiting for them to finish their work.
			scrapeLockAcq := time.Now().UnixMicro() // We're going to instrument this to see how long a scrape routine usually takes.
			debugLog("Lock Acquired at:", strconv.FormatInt(scrapeLockAcq, 10))

			pingoScrape.WithLabelValues("lock").Set(float64(scrapeLockAcq - scrapeStart))

			h.ServeHTTP(w, r) // call ServeHTTP on the original handler to serve up prometheus metrics.
			debugLog("Dump Complete:", strconv.FormatInt(time.Now().UnixMilli(), 10))

		}

	})
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	//Health check for nagios
	scrapeHealth := func() bool {
		if time.Now().UnixMilli()-lastScrape > 600000 {
			//Have we not had a scrape in a while?

			return false
		} else {

			return true
		}
	}

	if scrapeHealth() == true {
		io.WriteString(w, "OK")
	} else {
		io.WriteString(w, "Error, have not been scraped in > 10 mins")
	}
}

func main() {

	//Get environment variables
	if len(os.Getenv("PINGODEBUG")) > 0 {
		pingoDebug = true
	}

	if len(os.Getenv("PINGOTRIGDUMP")) > 0 {
		triggeredDump = true
	}

	if len(os.Getenv("PINGOMTR")) > 0 {
		generateMTR = true
	}

	if len(os.Getenv("PINGOCONFIG")) > 0 {
		pingoConfig = os.Getenv("PINGOCONFIG")
	}

	if len(os.Getenv("PINGOPORT")) > 0 {
		pingoPort = ":" + os.Getenv("PINGOPORT")
	} else {
		pingoPort = ":9106"
	}

	remoteDetails := make(pingTuple) //Build the map of all the various flows we'll be using along with their dedicated channels

	triggeredDump = false //Probably read this from an environment variable later. Decides if metric dumping is triggered by prometheus scrape or if it runs in a timer.

	//Build a prometheus registry for our metrics
	promReg := prometheus.NewRegistry()
	promReg.MustRegister(udpSent, udpRecv, udpLatency, pingoDump, pingoScrape, currentPath)

	fmt.Println(join("Opening config file from:", pingoConfig))

	// Read in config file
	file, err := os.Open(pingoConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	//New scanner to read config file in.
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		// Read in the config and put it in the RemoteDetails struct.

		pingEntry := strings.Split(scanner.Text(), "|")

		dst_dc := strings.ToLower(string(pingEntry[0]))
		local_ip := pingEntry[1]
		lport, _ := strconv.ParseInt(pingEntry[2], 10, 64)
		remote_ip := pingEntry[3]
		rport, _ := strconv.ParseInt(pingEntry[4], 10, 64)
		lpbr, _ := strconv.ParseInt(pingEntry[5], 10, 64)
		rpbr, _ := strconv.ParseInt(pingEntry[6], 10, 64)
		interval, _ := strconv.ParseFloat(pingEntry[7], 10)

		//Add flow to remoteDetails map
		remoteDetails[GetMD5Hash(scanner.Text())] = &pingDest{dst_dc, local_ip, lport, remote_ip, rport, lpbr, rpbr, interval, make(chan int64, 500), make(chan [2]int64, 500)}

	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	if triggeredDump == true {
		dumpLock.Lock() //Lock the dumplock initially if we're doing a triggered dump.
	}

	//Start receivers
	for key, _ := range remoteDetails {
		fmt.Println(join("Opening receiver on ", strconv.FormatInt(remoteDetails[key].LPORT, 10)))
		go receiver(remoteDetails, remoteDetails[key].LPORT, key)
	}

	if generateMTR == true {
		go fetchMTR(remoteDetails)
	}
	/*
	   Need to iterate here through the uniquePorts slice and open receive-only ports.

	*/

	fmt.Println("Finished opening pingers")

	http.Handle("/metrics", promScrapeMiddleware(promhttp.HandlerFor(promReg, promhttp.HandlerOpts{})))
	http.HandleFunc("/healthcheck", healthCheck)

	http.ListenAndServe(pingoPort, nil)

}
