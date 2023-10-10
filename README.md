# Pingo

## Pingo is a network statistics generation engine writtin in Golang.

Pingo generates a series of UDP "pings" to various destinations where a remote Pingo responder bounces them back.  
By including a timecode in each ping, several statistics can be built showing latency, loss, and even the effect of ECMP on the underlying network.

Pingo has been designed to be as lightweight as possible and require the minimum possible setup. Pingo natively generates Prometheus statistics that can be scraped directly from the pingo daemon. 

Suggested analysis by using the Pingo Grafana dashboard. 

## Usage:

After building, pingo is configured by setting several environment variables and specifying a config file.  The config file contains a list of ports on which to open a receieve listener, as well as a definition for each flow
to be generated. This file is pipe deliminted and is easy to generate using some form of script. 

## Environment Variables:

**PINGODEBUG** _(int)_ - If PINGODEBUG is set to any number above 0 it will cause Pingo to become very verbose

**PINGOTRIGDUMP** _(int)_ - If PINGOTRIGDUMP is set to any number above 0 it will shift how prometheus metrics are compiled.  Normally every 15 seconds each flows prometheus metrics are compiled.  A mutex lock prevents a prometheus scrape from finishing until all flows have finished their dump. Enabling triggered dump will cause the flows to only dump when prometheus actually scrapes the endpoint.  This will drive up scrape time but may provide more real-time statistics.

**PINGOCONFIG** _(string)_ - Location of the pingo config file that defines pingo flows. 

**PINGOBUFSIZE** _(int)_ - Set the UDP socket recieve buffer.  This may need to be increased to prevent drops on systems with high numbers of flows.  Be careful! Too high will crash Linux.

**PINGOPORT** _(int)_ - Set the port that Pingo will listen on for Prometheus scrape on the /metrics and /healthcheck endpoints.



## The Pingo config file format:

dstdc|localip|lport|target|rport|pbr|rpbr|interval

Those are defined as:

- **dstdc** - A tag for the remote host you're pinging. Should make sense to you.  Generates the "dstdc" label in Prometheus.

- **localip** - The local IP address from which pings should be generated, and responses listened on.  Will need to be an IP on the system running pingo.  Generates the "localip" label in Prometheus.

- **lport** - The UDP source port from which these pings will be sent. Generates the "lport" label in Prometheus.

- **target** - The IP of the remote host we're pinging. Generates the "target" label in Prometheus.

- **rport** - The port on the remote host we're pinging. Generates the "rport" label in Prometheus.

- **pbr** - A label for the local transit or link we're sending on. Could be ASN of transit provider or something else locally significant. Generates the "pbr" label in Prometheus.

- **rpbr**- A label for the remote transit or link the responses will be sent on. Could be ASN of transit provider or something else locally significant. Generates the "rpbr" label in Prometheus.

- **interval** - Interval between successive packets on this flow.  0.5 is a good number. 


Given the bidirecitonal nature of Pingo, only one side of a pair of hosts has to initiate pings in order to get useful information for both directions.  Many remote hosts that don't initiate will only open a series of reciever
ports that allow them to respond to pingo pings.  This is configured in a very similar format as outbound pinging

RECV|localip|lport|0|0|0|0|0|0

Those are defined as:

- **RECV** - Static string indicating this is a receive only socket. 

- **localip** - The local IP address that we will listen for pingo pings on. 

- **lport** - The local UDP port that we will listen ofr pingo pings on. 

* The rest of the fields are just 0'd out and ignored. 

## System design:

Since pingo is a simple engine that initiates/recieves pings and generates statistics, it has no method by which to dictate the path a given ping will take.  This is typically done by building a PBR or policy based route that will ensure that packets sent by pingo are routed via a given transit provider or link.  The PBR should be based on the UDP source port of the packet.  For example:


- Create a PBR that routes packets sent on ports 50000-50009 to transit provider 1

- Create a PBR that routse packets sent on ports 50010-50019 to transit provider 2. 


Each port to provider map is locally significant, as most work will be done by referencing the "pbr" and "rpbr" labels in Prometheus which can be set arbitrarily. That said, it's helpful to make sure that each port range is globally unique to a given upstream provider.  

That is, if 50000-50009 is used for AS1234 in one place, then use that same range for that provider elsewhere, and do not reuse it for other providers.   

Each provider/upstream/link must have a unique port range. 
