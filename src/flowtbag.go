/* 
 *  Copyright 2011 Daniel Arndt
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  @author: Daniel Arndt <danielarndt@gmail.com>
 *
 */

package main

import (
	"flag"
	"fmt"
	"gopcap"
	"log"
	"os"
	"time"
)

// Create some constants
const (
	TAB       = "\t"
	COPYRIGHT = "Copyright (C) 2010 Daniel Arndt\n" +
		"Licensed under the Apache License, Version 2.0 (the \"License\"); " +
		"you may not use this file except in compliance with the License." +
		" You may obtain a copy of the License at\n" +
		"\n    http://www.apache.org/licenses/LICENSE-2.0\n" +
		"\nFor more information, please visit: \n" +
		"http://web.cs.dal.ca/~darndt"
)

type flowTuple struct {
	ip1 string
	port1 uint16
	ip2 string
	port2 uint16
}

func (t *flowTuple) String() string {
	return fmt.Sprintf("%s,%d,%s,%d", t.ip1, t.port1, t.ip2, t.port2)
}

func (t *flowTuple) init(ip1 string, port1 uint16, ip2 string, port2 uint16) {
	if ip1 > ip2 {
		t.ip1 = ip1
		t.port1 = port1
		t.ip2 = ip2
		t.port2 = port2
		return
	} else {
		t.ip1 = ip2
		t.port1 = port2
		t.ip2 = ip1
		t.port2 = port1
		return
	}
}

// Check if an error has occured
func checkErr(err os.Error) {
	if err != nil {
		log.Fatalln("Error:", err)
	}
}

// Display a welcome message
func displayWelcome() {
	log.Println("\nWelcome to Flowtbag2 0.1b")
	log.Println("\n" + COPYRIGHT + "\n")
}

func usage() {
	log.Println("flowtbag2 [options] <capture file>")
	log.Println("options:")
	flag.PrintDefaults()
}

func cleanupActive(time int64) {
	count := 0
	for tuple, flow := range activeFlows {
		if flow.CheckIdle(time) {
			count++
			flow.Export()
			activeFlows[tuple] = new(Flow), false
		}
	}
	log.Printf("Removed %d flows. Currently at %d\n", count, time)
}

var (
	fileName string
	reportInterval  int64
	cleanupInterval int64
)
func init() {
	displayWelcome()
	flag.Int64Var(&reportInterval, "r", 5000000,
			"The interval at which to report the current state of the Flowtbag")
	flag.Int64Var(&reportInterval, "c", 5000000,
			"The interval at which to cleanup idle flows from the Flowtbag")
	flag.Parse()
	fileName = flag.Arg(0)
	if fileName == "" {
		usage()
		log.Fatalln("Missing required filename.")
	}
}

func main() {
	// This will be our capture file
	var (
		p *pcap.Pcap
		sErr string
	)
	log.Printf("%s\n", pcap.Version())
	p, sErr = pcap.Openoffline(fileName)
	if p == nil {
		log.Fatalf("Openoffline(%s) failed: %s\n", fileName, sErr)
	}	

	p.Setfilter("ip and (tcp or udp)")
	
	log.Println("Starting Flowtbag2")
	startTime = time.Seconds()
	for pkt := p.Next(); pkt != nil; pkt = p.Next() {
		process(pkt)
	}
	for _, flow := range(activeFlows) {
		flow.Export()
	}
}
var (
	count     int64 = 0
	flowCount int64 = 0
	startTime int64
	endTime   int64
	elapsed   int64
	activeFlows map[string]*Flow = make(map[string]*Flow, 200000)
)
func process(raw *pcap.Packet) {
	defer func() {
        //if r := recover(); r != nil {
        //    log.Println("Recovered in process", r)
        //}
		recover()
    }()
	count++
//	log.Printf("Count: %d\n", count)
	if (count % reportInterval) == 0 {
		timeInt := int64(raw.Time.Sec) * 1000000 + int64(raw.Time.Usec)
		endTime = time.Seconds()
		elapsed = endTime - startTime
		cleanupActive(timeInt)
		log.Printf("Currently processing packet %d. ", count)
		log.Printf("Took %ds to process %d packets", elapsed, reportInterval)
		startTime = time.Seconds()
	}
	raw.Decode()
		
	iph := raw.Headers[0].(*pcap.Iphdr)
	if iph.Version != 4 {
		log.Fatal("Not IPv4. Packet should not have made it through the filter")
	}
	pkt := make(map[string]int64, 10)
	var (
		srcip string
		srcport uint16
		dstip string
		dstport uint16
		proto uint8
	)
	pkt["num"] = count
	pkt["iphlen"] = int64(iph.Ihl * 4)
	pkt["dscp"] = int64(iph.Tos >> 2)
	pkt["len"] = int64(iph.Length)
	proto = iph.Protocol
	srcip = iph.SrcAddr()
	dstip = iph.DestAddr()
	if iph.Protocol == pcap.IP_TCP {
		tcph := raw.Headers[1].(*pcap.Tcphdr)
		srcport = tcph.SrcPort
		dstport = tcph.DestPort
		pkt["prhlen"] = int64(tcph.DataOffset * 4)
		pkt["flags"] = int64(tcph.Flags)
	} else if iph.Protocol == pcap.IP_UDP {
		udph := raw.Headers[1].(*pcap.Udphdr)
		srcport = udph.SrcPort
		dstport = udph.DestPort
		pkt["prhlen"] = int64(udph.Length)
	}
	pkt["time"] = int64(raw.Time.Sec) * 1000000 + int64(raw.Time.Usec)
	tuple := new(flowTuple)
	tuple.init(srcip, srcport, dstip, dstport)
	ts := tuple.String()
	flow, exists := activeFlows[ts]
	if exists {
		return_val := flow.Add(pkt, srcip)
		if return_val == 0 {
			return
		} else if return_val == 1 {
			flow.Export()
			activeFlows[ts] = new(Flow), false
			return
		} else {
			// Already in, but has expired
			flow.Export()
			flowCount++
			f := new(Flow)
			f.Init(srcip, srcport, dstip, dstport, proto, pkt, flowCount)
			activeFlows[ts] = f
			return
		}
	} else {
		// This flow does not yet exist in the map
		flowCount++
		f := new(Flow)
		f.Init(srcip, srcport, dstip, dstport, proto, pkt, flowCount)
		activeFlows[ts] = f
		return
	}
}	
