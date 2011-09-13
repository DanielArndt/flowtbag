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
	"github.com/akrennmair/gopcap"
	"log"
	"os"
	"runtime"
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
		"http://web.cs.dal.ca/~darndt/projects/flowtbag"
)

func sortIP(ip1 string, port1 uint16, ip2 string, port2 uint16) string {
	if ip1 > ip2 {
		return fmt.Sprintf("%s,%d,%s,%d", ip1, port1, ip2, port2)
	}
	return fmt.Sprintf("%s,%d,%s,%d", ip2, port2, ip1, port1)
}

// Display a welcome message
func displayWelcome() {
	log.Println("\nWelcome to Flowtbag2 0.1b")
	log.Println("\n" + COPYRIGHT + "\n")
}

func usage() {
	fmt.Fprintf(os.Stderr, "%s [options] <capture file>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "options:\n")
	flag.PrintDefaults()
}

func cleanupActive(time int64) {
	count := 0
	for tuple, flow := range activeFlows {
		if flow.CheckIdle(time) {
			count++
			flow.Export()
			activeFlows[tuple] = nil, false
		}
	}
	log.Printf("Removed %d flows. Currently at %d\n", count, time)
}

var (
	fileName string
	reportInterval  int64
)
func init() {
	flag.Int64Var(&reportInterval, "r", 500000,
			"The interval at which to report the current state of Flowtbag")
	flag.Parse()
	fileName = flag.Arg(0)
	if fileName == "" {
		usage()
		fmt.Println()
		log.Fatalln("Missing required filename.")
	}
}

func main() {
	displayWelcome()
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
	
	log.Println("Starting Flowtbag")
	startTime = time.Nanoseconds()
	for rawpkt := p.Next(); rawpkt != nil; rawpkt = p.Next() {
		process(rawpkt)
	}
	for _, flow := range(activeFlows) {
		flow.Export()
	}
}

var (
	count       int64			 = 0
	flowCount   int64			 = 0
	startTime   int64
	endTime     int64
	elapsed     float64
	activeFlows map[string]*Flow = make(map[string]*Flow)
)

/* This should probably be more informative and actually do something. But for
 * now it will just catch the panic and recover from it. This is useful for
 * packets which are not valid. */
func catchPanic() {
	recover()
}

func process(raw *pcap.Packet) {
	defer catchPanic()
	count++
	if (count % reportInterval) == 0 {
		timeInt := int64(raw.Time.Sec) * 1000000 + int64(raw.Time.Usec)
		endTime = time.Nanoseconds()
		cleanupActive(timeInt)
		runtime.GC()
		elapsed = float64(endTime - startTime) / 1000000000
		startTime = time.Nanoseconds()
		log.Printf("Currently processing packet %d. Flowtbag size: %d", 
			count, len(activeFlows))
		log.Printf("Took %fs to process %d packets", elapsed, reportInterval)
	}
	raw.Decode()
		
	iph := raw.Headers[0].(*pcap.Iphdr)
	if iph.Version != 4 {
		log.Fatal("Not IPv4. Packet should not have made it this far")
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
	if iph.Protocol == IP_TCP {
		tcph := raw.Headers[1].(*pcap.Tcphdr)
		srcport = tcph.SrcPort
		dstport = tcph.DestPort
		pkt["prhlen"] = int64(tcph.DataOffset * 4)
		pkt["flags"] = int64(tcph.Flags)
	} else if iph.Protocol == IP_UDP {
		udph := raw.Headers[1].(*pcap.Udphdr)
		srcport = udph.SrcPort
		dstport = udph.DestPort
		pkt["prhlen"] = int64(udph.Length)
	} else {
		log.Fatal("Not TCP or UDP. Packet should not have made it this far.")
	}
	pkt["time"] = int64(raw.Time.Sec) * 1000000 + int64(raw.Time.Usec)
	ts := sortIP(srcip, srcport, dstip, dstport)
	flow, exists := activeFlows[ts]
	if exists {
		return_val := flow.Add(pkt, srcip)
		if return_val == 0 {
			// The flow was successfully added
			return
		} else if return_val == 1 {
			flow.Export()
			activeFlows[ts] = nil, false
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
