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
	"fmt"
	"log"
)

const (
	IP_TCP  = 6
	IP_UDP  = 17

	P_FORWARD = 0
	P_BACKWARD = 1
)

const (
	// Configurables. These should at some point be read in from a configuration
	// file.
	FLOW_TIMEOUT = 600000000
	IDLE_THRESHOLD = 1000000
)

// This is how we represent each packet after it is decoded. A simple map from the
// string value for it's name to the value
type packet map[string]int64

var features []string = []string{
	"total_fpackets",
    "total_fvolume",
    "total_bpackets",
    "total_bvolume",
    "min_fpktl",
    "mean_fpktl",
    "max_fpktl",
    "std_fpktl",
    "min_bpktl",
    "mean_bpktl",
    "max_bpktl",
    "std_bpktl",
    "min_fiat",
    "mean_fiat",
    "max_fiat",
    "std_fiat",
    "min_biat",
    "mean_biat",
    "max_biat",
    "std_biat",
    "duration",
    "min_active",
    "mean_active",
    "max_active",
    "std_active",
    "min_idle",
    "mean_idle",
    "max_idle",
    "std_idle",
    "sflow_fpackets",
    "sflow_fbytes",
    "sflow_bpackets",
    "sflow_bbytes",
    "fpsh_cnt",
    "bpsh_cnt",
    "furg_cnt",
    "burg_cnt",
    "total_fhlen",
    "total_bhlen",
    "dscp",
}

var counters []string = []string {
	"fpktl_sqsum",
    "bpktl_sqsum",
    "fiat_sum",
    "fiat_sqsum",
    "fiat_count",
    "biat_sum",
    "biat_sqsum",
    "biat_count",
    "active_start",
    "active_time",
    "active_sqsum",
    "active_count",
    "idle_time",
    "idle_sqsum",
    "idle_count",
}

type Flow struct {
	f map [string] int64
	c map [string] int64

	id int64 // An identification number for the flow
	firstPacket packet // The first packet in the flow
	valid bool // Is the flow a valid, exportable flow or not?
	firstTime int64 // The time of the first packet in the flow
	flast int64 // The time of the last packet in the forward direction
	blast int64 // The time of the last packet in the backward direction
	cstate tcpState // Connection state of the client
	sstate tcpState // Connection state of the server
	hasData bool // Whether the connection has had any data transmitted.
	pdir int8 // Direction of the current packet
	srcip string // IP address of the source (client)
	srcport uint16 // Port number of the source connection
	dstip string // IP address of the destination (server)
	dstport uint16 // Port number of the destionation connection.
	proto uint8 // The IP protocol being used for the connection.
}

func (f *Flow) Init(srcip string, 
	                srcport uint16, 
	                dstip string,
	                dstport uint16,
	                proto uint8,
            	    pkt packet, 
                    id int64) {
	f.f = make(map[string]int64, 44)
	f.c = make(map[string]int64, 15)
	f.id = id
	f.firstPacket = pkt
	f.valid = false
	for i := 0; i < len(features); i++ {
		f.f[features[i]] = 0
	}
	for i := 0; i < len(counters); i++ {
		f.c[counters[i]] = 0
	}
	// Basic flow identification criteria
    f.srcip = srcip
    f.srcport = srcport
    f.dstip = dstip
    f.dstport = dstport
    f.proto = proto
    f.f["dscp"] = pkt["dscp"]
	// ---------------------------------------------------------
	f.f["total_fpackets"] = 1
	length := pkt["len"]
    f.f["total_fvolume"] = length
    f.f["min_fpktl"] = length
    f.f["max_fpktl"] = length
    f.c["fpktl_sqsum"] = (length * length)
	f.firstTime = pkt["time"]
	f.flast = f.firstTime
    f.c["active_start"] = f.firstTime
	if f.proto == IP_TCP {
		// TCP specific code:
		f.cstate.State = TCP_STATE_START
		f.sstate.State = TCP_STATE_START
		if (tcpSet(pkt["flags"], TCP_PSH)) {
			f.f["fpsh_cnt"] = 1
		}
        if (tcpSet(pkt["flags"], TCP_URG)) {
			f.f["furg_cnt"] = 1
		}
	}
	f.f["total_fhlen"] = pkt["iphlen"] + pkt["prhlen"]

	f.hasData = false
	f.pdir = P_FORWARD
	f.updateStatus(pkt)
	return
}

func (f *Flow) updateTcpState(pkt packet) {
	f.cstate.TcpUpdate(pkt["flags"], P_FORWARD, f.pdir)
	f.sstate.TcpUpdate(pkt["flags"], P_BACKWARD, f.pdir)
}

func (f *Flow) updateStatus(pkt packet) {
	if f.proto == IP_UDP {
		if f.valid { return }
		if pkt["len"] > 8 {
			f.hasData = true
		}
		if f.hasData && (f.f["total_bpackets"] > 0) {
			f.valid = true
		}
	} else if f.proto == IP_TCP {
		if !f.valid {
			if f.cstate.State == TCP_STATE_ESTABLISHED {
				if pkt["len"] > (pkt["iphlen"] + pkt["prhlen"]) {
					f.valid = true
				}
			}
		}
		f.updateTcpState(pkt)
	}
}

func (f *Flow) getLastTime() int64 {
	if f.blast == 0 { return f.flast } 
	if f.flast == 0 { return f.blast }
	if f.flast > f.blast { return f.flast }
	return f.blast
}

func (f *Flow) Add(pkt packet, srcip string) int {
	now := pkt["time"]
	last := f.getLastTime()
	diff := now - last
	if diff > FLOW_TIMEOUT {
		fmt.Printf("diff: %d now: %d last %d\n", diff, now, last)
		return 2
	}
	if now < last {
		log.Printf("Flow: ignoring reordered packet. %d < %d\n", now, last)
		return 0
	}
	length := pkt["len"]
	hlen := pkt["iphlen"] + pkt["prhlen"]
//	log.Printf("hlen: %d\n iphlen: %d prhlen: %d", 
//		hlen, 
//		pkt["iphlen"], 
//		pkt["prhlen"])
	if (now < f.firstTime) {
		log.Fatalf("Current packet is before start of flow. %d < %d\n", 
			now, 
			f.firstTime)
	}
	if srcip == f.srcip {
		f.pdir = P_FORWARD // Forward
	} else {
		f.pdir = P_BACKWARD
	}
	if diff > IDLE_THRESHOLD {
		if diff > f.f["max_idle"] {
			f.f["max_idle"] = diff
		}
		if (diff < f.f["min_idle"]) || 
			(f.f["min_idle"] == 0) {
			f.f["min_idle"] = diff
		}
		f.c["idle_time"] += diff
        f.c["idle_sqsum"] += (diff * diff)
        f.c["idle_count"]++
        // Active time stats - calculated by looking at the previous packet
        // time and the packet time for when the last idle time ended.
        diff = last - f.c["active_start"]
        if diff > f.f["max_active"] {
			f.f["max_active"] = diff
		}
        if (diff < f.f["min_active"]) || 
			(f.f["min_active"] == 0) {
			f.f["min_active"] = diff
		}
        f.c["active_time"] += diff
        f.c["active_sqsum"] += (diff * diff)
        f.c["active_count"]++
        f.flast = 0
        f.blast = 0
        f.c["active_start"] = now
	}
	if f.pdir == P_FORWARD {
		// Packet is travelling in the forward direction
        // Calculate some statistics
        // Packet length
        if (length < f.f["min_fpktl"]) || (f.f["min_fpktl"] == 0) {
			f.f["min_fpktl"] = length
		}
        if length > f.f["max_fpktl"] {
			f.f["max_fpktl"] = length
		}
		f.f["total_fvolume"] += length // Doubles up as c_fpktl_sum from NM
		f.c["fpktl_sqsum"] += (length * length)
		f.f["total_fpackets"]++
		f.f["total_fhlen"] += hlen
        // Interarrival time
		if f.flast > 0 {
			diff = now - f.flast
			if (diff < f.f["min_fiat"]) || (f.f["min_fiat"] == 0) {
				f.f["min_fiat"] = diff
			}
			if diff > f.f["max_fiat"] {
				f.f["max_fiat"] = diff
			}
            f.c["fiat_sum"] += diff
            f.c["fiat_sqsum"] += (diff * diff)
            f.c["fiat_count"]++
		}
        if f.proto == IP_TCP {
			// Packet is using TCP protocol
            if (tcpSet(pkt["flags"], TCP_PSH)) {
				f.f["fpsh_cnt"]++
			}
			if (tcpSet(pkt["flags"], TCP_URG)) {
                f.f["furg_cnt"]++
			}
			// Update the last forward packet time stamp
		}
		f.flast = now
	} else {
		// Packet is travelling in the backward direction, check if dscp is
        // set in this direction
        if f.blast == 0 && f.f["dscp"] == 0 {
			// Check only first packet in backward dir, and make sure it has
            // not been set already.
            f.f["dscp"] = pkt["dscp"]
		}
		// Calculate some statistics
        // Packet length
		if length < f.f["min_bpktl"] || f.f["min_bpktl"] == 0 {
			f.f["min_bpktl"] = length
		}
		if length > f.f["max_bpktl"] {
			f.f["max_bpktl"] = length
		}
		f.f["total_bvolume"] += length // Doubles up as c_bpktl_sum from NM
		f.c["bpktl_sqsum"] += (length * length)
		f.f["total_bpackets"]++
		f.f["total_bhlen"] += hlen
        // Inter-arrival time
		if f.blast > 0 {
			diff = now - f.blast
			if (diff < f.f["min_biat"]) || (f.f["min_biat"] == 0) {
				f.f["min_biat"] = diff
			}
			if diff > f.f["max_biat"] {
				f.f["max_biat"] = diff
			}
			f.c["biat_sum"] += diff
			f.c["biat_sqsum"] += (diff * diff)
			f.c["biat_count"]++
		}
		if f.proto == IP_TCP {
            // Packet is using TCP protocol
			if (tcpSet(pkt["flags"], TCP_PSH)) {
				f.f["bpsh_cnt"]++
			}
			if (tcpSet(pkt["flags"], TCP_URG)) {
				f.f["burg_cnt"]++
			}
		}
		// Update the last backward packet time stamp
		f.blast = now
	}

	// Update the status (validity, TCP connection state) of the flow.
    f.updateStatus(pkt)            

    if (f.proto == IP_TCP &&
		f.cstate.State == TCP_STATE_CLOSED &&
		f.sstate.State == TCP_STATE_CLOSED) {
        return 1
	}
    return 0
}

func (f *Flow) Export() {
	if !f.valid { return }
	fmt.Printf("%s,%d,%s,%d,%d", 
		f.srcip, 
		f.srcport, 
		f.dstip, 
		f.dstport, 
		f.proto)

	// -----------------------------------
	// First, lets consider the last active time in the calculations in case
	// this changes something.
	// -----------------------------------
	diff := f.getLastTime() - f.c["active_start"]
	if diff > f.f["max_active"] {
		f.f["max_active"] = diff
	}
	if (diff < f.f["min_active"]) || (f.f["min_active"] == 0) {
		f.f["min_active"] = diff
	}
	f.c["active_time"] += diff
	f.c["active_sqsum"] += (diff * diff)
	f.c["active_count"]++

	if (f.f["total_fpackets"] <= 0) {
		log.Fatalf("total_fpackets (%d) <= 0\n", f.f["total_fpackets"])
	}
	f.f["mean_fpktl"] = f.f["total_fvolume"] / f.f["total_fpackets"]
	//Standard deviation of packets in the forward direction
	if f.f["total_fpackets"] > 1 {
		f.f["std_fpktl"] = stddev(f.c["fpktl_sqsum"], 
			                      f.f["total_fvolume"],
                                  f.f["total_fpackets"])
	} else {
		f.f["std_fpktl"] = 0
	}
	// Mean packet length of packets in the packward direction
    if f.f["total_bpackets"] > 0 {
		f.f["mean_bpktl"] = f.f["total_bvolume"] / f.f["total_bpackets"]
	} else {
		f.f["mean_bpktl"] = -1
	}
	// Standard deviation of packets in the backward direction
    if f.f["total_bpackets"] > 1 {
		f.f["std_bpktl"] = stddev(f.c["bpktl_sqsum"],
                                  f.f["total_bvolume"],
                                  f.f["total_bpackets"])
	} else {
		f.f["std_bpktl"] = 0
	}
	// Mean forward inter-arrival time
    // TODO: Check if we actually need c_fiat_count ?
    if f.c["fiat_count"] > 0 {
		f.f["mean_fiat"] = f.c["fiat_sum"] / f.c["fiat_count"]
	} else {
		f.f["mean_fiat"] = 0
	}
	// Standard deviation of forward inter-arrival times
    if f.c["fiat_count"] > 1 {
		f.f["std_fiat"] = stddev(f.c["fiat_sqsum"],
                                 f.c["fiat_sum"],
                       		     f.c["fiat_count"])
	} else {
		f.f["std_fiat"] = 0
	}
	// Mean backward inter-arrival time
    if f.c["biat_count"] > 0 {
		f.f["mean_biat"] = f.c["biat_sum"] / f.c["biat_count"]
	} else {
		f.f["mean_biat"] = 0
	}
	// Standard deviation of backward inter-arrival times
    if f.c["biat_count"] > 1 {
		f.f["std_biat"] = stddev(f.c["biat_sqsum"],
                                 f.c["biat_sum"],
			                     f.c["biat_count"])
	} else {
		f.f["std_biat"] = 0
	}
	// Mean active time of the sub-flows
    if f.c["active_count"] > 0 {
		f.f["mean_active"] = f.c["active_time"] / f.c["active_count"]
	} else {
        // There should be packets in each direction if we're exporting 
        log.Fatalln("ERR: This shouldn't happen")
	}
	// Standard deviation of active times of sub-flows
    if f.c["active_count"] > 1 {
		f.f["std_active"] = stddev(f.c["active_sqsum"],
                                   f.c["active_time"],
			                       f.c["active_count"])
	} else {
		f.f["std_active"] = 0
	}
	// Mean of idle times between sub-flows
    if f.c["idle_count"] > 0 {
		f.f["mean_idle"] = f.c["idle_time"] / f.c["idle_count"]
	} else {
		f.f["mean_idle"] = 0
	}
	// Standard deviation of idle times between sub-flows
    if f.c["idle_count"] > 1 {
		f.f["std_idle"] = stddev(f.c["idle_sqsum"],
                               f.c["idle_time"],
                               f.c["idle_count"])
    } else {
		f.f["std_idle"] = 0
	}
	// More sub-flow calculations
    if f.c["active_count"] > 0 {
		f.f["sflow_fpackets"] = f.f["total_fpackets"] / f.c["active_count"]
		f.f["sflow_fbytes"]   = f.f["total_fvolume"]  / f.c["active_count"]
		f.f["sflow_bpackets"] = f.f["total_bpackets"] / f.c["active_count"]
		f.f["sflow_bbytes"]   = f.f["total_bvolume"]  / f.c["active_count"]
	}
	f.f["duration"] = f.getLastTime() - f.firstTime
	if f.f["duration"] < 0 {
		log.Fatalf("duration (%d) < 0", f.f["duration"])
	}
	
	// ---------------------------------
	// Update Flow stats which require counters or other final calculations
	// ---------------------------------
	
	for i:=0; i < len(features); i++ {
		fmt.Printf(",%d", f.f[features[i]])
	}
	fmt.Println()
}

func (f *Flow) CheckIdle(time int64) bool {
	if (time - f.getLastTime()) > FLOW_TIMEOUT {
		return true
	}
	return false
}