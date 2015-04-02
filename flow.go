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
	IP_TCP = 6
	IP_UDP = 17

	P_FORWARD  = 0
	P_BACKWARD = 1

	ADD_SUCCESS = 0
	ADD_CLOSED  = 1
	ADD_IDLE    = 2
)

const (
	// Configurables. These should at some point be read in from a configuration
	// file.
	FLOW_TIMEOUT   = 600000000
	IDLE_THRESHOLD = 1000000
)

// This is how we represent each packet after it is decoded. A simple map from the
// string value for it's name to the value
type packet map[string]int64

const (
	// To add new features, add the name here, then initialize the
	// value in init(), and calculate it in add(). You can finalize it
	// in Export()
	TOTAL_FPACKETS = iota
	TOTAL_FVOLUME
	TOTAL_BPACKETS
	TOTAL_BVOLUME
	FPKTL
	BPKTL
	FIAT
	BIAT
	DURATION
	ACTIVE
	IDLE
	SFLOW_FPACKETS
	SFLOW_FBYTES
	SFLOW_BPACKETS
	SFLOW_BBYTES
	FPSH_CNT
	BPSH_CNT
	FURG_CNT
	BURG_CNT
	TOTAL_FHLEN
	TOTAL_BHLEN
	NUM_FEATURES // Not a real feature. Just the total number of features.
)

type Flow struct {
	f []Feature // A map of the features to be exported

	valid       bool     // Has the flow met the requirements of a bi-directional flow
	activeStart int64    // The starting time of the latest activity
	firstTime   int64    // The time of the first packet in the flow
	flast       int64    // The time of the last packet in the forward direction
	blast       int64    // The time of the last packet in the backward direction
	cstate      tcpState // Connection state of the client
	sstate      tcpState // Connection state of the server
	hasData     bool     // Whether the connection has had any data transmitted.
	isBidir     bool     // Is the flow bi-directional?
	pdir        int8     // Direction of the current packet
	srcip       string   // IP address of the source (client)
	srcport     uint16   // Port number of the source connection
	dstip       string   // IP address of the destination (server)
	dstport     uint16   // Port number of the destionation connection.
	proto       uint8    // The IP protocol being used for the connection.
	dscp        uint8    // The first set DSCP field for the flow.
}

func (f *Flow) Init(srcip string,
	srcport uint16,
	dstip string,
	dstport uint16,
	proto uint8,
	pkt packet,
	id int64) {
	f.f = make([]Feature, NUM_FEATURES)
	f.valid = false
	f.f[TOTAL_FPACKETS] = new(ValueFeature)
	f.f[TOTAL_FVOLUME] = new(ValueFeature)
	f.f[TOTAL_BPACKETS] = new(ValueFeature)
	f.f[TOTAL_BVOLUME] = new(ValueFeature)
	f.f[FPKTL] = new(DistributionFeature)
	f.f[BPKTL] = new(DistributionFeature)
	f.f[FIAT] = new(DistributionFeature)
	f.f[BIAT] = new(DistributionFeature)
	f.f[DURATION] = new(ValueFeature)
	f.f[ACTIVE] = new(DistributionFeature)
	f.f[IDLE] = new(DistributionFeature)
	f.f[SFLOW_FPACKETS] = new(ValueFeature)
	f.f[SFLOW_FBYTES] = new(ValueFeature)
	f.f[SFLOW_BPACKETS] = new(ValueFeature)
	f.f[SFLOW_BBYTES] = new(ValueFeature)
	f.f[FPSH_CNT] = new(ValueFeature)
	f.f[BPSH_CNT] = new(ValueFeature)
	f.f[FURG_CNT] = new(ValueFeature)
	f.f[BURG_CNT] = new(ValueFeature)
	f.f[TOTAL_FHLEN] = new(ValueFeature)
	f.f[TOTAL_BHLEN] = new(ValueFeature)
	//for i := 0; i < NUM_FEATURES; i++ {
	//    f.f[i].Set(0)
	//}
	// Basic flow identification criteria
	f.srcip = srcip
	f.srcport = srcport
	f.dstip = dstip
	f.dstport = dstport
	f.proto = proto
	f.dscp = uint8(pkt["dscp"])
	// ---------------------------------------------------------
	f.f[TOTAL_FPACKETS].Set(1)
	length := pkt["len"]
	f.f[TOTAL_FVOLUME].Set(length)
	f.f[FPKTL].Add(length)
	f.firstTime = pkt["time"]
	f.flast = f.firstTime
	f.activeStart = f.firstTime
	if f.proto == IP_TCP {
		// TCP specific code:
		f.cstate.State = TCP_STATE_START
		f.sstate.State = TCP_STATE_START
		if tcpSet(TCP_PSH, pkt["flags"]) {
			f.f[FPSH_CNT].Set(1)
		}
		if tcpSet(TCP_URG, pkt["flags"]) {
			f.f[FURG_CNT].Set(1)
		}
	}
	f.f[TOTAL_FHLEN].Set(pkt["iphlen"] + pkt["prhlen"])

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
		if f.valid {
			return
		}
		if pkt["len"] > 8 {
			f.hasData = true
		}
		if f.hasData && f.isBidir {
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
	if f.blast == 0 {
		return f.flast
	}
	if f.flast == 0 {
		return f.blast
	}
	if f.flast > f.blast {
		return f.flast
	}
	return f.blast
}

func (f *Flow) Add(pkt packet, srcip string) int {
	now := pkt["time"]
	last := f.getLastTime()
	diff := now - last
	if diff > FLOW_TIMEOUT {
		return ADD_IDLE
	}
	if now < last {
		log.Printf("Flow: ignoring reordered packet. %d < %d\n", now, last)
		return ADD_SUCCESS
	}
	length := pkt["len"]
	hlen := pkt["iphlen"] + pkt["prhlen"]
	if now < f.firstTime {
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
		f.f[IDLE].Add(diff)
		// Active time stats - calculated by looking at the previous packet
		// time and the packet time for when the last idle time ended.
		diff = last - f.activeStart
		f.f[ACTIVE].Add(diff)

		f.flast = 0
		f.blast = 0
		f.activeStart = now
	}
	if f.pdir == P_FORWARD {
		if f.dscp == 0 {
			f.dscp = uint8(pkt["dscp"])
		}
		// Packet is travelling in the forward direction
		// Calculate some statistics
		// Packet length
		f.f[FPKTL].Add(length)
		f.f[TOTAL_FVOLUME].Add(length)
		f.f[TOTAL_FPACKETS].Add(1)
		f.f[TOTAL_FHLEN].Add(hlen)
		// Interarrival time
		if f.flast > 0 {
			diff = now - f.flast
			f.f[FIAT].Add(diff)
		}
		if f.proto == IP_TCP {
			// Packet is using TCP protocol
			if tcpSet(TCP_PSH, pkt["flags"]) {
				f.f[FPSH_CNT].Add(1)
			}
			if tcpSet(TCP_URG, pkt["flags"]) {
				f.f[FURG_CNT].Add(1)
			}
			// Update the last forward packet time stamp
		}
		f.flast = now
	} else {
		// Packet is travelling in the backward direction
		f.isBidir = true
		if f.dscp == 0 {
			f.dscp = uint8(pkt["dscp"])
		}
		// Calculate some statistics
		// Packet length
		f.f[BPKTL].Add(length)
		f.f[TOTAL_BVOLUME].Add(length) // Doubles up as c_bpktl_sum from NM
		f.f[TOTAL_BPACKETS].Add(1)
		f.f[TOTAL_BHLEN].Add(hlen)
		// Inter-arrival time
		if f.blast > 0 {
			diff = now - f.blast
			f.f[BIAT].Add(diff)
		}
		if f.proto == IP_TCP {
			// Packet is using TCP protocol
			if tcpSet(TCP_PSH, pkt["flags"]) {
				f.f[BPSH_CNT].Add(1)
			}
			if tcpSet(TCP_URG, pkt["flags"]) {
				f.f[BURG_CNT].Add(1)
			}
		}
		// Update the last backward packet time stamp
		f.blast = now
	}

	// Update the status (validity, TCP connection state) of the flow.
	f.updateStatus(pkt)

	if f.proto == IP_TCP &&
		f.cstate.State == TCP_STATE_CLOSED &&
		f.sstate.State == TCP_STATE_CLOSED {
		return ADD_CLOSED
	}
	return ADD_SUCCESS
}

func (f *Flow) Export() {
	if !f.valid {
		return
	}

	// -----------------------------------
	// First, lets consider the last active time in the calculations in case
	// this changes something.
	// -----------------------------------
	diff := f.getLastTime() - f.activeStart
	f.f[ACTIVE].Add(diff)

	// ---------------------------------
	// Update Flow stats which require counters or other final calculations
	// ---------------------------------

	// More sub-flow calculations
	if f.f[ACTIVE].Get() > 0 {
		f.f[SFLOW_FPACKETS].Set(f.f[TOTAL_FPACKETS].Get() / f.f[ACTIVE].Get())
		f.f[SFLOW_FBYTES].Set(f.f[TOTAL_FVOLUME].Get() / f.f[ACTIVE].Get())
		f.f[SFLOW_BPACKETS].Set(f.f[TOTAL_BPACKETS].Get() / f.f[ACTIVE].Get())
		f.f[SFLOW_BBYTES].Set(f.f[TOTAL_BVOLUME].Get() / f.f[ACTIVE].Get())
	}
	f.f[DURATION].Set(f.getLastTime() - f.firstTime)
	if f.f[DURATION].Get() < 0 {
		log.Fatalf("duration (%d) < 0", f.f[DURATION])
	}

	fmt.Printf("%s,%d,%s,%d,%d",
		f.srcip,
		f.srcport,
		f.dstip,
		f.dstport,
		f.proto)
	for i := 0; i < NUM_FEATURES; i++ {
		fmt.Printf(",%s", f.f[i].Export())
	}
	fmt.Printf(",%d", f.dscp)
	fmt.Println()
}

func (f *Flow) CheckIdle(time int64) bool {
	if (time - f.getLastTime()) > FLOW_TIMEOUT {
		return true
	}
	return false
}
