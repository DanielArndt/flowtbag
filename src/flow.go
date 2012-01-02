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
    // To add new features, add the name here, then inititialize the
    // value in init(), and calculate it in add(). You can finalize it
    // in Export()
    TOTAL_FPACKETS = iota
    TOTAL_FVOLUME
    TOTAL_BPACKETS
    TOTAL_BVOLUME
    MIN_FPKTL
    MEAN_FPKTL
    MAX_FPKTL
    STD_FPKTL
    MIN_BPKTL
    MEAN_BPKTL
    MAX_BPKTL
    STD_BPKTL
    MIN_FIAT
    MEAN_FIAT
    MAX_FIAT
    STD_FIAT
    MIN_BIAT
    MEAN_BIAT
    MAX_BIAT
    STD_BIAT
    DURATION
    MIN_ACTIVE
    MEAN_ACTIVE
    MAX_ACTIVE
    STD_ACTIVE
    MIN_IDLE
    MEAN_IDLE
    MAX_IDLE
    STD_IDLE
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
    DSCP
    NUM_FEATURES
)

const (
    FPKTL_SQSUM = iota
    BPKTL_SQSUM
    FIAT_SUM
    FIAT_SQSUM
    FIAT_COUNT
    BIAT_SUM
    BIAT_SQSUM
    BIAT_COUNT
    ACTIVE_START
    ACTIVE_TIME
    ACTIVE_SQSUM
    ACTIVE_COUNT
    IDLE_TIME
    IDLE_SQSUM
    IDLE_COUNT
    NUM_COUNTERS
)

type Flow struct {
    f    []int64            // A map of the features to be exported
    c    []int64            // A map of counters used for calculations
    bins map[string]Feature // A map of binning features

    valid     bool     // Is the flow a valid, exportable flow or not?
    firstTime int64    // The time of the first packet in the flow
    flast     int64    // The time of the last packet in the forward direction
    blast     int64    // The time of the last packet in the backward direction
    cstate    tcpState // Connection state of the client
    sstate    tcpState // Connection state of the server
    hasData   bool     // Whether the connection has had any data transmitted.
    pdir      int8     // Direction of the current packet
    srcip     string   // IP address of the source (client)
    srcport   uint16   // Port number of the source connection
    dstip     string   // IP address of the destination (server)
    dstport   uint16   // Port number of the destionation connection.
    proto     uint8    // The IP protocol being used for the connection.
}

func (f *Flow) Init(srcip string,
    srcport uint16,
    dstip string,
    dstport uint16,
    proto uint8,
    pkt packet,
    id int64) {
    f.f = make([]int64, NUM_FEATURES)
    f.c = make([]int64, NUM_COUNTERS)
    f.valid = false
    for i := 0; i < NUM_FEATURES; i++ {
        f.f[i] = 0
    }
    for i := 0; i < NUM_COUNTERS; i++ {
        f.c[i] = 0
    }
    // Basic flow identification criteria
    f.srcip = srcip
    f.srcport = srcport
    f.dstip = dstip
    f.dstport = dstport
    f.proto = proto
    f.f[DSCP] = pkt["dscp"]
    // ---------------------------------------------------------
    f.f[TOTAL_FPACKETS] = 1
    length := pkt["len"]
    f.f[TOTAL_FVOLUME] = length
    f.f[MIN_FPKTL] = length
    f.f[MAX_FPKTL] = length
    f.c[FPKTL_SQSUM] = (length * length)
    f.firstTime = pkt["time"]
    f.flast = f.firstTime
    f.c[ACTIVE_START] = f.firstTime
    if f.proto == IP_TCP {
        // TCP specific code:
        f.cstate.State = TCP_STATE_START
        f.sstate.State = TCP_STATE_START
        if tcpSet(TCP_PSH, pkt["flags"]) {
            f.f[FPSH_CNT] = 1
        }
        if tcpSet(TCP_URG, pkt["flags"]) {
            f.f[FURG_CNT] = 1
        }
    }
    f.f[TOTAL_FHLEN] = pkt["iphlen"] + pkt["prhlen"]

    f.bins = make(map[string]Feature)
    var binFeat *BinFeature
    binFeat = new(BinFeature)
    binFeat.Init(0, 250, 10)
    binFeat.Add(length)
    f.bins["fpktl"] = binFeat
    binFeat = new(BinFeature)
    binFeat.Init(0, 250, 10)
    f.bins["bpktl"] = binFeat
    binFeat = new(BinFeature)
    binFeat.Init(0, 200000, 10)
    f.bins["fiat"] = binFeat
    binFeat = new(BinFeature)
    binFeat.Init(0, 200000, 10)
    f.bins["biat"] = binFeat

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
        if f.hasData && (f.f[TOTAL_BPACKETS] > 0) {
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
        return 2
    }
    if now < last {
        log.Printf("Flow: ignoring reordered packet. %d < %d\n", now, last)
        return 0
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
        if diff > f.f[MAX_IDLE] {
            f.f[MAX_IDLE] = diff
        }
        if (diff < f.f[MIN_IDLE]) ||
            (f.f[MIN_IDLE] == 0) {
            f.f[MIN_IDLE] = diff
        }
        f.c[IDLE_TIME] += diff
        f.c[IDLE_SQSUM] += (diff * diff)
        f.c[IDLE_COUNT]++
        // Active time stats - calculated by looking at the previous packet
        // time and the packet time for when the last idle time ended.
        diff = last - f.c[ACTIVE_START]
        if diff > f.f[MAX_ACTIVE] {
            f.f[MAX_ACTIVE] = diff
        }
        if (diff < f.f[MIN_ACTIVE]) ||
            (f.f[MIN_ACTIVE] == 0) {
            f.f[MIN_ACTIVE] = diff
        }
        f.c[ACTIVE_TIME] += diff
        f.c[ACTIVE_SQSUM] += (diff * diff)
        f.c[ACTIVE_COUNT]++
        f.flast = 0
        f.blast = 0
        f.c[ACTIVE_START] = now
    }
    if f.pdir == P_FORWARD {
        if f.f[DSCP] == 0 {
            f.f[DSCP] = pkt["dscp"]
        }
        // Packet is travelling in the forward direction
        // Calculate some statistics
        // Packet length
        if (length < f.f[MIN_FPKTL]) || (f.f[MIN_FPKTL] == 0) {
            f.f[MIN_FPKTL] = length
        }
        if length > f.f[MAX_FPKTL] {
            f.f[MAX_FPKTL] = length
        }
        f.f[TOTAL_FVOLUME] += length // Doubles up as c_fpktl_sum from NM
        f.c[FPKTL_SQSUM] += (length * length)
        f.f[TOTAL_FPACKETS]++
        f.f[TOTAL_FHLEN] += hlen
        // Interarrival time
        if f.flast > 0 {
            diff = now - f.flast
            if (diff < f.f[MIN_FIAT]) || (f.f[MIN_FIAT] == 0) {
                f.f[MIN_FIAT] = diff
            }
            if diff > f.f[MAX_FIAT] {
                f.f[MAX_FIAT] = diff
            }
            f.c[FIAT_SUM] += diff
            f.c[FIAT_SQSUM] += (diff * diff)
            f.c[FIAT_COUNT]++
            f.bins["fiat"].Add(diff)
        }
        if f.proto == IP_TCP {
            // Packet is using TCP protocol
            if tcpSet(TCP_PSH, pkt["flags"]) {
                f.f[FPSH_CNT]++
            }
            if tcpSet(TCP_URG, pkt["flags"]) {
                f.f[FURG_CNT]++
            }
            // Update the last forward packet time stamp
        }
        f.bins["fpktl"].Add(length)
        f.flast = now
    } else {
        // Packet is travelling in the backward direction
        if f.f[DSCP] == 0 {
            f.f[DSCP] = pkt["dscp"]
        }
        // Calculate some statistics
        // Packet length
        if length < f.f[MIN_BPKTL] || f.f[MIN_BPKTL] == 0 {
            f.f[MIN_BPKTL] = length
        }
        if length > f.f[MAX_BPKTL] {
            f.f[MAX_BPKTL] = length
        }
        f.f[TOTAL_BVOLUME] += length // Doubles up as c_bpktl_sum from NM
        f.c[BPKTL_SQSUM] += (length * length)
        f.f[TOTAL_BPACKETS]++
        f.f[TOTAL_BHLEN] += hlen
        // Inter-arrival time
        if f.blast > 0 {
            diff = now - f.blast
            if (diff < f.f[MIN_BIAT]) || (f.f[MIN_BIAT] == 0) {
                f.f[MIN_BIAT] = diff
            }
            if diff > f.f[MAX_BIAT] {
                f.f[MAX_BIAT] = diff
            }
            f.c[BIAT_SUM] += diff
            f.c[BIAT_SQSUM] += (diff * diff)
            f.c[BIAT_COUNT]++
            f.bins["biat"].Add(diff)
        }
        if f.proto == IP_TCP {
            // Packet is using TCP protocol
            if tcpSet(TCP_PSH, pkt["flags"]) {
                f.f[BPSH_CNT]++
            }
            if tcpSet(TCP_URG, pkt["flags"]) {
                f.f[BURG_CNT]++
            }
        }
        f.bins["bpktl"].Add(length)
        // Update the last backward packet time stamp
        f.blast = now
    }

    // Update the status (validity, TCP connection state) of the flow.
    f.updateStatus(pkt)

    if f.proto == IP_TCP &&
        f.cstate.State == TCP_STATE_CLOSED &&
        f.sstate.State == TCP_STATE_CLOSED {
        return 1
    }
    return 0
}

func (f *Flow) Export() {
    if !f.valid {
        return
    }

    // -----------------------------------
    // First, lets consider the last active time in the calculations in case
    // this changes something.
    // -----------------------------------
    diff := f.getLastTime() - f.c[ACTIVE_START]
    if diff > f.f[MAX_ACTIVE] {
        f.f[MAX_ACTIVE] = diff
    }
    if (diff < f.f[MIN_ACTIVE]) || (f.f[MIN_ACTIVE] == 0) {
        f.f[MIN_ACTIVE] = diff
    }
    f.c[ACTIVE_TIME] += diff
    f.c[ACTIVE_SQSUM] += (diff * diff)
    f.c[ACTIVE_COUNT]++

    if f.f[TOTAL_FPACKETS] <= 0 {
        log.Fatalf("total_fpackets (%d) <= 0\n", f.f[TOTAL_FPACKETS])
    }

    // ---------------------------------
    // Update Flow stats which require counters or other final calculations
    // ---------------------------------
    f.f[MEAN_FPKTL] = f.f[TOTAL_FVOLUME] / f.f[TOTAL_FPACKETS]
    //Standard deviation of packets in the forward direction
    if f.f[TOTAL_FPACKETS] > 1 {
        f.f[STD_FPKTL] = stddev(f.c[FPKTL_SQSUM], f.f[TOTAL_FVOLUME], f.f[TOTAL_FPACKETS])
    } else {
        f.f[STD_FPKTL] = 0
    }
    // Mean packet length of packets in the packward direction
    if f.f[TOTAL_BPACKETS] > 0 {
        f.f[MEAN_BPKTL] = f.f[TOTAL_BVOLUME] / f.f[TOTAL_BPACKETS]
    } else {
        f.f[MEAN_BPKTL] = -1
    }
    // Standard deviation of packets in the backward direction
    if f.f[TOTAL_BPACKETS] > 1 {
        f.f[STD_BPKTL] = stddev(f.c[BPKTL_SQSUM],
            f.f[TOTAL_BVOLUME],
            f.f[TOTAL_BPACKETS])
    } else {
        f.f[STD_BPKTL] = 0
    }
    // Mean forward inter-arrival time
    // TODO: Check if we actually need c_fiat_count ?
    if f.c[FIAT_COUNT] > 0 {
        f.f[MEAN_FIAT] = f.c[FIAT_SUM] / f.c[FIAT_COUNT]
    } else {
        f.f[MEAN_FIAT] = 0
    }
    // Standard deviation of forward inter-arrival times
    if f.c[FIAT_COUNT] > 1 {
        f.f[STD_FIAT] = stddev(f.c[FIAT_SQSUM],
            f.c[FIAT_SUM],
            f.c[FIAT_COUNT])
    } else {
        f.f[STD_FIAT] = 0
    }
    // Mean backward inter-arrival time
    if f.c[BIAT_COUNT] > 0 {
        f.f[MEAN_BIAT] = f.c[BIAT_SUM] / f.c[BIAT_COUNT]
    } else {
        f.f[MEAN_BIAT] = 0
    }
    // Standard deviation of backward inter-arrival times
    if f.c[BIAT_COUNT] > 1 {
        f.f[STD_BIAT] = stddev(f.c[BIAT_SQSUM],
            f.c[BIAT_SUM],
            f.c[BIAT_COUNT])
    } else {
        f.f[STD_BIAT] = 0
    }
    // Mean active time of the sub-flows
    if f.c[ACTIVE_COUNT] > 0 {
        f.f[MEAN_ACTIVE] = f.c[ACTIVE_TIME] / f.c[ACTIVE_COUNT]
    } else {
        // There should be packets in each direction if we're exporting 
        log.Fatalln("ERR: This shouldn't happen")
    }
    // Standard deviation of active times of sub-flows
    if f.c[ACTIVE_COUNT] > 1 {
        f.f[STD_ACTIVE] = stddev(f.c[ACTIVE_SQSUM],
            f.c[ACTIVE_TIME],
            f.c[ACTIVE_COUNT])
    } else {
        f.f[STD_ACTIVE] = 0
    }
    // Mean of idle times between sub-flows
    if f.c[IDLE_COUNT] > 0 {
        f.f[MEAN_IDLE] = f.c[IDLE_TIME] / f.c[IDLE_COUNT]
    } else {
        f.f[MEAN_IDLE] = 0
    }
    // Standard deviation of idle times between sub-flows
    if f.c[IDLE_COUNT] > 1 {
        f.f[STD_IDLE] = stddev(f.c[IDLE_SQSUM],
            f.c[IDLE_TIME],
            f.c[IDLE_COUNT])
    } else {
        f.f[STD_IDLE] = 0
    }
    // More sub-flow calculations
    if f.c[ACTIVE_COUNT] > 0 {
        f.f[SFLOW_FPACKETS] = f.f[TOTAL_FPACKETS] / f.c[ACTIVE_COUNT]
        f.f[SFLOW_FBYTES] = f.f[TOTAL_FVOLUME] / f.c[ACTIVE_COUNT]
        f.f[SFLOW_BPACKETS] = f.f[TOTAL_BPACKETS] / f.c[ACTIVE_COUNT]
        f.f[SFLOW_BBYTES] = f.f[TOTAL_BVOLUME] / f.c[ACTIVE_COUNT]
    }
    f.f[DURATION] = f.getLastTime() - f.firstTime
    if f.f[DURATION] < 0 {
        log.Fatalf("duration (%d) < 0", f.f[DURATION])
    }

    fmt.Printf("%s,%d,%s,%d,%d",
        f.srcip,
        f.srcport,
        f.dstip,
        f.dstport,
        f.proto)
    for i := 0; i < NUM_FEATURES-1; i++ {
        fmt.Printf(",%d", f.f[i])
    }
    fmt.Printf(",%s", f.bins["fpktl"].Export())
    fmt.Printf(",%s", f.bins["bpktl"].Export())
    fmt.Printf(",%s", f.bins["fiat"].Export())
    fmt.Printf(",%s", f.bins["biat"].Export())
    fmt.Printf(",%d", f.f[NUM_FEATURES-1])
    fmt.Println()
}

func (f *Flow) CheckIdle(time int64) bool {
    if (time - f.getLastTime()) > FLOW_TIMEOUT {
        return true
    }
    return false
}
