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

var feat map[string]int = map[string]int{
        // To add new features, add the name here, then inititialize the
        // value in init(), and calculate it in add(). You can finalize it
        // in Export()
        "total_fpackets": 0,
        "total_fvolume":  1,
        "total_bpackets": 2,
        "total_bvolume":  3,
        "min_fpktl":      4,
        "mean_fpktl":     5,
        "max_fpktl":      6,
        "std_fpktl":      7,
        "min_bpktl":      8,
        "mean_bpktl":     9,
        "max_bpktl":      10,
        "std_bpktl":      11,
        "min_fiat":       12,
        "mean_fiat":      13,
        "max_fiat":       14,
        "std_fiat":       15,
        "min_biat":       16,
        "mean_biat":      17,
        "max_biat":       18,
        "std_biat":       19,
        "duration":       20,
        "min_active":     21,
        "mean_active":    22,
        "max_active":     23,
        "std_active":     24,
        "min_idle":       25,
        "mean_idle":      26,
        "max_idle":       27,
        "std_idle":       28,
        "sflow_fpackets": 29,
        "sflow_fbytes":   30,
        "sflow_bpackets": 31,
        "sflow_bbytes":   32,
        "fpsh_cnt":       33,
        "bpsh_cnt":       34,
        "furg_cnt":       35,
        "burg_cnt":       36,
        "total_fhlen":    37,
        "total_bhlen":    38,
        "dscp":           39,
}

var count map[string]int = map[string]int{
        "fpktl_sqsum":  0,
        "bpktl_sqsum":  1,
        "fiat_sum":     2,
        "fiat_sqsum":   3,
        "fiat_count":   4,
        "biat_sum":     5,
        "biat_sqsum":   6,
        "biat_count":   7,
        "active_start": 8,
        "active_time":  9,
        "active_sqsum": 10,
        "active_count": 11,
        "idle_time":    12,
        "idle_sqsum":   13,
        "idle_count":   14,
}

type Flow struct {
        f       []int64            // A map of the features to be exported
        c       []int64            // A map of counters used for calculations
        bins    map[string]Feature // A map of binning features

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
        f.f = make([]int64, len(feat))
        f.c = make([]int64, len(count))
        f.valid = false
        for i := 0; i < len(feat); i++ {
                f.f[i] = 0
        }
        for i := 0; i < len(count); i++ {
                f.c[i] = 0
        }
        // Basic flow identification criteria
        f.srcip = srcip
        f.srcport = srcport
        f.dstip = dstip
        f.dstport = dstport
        f.proto = proto
        f.f[feat["dscp"]] = pkt["dscp"]
        // ---------------------------------------------------------
        f.f[feat["total_fpackets"]] = 1
        length := pkt["len"]
        f.f[feat["total_fvolume"]] = length
        f.f[feat["min_fpktl"]] = length
        f.f[feat["max_fpktl"]] = length
        f.c[count["fpktl_sqsum"]] = (length * length)
        f.firstTime = pkt["time"]
        f.flast = f.firstTime
        f.c[count["active_start"]] = f.firstTime
        if f.proto == IP_TCP {
                // TCP specific code:
                f.cstate.State = TCP_STATE_START
                f.sstate.State = TCP_STATE_START
                if tcpSet(TCP_PSH, pkt["flags"]) {
                        f.f[feat["fpsh_cnt"]] = 1
                }
                if tcpSet(TCP_URG, pkt["flags"]) {
                        f.f[feat["furg_cnt"]] = 1
                }
        }
        f.f[feat["total_fhlen"]] = pkt["iphlen"] + pkt["prhlen"]

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
                if f.hasData && (f.f[feat["total_bpackets"]] > 0) {
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
                if diff > f.f[feat["max_idle"]] {
                        f.f[feat["max_idle"]] = diff
                }
                if (diff < f.f[feat["min_idle"]]) ||
                        (f.f[feat["min_idle"]] == 0) {
                        f.f[feat["min_idle"]] = diff
                }
                f.c[count["idle_time"]] += diff
                f.c[count["idle_sqsum"]] += (diff * diff)
                f.c[count["idle_count"]]++
                // Active time stats - calculated by looking at the previous packet
                // time and the packet time for when the last idle time ended.
                diff = last - f.c[count["active_start"]]
                if diff > f.f[feat["max_active"]] {
                        f.f[feat["max_active"]] = diff
                }
                if (diff < f.f[feat["min_active"]]) ||
                        (f.f[feat["min_active"]] == 0) {
                        f.f[feat["min_active"]] = diff
                }
                f.c[count["active_time"]] += diff
                f.c[count["active_sqsum"]] += (diff * diff)
                f.c[count["active_count"]]++
                f.flast = 0
                f.blast = 0
                f.c[count["active_start"]] = now
        }
        if f.pdir == P_FORWARD {
                if f.f[feat["dscp"]] == 0 {
                        f.f[feat["dscp"]] = pkt["dscp"]
                }
                // Packet is travelling in the forward direction
                // Calculate some statistics
                // Packet length
                if (length < f.f[feat["min_fpktl"]]) || (f.f[feat["min_fpktl"]] == 0) {
                        f.f[feat["min_fpktl"]] = length
                }
                if length > f.f[feat["max_fpktl"]] {
                        f.f[feat["max_fpktl"]] = length
                }
                f.f[feat["total_fvolume"]] += length // Doubles up as c_fpktl_sum from NM
                f.c[count["fpktl_sqsum"]] += (length * length)
                f.f[feat["total_fpackets"]]++
                f.f[feat["total_fhlen"]] += hlen
                // Interarrival time
                if f.flast > 0 {
                        diff = now - f.flast
                        if (diff < f.f[feat["min_fiat"]]) || (f.f[feat["min_fiat"]] == 0) {
                                f.f[feat["min_fiat"]] = diff
                        }
                        if diff > f.f[feat["max_fiat"]] {
                                f.f[feat["max_fiat"]] = diff
                        }
                        f.c[count["fiat_sum"]] += diff
                        f.c[count["fiat_sqsum"]] += (diff * diff)
                        f.c[count["fiat_count"]]++
                        f.bins["fiat"].Add(diff)
                }
                if f.proto == IP_TCP {
                        // Packet is using TCP protocol
                        if tcpSet(TCP_PSH, pkt["flags"]) {
                                f.f[feat["fpsh_cnt"]]++
                        }
                        if tcpSet(TCP_URG, pkt["flags"]) {
                                f.f[feat["furg_cnt"]]++
                        }
                        // Update the last forward packet time stamp
                }
                f.bins["fpktl"].Add(length)
                f.flast = now
        } else {
                // Packet is travelling in the backward direction
                if f.f[feat["dscp"]] == 0 {
                        f.f[feat["dscp"]] = pkt["dscp"]
                }
                // Calculate some statistics
                // Packet length
                if length < f.f[feat["min_bpktl"]] || f.f[feat["min_bpktl"]] == 0 {
                        f.f[feat["min_bpktl"]] = length
                }
                if length > f.f[feat["max_bpktl"]] {
                        f.f[feat["max_bpktl"]] = length
                }
                f.f[feat["total_bvolume"]] += length // Doubles up as c_bpktl_sum from NM
                f.c[count["bpktl_sqsum"]] += (length * length)
                f.f[feat["total_bpackets"]]++
                f.f[feat["total_bhlen"]] += hlen
                // Inter-arrival time
                if f.blast > 0 {
                        diff = now - f.blast
                        if (diff < f.f[feat["min_biat"]]) || (f.f[feat["min_biat"]] == 0) {
                                f.f[feat["min_biat"]] = diff
                        }
                        if diff > f.f[feat["max_biat"]] {
                                f.f[feat["max_biat"]] = diff
                        }
                        f.c[count["biat_sum"]] += diff
                        f.c[count["biat_sqsum"]] += (diff * diff)
                        f.c[count["biat_count"]]++
                        f.bins["biat"].Add(diff)
                }
                if f.proto == IP_TCP {
                        // Packet is using TCP protocol
                        if tcpSet(TCP_PSH, pkt["flags"]) {
                                f.f[feat["bpsh_cnt"]]++
                        }
                        if tcpSet(TCP_URG, pkt["flags"]) {
                                f.f[feat["burg_cnt"]]++
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
        diff := f.getLastTime() - f.c[count["active_start"]]
        if diff > f.f[feat["max_active"]] {
                f.f[feat["max_active"]] = diff
        }
        if (diff < f.f[feat["min_active"]]) || (f.f[feat["min_active"]] == 0) {
                f.f[feat["min_active"]] = diff
        }
        f.c[count["active_time"]] += diff
        f.c[count["active_sqsum"]] += (diff * diff)
        f.c[count["active_count"]]++

        if f.f[feat["total_fpackets"]] <= 0 {
                log.Fatalf("total_fpackets (%d) <= 0\n", f.f[feat["total_fpackets"]])
        }

        // ---------------------------------
        // Update Flow stats which require counters or other final calculations
        // ---------------------------------
        f.f[feat["mean_fpktl"]] = f.f[feat["total_fvolume"]] / f.f[feat["total_fpackets"]]
        //Standard deviation of packets in the forward direction
        if f.f[feat["total_fpackets"]] > 1 {
                f.f[feat["std_fpktl"]] = stddev(f.c[count["fpktl_sqsum"]],
                        f.f[feat["total_fvolume"]],
                        f.f[feat["total_fpackets"]])
        } else {
                f.f[feat["std_fpktl"]] = 0
        }
        // Mean packet length of packets in the packward direction
        if f.f[feat["total_bpackets"]] > 0 {
                f.f[feat["mean_bpktl"]] = f.f[feat["total_bvolume"]] / f.f[feat["total_bpackets"]]
        } else {
                f.f[feat["mean_bpktl"]] = -1
        }
        // Standard deviation of packets in the backward direction
        if f.f[feat["total_bpackets"]] > 1 {
                f.f[feat["std_bpktl"]] = stddev(f.c[count["bpktl_sqsum"]],
                        f.f[feat["total_bvolume"]],
                        f.f[feat["total_bpackets"]])
        } else {
                f.f[feat["std_bpktl"]] = 0
        }
        // Mean forward inter-arrival time
        // TODO: Check if we actually need c_fiat_count ?
        if f.c[count["fiat_count"]] > 0 {
                f.f[feat["mean_fiat"]] = f.c[count["fiat_sum"]] / f.c[count["fiat_count"]]
        } else {
                f.f[feat["mean_fiat"]] = 0
        }
        // Standard deviation of forward inter-arrival times
        if f.c[count["fiat_count"]] > 1 {
                f.f[feat["std_fiat"]] = stddev(f.c[count["fiat_sqsum"]],
                        f.c[count["fiat_sum"]],
                        f.c[count["fiat_count"]])
        } else {
                f.f[feat["std_fiat"]] = 0
        }
        // Mean backward inter-arrival time
        if f.c[count["biat_count"]] > 0 {
                f.f[feat["mean_biat"]] = f.c[count["biat_sum"]] / f.c[count["biat_count"]]
        } else {
                f.f[feat["mean_biat"]] = 0
        }
        // Standard deviation of backward inter-arrival times
        if f.c[count["biat_count"]] > 1 {
                f.f[feat["std_biat"]] = stddev(f.c[count["biat_sqsum"]],
                        f.c[count["biat_sum"]],
                        f.c[count["biat_count"]])
        } else {
                f.f[feat["std_biat"]] = 0
        }
        // Mean active time of the sub-flows
        if f.c[count["active_count"]] > 0 {
                f.f[feat["mean_active"]] = f.c[count["active_time"]] / f.c[count["active_count"]]
        } else {
                // There should be packets in each direction if we're exporting 
                log.Fatalln("ERR: This shouldn't happen")
        }
        // Standard deviation of active times of sub-flows
        if f.c[count["active_count"]] > 1 {
                f.f[feat["std_active"]] = stddev(f.c[count["active_sqsum"]],
                        f.c[count["active_time"]],
                        f.c[count["active_count"]])
        } else {
                f.f[feat["std_active"]] = 0
        }
        // Mean of idle times between sub-flows
        if f.c[count["idle_count"]] > 0 {
                f.f[feat["mean_idle"]] = f.c[count["idle_time"]] / f.c[count["idle_count"]]
        } else {
                f.f[feat["mean_idle"]] = 0
        }
        // Standard deviation of idle times between sub-flows
        if f.c[count["idle_count"]] > 1 {
                f.f[feat["std_idle"]] = stddev(f.c[count["idle_sqsum"]],
                        f.c[count["idle_time"]],
                        f.c[count["idle_count"]])
        } else {
                f.f[feat["std_idle"]] = 0
        }
        // More sub-flow calculations
        if f.c[count["active_count"]] > 0 {
                f.f[feat["sflow_fpackets"]] = f.f[feat["total_fpackets"]] / f.c[count["active_count"]]
                f.f[feat["sflow_fbytes"]] = f.f[feat["total_fvolume"]] / f.c[count["active_count"]]
                f.f[feat["sflow_bpackets"]] = f.f[feat["total_bpackets"]] / f.c[count["active_count"]]
                f.f[feat["sflow_bbytes"]] = f.f[feat["total_bvolume"]] / f.c[count["active_count"]]
        }
        f.f[feat["duration"]] = f.getLastTime() - f.firstTime
        if f.f[feat["duration"]] < 0 {
                log.Fatalf("duration (%d) < 0", f.f[feat["duration"]])
        }

        fmt.Printf("%s,%d,%s,%d,%d",
                f.srcip,
                f.srcport,
                f.dstip,
                f.dstport,
                f.proto)
        for i := 0; i < len(feat)-1; i++ {
                fmt.Printf(",%d", f.f[i])
        }
        fmt.Printf(",%s", f.bins["fpktl"].Export())
        fmt.Printf(",%s", f.bins["bpktl"].Export())
        fmt.Printf(",%s", f.bins["fiat"].Export())
        fmt.Printf(",%s", f.bins["biat"].Export())
        fmt.Printf(",%d", f.f[len(feat)-1])
        fmt.Println()
}

func (f *Flow) CheckIdle(time int64) bool {
        if (time - f.getLastTime()) > FLOW_TIMEOUT {
                return true
        }
        return false
}
