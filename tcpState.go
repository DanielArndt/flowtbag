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

const (
	TCP_FIN = 0x01
	TCP_SYN = 0x02
	TCP_RST = 0x04
	TCP_PSH = 0x08
	TCP_ACK = 0x10
	TCP_URG = 0x20
)

const (
	TCP_STATE_START = iota
	TCP_STATE_SYN
	TCP_STATE_SYNACK
	TCP_STATE_ESTABLISHED
	TCP_STATE_FIN
	TCP_STATE_CLOSED
)

type tcpState struct {
	State uint8
}

func tcpSet(find int64, flags int64) bool {
	return ((find & flags) == find)
}

func (t *tcpState) TcpUpdate(flags int64, dir int8, pdir int8) {
	if tcpSet(TCP_RST, flags) {
		t.State = TCP_STATE_CLOSED
	} else if tcpSet(TCP_FIN, flags) && (dir == pdir) {
		t.State = TCP_STATE_FIN
	} else if t.State == TCP_STATE_FIN {
		if tcpSet(TCP_ACK, flags) && (dir != pdir) {
			t.State = TCP_STATE_CLOSED
		}
	} else if t.State == TCP_STATE_START {
		if tcpSet(TCP_SYN, flags) && (dir == pdir) {
			t.State = TCP_STATE_SYN
		}
	} else if t.State == TCP_STATE_SYN {
		if tcpSet(TCP_SYN, flags) && tcpSet(TCP_ACK, flags) && (dir != pdir) {
			t.State = TCP_STATE_SYNACK
		}
	} else if t.State == TCP_STATE_SYNACK {
		if tcpSet(TCP_ACK, flags) && (dir == pdir) {
			t.State = TCP_STATE_ESTABLISHED
		}
	}
}
