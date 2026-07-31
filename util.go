/*	shdns, a port of ChinaDNS in go with IPv6 support
	Copyright (C) 2019–2021 domosekai

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"bytes"
	"fmt"
	"net"
)

type byByte []net.IPNet

func (n byByte) Len() int { return len(n) }
func (n byByte) Less(i, j int) bool {
	for b := 0; b < len(n[i].IP); b++ {
		if n[i].IP[b] < n[j].IP[b] {
			return true
		} else if n[i].IP[b] > n[j].IP[b] {
			return false
		}
	}
	return false
}
func (n byByte) Swap(i, j int) { n[i], n[j] = n[j], n[i] }

func cmpIPIPNet(ip net.IP, ipnet net.IPNet) int { // based on net.Contains()
	for i := 0; i < len(ip); i++ {
		if a, b := ip[i]&ipnet.Mask[i], ipnet.IP[i]&ipnet.Mask[i]; a < b {
			return -1
		} else if a > b {
			return 1
		}
	}
	return 0
}

func findIPInNet(ip net.IP, ipnets []net.IPNet) bool { // based on sort.Search()
	for i, j := 0, len(ipnets); i < j; {
		switch k := int(uint(i+j) >> 1); cmpIPIPNet(ip, ipnets[k]) { // i <= k < j
		case -1:
			j = k
		case 0:
			return true
		case 1:
			i = k + 1
		}
	}
	return false
}

func addTag(bufs []bytes.Buffer, tag string) {
	for i := range bufs {
		fmt.Fprint(&bufs[i], tag)
	}
}
