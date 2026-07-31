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
	"net"
	"strings"
	"sync"
	"time"
)

type cacheEntry struct {
	value    string
	ns       string
	modified time.Time
}

type cache struct {
	table map[string]cacheEntry
	rw    sync.RWMutex
}

func (c *cache) add(key, value, ns string) {
	c.rw.Lock()
	defer c.rw.Unlock()
	c.table[key] = cacheEntry{value, ns, time.Now()}
}

func (c *cache) insert(m map[string]string, ns string) {
	c.rw.Lock()
	defer c.rw.Unlock()
	t := time.Now()
	for key, value := range m {
		c.table[key] = cacheEntry{value, ns, t}
	}
}

func (c *cache) lookup(key string) (string, string) {
	c.rw.RLock()
	defer c.rw.RUnlock()
	if e, ok := c.table[key]; ok {
		return e.value, e.ns
	}
	return "", ""
}

func (c *cache) purge(t time.Duration) {
	c.rw.Lock()
	defer c.rw.Unlock()
	for key, value := range c.table {
		if value.modified.Add(t).Before(time.Now()) {
			delete(c.table, key)
		}
	}
}

func handleReverse(conn *net.UDPConn) {
	defer conn.Close()
	for {
		var payload [1500]byte
		if n, addr, err := conn.ReadFromUDP(payload[:]); err != nil {
			errlog.Println(err)
		} else if n == 5 || n == 17 {
			ip := net.IP(payload[1:n])
			host, ns := reverseTable.lookup(ip.String())
			// remove trailing dot (if any)
			host = strings.TrimSuffix(host, ".")
			switch payload[0] {
			case 1:
				op := []byte{2}
				_, err := conn.WriteToUDP(append(op, host...), addr)
				if err != nil {
					errlog.Println(err)
				}
			case 3:
				op := []byte{4}
				op = append(op, byte(len(host)))
				op = append(op, host...)
				op = append(op, byte(len(ns)))
				op = append(op, ns...)
				_, err := conn.WriteToUDP(op, addr)
				if err != nil {
					errlog.Println(err)
				}
			}
		}
	}
}
