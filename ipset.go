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
	"fmt"
	"net"
	"strings"
)

type nftSetConfig struct {
	family  string // ip, ip6, inet (default inet)
	table   string
	setName string
	v4Only  bool // only add IPv4 addresses (4# prefix)
	v6Only  bool // only add IPv6 addresses (6# prefix)
}

type ipsetSpec struct {
	domains []string // empty = match all
	setName string
}

type nftSetSpec struct {
	domains []string
	config  nftSetConfig
}

func parseSetDomains(spec string) (domains []string, names []string) {
	if !strings.HasPrefix(spec, "/") {
		for _, n := range strings.Split(spec, ",") {
			n = strings.TrimSpace(n)
			if n != "" {
				names = append(names, n)
			}
		}
		return nil, names
	}
	parts := strings.Split(spec, "/")
	// /<d1>/<d2>/name1,name2 -> ["", "d1", "d2", "name1,name2"]
	if len(parts) < 3 || parts[len(parts)-1] == "" {
		return nil, strings.Split(spec, ",")
	}
	for _, n := range strings.Split(parts[len(parts)-1], ",") {
		n = strings.TrimSpace(n)
		if n != "" {
			names = append(names, n)
		}
	}
	for _, p := range parts[1 : len(parts)-1] {
		if p != "" {
			domains = append(domains, strings.ToLower(p))
		}
	}
	return
}

func domainMatch(qName string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	name := strings.ToLower(strings.TrimSuffix(qName, "."))
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func parseNFTSetSpec(spec string) (nftSetConfig, error) {
	s := spec
	var cfg nftSetConfig
	// Check for 4# or 6# prefix
	if len(s) > 2 && s[1] == '#' {
		switch s[0] {
		case '4':
			cfg.v4Only = true
			s = s[2:]
		case '6':
			cfg.v6Only = true
			s = s[2:]
		}
	}
	parts := strings.SplitN(s, "#", 3)
	switch len(parts) {
	case 2:
		cfg.family = "inet"
		cfg.table = parts[0]
		cfg.setName = parts[1]
	case 3:
		cfg.family = parts[0]
		cfg.table = parts[1]
		cfg.setName = parts[2]
	default:
		return nftSetConfig{}, fmt.Errorf("invalid nftset spec %q (expected [4#|6#][family#]table#set)", spec)
	}
	if cfg.family != "ip" && cfg.family != "ip6" && cfg.family != "inet" {
		return nftSetConfig{}, fmt.Errorf("invalid nftset family %q (must be ip, ip6, or inet)", cfg.family)
	}
	return cfg, nil
}

type nftSetKey struct {
	family  string
	table   string
	setName string
}

func addIPsToSet(ips []net.IP, qName string, id uint16) {
	if len(ips) == 0 {
		return
	}

	if len(ipsetSpecs) > 0 {
		batches := make(map[string][]net.IP)
		for _, ip := range ips {
			for _, spec := range ipsetSpecs {
				if domainMatch(qName, spec.domains) {
					batches[spec.setName] = append(batches[spec.setName], ip)
				}
			}
		}
		for name, batch := range batches {
			ipsetAddElements(name, batch, qName, id)
		}
	}

	if len(nftSetSpecs) > 0 {
		batches := make(map[nftSetKey][]net.IP)
		for _, ip := range ips {
			is4 := ip.To4() != nil
			for _, spec := range nftSetSpecs {
				if !domainMatch(qName, spec.domains) {
					continue
				}
				set := spec.config
				if (is4 && set.family == "ip6") || (!is4 && set.family == "ip") {
					continue
				}
				if set.v4Only && !is4 || set.v6Only && is4 {
					continue
				}
				key := nftSetKey{set.family, set.table, set.setName}
				var elemKey []byte
				if is4 {
					elemKey = ip.To4()
				} else {
					elemKey = ip.To16()
				}
				batches[key] = append(batches[key], elemKey)
			}
		}
		nftAddElements(batches, qName, id)
	}
}
