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
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

var configNameMap = map[string]string{
	"bind":                "b",
	"nameserver-domestic": "d",
	"nameserver-foreign":  "f",
	"trustworthy":         "t",
	"fast":                "F",
	"list-domestic-ipv4":  "l4",
	"list-domestic-ipv6":  "l6",
	"blacklist-ipv4":      "k4",
	"blacklist-ipv6":      "k6",
	"min-rtt":             "m",
	"safe-rtt":            "s",
	"wait-domestic":       "w",
	"timeout":             "M",
	"reverse-listen":      "r",
	"cache-life":          "c",
	"verbose":             "v",
	"ipset":               "",
	"nftset":              "",
}

func parseUDPAddr(str string) (*net.UDPAddr, error) {
	_, _, err := net.SplitHostPort(str)
	if err == nil {
		return net.ResolveUDPAddr("udp", str)
	}
	if _, _, err := net.SplitHostPort(str + ":53"); err == nil {
		return net.ResolveUDPAddr("udp", str+":53")
	}
	if _, _, err := net.SplitHostPort("[" + str + "]:53"); err == nil {
		return net.ResolveUDPAddr("udp", "["+str+"]:53")
	}
	return nil, err
}

func parseServers(str string, sType serverType) {
	if err := parseServersE(str, sType, &servers); err != nil {
		errlog.Fatalf("Invalid nameserver: %v", err)
	}
}

func parseServersE(str string, sType serverType, dest *[]nameserver) error {
	serverstr := strings.Split(str, ",")
	for _, s := range serverstr {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		addr, err := parseUDPAddr(s)
		if err != nil {
			return fmt.Errorf("%s: %v", s, err)
		}
		if addr.Zone != "" {
			if zoneid, err := strconv.Atoi(addr.Zone); err == nil {
				if ifi, err := net.InterfaceByIndex(zoneid); err == nil {
					addr.Zone = ifi.Name
				} else {
					return fmt.Errorf("IPv6 zone invalid: %s", s)
				}
			} else if _, err := net.InterfaceByName(addr.Zone); err != nil {
				return fmt.Errorf("IPv6 zone invalid: %s", s)
			}
		}
		if _, exist := lookupServerIn(addr, *dest); exist {
			return fmt.Errorf("Nameserver exists: %s", s)
		}
		*dest = append(*dest, nameserver{udpAddr: addr, sType: sType})
		logger.Printf("Using nameserver %s", addr)
	}
	return nil
}

func parseIPList(filename string, iplen int) (ipnets []net.IPNet) {
	ipnets, err := parseIPListE(filename, iplen)
	if err != nil {
		errlog.Fatalln(err)
	}
	return ipnets
}

func parseIPListE(filename string, iplen int) ([]net.IPNet, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var ipnets []net.IPNet
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ipstr := scanner.Text()
		if !strings.Contains(ipstr, "/") {
			if strings.Contains(ipstr, ":") {
				ipstr += "/128"
			} else {
				ipstr += "/32"
			}
		}
		_, ipnet, err := net.ParseCIDR(ipstr)
		if err != nil {
			return nil, fmt.Errorf("Invalid IP/CIDR: %s in file %s", scanner.Text(), filename)
		}
		if len(ipnet.IP) == iplen {
			ipnets = append(ipnets, *ipnet)
		} else if iplen == net.IPv4len {
			return nil, fmt.Errorf("IPv4 address needed: %s in file %s", scanner.Text(), filename)
		} else {
			return nil, fmt.Errorf("IPv6 address needed: %s in file %s", scanner.Text(), filename)
		}
	}
	return ipnets, nil
}

func parseConfig(filename string) (map[string]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineno := 0
	for scanner.Scan() {
		lineno++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key := line
		val := ""
		if i := strings.IndexByte(line, '='); i >= 0 {
			key = strings.TrimSpace(line[:i])
			val = strings.TrimSpace(line[i+1:])
		}
		if key == "" {
			return nil, fmt.Errorf("config line %d: empty key", lineno)
		}
		if _, exists := configNameMap[key]; !exists {
			return nil, fmt.Errorf("config line %d: unknown option %q", lineno, key)
		}
		if _, dup := cfg[key]; dup {
			if key == "ipset" || key == "nftset" {
				cfg[key] += "\n" + val
			} else {
				return nil, fmt.Errorf("config line %d: duplicate option %q", lineno, key)
			}
		} else {
			cfg[key] = val
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyConfig(cfg map[string]string, cliSet map[string]bool) error {
	for name, val := range cfg {
		flagName, ok := configNameMap[name]
		if !ok {
			return fmt.Errorf("unknown option: %s", name)
		}
		if cliSet[flagName] {
			continue
		}
		switch flagName {
		case "b":
			*localnet = val
		case "d":
			*dservers = val
		case "f":
			*fservers = val
		case "t":
			if val == "" || val == "true" {
				*trusted = true
			} else if val != "false" {
				return fmt.Errorf("invalid bool for %s: %s", name, val)
			}
		case "F":
			if val == "" || val == "true" {
				*fast = true
			} else if val != "false" {
				return fmt.Errorf("invalid bool for %s: %s", name, val)
			}
		case "l4":
			*ipnet4file = val
		case "l6":
			*ipnet6file = val
		case "k4":
			*blacklist4file = val
		case "k6":
			*blacklist6file = val
		case "v":
			if val == "" || val == "true" {
				*verbose = true
			} else if val != "false" {
				return fmt.Errorf("invalid bool for %s: %s", name, val)
			}
		case "m":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("invalid int for %s: %s", name, val)
			}
			*minrtt = n
		case "s":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("invalid int for %s: %s", name, val)
			}
			*minsafe = n
		case "w":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("invalid int for %s: %s", name, val)
			}
			*minwait = n
		case "M":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("invalid int for %s: %s", name, val)
			}
			*timeout = n
		case "r":
			*reversenet = val
		case "c":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("invalid int for %s: %s", name, val)
			}
			*cachelife = n
		}
	}
	if runtime.GOOS != "linux" {
		if _, ok := cfg["ipset"]; ok {
			logger.Print("Warning: ipset option ignored (Linux only)")
		}
		if _, ok := cfg["nftset"]; ok {
			logger.Print("Warning: nftset option ignored (Linux only)")
		}
		return nil
	}
	if raw, ok := cfg["ipset"]; ok {
		var specs []ipsetSpec
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			domains, names := parseSetDomains(line)
			if len(names) == 0 {
				return fmt.Errorf("invalid ipset spec: %s", line)
			}
			for _, name := range names {
				specs = append(specs, ipsetSpec{domains: domains, setName: name})
			}
		}
		parsedIPSetSpecs = specs
	}
	if raw, ok := cfg["nftset"]; ok {
		var specs []nftSetSpec
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			domains, names := parseSetDomains(line)
			if len(names) == 0 {
				return fmt.Errorf("invalid nftset spec: %s", line)
			}
			for _, name := range names {
				cfg, err := parseNFTSetSpec(name)
				if err != nil {
					return err
				}
				specs = append(specs, nftSetSpec{domains: domains, config: cfg})
			}
		}
		parsedNFTSetSpecs = specs
	}
	return nil
}

func loadConfig() error {
	// Load IPv4 domestic list
	if *ipnet4file == "" {
		return errors.New("Domestic IPv4 list must be provided")
	}
	newIPNet4, err := parseIPListE(*ipnet4file, net.IPv4len)
	if err != nil {
		return err
	}
	sort.Sort(byByte(newIPNet4))
	logger.Printf("Loaded %d domestic IPv4 entries", len(newIPNet4))

	// Load IPv6 domestic list
	var newIPNet6 []net.IPNet
	if *ipnet6file != "" {
		newIPNet6, err = parseIPListE(*ipnet6file, net.IPv6len)
		if err != nil {
			return err
		}
		sort.Sort(byByte(newIPNet6))
		logger.Printf("Loaded %d domestic IPv6 entries", len(newIPNet6))
	}

	// Load blacklists
	var newBlack4, newBlack6 []net.IPNet
	if *blacklist4file != "" {
		newBlack4, err = parseIPListE(*blacklist4file, net.IPv4len)
		if err != nil {
			return err
		}
		logger.Printf("Loaded %d blacklisted IPv4 entries", len(newBlack4))
	}
	if *blacklist6file != "" {
		newBlack6, err = parseIPListE(*blacklist6file, net.IPv6len)
		if err != nil {
			return err
		}
		logger.Printf("Loaded %d blacklisted IPv6 entries", len(newBlack6))
	}

	// Parse nameservers
	var newServers []nameserver
	if err := parseServersE(*dservers, domestic, &newServers); err != nil {
		return err
	}
	if err := parseServersE(*fservers, foreign, &newServers); err != nil {
		return err
	}

	// Apply trustworthy mode
	if *trusted {
		logger.Print("Foreign servers in trustworthy mode")
		*minsafe = 0
		*minrtt = 0
	}

	// Parse ipset/nftset configs
	for _, spec := range parsedIPSetSpecs {
		if len(spec.domains) > 0 {
			logger.Printf("ipset: %s -> %s", strings.Join(spec.domains, ", "), spec.setName)
		} else {
			logger.Printf("ipset: %s (all)", spec.setName)
		}
	}
	for _, spec := range parsedNFTSetSpecs {
		nft := spec.config
		if len(spec.domains) > 0 {
			logger.Printf("nftset: %s -> %s#%s#%s", strings.Join(spec.domains, ", "), nft.family, nft.table, nft.setName)
		} else {
			logger.Printf("nftset: %s#%s#%s (all)", nft.family, nft.table, nft.setName)
		}
	}

	// Update global state
	cnIPNet4 = newIPNet4
	cnIPNet6 = newIPNet6
	blackIPs4 = newBlack4
	blackIPs6 = newBlack6
	ipsetSpecs = parsedIPSetSpecs
	nftSetSpecs = parsedNFTSetSpecs
	servers = newServers

	return nil
}

func reloadConfig() {
	if *conffile == "" {
		logger.Print("SIGHUP received but no config file specified (-C), ignoring")
		return
	}
	cfg, err := parseConfig(*conffile)
	if err != nil {
		errlog.Printf("Config reload failed: %v", err)
		return
	}
	// Skip bind and reverse-listen (cannot be changed at runtime)
	skipSet := map[string]bool{"b": true, "r": true}
	if err := applyConfig(cfg, skipSet); err != nil {
		errlog.Printf("Config reload failed: %v", err)
		return
	}

	if err := loadConfig(); err != nil {
		errlog.Printf("Config reload failed: %v", err)
		return
	}

	if len(ipsetSpecs) > 0 && ipsetSock < 0 {
		ipsetInit()
	}
	logger.Print("Configuration reloaded successfully")
}
