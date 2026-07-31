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
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"shdns/dnsmessage"
)

var localnet = flag.String("b", "localhost:5353", "Local binding address and UDP port (e.g. 127.0.0.1:5353 [::1]:5353)")
var dservers = flag.String("d", "114.114.114.114,223.5.5.5", "Domestic nameservers. Default port 53. Use format [IP]:port for IPv6.")
var fservers = flag.String("f", "8.8.8.8,8.8.4.4", "Foreign nameservers. Default port 53. Use format [IP]:port for IPv6.")
var trusted = flag.Bool("t", false, "Trustworthy mode. Foreign answers will not be checked for validity.")
var fast = flag.Bool("F", false, "Fast mode. Accept foreign IP from domestic nameservers if it passes basic checks.")
var ipnet4file = flag.String("l4", "", "Domestic IPv4 list file (one IP/CIDR each line) (Required)")
var ipnet6file = flag.String("l6", "", "Domestic IPv6 list file (one IP/CIDR each line)")
var blacklist4file = flag.String("k4", "", "IPv4 blacklist file for all nameservers (one IP/CIDR each line)")
var blacklist6file = flag.String("k6", "", "IPv6 blacklist file for all nameservers (one IP/CIDR each line)")
var minrtt = flag.Int("m", 30, "Minimum possible RTT (ms) for foreign nameservers. Packets with shorter RTT will be dropped.")
var minsafe = flag.Int("s", 100, "Minimum safe RTT (ms) for foreign nameservers. Packets with longer RTT will be immediately accepted. Packets with shorter RTT will be delayed until this threshold.")
var minwait = flag.Int("w", 100, "Time (ms) during which domestic answers are prioritized. Usually used with a local caching resolver.")
var timeout = flag.Int("M", 3000, "DNS query timeout (ms). Use a larger value for high-latency network or DNS-over-HTTPS.")
var reversenet = flag.String("r", "", "Address and port for listening to reverse DNS queries from cache")
var cachelife = flag.Int("c", 60, "DNS cache lifetime (minutes) for reverse lookup")
var verbose = flag.Bool("v", false, "Verbose mode. Connection will remain open after replied until timeout.")
var showver = flag.Bool("V", false, "Show version")
var conffile = flag.String("C", "", "Configuration file (dnsmasq-style)")
var version = "unknown"
var builddate = "unknown"

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

type serverType int

const (
	domestic serverType = iota
	foreign
)

type nameserver struct {
	udpAddr *net.UDPAddr
	sType   serverType
}

type answer struct {
	payload []byte
	sType   serverType
	ips     []net.IP
}

type cacheEntry struct {
	value    string
	ns       string
	modified time.Time
}

type cache struct {
	table map[string]cacheEntry
	rw    sync.RWMutex
}

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

var (
	cnIPNet4, cnIPNet6   []net.IPNet
	blackIPs4, blackIPs6 []net.IPNet
	servers              []nameserver
	reverseTable         cache
	logger               = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	errlog               = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lmicroseconds)
	ipsetSpecs           []ipsetSpec
	nftSetSpecs          []nftSetSpec
	parsedIPSetSpecs     []ipsetSpec
	parsedNFTSetSpecs    []nftSetSpec
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
			domains = append(domains, p)
		}
	}
	return
}

func domainMatch(qName string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	name := strings.TrimSuffix(qName, ".")
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
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

func handleQuery(addr *net.UDPAddr, payload []byte, inConn *net.UDPConn) { // net.Addr is *net.UDPAddr, net.PacketConn is *net.UDPConn
	var p dnsmessage.Parser
	h, err := p.Start(payload)
	if err != nil {
		errlog.Println(err)
		return
	}
	var bufs []bytes.Buffer
	qs, err := p.AllQuestions()
	if err != nil || len(qs) == 0 {
		return
	}
	if *verbose {
		for _, q := range qs {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "%d %s Query[%s] %s len %d", h.ID, addr, strings.TrimPrefix(q.Type.String(), "Type"), q.Name.String(), len(payload))
			bufs = append(bufs, buf)
		}
	}
	if p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return
	}
	dnssec := false
	hasOPT := false
	for {
		rh, err := p.AdditionalHeader()
		if err != nil {
			break
		}
		if rh.Type == dnsmessage.TypeOPT {
			hasOPT = true
			if rh.DNSSECAllowed() {
				dnssec = true
			}
		}
		if p.SkipAdditional() != nil {
			return
		}
	}
	if *verbose {
		if hasOPT {
			addTag(bufs, " OPT")
		}
		if dnssec {
			addTag(bufs, " DNSSEC")
		}
		for _, buf := range bufs {
			logger.Println(&buf)
		}
	}
	chAnswer := make(chan answer)
	chSave := make(chan answer)
	chFail := make(chan []byte)
	loc, _ := net.ResolveUDPAddr("udp", "")
	outConn, err := net.ListenUDP("udp", loc)
	if err != nil {
		errlog.Println(err)
		return
	}
	defer outConn.Close()
	go forwardQueryAndReply(payload, outConn, chAnswer, chSave, chFail, qs[0].Type, qs[0].Name.String(), hasOPT, dnssec)
	qName := qs[0].Name.String()
	answered := false
	waiting := true
	var savedAnswer, waitedAnswer answer
	var failedAnswer []byte
	timerSafe := time.NewTimer(time.Duration(*minsafe) * time.Millisecond)
	timerWait := time.NewTimer(time.Duration(*minwait) * time.Millisecond)
	for {
		select {
		case a, ok := <-chAnswer:
			if ok {
				if !answered {
					if a.sType == domestic && a.payload == nil {
						waiting = false
						if waitedAnswer.payload != nil {
							addIPsToSet(waitedAnswer.ips, qName, h.ID)
							if _, err := inConn.WriteToUDP(waitedAnswer.payload, addr); err != nil {
								errlog.Println(err)
							}
							answered = true
						}
					} else if a.sType == domestic || !waiting || qs[0].Type != dnsmessage.TypeA && qs[0].Type != dnsmessage.TypeAAAA && qs[0].Type != dnsmessage.TypeHTTPS {
						// assume domestic nameservers can handle A, AAAA and HTTPS properly
						addIPsToSet(a.ips, qName, h.ID)
						if _, err := inConn.WriteToUDP(a.payload, addr); err != nil {
							errlog.Println(err)
						}
						answered = true
					} else if waitedAnswer.payload == nil {
						waitedAnswer = a
					}
				}
			} else {
				// chAnswer is closed
				if !answered {
					if failedAnswer != nil {
						if _, err := inConn.WriteToUDP(failedAnswer, addr); err != nil {
							errlog.Println(err)
						}
					} else {
						// warn user that no answer is returned
						q := qs[0]
						errlog.Printf("%d Timeout for Query[%s] %s", h.ID, strings.TrimPrefix(q.Type.String(), "Type"), q.Name.String())
					}
				}
				if *verbose {
					logger.Printf("%d Connection closed", h.ID)
				}
				return
			}
		case <-timerWait.C:
			waiting = false
			if !answered && waitedAnswer.payload != nil {
				addIPsToSet(waitedAnswer.ips, qName, h.ID)
				if _, err := inConn.WriteToUDP(waitedAnswer.payload, addr); err != nil {
					errlog.Println(err)
				}
				answered = true
			}
		case <-timerSafe.C:
			if !answered && savedAnswer.payload != nil {
				addIPsToSet(savedAnswer.ips, qName, h.ID)
				if _, err := inConn.WriteToUDP(savedAnswer.payload, addr); err != nil {
					errlog.Println(err)
				}
				answered = true
			}
		case a := <-chSave:
			if !answered {
				savedAnswer = a
			}
		case a := <-chFail:
			if !answered {
				failedAnswer = a
			}
		}
	}
}

func forwardQueryAndReply(payload []byte, outConn *net.UDPConn, chAnswer, chSave chan<- answer, chFail chan<- []byte, qType dnsmessage.Type, qName string, hasOPT, dnssec bool) {
	defer close(chAnswer)
	sentTime := time.Now()
	for _, ns := range servers {
		outConn.WriteToUDP(payload, ns.udpAddr)
	}
	outConn.SetReadDeadline(sentTime.Add(time.Duration(*timeout) * time.Millisecond))
	parseAnswers(outConn, sentTime, chAnswer, chSave, chFail, qType, qName, hasOPT, dnssec)
}

func lookupServer(addr *net.UDPAddr) (nameserver, bool) {
	return lookupServerIn(addr, servers)
}

func lookupServerIn(addr *net.UDPAddr, list []nameserver) (nameserver, bool) {
	for _, s := range list {
		if s.udpAddr.IP.Equal(addr.IP) && s.udpAddr.Port == addr.Port && s.udpAddr.Zone == addr.Zone {
			return s, true
		}
	}
	return nameserver{}, false
}

func parseAnswers(conn *net.UDPConn, sentTime time.Time, chAnswer, chSave chan<- answer, chFail chan<- []byte, qType dnsmessage.Type, qName string, hasOPT, dnssec bool) {
	for {
		var payload [5000]byte
		// receive from nameserver
		n, addr, err := conn.ReadFromUDP(payload[:])
		if err != nil {
			// out connection either timeout or closed
			return
		}
		// match nameserver
		ns, ok := lookupServer(addr)
		if !ok {
			continue
		}
		// start parsing
		a := payload[:n]
		rtt := time.Since(sentTime)
		tooFast := false
		if ns.sType == foreign && rtt < time.Duration(*minrtt)*time.Millisecond {
			tooFast = true
		}
		var p dnsmessage.Parser
		h, err := p.Start(a)
		if err != nil {
			errlog.Println(err)
			continue
		}
		if !h.Response || h.Truncated {
			continue
		}
		if p.SkipAllQuestions() != nil {
			continue
		}
		var geoErr, typeErr, hasCNAME, hasA, hasAAAA, hasHTTPS, inBlacklist, dnssecErr, optErr, invalidResponse bool
		ansCount := 0
		var bufs []bytes.Buffer
		reverse := make(map[string]string)
		var ips []net.IP
		for {
			// each loop parses one answer from a reply packet
			ah, err := p.AnswerHeader()
			if err != nil {
				break
			}
			ansCount++
			var buf bytes.Buffer
			if *verbose {
				fmt.Fprintf(&buf, "%d %s Answer[%s]", h.ID, ns.udpAddr, strings.TrimPrefix(ah.Type.String(), "Type"))
			}
			switch ah.Type {
			case dnsmessage.TypeA:
				hasA = true
				if cnIPNet4 != nil || blackIPs4 != nil || *verbose || *reversenet != "" {
					r, err := p.AResource()
					if err != nil {
						invalidResponse = true
						break
					}
					ip := net.IP(r.A[:]) //r.A is 4-byte
					if *reversenet != "" {
						reverse[ip.String()] = qName
					}
					if len(ipsetSpecs) > 0 || len(nftSetSpecs) > 0 {
						ips = append(ips, ip)
					}
					if *verbose {
						fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), ip.String(), len(a), rtt.Nanoseconds()/1000000)
					}
					if ns.sType == domestic && cnIPNet4 != nil {
						if !findIPInNet(ip, cnIPNet4) {
							geoErr = true
							if *verbose {
								fmt.Fprint(&buf, " GEOERR")
							}
						}
					}
					if blackIPs4 != nil {
						if findIPInNet(ip, blackIPs4) {
							inBlacklist = true
							if *verbose {
								fmt.Fprint(&buf, " BLACKLIST")
							}
						}
					}
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
				if qType == dnsmessage.TypeAAAA || qType == dnsmessage.TypeHTTPS {
					typeErr = true
					if *verbose {
						fmt.Fprint(&buf, " TYPEERR")
					}
				}
			case dnsmessage.TypeAAAA:
				hasAAAA = true
				if cnIPNet6 != nil || blackIPs6 != nil || *verbose || *reversenet != "" {
					r, err := p.AAAAResource()
					if err != nil {
						invalidResponse = true
						break
					}
					ip := net.IP(r.AAAA[:])
					if *reversenet != "" {
						reverse[ip.String()] = qName
					}
					if len(ipsetSpecs) > 0 || len(nftSetSpecs) > 0 {
						ips = append(ips, ip)
					}
					if *verbose {
						fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), ip.String(), len(a), rtt.Nanoseconds()/1000000)
					}
					if ns.sType == domestic && cnIPNet6 != nil {
						if !findIPInNet(ip, cnIPNet6) {
							geoErr = true
							if *verbose {
								fmt.Fprint(&buf, " GEOERR")
							}
						}
					}
					if blackIPs6 != nil {
						if findIPInNet(ip, blackIPs6) {
							inBlacklist = true
							if *verbose {
								fmt.Fprint(&buf, " BLACKLIST")
							}
						}
					}
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
			case dnsmessage.TypeCNAME:
				if *verbose {
					r, err := p.CNAMEResource()
					if err != nil {
						invalidResponse = true
						break
					}
					fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), r.CNAME, len(a), rtt.Nanoseconds()/1000000)
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
				hasCNAME = true
			case dnsmessage.TypePTR:
				if *verbose {
					r, err := p.PTRResource()
					if err != nil {
						invalidResponse = true
						break
					}
					fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), r.PTR, len(a), rtt.Nanoseconds()/1000000)
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
			case dnsmessage.TypeTXT:
				if *verbose {
					r, err := p.TXTResource()
					if err != nil {
						invalidResponse = true
						break
					}
					fmt.Fprintf(&buf, " %s %s len %d %dms", ah.Name.String(), r.TXT, len(a), rtt.Nanoseconds()/1000000)
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
			case dnsmessage.TypeSRV:
				if *verbose {
					r, err := p.SRVResource()
					if err != nil {
						invalidResponse = true
						break
					}
					fmt.Fprintf(&buf, " %s %d %d %d %s len %d %dms", ah.Name.String(), r.Priority, r.Weight, r.Port, r.Target, len(a), rtt.Nanoseconds()/1000000)
				} else {
					if p.SkipAnswer() != nil {
						invalidResponse = true
						break
					}
				}
			case dnsmessage.TypeHTTPS:
				hasHTTPS = true
				r, err := p.HTTPSResource()
				if err != nil {
					invalidResponse = true
					break
				}
				if *verbose {
					fmt.Fprintf(&buf, " %s %d %s", ah.Name.String(), r.Priority, r.Target)
					if r.ALPN != nil {
						fmt.Fprintf(&buf, " alpn %s", r.ALPN)
					}
					if r.Port != 0 {
						fmt.Fprintf(&buf, " port %d", r.Port)
					}
				}
				if r.IPv4Hint != nil {
					for i := range r.IPv4Hint {
						ip := net.IP(r.IPv4Hint[i][:])
						if *verbose {
							fmt.Fprintf(&buf, " %s", ip.String())
						}
						if *reversenet != "" {
							reverse[ip.String()] = qName
						}
						if len(ipsetSpecs) > 0 || len(nftSetSpecs) > 0 {
							ips = append(ips, ip)
						}
						if ns.sType == domestic && cnIPNet4 != nil {
							if !findIPInNet(ip, cnIPNet4) {
								geoErr = true
								if *verbose {
									fmt.Fprint(&buf, " GEOERR")
								}
							}
						}
						if blackIPs4 != nil {
							if findIPInNet(ip, blackIPs4) {
								inBlacklist = true
								if *verbose {
									fmt.Fprint(&buf, " BLACKLIST")
								}
							}
						}
					}
				}
				if r.IPv6Hint != nil {
					for i := range r.IPv6Hint {
						ip := net.IP(r.IPv6Hint[i][:])
						if *verbose {
							fmt.Fprintf(&buf, " %s", ip.String())
						}
						if *reversenet != "" {
							reverse[ip.String()] = qName
						}
						if len(ipsetSpecs) > 0 || len(nftSetSpecs) > 0 {
							ips = append(ips, ip)
						}
						if ns.sType == domestic && cnIPNet6 != nil {
							if !findIPInNet(ip, cnIPNet6) {
								geoErr = true
								if *verbose {
									fmt.Fprint(&buf, " GEOERR")
								}
							}
						}
						if blackIPs6 != nil {
							if findIPInNet(ip, blackIPs6) {
								inBlacklist = true
								if *verbose {
									fmt.Fprint(&buf, " BLACKLIST")
								}
							}
						}
					}
				}
				if *verbose {
					fmt.Fprintf(&buf, " len %d %dms", len(a), rtt.Nanoseconds()/1000000)
				}
			default:
				if *verbose {
					fmt.Fprintf(&buf, " %s len %d %dms", ah.Name.String(), len(a), rtt.Nanoseconds()/1000000)
				}
				if p.SkipAnswer() != nil {
					invalidResponse = true
				}
			}
			if invalidResponse {
				break
			}
			if *verbose {
				if tooFast {
					fmt.Fprint(&buf, " TOOFAST")
				}
				bufs = append(bufs, buf)
			}
		} // answer section parsed
		if invalidResponse {
			continue
		}
		if *verbose && ansCount == 0 {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "%d %s Answer[Empty] len %d %dms", h.ID, ns.udpAddr, len(a), rtt.Nanoseconds()/1000000)
			bufs = append(bufs, buf)
		}
		authCount := 0
		for {
			if _, err := p.AuthorityHeader(); err != nil {
				break
			}
			authCount++
			if p.SkipAuthority() != nil {
				invalidResponse = true
				break
			}
		}
		if invalidResponse {
			continue
		}
		addtCount := 0
		dnssecErr = dnssec && (ns.sType == foreign || qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS)
		optErr = hasOPT && (ns.sType == foreign || qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS)
		for {
			rh, err := p.AdditionalHeader()
			if err != nil {
				break
			}
			addtCount++
			switch rh.Type {
			case dnsmessage.TypeOPT:
				optErr = false
				// ISP nameservers most likely cannot hold DNSSEC query
				if ns.sType == foreign || qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS {
					if dnssec == rh.DNSSECAllowed() {
						dnssecErr = false
					} else {
						dnssecErr = true
					}
				}
			}
			if p.SkipAdditional() != nil {
				invalidResponse = true
				break
			}
		}
		if invalidResponse {
			continue
		}
		if *verbose {
			if optErr {
				addTag(bufs, " OPTERR")
			}
			if dnssecErr {
				addTag(bufs, " DNSSECERR")
			}
			if h.RCode != dnsmessage.RCodeSuccess {
				addTag(bufs, " "+h.RCode.String())
			}
			addTag(bufs, " "+strconv.Itoa(ansCount)+"/"+strconv.Itoa(authCount)+"/"+strconv.Itoa(addtCount))
		}
		if ns.sType == foreign && *trusted || !dnssecErr && (!geoErr || *fast && ansCount > 1) && !typeErr && !optErr && !tooFast && !inBlacklist &&
			(h.RCode == dnsmessage.RCodeSuccess && qType == dnsmessage.TypeA && (hasA || ns.sType == foreign) ||
				h.RCode == dnsmessage.RCodeSuccess && qType == dnsmessage.TypeAAAA && (hasAAAA || authCount > 0 || ns.sType == foreign) ||
				h.RCode == dnsmessage.RCodeSuccess && qType == dnsmessage.TypeHTTPS && (hasHTTPS || authCount > 0 || ns.sType == foreign) ||
				h.RCode == dnsmessage.RCodeSuccess && qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS && ns.sType == foreign ||
				h.RCode == dnsmessage.RCodeNameError && ns.sType == foreign) {
			switch ns.sType {
			case domestic:
				if *verbose {
					addTag(bufs, " [ACCEPT]")
				}
				chAnswer <- answer{a, domestic, ips}
			case foreign:
				if qType != dnsmessage.TypeA && qType != dnsmessage.TypeAAAA && qType != dnsmessage.TypeHTTPS ||
					rtt > time.Duration(*minsafe)*time.Millisecond || hasCNAME || ansCount > 1 {
					if *verbose {
						addTag(bufs, " [ACCEPT]")
					}
					chAnswer <- answer{a, foreign, ips}
				} else {
					if *verbose {
						addTag(bufs, " [SAVE]")
					}
					chSave <- answer{a, foreign, ips}
				}
			}
			// add to cache for reverse lookup (even for those saved but not used)
			if *reversenet != "" {
				reverseTable.insert(reverse, ns.udpAddr.String())
			}
		} else if h.RCode == dnsmessage.RCodeServerFailure && ns.sType == foreign {
			if *verbose {
				addTag(bufs, " [SAVE]")
			}
			chFail <- a
		} else {
			// send empty answer to signal that domestic has replied
			if ns.sType == domestic {
				chAnswer <- answer{nil, domestic, nil}
			}
			if *verbose {
				addTag(bufs, " [DROP]")
			}
		}
		if *verbose {
			for _, buf := range bufs {
				logger.Println(&buf)
			}
		}
	}
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

func addIPsToSet(ips []net.IP, qName string, id uint16) {
	if len(ips) == 0 {
		return
	}
	seen := make(map[string]bool)
	for _, ip := range ips {
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		is4 := ip.To4() != nil
		for _, spec := range ipsetSpecs {
			if !domainMatch(qName, spec.domains) {
				continue
			}
			if err := ipsetAddToSet(spec.setName, ip); err != nil {
				errlog.Printf("ipset add %s %s: %v", spec.setName, s, err)
			} else if *verbose {
				logger.Printf("%d ipset %s <- %s (%s)", id, spec.setName, s, qName)
			}
		}
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
			cmd := exec.Command("nft", "add", "element", set.family, set.table, set.setName, "{", s, "}")
			if err := cmd.Run(); err != nil {
				errlog.Printf("nft add element %s %s %s { %s }: %v", set.family, set.table, set.setName, s, err)
			} else if *verbose {
				logger.Printf("%d nftset %s#%s#%s <- %s (%s)", id, set.family, set.table, set.setName, s, qName)
			}
		}
	}
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

func main() {
	flag.Parse()
	if *showver {
		fmt.Printf("shdns version %s (built %s)\n", version, builddate)
		return
	}
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Build set of explicitly provided CLI flags
	cliSet := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		cliSet[f.Name] = true
	})

	// Load config file if specified
	if *conffile != "" {
		cfg, err := parseConfig(*conffile)
		if err != nil {
			errlog.Fatalf("Config file error: %v", err)
		}
		if err := applyConfig(cfg, cliSet); err != nil {
			errlog.Fatalf("Config file error: %v", err)
		}
	}

	// Ensure at least one way to provide config exists
	if len(os.Args) == 1 && *conffile == "" {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := loadConfig(); err != nil {
		errlog.Fatalln(err)
	}

	if len(ipsetSpecs) > 0 {
		ipsetInit()
		defer ipsetClose()
	}

	addr, err := parseUDPAddr(*localnet)
	if err != nil {
		errlog.Fatalf("Invalid binding address: %s", *localnet)
	}
	inConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		errlog.Fatalln(err)
	}
	defer inConn.Close()
	logger.Printf("Listening on UDP %s", addr)
	if *reversenet != "" {
		reverseTable.table = make(map[string]cacheEntry)
		if addr, err := net.ResolveUDPAddr("udp", *reversenet); err == nil {
			conn, err := net.ListenUDP("udp", addr)
			if err == nil {
				go func() {
					ticker := time.Tick(15 * time.Minute)
					for range ticker {
						reverseTable.purge(time.Minute * time.Duration(*cachelife))
					}
				}()
				go handleReverse(conn)
			}
		}
	}

	// Handle SIGHUP for config reload
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	go func() {
		for range sigHup {
			logger.Print("Received SIGHUP, reloading configuration...")
			reloadConfig()
		}
	}()

	for {
		var payload [1500]byte
		if n, addr, err := inConn.ReadFromUDP(payload[:]); err != nil {
			errlog.Println(err)
			continue
		} else {
			go handleQuery(addr, payload[:n], inConn)
		}
	}
}
