//go:build linux
// +build linux

package main

import (
	"net"
	"sync"

	"github.com/google/nftables"
)

var (
	nftConn     *nftables.Conn
	nftConnMu   sync.Mutex
	nftSetCache map[nftSetKey]*nftables.Set
)

func nftInit() {
	nftConnMu.Lock()
	defer nftConnMu.Unlock()
	if nftConn != nil {
		nftSetCache = make(map[nftSetKey]*nftables.Set)
		return
	}
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		errlog.Printf("nftables init failed: %v (nftset disabled)", err)
		return
	}
	nftConn = conn
	nftSetCache = make(map[nftSetKey]*nftables.Set)
}

func nftClose() {
	nftConnMu.Lock()
	defer nftConnMu.Unlock()
	if nftConn != nil {
		nftConn.CloseLasting()
		nftConn = nil
		nftSetCache = nil
	}
}

func nftFamily(family string) nftables.TableFamily {
	switch family {
	case "ip":
		return nftables.TableFamilyIPv4
	case "ip6":
		return nftables.TableFamilyIPv6
	case "inet":
		return nftables.TableFamilyINet
	default:
		return nftables.TableFamilyINet
	}
}

func nftLookupSet(family, table, setName string) (*nftables.Set, error) {
	key := nftSetKey{family, table, setName}
	if s, ok := nftSetCache[key]; ok {
		return s, nil
	}
	t := &nftables.Table{Name: table, Family: nftFamily(family)}
	s, err := nftConn.GetSetByName(t, setName)
	if err != nil {
		return nil, err
	}
	nftSetCache[key] = s
	return s, nil
}

func nftAddElements(batches map[nftSetKey][]net.IP, qName string, id uint16) {
	nftConnMu.Lock()
	defer nftConnMu.Unlock()
	if nftConn == nil || len(batches) == 0 {
		return
	}

	type setBatch struct {
		set      *nftables.Set
		elements []nftables.SetElement
	}
	setBatches := make(map[nftSetKey]*setBatch)

	for key, ips := range batches {
		b, ok := setBatches[key]
		if !ok {
			s, err := nftLookupSet(key.family, key.table, key.setName)
			if err != nil {
				errlog.Printf("nftset %s#%s#%s: %v", key.family, key.table, key.setName, err)
				continue
			}
			b = &setBatch{set: s}
			setBatches[key] = b
		}
		for _, ip := range ips {
			b.elements = append(b.elements, nftables.SetElement{
				Key:     ip,
				Timeout: b.set.Timeout,
				Expires: b.set.Timeout,
			})
		}
	}

	for key, b := range setBatches {
		if err := nftConn.SetAddElements(b.set, b.elements); err != nil {
			errlog.Printf("nftset %s#%s#%s: %v", key.family, key.table, key.setName, err)
			continue
		}
		if err := nftConn.Flush(); err != nil {
			errlog.Printf("nftset %s#%s#%s: %v", key.family, key.table, key.setName, err)
			continue
		}
		if *verbose {
			for _, elem := range b.elements {
				logger.Printf("%d nftset %s#%s#%s <- %s (%s)", id, key.family, key.table, key.setName, net.IP(elem.Key), qName)
			}
		}
	}
}
