//go:build linux
// +build linux

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"syscall"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	ipset_PROTOCOL         = 6
	ipset_ATTR_PROTOCOL    = 1
	ipset_ATTR_SETNAME     = 2
	ipset_ATTR_DATA        = 7
	ipset_ATTR_IP          = 1
	ipset_ATTR_IPADDR_IPV4 = 1
	ipset_ATTR_IPADDR_IPV6 = 2
	ipset_CMD_ADD          = 9
	ipset_MAXNAMELEN       = 32
	nfNL_SUBSYS_IPSET      = 6
)

var (
	ipsetConn   *netlink.Conn
	ipsetConnMu sync.Mutex
)

func ipsetInit() {
	ipsetConnMu.Lock()
	defer ipsetConnMu.Unlock()
	if ipsetConn != nil {
		return
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		errlog.Fatalf("ipset netlink: %v", err)
	}
	ipsetConn = conn
}

func ipsetClose() {
	ipsetConnMu.Lock()
	defer ipsetConnMu.Unlock()
	if ipsetConn != nil {
		ipsetConn.Close()
		ipsetConn = nil
	}
}

func ipsetAddElements(name string, ips []net.IP, qName string, id uint16) {
	if len(name) >= ipset_MAXNAMELEN {
		errlog.Printf("ipset add %s: name too long", name)
		return
	}
	for _, ip := range ips {
		is4 := ip.To4() != nil
		var af int
		var ipAttrType uint16
		var addr []byte
		if is4 {
			af = syscall.AF_INET
			ipAttrType = ipset_ATTR_IPADDR_IPV4
			addr = ip.To4()
		} else {
			af = syscall.AF_INET6
			ipAttrType = ipset_ATTR_IPADDR_IPV6
			addr = ip.To16()
		}

		msg := netlink.Message{
			Header: netlink.Header{
				Type:  netlink.HeaderType((nfNL_SUBSYS_IPSET << 8) | ipset_CMD_ADD),
				Flags: netlink.Request | netlink.Acknowledge,
			},
			Data: buildIpsetAdd(af, name, ipAttrType, addr),
		}

		_, err := ipsetConn.Execute(msg)
		if err != nil {
			if errors.Is(err, unix.EINVAL) {
				continue
			}
			errlog.Printf("ipset add %s %s: %v", name, ip, err)
			continue
		}
		if *verbose {
			logger.Printf("%d ipset %s <- %s (%s)", id, name, ip, qName)
		}
	}
}

func buildIpsetAdd(af int, setName string, ipAttrType uint16, addr []byte) []byte {
	// nfgenmsg
	nfg := []byte{byte(af), 0, 0, 0}

	// IPSET_ATTR_PROTOCOL
	proto := nlattr(ipset_ATTR_PROTOCOL, []byte{ipset_PROTOCOL})

	// IPSET_ATTR_SETNAME
	nameBytes := append([]byte(setName), 0)
	sname := nlattr(ipset_ATTR_SETNAME, nameBytes)

	// IPSET_ATTR_IP (nested)
	ipAddr := nlattr(ipAttrType|unix.NLA_F_NET_BYTEORDER, addr)
	ipNest := nlattr(ipset_ATTR_IP|unix.NLA_F_NESTED, ipAddr)

	// IPSET_ATTR_DATA (nested)
	data := nlattr(ipset_ATTR_DATA|unix.NLA_F_NESTED, ipNest)

	// Concatenate: nfgenmsg + aligned(proto) + aligned(sname) + aligned(data)
	total := len(nfg) + nlAlign(len(proto)) + nlAlign(len(sname)) + nlAlign(len(data))
	buf := make([]byte, total)
	off := copy(buf, nfg)
	off += copy(buf[off:], proto)
	off += copy(buf[off:], make([]byte, nlAlign(off)-off))
	off += copy(buf[off:], sname)
	off += copy(buf[off:], make([]byte, nlAlign(off)-off))
	off += copy(buf[off:], data)
	return buf[:off]
}

func nlattr(typ uint16, data []byte) []byte {
	l := uint16(4 + len(data))
	buf := make([]byte, nlAlign(int(l)))
	binary.LittleEndian.PutUint16(buf[0:], l)
	binary.LittleEndian.PutUint16(buf[2:], typ)
	copy(buf[4:], data)
	return buf
}

func nlAlign(n int) int {
	return (n + 3) & ^3
}
