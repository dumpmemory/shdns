//go:build linux
// +build linux

package main

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

const (
	ipset_CMD_ADD          = 9
	ipset_PROTOCOL         = 6
	ipset_ATTR_PROTOCOL    = 1
	ipset_ATTR_SETNAME     = 2
	ipset_ATTR_DATA        = 7
	ipset_ATTR_IP          = 1
	ipset_ATTR_IPADDR_IPV4 = 1
	ipset_ATTR_IPADDR_IPV6 = 2
	ipset_MAXNAMELEN       = 32
	nfNETLINK_V0           = 0
	nfNL_SUBSYS_IPSET      = 6
	nla_F_NESTED           = 1 << 15
	nla_F_NET_BYTEORDER    = 1 << 14
	nlm_F_REQUEST          = 0x0001
	nlm_F_ACK              = 0x0004
)

type nfgenmsg struct {
	Family  uint8
	Version uint8
	ResId   uint16
}

var ipsetSock int = -1

func nlAlign(len int) int {
	return (len + 3) & ^3
}

func ipsetInit() {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		errlog.Fatalf("ipset Netlink socket: %v", err)
	}
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		errlog.Fatalf("ipset Netlink bind: %v", err)
	}
	ipsetSock = fd
}

func ipsetClose() {
	if ipsetSock >= 0 {
		syscall.Close(ipsetSock)
		ipsetSock = -1
	}
}

func ipsetAddToSet(name string, ip net.IP) error {
	if len(name) >= ipset_MAXNAMELEN {
		return syscall.ENAMETOOLONG
	}

	is4 := ip.To4() != nil
	var af, addrsz int
	var ipAttrType uint16
	if is4 {
		af = syscall.AF_INET
		addrsz = net.IPv4len
		ipAttrType = ipset_ATTR_IPADDR_IPV4 | nla_F_NET_BYTEORDER
	} else {
		af = syscall.AF_INET6
		addrsz = net.IPv6len
		ipAttrType = ipset_ATTR_IPADDR_IPV6 | nla_F_NET_BYTEORDER
	}

	buf := make([]byte, 256)
	nlhLen := int(unsafe.Sizeof(syscall.NlMsghdr{}))
	nfgLen := int(unsafe.Sizeof(nfgenmsg{}))

	// nlmsghdr
	nlh := (*syscall.NlMsghdr)(unsafe.Pointer(&buf[0]))
	nlh.Len = uint32(nlhLen)
	nlh.Type = uint16(ipset_CMD_ADD | (nfNL_SUBSYS_IPSET << 8))
	nlh.Flags = nlm_F_REQUEST | nlm_F_ACK
	nlh.Seq = 1
	nlh.Pid = 0

	// nfgenmsg
	off := nlAlign(int(nlh.Len))
	nfg := (*nfgenmsg)(unsafe.Pointer(&buf[off]))
	nfg.Family = uint8(af)
	nfg.Version = nfNETLINK_V0
	nfg.ResId = 0
	nlh.Len = uint32(off + nfgLen)

	// IPSET_ATTR_PROTOCOL
	off = nlAlign(int(nlh.Len))
	binary.LittleEndian.PutUint16(buf[off:], 4+1)
	binary.LittleEndian.PutUint16(buf[off+2:], ipset_ATTR_PROTOCOL)
	buf[off+4] = ipset_PROTOCOL
	nlh.Len = uint32(off + nlAlign(5))

	// IPSET_ATTR_SETNAME
	off = nlAlign(int(nlh.Len))
	nameBytes := append([]byte(name), 0)
	nlaLen := 4 + len(nameBytes)
	binary.LittleEndian.PutUint16(buf[off:], uint16(nlaLen))
	binary.LittleEndian.PutUint16(buf[off+2:], ipset_ATTR_SETNAME)
	copy(buf[off+4:], nameBytes)
	nlh.Len = uint32(off + nlAlign(nlaLen))

	// Nested IPSET_ATTR_DATA
	dataNlaOff := nlAlign(int(nlh.Len))
	nlh.Len = uint32(dataNlaOff + nlAlign(4))

	// Nested IPSET_ATTR_IP
	ipNlaOff := nlAlign(int(nlh.Len))
	nlh.Len = uint32(ipNlaOff + nlAlign(4))

	// IP address attribute
	off = nlAlign(int(nlh.Len))
	ipNlaLen := 4 + addrsz
	binary.LittleEndian.PutUint16(buf[off:], uint16(ipNlaLen))
	binary.LittleEndian.PutUint16(buf[off+2:], ipAttrType)
	if is4 {
		copy(buf[off+4:], ip.To4())
	} else {
		copy(buf[off+4:], ip.To16())
	}
	nlh.Len = uint32(off + nlAlign(ipNlaLen))

	// Patch nested lengths
	total := int(nlh.Len)
	binary.LittleEndian.PutUint16(buf[ipNlaOff:], uint16(total-ipNlaOff))
	binary.LittleEndian.PutUint16(buf[ipNlaOff+2:], nla_F_NESTED|ipset_ATTR_IP)
	binary.LittleEndian.PutUint16(buf[dataNlaOff:], uint16(total-dataNlaOff))
	binary.LittleEndian.PutUint16(buf[dataNlaOff+2:], nla_F_NESTED|ipset_ATTR_DATA)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Sendto(ipsetSock, buf[:nlh.Len], 0, sa); err != nil {
		return err
	}

	// Read response
	resp := make([]byte, 256)
	n, _, err := syscall.Recvfrom(ipsetSock, resp, 0)
	if err != nil {
		return err
	}

	errLen := int(unsafe.Sizeof(syscall.NlMsgerr{}))
	if n >= nlhLen {
		rnlh := (*syscall.NlMsghdr)(unsafe.Pointer(&resp[0]))
		if rnlh.Type == syscall.NLMSG_ERROR && n >= errLen {
			nlerr := (*syscall.NlMsgerr)(unsafe.Pointer(&resp[nlhLen]))
			if nlerr.Error != 0 {
				return syscall.Errno(-nlerr.Error)
			}
		}
	}

	return nil
}
