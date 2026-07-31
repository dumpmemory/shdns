//go:build !linux
// +build !linux

package main

import "net"

var ipsetSock int = -1

func ipsetInit() {}

func ipsetClose() {}

func ipsetAddToSet(name string, ip net.IP) error {
	return nil
}
