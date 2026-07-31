//go:build !linux
// +build !linux

package main

import "net"

func ipsetInit() {}

func ipsetClose() {}

func ipsetAddElements(name string, ips []net.IP, qName string, id uint16) {}
