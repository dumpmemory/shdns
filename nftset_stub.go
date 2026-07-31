//go:build !linux
// +build !linux

package main

import "net"

func nftInit() {}

func nftClose() {}

func nftAddElements(batches map[nftSetKey][]net.IP, qName string, id uint16) {}
