package ipset

import (
	"encoding/binary"
)

var (
	networkOrder = binary.BigEndian
)

func htonl(val uint32) []byte {
	bytes := make([]byte, 4)
	networkOrder.PutUint32(bytes, val)
	return bytes
}

func htons(val uint16) []byte {
	bytes := make([]byte, 2)
	networkOrder.PutUint16(bytes, val)
	return bytes
}

func ntohl(buf []byte) uint32 {
	return networkOrder.Uint32(buf)
}

func ntohs(buf []byte) uint16 {
	return networkOrder.Uint16(buf)
}
