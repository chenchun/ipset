package ipset

import (
	"net"

	"github.com/vishvananda/netlink/nl"
)

var (
	endian = nl.NativeEndian()
)

func ip4ToInt(ip net.IP) uint32 {
	byties := ip.To4()
	if byties == nil {
		return 0
	}
	return endian.Uint32(byties)
}

func intToIP4(num uint32) net.IP {
	ip := make(net.IP, 4)
	endian.PutUint32(ip, num)
	return ip
}
