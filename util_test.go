package ipset

import (
	"testing"
	"net"
)

func TestIP4ToInt(t *testing.T) {
	intip := ip4ToInt(net.ParseIP("192.168.0.1"))
	if intip != 16820416 {
		t.Error(intip)
	}
}

func TestIntToIP4(t *testing.T) {
	ip := intToIP4(16820416)
	if ip == nil || ip.String() != "192.168.0.1" {
		t.Error(ip)
	}
}
