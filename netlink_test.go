package ipset

import (
	"encoding/binary"
	"testing"

	"github.com/vishvananda/netlink/nl"
)

func TestNetlinkRouteAttrAndValue(t *testing.T) {
	// For ipset IPSET_ATTR_DATA, kernel returns attr header: [36, 0, 7, 128]
	// Because 128 (signed byte) represents 0, while golang byte is unsigned byte which decode it as 128
	var testCase = []byte{36, 0, 7, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if nl.NativeEndian() == binary.BigEndian {
		testCase = []byte{0, 36, 128, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	}
	attr, _, _, err := netlinkRouteAttrAndValue(testCase)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Len != 36 {
		t.Error(attr.Len)
	}
	if attr.Type != 7 {
		t.Error(attr.Type)
	}
}
