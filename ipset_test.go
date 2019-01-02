package ipset

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProtocol(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if proto, err := h.Protocol(); err != nil {
		t.Fatal(err)
	} else if proto < IPSET_PROTOCOL_MIN || proto > IPSET_PROTOCOL {
		t.Fatal(err)
	}
}

func allSetType() []SetType {
	return []SetType{
		BitmapIP,
		BitmapIPMac,
		BitmapPort,
		HashIP,
		HashMac,
		HashIPMac,
		HashNet,
		HashNetNet,
		HashIPPort,
		HashNetPort,
		HashIPPortIP,
		HashIPPortNet,
		HashIPMark,
		HashNetPortNet,
		HashNetIface,
		ListSet,
	}
}

func TestCreateDestroy(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Create(&IPSet{Name: "TestCreate-inet", SetType: HashIP, Family: "inet"}); err != nil {
		t.Error(err)
	}
	if err := h.Destroy("TestCreate-inet"); err != nil {
		t.Error(err)
	}
	if err := h.Create(&IPSet{Name: "TestCreate-inet6", SetType: HashIP, Family: "inet6"}); err != nil {
		t.Error(err)
	}
	if err := h.Destroy("TestCreate-inet6"); err != nil {
		t.Error(err)
	}
	for _, setType := range allSetType() {
		name := "TestCreate" + string(setType)
		if err := h.Create(&IPSet{Name: name, SetType: setType}); err != nil {
			errno := *TryConvertErrno(err)
			if errno != IPSET_ERR_PROTOCOL && errno != IPSET_ERR_FIND_TYPE {
				t.Errorf("create setType %s failed: %v", string(setType), err)
			} else {
				// skip some settypes which may not be supported
				t.Logf("skip creating setType %s: %v", string(setType), err)
			}
		} else {
			if err := h.Destroy(name); err != nil {
				t.Errorf("destroy setType %s failed: %v", string(setType), err)
			}
		}
	}
}

func TestTryConvertErrno(t *testing.T) {
	if err := TryConvertErrno(errors.New("errno 4106")); err == nil || (*err) != IPSET_ERR_INVALID_FAMILY {
		t.Fatal(err)
	}
	if err := TryConvertErrno(errors.New("errno -1")); err != nil {
		t.Fatal(err)
	}
}

func TestList(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Create(&IPSet{Name: "TestList", SetType: HashIP}); err != nil {
		t.Error(err)
	}
	if sets, err := h.List(""); err != nil {
		t.Error(err)
	} else if !strings.Contains(fmt.Sprintf("%+v", sets), `{Name:TestList SetType:hash:ip Family:inet HashSize:0 MaxElem:0 PortRange: Comment: SetRevison:`) {
		t.Errorf(fmt.Sprintf("%+v", sets))
	}
	if err := h.Destroy("TestList"); err != nil {
		t.Errorf("destroy failed: %v", err)
	}
}

func TestAddDelHashIP(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	set := &IPSet{Name: "TestAddDelHashIP", SetType: HashIP}
	if err := h.Create(set); err != nil {
		t.Error(err)
	}
	entry := &Entry{IP: "192.168.0.1"}
	// expect send bytes
	// len      type flags seq          pid               Protocol         SET_NAME  TestAdd                      DATA         IP         IPADDR_IPV4            LINENO
	// 64 0 0 0  9 6  5 2  1   0  0  0  0 0 0 0  2 0 0 0  5 0 1 0 6 0 0 0  12 0 2 0  84 101 115 116 65 100 100 0  24 0 7 128  12 0 1 128  8 0 1 64 192 168 0 1   8 0 9 64  0 0 0 0
	if err := h.Add(set, entry); err != nil {
		t.Error(err)
	}
	if err := checkFirstMember(set.Name, "192.168.0.1"); err != nil {
		t.Error(err)
	}
	if err := h.Del(set, entry); err != nil {
		t.Error(err)
	}
	if err := h.Destroy(set.Name); err != nil {
		t.Errorf("destroy failed: %v", err)
	}
}

func listMembers(set string) ([]string, error) {
	data, err := exec.Command("ipset", "list", set).CombinedOutput()
	if err != nil {
		return nil, err
	}
	var entries []string
	var members bool
	for _, line := range strings.Split(string(data), "\n") {
		if members {
			if line != "" {
				entries = append(entries, line)
			}
		}
		if strings.HasPrefix(line, "Members:") {
			members = true
		}
	}
	return entries, nil
}

func checkFirstMember(set, expectFirst string) error {
	if members, err := listMembers(set); err != nil {
		return err
	} else {
		if len(members) == 0 {
			return fmt.Errorf("expect first member %q, real %q", expectFirst, "")
		}
		if members[0] != expectFirst {
			return fmt.Errorf("expect first member %q, real %q", expectFirst, members[0])
		}
		return nil
	}
}

type addDelCase struct {
	set           *IPSet
	entry         *Entry
	expectFirst   string
	expectEntries []string
}

func TestAddDel(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	cidr24 := uint8(24)
	for _, test := range []addDelCase{
		{
			set:         &IPSet{Name: "TestAddDelHashIP", SetType: HashIP},
			entry:       &Entry{IP: "192.168.0.1"},
			expectFirst: "192.168.0.1",
		},
		{
			set:         &IPSet{Name: "TestAddDelHashNet", SetType: HashNet},
			entry:       &Entry{IP: "192.168.0.1", CIDR: &cidr24},
			expectFirst: "192.168.0.0/24",
		},
		{
			set:         &IPSet{Name: "TestAddDelHashIPPort", SetType: HashIPPort},
			entry:       &Entry{IP: "192.168.0.1", Port: 34},
			expectFirst: "192.168.0.1,tcp:34",
		},
		{
			set:           &IPSet{Name: "TestAddDelHashIPPortRange", SetType: HashIPPort},
			entry:         &Entry{IP: "192.168.0.1", Port: 34, PortTo: 35, Proto: unix.IPPROTO_UDP},
			expectEntries: []string{"192.168.0.1,udp:35", "192.168.0.1,udp:34"},
		},
		{
			set:         &IPSet{Name: "TestAddDelHashNetPort", SetType: HashNetPort},
			entry:       &Entry{IP: "192.168.0.1", CIDR: &cidr24, Port: 34, Proto: unix.IPPROTO_TCP},
			expectFirst: "192.168.0.0/24,tcp:34",
		},
		{
			set:           &IPSet{Name: "TestAddDelHashNetPortRange", SetType: HashNetPort},
			entry:         &Entry{IP: "192.168.0.1", CIDR: &cidr24, Port: 34, PortTo: 35, Proto: unix.IPPROTO_UDP},
			expectEntries: []string{"192.168.0.0/24,udp:35", "192.168.0.0/24,udp:34"},
		},
	} {
		if err := h.Create(test.set); err != nil {
			t.Errorf("case %s create: %v", test.set.Name, err)
		}
		if err := h.Add(test.set, test.entry); err != nil {
			t.Errorf("case %s add: %v", test.set.Name, err)
		}
		if test.expectEntries != nil {
			if entries, err := listMembers(test.set.Name); err != nil {
				t.Errorf("case %s check: %v", test.set.Name, err)
			} else {
				if fmt.Sprintf("%v", entries) != fmt.Sprintf("%v", test.expectEntries) {
					t.Errorf("case %s checkEntries: expect %q, real %q", test.set.Name, test.expectEntries, entries)
				}
			}
		} else {
			if err := checkFirstMember(test.set.Name, test.expectFirst); err != nil {
				t.Errorf("case %s checkFirstMember: %v", test.set.Name, err)
			}
		}
		if err := h.Del(test.set, test.entry); err != nil {
			t.Errorf("case %s del: %v", test.set.Name, err)
		}
		if err := h.Destroy(test.set.Name); err != nil {
			t.Errorf("case %s destroy: %v", test.set.Name, err)
		}
	}
}
