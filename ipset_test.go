package ipset

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"encoding/json"
	"github.com/chenchun/ipset/log"
	"golang.org/x/sys/unix"
)

func TestProtocol(t *testing.T) {
	h := &Handle{l: &log.Log{}}
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
	h := &Handle{l: &log.Log{}}
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
			errno := TryConvertErrno(err)
			if errno == nil {
				t.Error(err)
			} else {
				if *errno != IPSET_ERR_PROTOCOL && *errno != IPSET_ERR_FIND_TYPE {
					t.Errorf("create setType %s failed: %v", string(setType), err)
				} else {
					// skip some settypes which may not be supported
					t.Logf("skip creating setType %s: %v", string(setType), err)
				}
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
	h := &Handle{l: &log.Log{}}
	testSet := &IPSet{Name: "TestList", SetType: HashIP}
	if err := h.Create(testSet); err != nil {
		t.Fatal(err)
	}
	testEntry1 := Entry{IP: "192.168.0.1"}
	if err := h.Add(testSet, &testEntry1); err != nil {
		t.Fatalf("case %s add: %v", testSet.Name, err)
	}
	sets, err := h.List("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprintf("%+v", sets), `{Name:TestList SetType:hash:ip Family:inet HashSize:0 MaxElem:0 PortRange: Comment: SetRevison:`) {
		t.Errorf(fmt.Sprintf("%+v", sets))
	}
	if len(sets) <= 0 {
		t.Fatal()
	}
	for i := range sets {
		if sets[i].Name == testSet.Name {
			if len(sets[i].Entries) != 1 {
				t.Fatalf("expect 1 entry, real entries: %v", sets[i].Entries)
			}
			expectEntry := fmt.Sprintf("%v", testEntry1)
			if fmt.Sprintf("%v", sets[i].Entries[0]) != expectEntry {
				t.Errorf("expect entry %v, real entry: %v", expectEntry, sets[i].Entries[0])
			}
		}
	}
	testEntry2 := Entry{IP: "192.168.0.2"}
	if err := h.Add(testSet, &testEntry2); err != nil {
		t.Errorf("case %s add: %v", testSet.Name, err)
	}
	sets, err = h.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) <= 0 {
		t.Fatal()
	}
	for i := range sets {
		if sets[i].Name == testSet.Name {
			if len(sets[i].Entries) != 2 {
				t.Errorf("expect 2 entry, real entries: %v", sets[i].Entries)
				continue
			}
			var entryStrs []string
			for j := range sets[i].Entries {
				entryStrs = append(entryStrs, fmt.Sprintf("%+v", sets[i].Entries[j]))
			}
			sort.Strings(entryStrs)
			expect := fmt.Sprintf("%+v", []Entry{testEntry1, testEntry2})
			if fmt.Sprintf("%v", entryStrs) != expect {
				t.Errorf("expect entry %v, real entry: %v", expect, entryStrs)
			}
		}
	}
	if err := h.Destroy(testSet.Name); err != nil {
		t.Errorf("destroy failed: %v", err)
	}
}

func TestAddDelHashIP(t *testing.T) {
	h := &Handle{l: &log.Log{}}
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

func checkListEntries(h *Handle, test addDelCase) error {
	iterms, err := h.List(test.set.Name)
	if err != nil {
		return err
	}
	if len(iterms) != 1 {
		return fmt.Errorf("zero iterms %s", test.set.Name)
	} else {
		if len(iterms[0].Entries) != len(test.expectEntries) {
			return fmt.Errorf("expect %+v, real %+v", test.expectEntries, iterms[0].Entries)
		}
		sort.Sort(by(test.expectEntries))
		expectJson, err := json.Marshal(test.expectEntries)
		if err != nil {
			return err
		}
		sort.Sort(by(iterms[0].Entries))
		realJson, err := json.Marshal(iterms[0].Entries)
		if err != nil {
			return err
		}
		if string(expectJson) != string(realJson) {
			return fmt.Errorf("expect %s, real %s", expectJson, realJson)
		}
	}
	return nil
}

type by []Entry

func (b by) Len() int {
	return len(b)
}

func (b by) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func (b by) Less(i, j int) bool {
	if b[i].IP != b[j].IP {
		return b[i].IP < b[j].IP
	}
	if b[i].CIDR != nil && b[j].CIDR != nil {
		if *b[i].CIDR != *b[j].CIDR {
			return *b[i].CIDR < *b[j].CIDR
		}
	}
	if b[i].Port != b[j].Port {
		return b[i].Port < b[j].Port
	}
	if b[i].Proto != b[j].Proto {
		return b[i].Proto < b[j].Proto
	}
	if b[i].IP2 != b[j].IP2 {
		return b[i].IP2 < b[j].IP2
	}
	if b[i].CIDR2 != nil && b[j].CIDR2 != nil {
		if *b[i].CIDR2 != *b[j].CIDR2 {
			return *b[i].CIDR2 < *b[j].CIDR2
		}
	}
	return true
}

type addDelCase struct {
	set            *IPSet
	entry          *Entry
	expectEntryStr []string
	expectEntries  []Entry
}

func TestAddDelList(t *testing.T) {
	h := &Handle{l: &log.Log{}}
	mac, err := net.ParseMAC("01:23:45:67:89:ab")
	if err != nil {
		t.Fatal(err)
	}
	cidr24 := uint8(24)
	for _, test := range []addDelCase{
		{
			set:            &IPSet{Name: "TestAddDelHashIP", SetType: HashIP},
			entry:          &Entry{IP: "192.168.0.1"},
			expectEntryStr: []string{"192.168.0.1"},
			expectEntries:  []Entry{{IP: "192.168.0.1"}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashMac", SetType: HashMac},
			entry:          &Entry{Mac: mac},
			expectEntryStr: []string{"01:23:45:67:89:AB"},
			expectEntries:  []Entry{{Mac: mac}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashIPMac", SetType: HashIPMac},
			entry:          &Entry{IP: "192.168.0.1", Mac: mac},
			expectEntryStr: []string{"192.168.0.1,01:23:45:67:89:AB"},
			expectEntries:  []Entry{{IP: "192.168.0.1", Mac: mac}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashNet", SetType: HashNet},
			entry:          &Entry{IP: "192.168.0.1", CIDR: &cidr24},
			expectEntryStr: []string{"192.168.0.0/24"},
			expectEntries:  []Entry{{IP: "192.168.0.0", CIDR: &cidr24}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashNetNet", SetType: HashNetNet},
			entry:          &Entry{IP: "192.168.0.1", CIDR: &cidr24, IP2: "192.168.0.2", CIDR2: &cidr24},
			expectEntryStr: []string{"192.168.0.0/24,192.168.0.0/24"},
			expectEntries:  []Entry{{IP: "192.168.0.0", CIDR: &cidr24, IP2: "192.168.0.0", CIDR2: &cidr24}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashIPPort", SetType: HashIPPort},
			entry:          &Entry{IP: "192.168.0.1", Port: 34},
			expectEntryStr: []string{"192.168.0.1,tcp:34"},
			expectEntries:  []Entry{{IP: "192.168.0.1", Port: 34, Proto: unix.IPPROTO_TCP}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashIPPort-Range", SetType: HashIPPort},
			entry:          &Entry{IP: "192.168.0.1", Port: 34, PortTo: 35, Proto: unix.IPPROTO_UDP},
			expectEntryStr: []string{"192.168.0.1,udp:35", "192.168.0.1,udp:34"},
			expectEntries:  []Entry{{IP: "192.168.0.1", Port: 34, Proto: unix.IPPROTO_UDP}, {IP: "192.168.0.1", Port: 35, Proto: unix.IPPROTO_UDP}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashNetPort", SetType: HashNetPort},
			entry:          &Entry{IP: "192.168.0.1", CIDR: &cidr24, Port: 34, Proto: unix.IPPROTO_TCP},
			expectEntryStr: []string{"192.168.0.0/24,tcp:34"},
			expectEntries:  []Entry{{IP: "192.168.0.0", CIDR: &cidr24, Port: 34, Proto: unix.IPPROTO_TCP}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashNetPort", SetType: HashNetPort},
			entry:          &Entry{IP: "192.168.0.1", CIDR: &cidr24, Port: 34, Proto: unix.IPPROTO_UDP},
			expectEntryStr: []string{"192.168.0.0/24,udp:34"},
			expectEntries:  []Entry{{IP: "192.168.0.0", CIDR: &cidr24, Port: 34, Proto: unix.IPPROTO_UDP}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashIPPortIP", SetType: HashIPPortIP},
			entry:          &Entry{IP: "192.168.0.1", Port: 34, Proto: unix.IPPROTO_UDP, IP2: "192.168.0.2"},
			expectEntryStr: []string{"192.168.0.1,udp:34,192.168.0.2"},
			expectEntries:  []Entry{{IP: "192.168.0.1", Port: 34, Proto: unix.IPPROTO_UDP, IP2: "192.168.0.2"}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashIPPortNet", SetType: HashIPPortNet},
			entry:          &Entry{IP: "192.168.0.1", Port: 34, Proto: unix.IPPROTO_UDP, IP2: "192.168.1.2", CIDR2: &cidr24},
			expectEntryStr: []string{"192.168.0.1,udp:34,192.168.1.0/24"},
			expectEntries:  []Entry{{IP: "192.168.0.1", Port: 34, Proto: unix.IPPROTO_UDP, IP2: "192.168.1.0", CIDR2: &cidr24}},
		},
		{
			set:            &IPSet{Name: "TestAddDelHashNetPortNet", SetType: HashNetPortNet},
			entry:          &Entry{IP: "192.168.0.1", CIDR: &cidr24, Port: 34, Proto: unix.IPPROTO_UDP, IP2: "192.168.1.2", CIDR2: &cidr24},
			expectEntryStr: []string{"192.168.0.0/24,udp:34,192.168.1.0/24"},
			expectEntries:  []Entry{{IP: "192.168.0.0", CIDR: &cidr24, Port: 34, Proto: unix.IPPROTO_UDP, IP2: "192.168.1.0", CIDR2: &cidr24}},
		},
	} {
		if err := h.Create(test.set); err != nil {
			errno := TryConvertErrno(err)
			if errno == nil {
				t.Error(err)
			} else {
				if *errno != IPSET_ERR_PROTOCOL && *errno != IPSET_ERR_FIND_TYPE {
					t.Errorf("create setType %s failed: %v", string(test.set.SetType), err)
				} else {
					// skip some settypes which may not be supported
					t.Logf("skip creating setType %s: %v", string(test.set.SetType), err)
					continue
				}
			}
		}
		if err := h.Add(test.set, test.entry); err != nil {
			t.Errorf("case %s add: %v", test.set.Name, err)
		}
		if entries, err := listMembers(test.set.Name); err != nil {
			t.Errorf("case %s check: %v", test.set.Name, err)
		} else {
			sort.Strings(entries)
			sort.Strings(test.expectEntryStr)
			if fmt.Sprintf("%v", entries) != fmt.Sprintf("%v", test.expectEntryStr) {
				t.Errorf("case %s checkEntries: expect %q, real %q", test.set.Name, test.expectEntryStr, entries)
			}
		}
		if err := checkListEntries(h, test); err != nil {
			t.Errorf("case %s list: %v", test.set.Name, err)
		}
		if err := h.Del(test.set, test.entry); err != nil {
			t.Errorf("case %s del: %v", test.set.Name, err)
		}
		if err := h.Destroy(test.set.Name); err != nil {
			t.Errorf("case %s destroy: %v", test.set.Name, err)
		}
	}
}
