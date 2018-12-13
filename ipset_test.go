package ipset

import (
	"errors"
	"testing"
	"fmt"
	"strings"
)

func TestProtocol(t *testing.T) {
	h, err := New("")
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
	h, err := New("")
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
	h, err := New("")
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
