package ipset

import (
	"errors"
	"testing"
)

func TestProtocol(t *testing.T) {
	h, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Protocol(); err != nil {
		t.Fatal(err)
	}
}

func TestCreate(t *testing.T) {
	h, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.CreateSet(&IPSet{Name: "TestCreate-inet4", SetType: HashIP, Family: "inet"}, true); err != nil {
		t.Fatal(err)
	}
	// defer delete set
	if err := h.CreateSet(&IPSet{Name: "TestCreate-inet6", SetType: HashIP, Family: "inet6"}, true); err != nil {
		t.Fatal(err)
	}
}

func TestTryConvertErrno(t *testing.T) {
	if err := TryConvertErrno(errors.New("errno 4106")); err != nil || *err != IPSET_ERR_INVALID_FAMILY {
		t.Fatal(err)
	}
	if err := TryConvertErrno(errors.New("errno -1")); err != nil {
		t.Fatal(err)
	}
}
