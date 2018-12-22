package ipset

import (
	"fmt"
	"net"
	"strconv"

	"github.com/chenchun/ipset/log"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Handle provides a namespace specific ipvs handle to program ipvs
// rules.
type Handle struct {
}

// New provides a new ipset handle in the namespace pointed to by the
// passed path. It will return a valid handle or an error in case an
// error occurred while creating the handle.
func New(path string) (*Handle, error) {
	n := netns.None()
	if path != "" {
		var err error
		n, err = netns.GetFromPath(path)
		if err != nil {
			return nil, err
		}
	}
	defer n.Close()

	//sock, err := nl.GetNetlinkSocketAt(n, netns.None(), syscall.NETLINK_GENERIC)
	//if err != nil {
	//	return nil, err
	//}

	return &Handle{}, nil
}

func (h *Handle) Create(set *IPSet, opts ...Opt) error {
	if set.Name == "" {
		return fmt.Errorf("Invalid create command: missing setname")
	}
	if string(set.SetType) == "" {
		return fmt.Errorf("Invalid create command: missing settype")
	}
	req, err := newRequest(IPSET_CMD_CREATE)
	if err != nil {
		return err
	}
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(set.Name)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_TYPENAME, nl.ZeroTerminated(string(set.SetType))))
	fillRevision(req, set.SetType, set.SetRevison)
	fillFamily(req, set.Family)
	_, err = req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

func (h *Handle) Destroy(setName string, opts ...Opt) error {
	if setName == "" {
		return fmt.Errorf("invalid destroy command: missing setname")
	}
	req, err := newRequest(IPSET_CMD_DESTROY)
	if err != nil {
		return err
	}
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))
	_, err = req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

func fillRevision(req *nl.NetlinkRequest, setType SetType, revision *uint8) {
	if revision != nil {
		req.AddData(nl.NewRtAttr(IPSET_ATTR_REVISION, nl.Uint8Attr(uint8(*revision))))
	} else {
		req.AddData(nl.NewRtAttr(IPSET_ATTR_REVISION, nl.Uint8Attr(setRevisionMap[setType])))
	}
}

func fillFamily(req *nl.NetlinkRequest, hashFamily string) {
	switch hashFamily {
	case "inet6":
		req.AddData(nl.NewRtAttr(IPSET_ATTR_FAMILY, nl.Uint8Attr(uint8(NFPROTO_IPV6))))
	case "inet":
		fallthrough
	default:
		req.AddData(nl.NewRtAttr(IPSET_ATTR_FAMILY, nl.Uint8Attr(uint8(NFPROTO_IPV4))))
	}
}

func (h *Handle) Protocol() (uint8, error) {
	req, err := newRequest(IPSET_CMD_PROTOCOL)
	if err != nil {
		return 0, err
	}
	msgs, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	if err != nil {
		return 0, err
	}
	var min, max uint8
	for i := range msgs {
		if len(msgs[i]) < SizeofNFGenMsg {
			return 0, fmt.Errorf("possible corrupt msg %v", msgs[i])
		}
		//nlGenlMsg := DeserializeNFGenlMsg(msgs[i])
		attrs, err := nl.ParseRouteAttr(msgs[i][SizeofNFGenMsg:])
		if err != nil {
			return 0, fmt.Errorf("possible corrupt msg %v", msgs[i])
		}
		for i := range attrs {
			switch attrs[i].Attr.Type {
			case IPSET_ATTR_PROTOCOL:
				if attrs[i].Attr.Len != unix.SizeofRtAttr+1 {
					return 0, fmt.Errorf("possible corrupt msg %v", msgs[i])
				}
				max = uint8(attrs[i].Value[0])
				if min == 0 {
					min = max
				}
			case IPSET_ATTR_PROTOCOL_MIN:
				min = uint8(attrs[i].Value[0])
			}
		}
		break
	}
	log.Debugf("supported protocol %d, min supported %d", max, min)
	return max, nil
}

func (h *Handle) List(setName string, opts ...Opt) ([]IPSet, error) {
	req, err := newRequest(IPSET_CMD_LIST)
	if err != nil {
		return nil, err
	}
	if setName != "" {
		req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))
	}
	req.AddData(nl.NewRtAttr(IPSET_ATTR_FLAGS, nl.Uint32Attr(IPSET_FLAG_LIST_SETNAME|IPSET_FLAG_LIST_HEADER)))
	msgs, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	if err != nil {
		return nil, err
	}
	var sets []IPSet
	for i := range msgs {
		ipset := &IPSet{}
		if len(msgs[i]) < SizeofNFGenMsg {
			return nil, fmt.Errorf("possible corrupt msg %v", msgs[i])
		}
		//nlGenlMsg := DeserializeNFGenlMsg(msgs[i])
		attrs, err := nl.ParseRouteAttr(msgs[i][SizeofNFGenMsg:])
		if err != nil {
			return nil, fmt.Errorf("possible corrupt msg %v", msgs[i])
		}
		for i := range attrs {
			switch attrs[i].Attr.Type {
			case IPSET_ATTR_PROTOCOL:
				if attrs[i].Attr.Len != unix.SizeofRtAttr+1 {
					return nil, fmt.Errorf("possible corrupt msg %v", msgs[i])
				}
				//protocol := uint8(attrs[i].Value[0])
			case IPSET_ATTR_SETNAME:
				// 0 terminated
				ipset.Name = string(attrs[i].Value[:len(attrs[i].Value)-1])
			case IPSET_ATTR_TYPENAME:
				ipset.SetType = SetType(attrs[i].Value[:len(attrs[i].Value)-1])
			case IPSET_ATTR_REVISION:
				if attrs[i].Attr.Len != unix.SizeofRtAttr+1 {
					return nil, fmt.Errorf("possible corrupt msg %v", msgs[i])
				}
				ipset.SetRevison = &attrs[i].Value[0]
			case IPSET_ATTR_FAMILY:
				if attrs[i].Attr.Len != unix.SizeofRtAttr+1 {
					return nil, fmt.Errorf("possible corrupt msg %v", msgs[i])
				}
				switch attrs[i].Value[0] {
				case NFPROTO_IPV4:
					ipset.Family = "inet"
				case NFPROTO_IPV6:
					ipset.Family = "inet6"
				}
			case IPSET_ATTR_DATA | unix.NLA_F_NESTED:
				//nest attrs
				nestAttrs, err := nl.ParseRouteAttr(attrs[i].Value)
				if err != nil {
					return nil, fmt.Errorf("possible corrupt msg %v", msgs[i])
				}
				_ = nestAttrs
				// TODO deserialize entries
			}
		}
		sets = append(sets, *ipset)
	}
	return sets, nil
}

func (h *Handle) Add(set *IPSet, entry *Entry, opts ...Opt) error {
	return h.addOrDel(IPSET_CMD_ADD, set, entry, opts...)
}

func (h *Handle) Del(set *IPSet, entry *Entry, opts ...Opt) error {
	return h.addOrDel(IPSET_CMD_DEL, set, entry, opts...)
}

func (h *Handle) addOrDel(command int, set *IPSet, entry *Entry, opts ...Opt) error {
	if set.Name == "" {
		return fmt.Errorf("invalid add command: missing setname")
	}
	req, err := newRequest(command)
	if err != nil {
		return err
	}
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(set.Name)))
	dataAttr := nl.NewRtAttr(IPSET_ATTR_DATA|unix.NLA_F_NESTED, nil)
	//for i := IPSET_ATTR_UNSPEC + 1; i <= IPSET_ATTR_ADT_MAX; i++ {
	//
	//}
	if set.SetType == HashIP {
		// TODO netmask
		if err := fillIP(dataAttr, entry.IP); err != nil {
			return err
		}
		dataAttr.AddRtAttr(IPSET_ATTR_LINENO|unix.NLA_F_NET_BYTEORDER, nl.Uint32Attr(0))
	}
	req.AddData(dataAttr)
	data := req.Serialize()
	log.Debugf("%v", data)
	_, err = req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

func fillIP(parent *nl.RtAttr, ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid add command: bad ip: %s", ipStr)
	}
	ipAttr := nl.NewRtAttr(IPSET_ATTR_IP|unix.NLA_F_NESTED, nil)
	if ip4 := ip.To4(); ip4 != nil {
		ipAttr.AddRtAttr(IPSET_ATTR_IPADDR_IPV4|unix.NLA_F_NET_BYTEORDER, nl.Uint32Attr(ip4ToInt(ip)))
	} else if ip6 := ip.To16(); ip6 != nil {
		// TODO ip6
	}
	parent.AddChild(ipAttr)
	return nil
}

func newRequest(cmd int) (*nl.NetlinkRequest, error) {
	if cmd <= IPSET_CMD_NONE || cmd >= IPSET_MSG_MAX {
		return nil, fmt.Errorf("cmd should between IPSET_CMD_NONE and IPSET_MSG_MAX")
	}
	req := nl.NewNetlinkRequest(cmd|(NFNL_SUBSYS_IPSET<<8), IPSetCmdflags[cmd-1])
	req.AddData(&nfgenmsg{family: unix.AF_INET, version: NFNETLINK_V0, resid: 0})
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(uint8(IPSET_PROTOCOL_MIN))))
	return req, nil
}

func print(msg [][]byte) {
	for i := range msg {
		log.Infof("i=%d %v", i, string(msg[i]))
	}
}

// TryConvertErrno tries to convert input err to a IPSETErrno
// Return the IPSetErrno pointer if it succeeds, otherwise nil
func TryConvertErrno(err error) *int32 {
	if len(err.Error()) < len("errno ") {
		return nil
	}
	no, err := strconv.Atoi(err.Error()[len("errno "):])
	if err != nil {
		return nil
	}
	ipsetNo := int32(no)
	if ipsetNo >= IPSET_ERR_PRIVATE && ipsetNo <= IPSET_ERR_SKBINFO {
		return &ipsetNo
	}
	return nil
}
