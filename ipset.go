package ipset

import (
	"fmt"
	"net"
	"strconv"

	"github.com/chenchun/ipset/log"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Handle provides a specific ipset handle to program ipset rules.
type Handle struct {
}

func New() (*Handle, error) {
	return &Handle{}, nil
}

func (h *Handle) Create(set *IPSet, opts ...Opt) error {
	if set.Name == "" {
		return fmt.Errorf("Invalid create command: missing setname")
	}
	if string(set.SetType) == "" {
		return fmt.Errorf("Invalid create command: missing settype")
	}
	if set.Family == "" {
		// family must be set as empty for HashMac
		if set.SetType != HashMac {
			set.Family = "inet"
		}
	}
	req, err := newRequest(IPSET_CMD_CREATE)
	if err != nil {
		return err
	}
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(set.Name)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_TYPENAME, nl.ZeroTerminated(string(set.SetType))))
	fillRevision(req, set.SetType, set.SetRevison)
	fillFamily(req, set.Family)
	log.Debugf("create %v", req.Serialize())
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
		req.AddData(nl.NewRtAttr(IPSET_ATTR_FAMILY, nl.Uint8Attr(uint8(NFPROTO_IPV4))))
	default:
		req.AddData(nl.NewRtAttr(IPSET_ATTR_FAMILY, nl.Uint8Attr(uint8(NFPROTO_UNSPEC))))
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
	if err := fillEntries(dataAttr, set, entry); err != nil {
		return err
	}
	req.AddData(dataAttr)
	log.Debugf("addOrDel %v", req.Serialize())
	_, err = req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

type fillAddAttr func(parent *nl.RtAttr, entry *Entry) error

var setTypeFillFuncMap = map[SetType][]fillAddAttr{
	HashIP:         {fillIP},
	HashMac:        {fillMac},
	HashIPMac:      {fillIP, fillMac},
	HashNet:        {fillIP},
	HashNetNet:     {fillIP, fillIP2},
	HashIPPort:     {fillIP, fillPort},
	HashNetPort:    {fillIP, fillPort},
	HashIPPortIP:   {fillIP, fillPort, fillIP2},
	HashIPPortNet:  {fillIP, fillPort, fillIP2},
	HashNetPortNet: {fillIP, fillPort, fillIP2},
}

func fillEntries(parent *nl.RtAttr, set *IPSet, entry *Entry) error {
	if funcs, exist := setTypeFillFuncMap[set.SetType]; !exist {
		return fmt.Errorf("adding entries for setType %s not supported now", set.SetType)
	} else {
		for i := range funcs {
			if err := funcs[i](parent, entry); err != nil {
				return err
			}
		}
	}
	fillLineno(parent)
	return nil
}

func fillLineno(parent *nl.RtAttr) {
	parent.AddRtAttr(IPSET_ATTR_LINENO|unix.NLA_F_NET_BYTEORDER, nl.Uint32Attr(0))
}

func fillIP(parent *nl.RtAttr, entry *Entry) error {
	ip := net.ParseIP(entry.IP)
	if ip == nil {
		return fmt.Errorf("invalid add command: bad ip: %s", entry.IP)
	}
	ipAttr := nl.NewRtAttr(IPSET_ATTR_IP|unix.NLA_F_NESTED, nil)
	if ip4 := ip.To4(); ip4 != nil {
		ipAttr.AddRtAttr(IPSET_ATTR_IPADDR_IPV4|unix.NLA_F_NET_BYTEORDER, []byte(ip4))
	} else if ip6 := ip.To16(); ip6 != nil {
		// TODO ip6
	}
	parent.AddChild(ipAttr)
	if entry.CIDR != nil {
		parent.AddRtAttr(IPSET_ATTR_CIDR, nl.Uint8Attr(*entry.CIDR))
	}
	return nil
}

func fillPort(parent *nl.RtAttr, entry *Entry) error {
	parent.AddRtAttr(IPSET_ATTR_PORT|unix.NLA_F_NET_BYTEORDER, htons(entry.Port))
	if entry.PortTo != 0 {
		parent.AddRtAttr(IPSET_ATTR_PORT_TO|unix.NLA_F_NET_BYTEORDER, htons(entry.PortTo))
	}
	if entry.Proto == 0 {
		parent.AddRtAttr(IPSET_ATTR_PROTO, nl.Uint8Attr(unix.IPPROTO_TCP))
	} else {
		parent.AddRtAttr(IPSET_ATTR_PROTO, nl.Uint8Attr(entry.Proto))
	}
	return nil
}

func fillIP2(parent *nl.RtAttr, entry *Entry) error {
	ip := net.ParseIP(entry.IP2)
	if ip == nil {
		return fmt.Errorf("invalid add command: bad ip: %s", entry.IP2)
	}
	ipAttr := nl.NewRtAttr(IPSET_ATTR_IP2|unix.NLA_F_NESTED, nil)
	if ip4 := ip.To4(); ip4 != nil {
		ipAttr.AddRtAttr(IPSET_ATTR_IPADDR_IPV4|unix.NLA_F_NET_BYTEORDER, []byte(ip4))
	} else if ip6 := ip.To16(); ip6 != nil {
		// TODO ip6
	}
	parent.AddChild(ipAttr)
	if entry.CIDR2 != nil {
		parent.AddRtAttr(IPSET_ATTR_CIDR2, nl.Uint8Attr(*entry.CIDR2))
	}
	return nil
}

func fillMac(parent *nl.RtAttr, entry *Entry) error {
	if len(entry.Mac) == 0 {
		return fmt.Errorf("invalid add command: bad mac: %v", entry.Mac)
	}
	parent.AddRtAttr(IPSET_ATTR_ETHER, []byte(entry.Mac))
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
