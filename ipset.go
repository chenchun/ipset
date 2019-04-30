package ipset

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/chenchun/ipset/log"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var (
	revisionLock   sync.RWMutex
	setRevisionMap = map[SetType][]uint8{} // check ipset/lib/ipset_hash_ip.c ...
)

// Handle provides a specific ipset handle to program ipset rules.
type Handle struct {
	l         log.LOG
	protolcol uint8
}

func New(l log.LOG) (*Handle, error) {
	h := &Handle{l: l}
	if proto, err := h.protocol(); err != nil {
		return nil, fmt.Errorf("failed to get kernel supported ipset protocol version: %v", err)
	} else {
		h.protolcol = proto
	}
	return h, nil
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
	req, err := h.newRequest(IPSET_CMD_CREATE)
	if err != nil {
		return err
	}
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(set.Name)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_TYPENAME, nl.ZeroTerminated(string(set.SetType))))
	if err := h.fillRevision(req, set.SetType, set.SetRevison); err != nil {
		return err
	}
	fillFamily(req, set.Family)
	h.l.Debugf("create %v", req.Serialize())
	_, err = req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

func (h *Handle) Destroy(setName string, opts ...Opt) error {
	if setName == "" {
		return fmt.Errorf("invalid destroy command: missing setname")
	}
	req, err := h.newRequest(IPSET_CMD_DESTROY)
	if err != nil {
		return err
	}
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))
	_, err = req.Execute(unix.NETLINK_NETFILTER, 0)
	return err
}

func (h *Handle) fillRevision(req *nl.NetlinkRequest, setType SetType, revision *uint8) error {
	var revisions []uint8
	revisionLock.RLock()
	cached, ok := setRevisionMap[setType]
	revisionLock.RUnlock()
	if ok {
		revisions = cached
	} else {
		max, min, err := h.getRevision(setType)
		if err != nil {
			return err
		}
		revisions = []uint8{min, max}
		revisionLock.Lock()
		setRevisionMap[setType] = revisions
		revisionLock.Unlock()
	}
	if revision != nil {
		if *revision < revisions[0] {
			return fmt.Errorf("revision %d is smaller than min supported %d", *revision, revisions[0])
		}
		if *revision > revisions[1] {
			return fmt.Errorf("revision %d is larger than max supported %d", *revision, revisions[1])
		}
		req.AddData(nl.NewRtAttr(IPSET_ATTR_REVISION, nl.Uint8Attr(uint8(*revision))))
	} else {
		req.AddData(nl.NewRtAttr(IPSET_ATTR_REVISION, nl.Uint8Attr(uint8(revisions[1]))))
	}
	return nil
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

//buffers: 28 0 0 0 1 6 1 0 124 248 115 92 0 0 0 0 2 0 0 0 5 0 1 0 7 0 0 0
//Message header: sent cmd  PROTOCOL (1)
//len 28
//flag EXIST
//seq 1551104124
//Command attributes:
//PROTOCOL: 7
//buffers: 28 0 0 0 1 6 0 0 124 248 115 92 57 10 0 0 2 0 0 0 5 0 1 0 6 0 0 0
//Message header: received cmd  PROTOCOL (1)
//len 28
//flag EXIST
//seq 1551104124
//Command attributes:
//PROTOCOL: 6
func (h *Handle) protocol() (uint8, error) {
	req, err := h.newRequest(IPSET_CMD_PROTOCOL)
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
	h.l.Debugf("supported protocol %d, min supported %d", max, min)
	return max, nil
}

func (h *Handle) List(setName string, opts ...Opt) ([]ListItem, error) {
	//req:	msg:	IPSET_CMD_LIST|SAVE
	//attr:	IPSET_ATTR_PROTOCOL
	//	IPSET_ATTR_SETNAME	(optional)
	//
	//resp:	attr:	IPSET_ATTR_SETNAME
	//		IPSET_ATTR_TYPENAME
	//		IPSET_ATTR_REVISION
	//		IPSET_ATTR_FAMILY
	//		IPSET_ATTR_DATA
	//			create-specific-data
	//		IPSET_ATTR_ADT
	//			IPSET_ATTR_DATA
	//				adt-specific-data
	//		IPSET_ATTR_ADT
	//			IPSET_ATTR_DATA
	//				adt-specific-data
	//		...
	req, err := h.newRequest(IPSET_CMD_LIST)
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
	var sets []ListItem
	for k := range msgs {
		h.l.Debugf("receive msgs[%d]=%v", k, msgs[k])
		var ipset ListItem
		if len(msgs[k]) < SizeofNFGenMsg {
			return nil, fmt.Errorf("possible corrupt msg %v", msgs[k])
		}
		//nlGenlMsg := DeserializeNFGenlMsg(msgs[k])
		attrs, err := nl.ParseRouteAttr(msgs[k][SizeofNFGenMsg:])
		if err != nil {
			return nil, fmt.Errorf("possible corrupt msg %v", msgs[k])
		}
		for i := range attrs {
			switch attrs[i].Attr.Type {
			case IPSET_ATTR_PROTOCOL:
				if attrs[i].Attr.Len != unix.SizeofRtAttr+1 {
					return nil, fmt.Errorf("possible corrupt msg %v", msgs[k])
				}
				//protocol := uint8(attrs[i].Value[0])
			case IPSET_ATTR_SETNAME:
				ipset.Name = string(attrs[i].Value[:len(attrs[i].Value)-1])
			case IPSET_ATTR_TYPENAME:
				ipset.SetType = SetType(attrs[i].Value[:len(attrs[i].Value)-1])
			case IPSET_ATTR_REVISION:
				if attrs[i].Attr.Len != unix.SizeofRtAttr+1 {
					return nil, fmt.Errorf("possible corrupt msg %v", msgs[k])
				}
				ipset.SetRevison = &attrs[i].Value[0]
			case IPSET_ATTR_FAMILY:
				if attrs[i].Attr.Len != unix.SizeofRtAttr+1 {
					return nil, fmt.Errorf("possible corrupt msg %v", msgs[k])
				}
				switch attrs[i].Value[0] {
				case NFPROTO_IPV4:
					ipset.Family = "inet"
				case NFPROTO_IPV6:
					ipset.Family = "inet6"
				}
			case IPSET_ATTR_DATA | unix.NLA_F_NESTED:
				nestAttrs, err := nl.ParseRouteAttr(attrs[i].Value)
				if err != nil {
					return nil, fmt.Errorf("possible corrupt msg %v", msgs[k])
				}
				for j := range nestAttrs {
					switch nestAttrs[j].Attr.Type {
					default:
						// TODO Parse create attr
						//HASHSIZE: 1024
						//MAXELEM: 65536
						//REFERENCES: 0
						//MEMSIZE: 176
						//log.Infof("unknown attr %v", nestAttrs[j].Attr.Type)
					}
				}
			case IPSET_ATTR_ADT | unix.NLA_F_NESTED:
				entries, err := parseAdtAttr(attrs[i].Value)
				if err != nil {
					return nil, err
				}
				ipset.Entries = append(ipset.Entries, entries...)
			}
		}
		sets = append(sets, ipset)
	}
	return sets, nil
}

func parseAdtAttr(data []byte) ([]Entry, error) {
	nestAttrs, err := nl.ParseRouteAttr(data)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for j := range nestAttrs {
		switch nestAttrs[j].Attr.Type {
		case IPSET_ATTR_DATA | unix.NLA_F_NESTED:
			var entry Entry
			nestGrandAttrs, err := nl.ParseRouteAttr(nestAttrs[j].Value)
			if err != nil {
				return nil, err
			}
			for k := range nestGrandAttrs {
				switch nestGrandAttrs[k].Attr.Type {
				case IPSET_ATTR_IP | unix.NLA_F_NESTED:
					fallthrough
				case IPSET_ATTR_IP2 | unix.NLA_F_NESTED:
					ip, err := parseIP(nestGrandAttrs[k].Value)
					if err != nil {
						return nil, err
					}
					if nestGrandAttrs[k].Attr.Type == IPSET_ATTR_IP2|unix.NLA_F_NESTED {
						entry.IP2 = ip.String()
					} else {
						entry.IP = ip.String()
					}
				case IPSET_ATTR_CIDR:
					fallthrough
				case IPSET_ATTR_CIDR2:
					if nestGrandAttrs[k].Attr.Len != unix.SizeofRtAttr+1 {
						return nil, fmt.Errorf("possible corrupt cidr msg %v", nestGrandAttrs)
					}
					cidr := uint8(nestGrandAttrs[k].Value[0])
					if nestGrandAttrs[k].Attr.Type == IPSET_ATTR_CIDR2 {
						entry.CIDR2 = &cidr
					} else {
						entry.CIDR = &cidr
					}
				case IPSET_ATTR_ETHER:
					if nestGrandAttrs[k].Attr.Len != unix.SizeofRtAttr+6 {
						return nil, fmt.Errorf("possible corrupt mac msg %v", nestGrandAttrs)
					}
					entry.Mac = net.HardwareAddr(nestGrandAttrs[k].Value)
				case IPSET_ATTR_PORT | unix.NLA_F_NET_BYTEORDER:
					if nestGrandAttrs[k].Attr.Len != unix.SizeofRtAttr+2 {
						return nil, fmt.Errorf("possible corrupt port msg %v", nestGrandAttrs)
					}
					port := ntohs(nestGrandAttrs[k].Value)
					entry.Port = uint16(port)
				case IPSET_ATTR_PROTO:
					if nestGrandAttrs[k].Attr.Len != unix.SizeofRtAttr+1 {
						return nil, fmt.Errorf("possible corrupt port msg %v", nestGrandAttrs)
					}
					entry.Proto = uint8(nestGrandAttrs[k].Value[0])
				default:
					return nil, fmt.Errorf("unknown attr %v", nestGrandAttrs[k].Attr.Type)
				}
			}
			entries = append(entries, entry)
		default:
			return nil, fmt.Errorf("unknown attr %v, expect only IPSET_ATTR_DATA attr", nestAttrs[j].Attr.Type)
		}
	}
	return entries, nil
}

func parseIP(ipData []byte) (net.IP, error) {
	nestAttrs, err := nl.ParseRouteAttr(ipData)
	if err != nil {
		return nil, fmt.Errorf("possible corrupt ip msg %v", ipData)
	}
	for i := range nestAttrs {
		switch nestAttrs[i].Attr.Type {
		case IPSET_ATTR_IPADDR_IPV4:
			if nestAttrs[i].Attr.Len != unix.SizeofRtAttr+4 {
				return nil, fmt.Errorf("possible corrupt ip msg %v", ipData)
			}
			return net.IP(nestAttrs[i].Value), nil
			//TODO ipv6
		}
	}
	return nil, fmt.Errorf("possible corrupt ip msg %v, nestAttrs %v", ipData, nestAttrs)
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
	req, err := h.newRequest(command)
	if err != nil {
		return err
	}
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(set.Name)))
	dataAttr := nl.NewRtAttr(IPSET_ATTR_DATA|unix.NLA_F_NESTED, nil)
	if err := fillEntries(dataAttr, set, entry); err != nil {
		return err
	}
	req.AddData(dataAttr)
	h.l.Debugf("addOrDel %v", req.Serialize())
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

func (h *Handle) newRequest(cmd int) (*nl.NetlinkRequest, error) {
	if cmd <= IPSET_CMD_NONE || cmd >= IPSET_MSG_MAX {
		return nil, fmt.Errorf("cmd should between IPSET_CMD_NONE and IPSET_MSG_MAX")
	}
	req := nl.NewNetlinkRequest(cmd|(NFNL_SUBSYS_IPSET<<8), IPSetCmdflags[cmd-1])
	req.AddData(&nfgenmsg{family: unix.AF_INET, version: NFNETLINK_V0, resid: 0})
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(h.protolcol)))
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

//buffers: 48 0 0 0 13 6 1 0 125 248 115 92 0 0 0 0 2 0 0 0 5 0 1 0 6 0 0 0 12 0 3 0 104 97 115 104 58 105 112 0 5 0 5 0 2 0 0 0
//Message header: sent cmd  TYPE (13)
//len 48
//flag EXIST
//seq 1551104125
//Command attributes:
//PROTOCOL: 6
//TYPENAME: hash:ip
//FAMILY: 2
//buffers: 64 0 0 0 13 6 0 0 125 248 115 92 57 10 0 0 2 0 0 0 5 0 1 0 6 0 0 0 12 0 3 0 104 97 115 104 58 105 112 0 5 0 5 0 2 0 0 0 5 0 4 0 4 0 0 0 5 0 10 0 0 0 0 0
//Message header: received cmd  TYPE (13)
//len 64
//flag EXIST
//seq 1551104125
//Command attributes:
//PROTOCOL: 6
//TYPENAME: hash:ip
//REVISION: 4
//FAMILY: 2
//PROTO_MIN: 0
func (h *Handle) getRevision(setType SetType) (uint8, uint8, error) {
	req, err := h.newRequest(IPSET_CMD_TYPE)
	if err != nil {
		return 0, 0, err
	}
	h.l.Debugf("type %v", req.Serialize())
	req.AddData(nl.NewRtAttr(IPSET_ATTR_TYPENAME, nl.ZeroTerminated(string(setType))))
	fillFamily(req, "inet")
	msgs, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	if err != nil {
		return 0, 0, err
	}
	var min, max uint8
	for k := range msgs {
		h.l.Debugf("receive msgs[%d]=%v", k, msgs[k])
		if len(msgs[k]) < SizeofNFGenMsg {
			return 0, 0, fmt.Errorf("possible corrupt msg %v", msgs[k])
		}
		//nlGenlMsg := DeserializeNFGenlMsg(msgs[i])
		attrs, err := nl.ParseRouteAttr(msgs[k][SizeofNFGenMsg:])
		if err != nil {
			return 0, 0, fmt.Errorf("possible corrupt msg %v", msgs[k])
		}
		for i := range attrs {
			switch attrs[i].Attr.Type {
			case IPSET_ATTR_REVISION:
				if attrs[i].Attr.Len != unix.SizeofRtAttr+1 {
					return 0, 0, fmt.Errorf("possible corrupt msg %v", msgs[i])
				}
				max = uint8(attrs[i].Value[0])
			case IPSET_ATTR_REVISION_MIN:
				min = uint8(attrs[i].Value[0])
			}
		}
		break
	}
	h.l.Debugf("supported revision of %v is %d, min supported %d", setType, max, min)
	return max, min, nil
}
