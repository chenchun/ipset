package ipset

import (
	"syscall"
)

const (
	NFNL_SUBSYS_IPSET = 6

	NFNETLINK_V0 = 0

	IPSET_PROTOCOL     = 7
	IPSET_PROTOCOL_MIN = 6

	/* The max length of strings including NUL: set and type identifiers */
	IPSET_MAXNAMELEN = 32

	/* The maximum permissible comment length we will accept over netlink */
	IPSET_MAX_COMMENT_SIZE = 255
)

// /* Message types and commands */
// enum ipset_cmd {
// 	IPSET_CMD_NONE,
// 	IPSET_CMD_PROTOCOL,	/* 1: Return protocol version */
// 	IPSET_CMD_CREATE,	/* 2: Create a new (empty) set */
// 	IPSET_CMD_DESTROY,	/* 3: Destroy a (empty) set */
// 	IPSET_CMD_FLUSH,	/* 4: Remove all elements from a set */
// 	IPSET_CMD_RENAME,	/* 5: Rename a set */
// 	IPSET_CMD_SWAP,		/* 6: Swap two sets */
// 	IPSET_CMD_LIST,		/* 7: List sets */
// 	IPSET_CMD_SAVE,		/* 8: Save sets */
// 	IPSET_CMD_ADD,		/* 9: Add an element to a set */
// 	IPSET_CMD_DEL,		/* 10: Delete an element from a set */
// 	IPSET_CMD_TEST,		/* 11: Test an element in a set */
// 	IPSET_CMD_HEADER,	/* 12: Get set header data only */
// 	IPSET_CMD_TYPE,		/* 13: Get set type */
// 	IPSET_CMD_GET_BYNAME,	/* 14: Get set index by name */
// 	IPSET_CMD_GET_BYINDEX,	/* 15: Get set name by index */
// 	IPSET_MSG_MAX,		/* Netlink message commands */

// 	/* Commands in userspace: */
// 	IPSET_CMD_RESTORE = IPSET_MSG_MAX, /* 16: Enter restore mode */
// 	IPSET_CMD_HELP,		/* 17: Get help */
// 	IPSET_CMD_VERSION,	/* 18: Get program version */
// 	IPSET_CMD_QUIT,		/* 19: Quit from interactive mode */

// 	IPSET_CMD_MAX,

// 	IPSET_CMD_COMMIT = IPSET_CMD_MAX, /* 20: Commit buffered commands */
// };

const (
	IPSET_CMD_NONE        = iota
	IPSET_CMD_PROTOCOL    /* 1: Return protocol version */
	IPSET_CMD_CREATE      /* 2: Create a new (empty) set */
	IPSET_CMD_DESTROY     /* 3: Destroy a (empty) set */
	IPSET_CMD_FLUSH       /* 4: Remove all elements from a set */
	IPSET_CMD_RENAME      /* 5: Rename a set */
	IPSET_CMD_SWAP        /* 6: Swap two sets */
	IPSET_CMD_LIST        /* 7: List sets */
	IPSET_CMD_SAVE        /* 8: Save sets */
	IPSET_CMD_ADD         /* 9: Add an element to a set */
	IPSET_CMD_DEL         /* 10: Delete an element from a set */
	IPSET_CMD_TEST        /* 11: Test an element in a set */
	IPSET_CMD_HEADER      /* 12: Get set header data only */
	IPSET_CMD_TYPE        /* 13: Get set type */
	IPSET_CMD_GET_BYNAME  /* 14: Get set index by name */
	IPSET_CMD_GET_BYINDEX /* 15: Get set name by index */
	IPSET_MSG_MAX         /* Netlink message commands */
)

// /* Attributes at command level */
// enum {
// 	IPSET_ATTR_UNSPEC,
// 	IPSET_ATTR_PROTOCOL,	/* 1: Protocol version */
// 	IPSET_ATTR_SETNAME,	/* 2: Name of the set */
// 	IPSET_ATTR_TYPENAME,	/* 3: Typename */
// 	IPSET_ATTR_SETNAME2 = IPSET_ATTR_TYPENAME, /* Setname at rename/swap */
// 	IPSET_ATTR_REVISION,	/* 4: Settype revision */
// 	IPSET_ATTR_FAMILY,	/* 5: Settype family */
// 	IPSET_ATTR_FLAGS,	/* 6: Flags at command level */
// 	IPSET_ATTR_DATA,	/* 7: Nested attributes */
// 	IPSET_ATTR_ADT,		/* 8: Multiple data containers */
// 	IPSET_ATTR_LINENO,	/* 9: Restore lineno */
// 	IPSET_ATTR_PROTOCOL_MIN, /* 10: Minimal supported version number */
// 	IPSET_ATTR_REVISION_MIN	= IPSET_ATTR_PROTOCOL_MIN, /* type rev min */
// 	IPSET_ATTR_INDEX,	/* 11: Kernel index of set */
// 	__IPSET_ATTR_CMD_MAX,
// };

const (
	IPSET_ATTR_UNSPEC       = iota
	IPSET_ATTR_PROTOCOL     /* 1: Protocol version */
	IPSET_ATTR_SETNAME      /* 2: Name of the set */
	IPSET_ATTR_TYPENAME     /* 3: Typename */
	IPSET_ATTR_REVISION     /* 4: Settype revision */
	IPSET_ATTR_FAMILY       /* 5: Settype family */
	IPSET_ATTR_FLAGS        /* 6: Flags at command level */
	IPSET_ATTR_DATA         /* 7: Nested attributes */
	IPSET_ATTR_ADT          /* 8: Multiple data containers */
	IPSET_ATTR_LINENO       /* 9: Restore lineno */
	IPSET_ATTR_PROTOCOL_MIN /* 10: Minimal supported version number */
	IPSET_ATTR_INDEX        /* 11: Kernel index of set */
	__IPSET_ATTR_CMD_MAX

	IPSET_ATTR_SETNAME2     = IPSET_ATTR_TYPENAME     /* Setname at rename/swap */
	IPSET_ATTR_REVISION_MIN = IPSET_ATTR_PROTOCOL_MIN /* type rev min */
)

// /* Netlink flags of the commands */
// static const uint16_t cmdflags[] = {
// 	[IPSET_CMD_CREATE-1]	= NLM_F_REQUEST|NLM_F_ACK|
// 					NLM_F_CREATE|NLM_F_EXCL,
// 	[IPSET_CMD_DESTROY-1]	= NLM_F_REQUEST|NLM_F_ACK,
// 	[IPSET_CMD_FLUSH-1]	= NLM_F_REQUEST|NLM_F_ACK,
// 	[IPSET_CMD_RENAME-1]	= NLM_F_REQUEST|NLM_F_ACK,
// 	[IPSET_CMD_SWAP-1]	= NLM_F_REQUEST|NLM_F_ACK,
// 	[IPSET_CMD_LIST-1]	= NLM_F_REQUEST|NLM_F_ACK|NLM_F_DUMP,
// 	[IPSET_CMD_SAVE-1]	= NLM_F_REQUEST|NLM_F_ACK|NLM_F_DUMP,
// 	[IPSET_CMD_ADD-1]	= NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL,
// 	[IPSET_CMD_DEL-1]	= NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL,
// 	[IPSET_CMD_TEST-1]	= NLM_F_REQUEST|NLM_F_ACK,
// 	[IPSET_CMD_HEADER-1]	= NLM_F_REQUEST,
// 	[IPSET_CMD_TYPE-1]	= NLM_F_REQUEST,
// 	[IPSET_CMD_PROTOCOL-1]	= NLM_F_REQUEST,
// };

var IPSetCmdflags = []int{
	0,
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_CREATE | syscall.NLM_F_EXCL, //IPSET_CMD_CREATE-1
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,                                             // IPSET_CMD_DESTROY-1
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,                                             // IPSET_CMD_FLUSH-1
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,                                             // IPSET_CMD_RENAME-1
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,                                             // IPSET_CMD_SWAP-1
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_DUMP,                        // IPSET_CMD_LIST-1
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_DUMP,                        // IPSET_CMD_SAVE-1
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_EXCL,                        // IPSET_CMD_ADD-1
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_EXCL,                        // IPSET_CMD_DEL-1
	syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,                                             // IPSET_CMD_TEST-1
	syscall.NLM_F_REQUEST,                                                                 // IPSET_CMD_HEADER-1
	syscall.NLM_F_REQUEST,                                                                 // IPSET_CMD_TYPE-1
	syscall.NLM_F_REQUEST,                                                                 // IPSET_CMD_PROTOCOL-1
}

// /* Data options */
// enum ipset_opt {
// 	IPSET_OPT_NONE = 0,
// 	/* Common ones */
// 	IPSET_SETNAME,
// 	IPSET_OPT_TYPENAME,
// 	IPSET_OPT_FAMILY,
// 	/* CADT options */
// 	IPSET_OPT_IP,
// 	IPSET_OPT_IP_FROM = IPSET_OPT_IP,
// 	IPSET_OPT_IP_TO,
// 	IPSET_OPT_CIDR,
// 	IPSET_OPT_MARK,
// 	IPSET_OPT_PORT,
// 	IPSET_OPT_PORT_FROM = IPSET_OPT_PORT,
// 	IPSET_OPT_PORT_TO,
// 	IPSET_OPT_TIMEOUT,
// 	/* Create-specific options */
// 	IPSET_OPT_GC,
// 	IPSET_OPT_HASHSIZE,
// 	IPSET_OPT_MAXELEM,
// 	IPSET_OPT_MARKMASK,
// 	IPSET_OPT_NETMASK,
// 	IPSET_OPT_PROBES,
// 	IPSET_OPT_RESIZE,
// 	IPSET_OPT_SIZE,
// 	IPSET_OPT_FORCEADD,
// 	/* Create-specific options, filled out by the kernel */
// 	IPSET_OPT_ELEMENTS,
// 	IPSET_OPT_REFERENCES,
// 	IPSET_OPT_MEMSIZE,
// 	/* ADT-specific options */
// 	IPSET_OPT_ETHER,
// 	IPSET_OPT_NAME,
// 	IPSET_OPT_NAMEREF,
// 	IPSET_OPT_IP2,
// 	IPSET_OPT_CIDR2,
// 	IPSET_OPT_IP2_TO,
// 	IPSET_OPT_PROTO,
// 	IPSET_OPT_IFACE,
// 	/* Swap/rename to */
// 	IPSET_OPT_SETNAME2,
// 	/* Flags */
// 	IPSET_OPT_EXIST,
// 	IPSET_OPT_BEFORE,
// 	IPSET_OPT_PHYSDEV,
// 	IPSET_OPT_NOMATCH,
// 	IPSET_OPT_COUNTERS,
// 	IPSET_OPT_PACKETS,
// 	IPSET_OPT_BYTES,
// 	IPSET_OPT_CREATE_COMMENT,
// 	IPSET_OPT_ADT_COMMENT,
// 	IPSET_OPT_SKBINFO,
// 	IPSET_OPT_SKBMARK,
// 	IPSET_OPT_SKBPRIO,
// 	IPSET_OPT_SKBQUEUE,
// 	/* Internal options */
// 	IPSET_OPT_FLAGS = 48,	/* IPSET_FLAG_EXIST| */
// 	IPSET_OPT_CADT_FLAGS,	/* IPSET_FLAG_BEFORE| */
// 	IPSET_OPT_ELEM,
// 	IPSET_OPT_TYPE,
// 	IPSET_OPT_LINENO,
// 	IPSET_OPT_REVISION,
// 	IPSET_OPT_REVISION_MIN,
// 	IPSET_OPT_INDEX,
// 	IPSET_OPT_MAX,
// };

type Opt int

/* Data options */
const (
	IPSET_OPT_NONE Opt = iota
	/* Common ones */
	IPSET_SETNAME
	IPSET_OPT_TYPENAME
	IPSET_OPT_FAMILY
	/* CADT options */
	IPSET_OPT_IP
	IPSET_OPT_IP_TO
	IPSET_OPT_CIDR
	IPSET_OPT_MARK
	IPSET_OPT_PORT
	IPSET_OPT_PORT_TO
	IPSET_OPT_TIMEOUT
	/* Create-specific options */
	IPSET_OPT_GC
	IPSET_OPT_HASHSIZE
	IPSET_OPT_MAXELEM
	IPSET_OPT_MARKMASK
	IPSET_OPT_NETMASK
	IPSET_OPT_PROBES
	IPSET_OPT_RESIZE
	IPSET_OPT_SIZE
	IPSET_OPT_FORCEADD
	/* Create-specific options filled out by the kernel */
	IPSET_OPT_ELEMENTS
	IPSET_OPT_REFERENCES
	IPSET_OPT_MEMSIZE
	/* ADT-specific options */
	IPSET_OPT_ETHER
	IPSET_OPT_NAME
	IPSET_OPT_NAMEREF
	IPSET_OPT_IP2
	IPSET_OPT_CIDR2
	IPSET_OPT_IP2_TO
	IPSET_OPT_PROTO
	IPSET_OPT_IFACE
	/* Swap/rename to */
	IPSET_OPT_SETNAME2
	/* Flags */
	IPSET_OPT_EXIST
	IPSET_OPT_BEFORE
	IPSET_OPT_PHYSDEV
	IPSET_OPT_NOMATCH
	IPSET_OPT_COUNTERS
	IPSET_OPT_PACKETS
	IPSET_OPT_BYTES
	IPSET_OPT_CREATE_COMMENT
	IPSET_OPT_ADT_COMMENT
	IPSET_OPT_SKBINFO
	IPSET_OPT_SKBMARK
	IPSET_OPT_SKBPRIO
	IPSET_OPT_SKBQUEUE
	/* Internal options */
	IPSET_OPT_FLAGS      Opt = 48 /* IPSET_FLAG_EXIST| */
	IPSET_OPT_CADT_FLAGS          /* IPSET_FLAG_BEFORE| */
	IPSET_OPT_ELEM
	IPSET_OPT_TYPE
	IPSET_OPT_LINENO
	IPSET_OPT_REVISION
	IPSET_OPT_REVISION_MIN
	IPSET_OPT_INDEX
	IPSET_OPT_MAX

	IPSET_OPT_IP_FROM   = IPSET_OPT_IP
	IPSET_OPT_PORT_FROM = IPSET_OPT_PORT
)

// /* Attribute policies and mapping to options */
// static const struct ipset_attr_policy cmd_attrs[] = {
// 	[IPSET_ATTR_PROTOCOL] = {
// 		.type = MNL_TYPE_U8,
// 	},
// 	[IPSET_ATTR_SETNAME] = {
// 		.type = MNL_TYPE_NUL_STRING,
// 		.opt  = IPSET_SETNAME,
// 		.len  = IPSET_MAXNAMELEN,
// 	},
// 	[IPSET_ATTR_TYPENAME] = {
// 		.type = MNL_TYPE_NUL_STRING,
// 		.opt = IPSET_OPT_TYPENAME,
// 		.len  = IPSET_MAXNAMELEN,
// 	},
// 	/* IPSET_ATTR_SETNAME2 is an alias for IPSET_ATTR_TYPENAME */
// 	[IPSET_ATTR_REVISION] = {
// 		.type = MNL_TYPE_U8,
// 		.opt = IPSET_OPT_REVISION,
// 	},
// 	[IPSET_ATTR_FAMILY] = {
// 		.type = MNL_TYPE_U8,
// 		.opt = IPSET_OPT_FAMILY,
// 	},
// 	[IPSET_ATTR_FLAGS] = {
// 		.type = MNL_TYPE_U32,
// 		.opt = IPSET_OPT_FLAGS,
// 	},
// 	[IPSET_ATTR_DATA] = {
// 		.type = MNL_TYPE_NESTED,
// 	},
// 	[IPSET_ATTR_ADT] = {
// 		.type = MNL_TYPE_NESTED,
// 	},
// 	[IPSET_ATTR_REVISION_MIN] = {
// 		.type = MNL_TYPE_U8,
// 		.opt = IPSET_OPT_REVISION_MIN,
// 	},
// 	/* IPSET_ATTR_PROTOCOL_MIN is an alias for IPSET_ATTR_REVISION_MIN */
// 	[IPSET_ATTR_LINENO] = {
// 		.type = MNL_TYPE_U32,
// 		.opt = IPSET_OPT_LINENO,
// 	},
// 	[IPSET_ATTR_INDEX] = {
// 		.type = MNL_TYPE_U16,
// 		.opt = IPSET_OPT_INDEX,
// 	},
// };

/*
 * The constants to select, same as in linux/netfilter.h.
 * Like nf_inet_addr.h, this is just here so that we need not to rely on
 * the presence of a recent-enough netfilter.h.
 */
//enum {
//	NFPROTO_UNSPEC =  0,
//	NFPROTO_IPV4   =  2,
//	NFPROTO_ARP    =  3,
//	NFPROTO_BRIDGE =  7,
//	NFPROTO_IPV6   = 10,
//	NFPROTO_DECNET = 12,
//	NFPROTO_NUMPROTO,
//};

const (
	NFPROTO_UNSPEC = 0
	NFPROTO_IPV4   = 2
	NFPROTO_ARP    = 3
	NFPROTO_BRIDGE = 7
	NFPROTO_IPV6   = 10
	NFPROTO_DECNET = 12
	NFPROTO_NUMPROTO
)

///* Error codes */
//enum ipset_errno {
//IPSET_ERR_PRIVATE = 4096,
//IPSET_ERR_PROTOCOL,
//IPSET_ERR_FIND_TYPE,
//IPSET_ERR_MAX_SETS,
//IPSET_ERR_BUSY,
//IPSET_ERR_EXIST_SETNAME2,
//IPSET_ERR_TYPE_MISMATCH,
//IPSET_ERR_EXIST,
//IPSET_ERR_INVALID_CIDR,
//IPSET_ERR_INVALID_NETMASK,
//IPSET_ERR_INVALID_FAMILY,
//IPSET_ERR_TIMEOUT,
//IPSET_ERR_REFERENCED,
//IPSET_ERR_IPADDR_IPV4,
//IPSET_ERR_IPADDR_IPV6,
//IPSET_ERR_COUNTER,
//IPSET_ERR_COMMENT,
//IPSET_ERR_INVALID_MARKMASK,
//IPSET_ERR_SKBINFO,
//
///* Type specific error codes */
//IPSET_ERR_TYPE_SPECIFIC = 4352,
//};

type IPSetErrno int

const (
	IPSET_ERR_PRIVATE IPSetErrno = 4096 + iota
	IPSET_ERR_PROTOCOL
	IPSET_ERR_FIND_TYPE
	IPSET_ERR_MAX_SETS
	IPSET_ERR_BUSY
	IPSET_ERR_EXIST_SETNAME2
	IPSET_ERR_TYPE_MISMATCH
	IPSET_ERR_EXIST
	IPSET_ERR_INVALID_CIDR
	IPSET_ERR_INVALID_NETMASK
	IPSET_ERR_INVALID_FAMILY
	IPSET_ERR_TIMEOUT
	IPSET_ERR_REFERENCED
	IPSET_ERR_IPADDR_IPV4
	IPSET_ERR_IPADDR_IPV6
	IPSET_ERR_COUNTER
	IPSET_ERR_COMMENT
	IPSET_ERR_INVALID_MARKMASK
	IPSET_ERR_SKBINFO

	/* Type specific error codes */
	IPSET_ERR_TYPE_SPECIFIC = 4352
)

// /* IP specific attributes */
// enum {
// 	IPSET_ATTR_IPADDR_IPV4 = IPSET_ATTR_UNSPEC + 1,
// 	IPSET_ATTR_IPADDR_IPV6,
// 	__IPSET_ATTR_IPADDR_MAX,
// };

const (
	IPSET_ATTR_IPADDR_IPV4 = IPSET_ATTR_UNSPEC + 1 + iota
	IPSET_ATTR_IPADDR_IPV6
	__IPSET_ATTR_IPADDR_MAX
)

// IPSet implements an Interface to an set.
type IPSet struct {
	// Name is the set name.
	Name string
	// SetType specifies the ipset type.
	SetType Type
	// Family is valid for the create command of all hash type sets except for hash:mac.
	// It defines the protocol family of the IP addresses to be stored in the set.
	// The default is inet, i.e IPv4. For the inet family one can add or delete multiple entries by specifying a range
	// or a network of IPv4 addresses in the IP address part of the entry:
	Family string
	// HashSize specifies the hash table size of ipset.
	HashSize int
	// MaxElem specifies the max element number of ipset.
	MaxElem int
	// PortRange specifies the port range of bitmap:port type ipset.
	PortRange string
	// TODO: add comment message for ipset
}

// Entry represents a ipset entry.
type Entry struct {
	// IP is the entry's IP.  The IP address protocol corresponds to the HashFamily of IPSet.
	// All entries' IP addresses in the same ip set has same the protocol, IPv4 or IPv6.
	IP string
	// Port is the entry's Port.
	Port int
	// Protocol is the entry's Protocol.  The protocols of entries in the same ip set are all
	// the same.  The accepted protocols are TCP and UDP.
	Protocol string
	// Net is the entry's IP network address.  Network address with zero prefix size can NOT
	// be stored.
	Net string
	// IP2 is the entry's second IP.  IP2 may not be empty for `hash:ip,port,ip` type ip set.
	IP2 string
	// SetType is the type of ipset where the entry exists.
	SetType Type
	//  [ timeout value ] [ packets value ] [ bytes value ] [ comment string ] [ skbmark value ] [ skbprio value ] [ skbqueue value ]
	Options []string
}

// Type represents the ipset type
type Type string

const (
	HashIP Type = "hash:ip"
	// HashIPPort represents the `hash:ip,port` type ipset.  The hash:ip,port is similar to hash:ip but
	// you can store IP address and protocol-port pairs in it.  TCP, SCTP, UDP, UDPLITE, ICMP and ICMPv6 are supported
	// with port numbers/ICMP(v6) types and other protocol numbers without port information.
	HashIPPort Type = "hash:ip,port"
	// HashIPPortIP represents the `hash:ip,port,ip` type ipset.  The hash:ip,port,ip set type uses a hash to store
	// IP address, port number and a second IP address triples.  The port number is interpreted together with a
	// protocol (default TCP) and zero protocol number cannot be used.
	HashIPPortIP Type = "hash:ip,port,ip"
	// HashIPPortNet represents the `hash:ip,port,net` type ipset.  The hash:ip,port,net set type uses a hash to store IP address, port number and IP network address triples.  The port
	// number is interpreted together with a protocol (default TCP) and zero protocol number cannot be used.   Network address
	// with zero prefix size cannot be stored either.
	HashIPPortNet Type = "hash:ip,port,net"
	// BitmapPort represents the `bitmap:port` type ipset.  The bitmap:port set type uses a memory range, where each bit
	// represents one TCP/UDP port.  A bitmap:port type of set can store up to 65535 ports.
	BitmapPort Type = "bitmap:port"

	HashNet Type = "hash:net"

	HashNetPort Type = "hash:net,port"
)
