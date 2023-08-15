import socket

from pallium.nft.constants import *


class Datatype:  # nftables
    type = None
    byteorder = None
    flags = None
    size = None
    subtypes = None
    name = None
    desc = None
    basefmt = None
    symbols = {}


class InvalidType(Datatype):
    type = TYPE_INVALID
    name = "invalid"


class VerdictType(Datatype):
    type = TYPE_VERDICT
    name = "verdict"


class IntegerType(Datatype):
    type = TYPE_INTEGER
    name = "integer"


class NfprotoType(IntegerType):
    type = TYPE_NFPROTO
    name = "nf_proto"
    size = 8
    symbols = {
        'ipv4': NFPROTO_IPV4,
        'ipv6': NFPROTO_IPV6
    }


class BitmaskType(IntegerType):
    type = TYPE_BITMASK
    name = "bitmask"
    basefmt = "0x%Zx"


class StringType(Datatype):
    type = TYPE_STRING
    name = "string"
    byteorder = BYTEORDER_HOST_ENDIAN


class LlAddrType(IntegerType):
    type = TYPE_LLADDR
    name = "ll_addr"
    byteorder = BYTEORDER_BIG_ENDIAN


class EtherAddrType(LlAddrType):
    type = TYPE_ETHERADDR
    name = "ether_addr"
    size = 48


class IpAddrType(IntegerType):
    type = TYPE_IPADDR
    name = "ipv4_addr"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 32
    flags = DTYPE_F_PREFIX


class Ip6AddrType(IntegerType):
    type = TYPE_IP6ADDR
    name = "ipv4_addr"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 128
    flags = DTYPE_F_PREFIX


class InetProtocolType(IntegerType):
    type = TYPE_INET_PROTOCOL
    name = "inet_proto"
    size = 8


class InetServiceType(IntegerType):
    type = TYPE_INET_SERVICE
    name = "inet_service"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 16


class IfindexType(IntegerType):
    type = TYPE_IFINDEX
    name = "iface_index"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32


class MarkType(IntegerType):
    type = TYPE_MARK
    name = "mark"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32


class IcmpCodeType(IntegerType):
    type = TYPE_ICMP_CODE
    name = "icmp_code"
    size = 8
    byteorder = BYTEORDER_BIG_ENDIAN
    symbols = {
        "net-unreachable": ICMP_NET_UNREACH,
        "host-unreachable": ICMP_HOST_UNREACH,
        "prot-unreachable": ICMP_PROT_UNREACH,
        "port-unreachable": ICMP_PORT_UNREACH,
        "net-prohibited": ICMP_NET_ANO,
        "host-prohibited": ICMP_HOST_ANO,
        "admin-prohibited": ICMP_PKT_FILTERED,
        "frag-needed": ICMP_FRAG_NEEDED,
    }


class Icmpv6CodeType(IntegerType):
    type = TYPE_ICMPV6_CODE
    name = "icmpv6_code"
    size = 8
    byteorder = BYTEORDER_BIG_ENDIAN
    symbols = {
        "no-route": ICMPV6_NOROUTE,
        "admin-prohibited": ICMPV6_ADM_PROHIBITED,
        "addr-unreachable": ICMPV6_ADDR_UNREACH,
        "port-unreachable": ICMPV6_PORT_UNREACH,
        "policy-fail": ICMPV6_POLICY_FAIL,
        "reject-route": ICMPV6_REJECT_ROUTE,
    }


class TcpFlagType(BitmaskType):
    type = TYPE_TCP_FLAG
    name = "tcp_flag"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 8
    symbols = {
        'fin': 0x01,
        'syn': 0x02,
        'rst': 0x04,
        'psh': 0x08,
        'ack': 0x10,
        'urg': 0x20,
        'ecn': 0x40,
        'cwr': 0x80
    }


class CtStateType(BitmaskType):
    type = TYPE_CT_STATE
    name = "ct_state"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32
    symbols = {
        'invalid': 0x1,
        'established': 0x2,
        'related': 0x4,
        'new': 0x8,
        'untracked': 0x40
    }


class CtDirType(IntegerType):
    type = TYPE_CT_DIR
    name = "ct_dir"
    size = 8
    symbols = {
        'original': 0,
        'reply': 1
    }


class IfnameType(StringType):
    type = TYPE_IFNAME
    name = "ifname"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = IFNAMSIZ * 8


class IcmpTypeType(IntegerType):
    type = TYPE_ICMP_TYPE
    name = "icmp_type"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 8
    symbols = {
        "echo-reply": ICMP_ECHOREPLY,
        "destination-unreachable": ICMP_DEST_UNREACH,
        "source-quench": ICMP_SOURCE_QUENCH,
        "redirect": ICMP_REDIRECT,
        "echo-request": ICMP_ECHO,
        "router-advertisement": ICMP_ROUTERADVERT,
        "router-solicitation": ICMP_ROUTERSOLICIT,
        "time-exceeded": ICMP_TIME_EXCEEDED,
        "parameter-problem": ICMP_PARAMETERPROB,
        "timestamp-request": ICMP_TIMESTAMP,
        "timestamp-reply": ICMP_TIMESTAMPREPLY,
        "info-request": ICMP_INFO_REQUEST,
        "info-reply": ICMP_INFO_REPLY,
        "address-mask-request": ICMP_ADDRESS,
        "address-mask-reply": ICMP_ADDRESSREPLY,
    }


class IcmpxCodeType(IntegerType):
    type = TYPE_ICMPX_CODE
    name = "icmpx_code"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 8
    symbols = {
        'port-unreachable': NFT_REJECT_ICMPX_PORT_UNREACH,
        'admin-prohibited': NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
        'no-route': NFT_REJECT_ICMPX_NO_ROUTE,
        'host-unreachable': NFT_REJECT_ICMPX_HOST_UNREACH
    }


class IgmpTypeType(IntegerType):
    type = TYPE_IGMP_TYPE
    name = "igmp_type"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 8
    symbols = {
        "membership-query": IGMP_MEMBERSHIP_QUERY,
        "membership-report-v1": IGMP_V1_MEMBERSHIP_REPORT,
        "membership-report-v2": IGMP_V2_MEMBERSHIP_REPORT,
        "membership-report-v3": IGMP_V3_MEMBERSHIP_REPORT,
        "leave-group": IGMP_V2_LEAVE_GROUP,

    }


class TimeType(IntegerType):
    type = TYPE_TIME
    name = "time"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 64


class DateType(IntegerType):
    type = TYPE_TIME_DATE
    name = "time"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 64


class DayType(IntegerType):
    type = TYPE_TIME_DAY
    name = "day"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 8
    symbols = {
        'Sunday': 0,
        'Monday': 1,
        'Tuesday': 3,
        'Thursday': 4,
        'Friday': 5,
        'Saturday': 6
    }


class HourType(IntegerType):
    type = TYPE_TIME_DAY
    name = "hour"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32


class PriorityType(StringType):
    type = TYPE_STRING
    name = "length"


class PolicyType(StringType):
    type = TYPE_STRING
    name = "length"


class Cgroupv2Type(IntegerType):
    type = TYPE_CGROUPV2
    name = "cgroupsv2"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 64


class BooleanType(IntegerType):
    type = TYPE_BOOLEAN
    name = "boolean"
    size = 1
    symbols = {
        'exists': 1,
        'missing': 0
    }


class RealmType(IntegerType):
    type = TYPE_REALM
    name = "realm"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32
    flags = DTYPE_F_PREFIX


class MhTypeType(IntegerType):
    type = TYPE_MH_TYPE
    name = "mh_type"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 8
    symbols = {
        "binding-refresh-request": IP6_MH_TYPE_BRR,
        "home-test-init": IP6_MH_TYPE_HOTI,
        "careof-test-init": IP6_MH_TYPE_COTI,
        "home-test": IP6_MH_TYPE_HOT,
        "careof-test": IP6_MH_TYPE_COT,
        "binding-update": IP6_MH_TYPE_BU,
        "binding-acknowledgement": IP6_MH_TYPE_BACK,
        "binding-error": IP6_MH_TYPE_BERROR,
        "fast-binding-update": IP6_MH_TYPE_FBU,
        "fast-binding-acknowledgement": IP6_MH_TYPE_FBACK,
        "fast-binding-advertisement": IP6_MH_TYPE_FNA,
        "experimental-mobility-header": IP6_MH_TYPE_EMH,
        "home-agent-switch-message": IP6_MH_TYPE_HASM,
    }


class DccpPkttypeType(IntegerType):
    type = TYPE_DCCP_PKTTYPE
    name = "dccp_pkttype"
    size = 4
    symbols = {
        "host": PACKET_HOST,
        "unicast": PACKET_HOST,
        "broadcast": PACKET_BROADCAST,
        "multicast": PACKET_MULTICAST,
        "other": PACKET_OTHERHOST,
    }


class DscpType(IntegerType):
    type = TYPE_DSCP
    name = "dscp"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 6
    symbols = {
        "cs0": 0x00,
        "cs1": 0x08,
        "cs2": 0x10,
        "cs3": 0x18,
        "cs4": 0x20,
        "cs5": 0x28,
        "cs6": 0x30,
        "cs7": 0x38,
        "be": 0x00,
        "af11": 0x0a,
        "af12": 0x0c,
        "af13": 0x0e,
        "af21": 0x12,
        "af22": 0x14,
        "af23": 0x16,
        "af31": 0x1a,
        "af32": 0x1c,
        "af33": 0x1e,
        "af41": 0x22,
        "af42": 0x24,
        "af43": 0x26,
        "ef": 0x2e,
    }


class EcnType(IntegerType):
    type = TYPE_ECN
    name = "ecn"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 2
    symbols = {
        "not-ect": 0x00,
        "ect1": 0x01,
        "ect0": 0x02,
        "ce": 0x03,
    }


class Icmp6TypeType(IntegerType):
    type = TYPE_ICMP6_TYPE
    name = "icmpv6_type"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 8
    symbols = {
        "destination-unreachable": ICMP6_DST_UNREACH,
        "packet-too-big": ICMP6_PACKET_TOO_BIG,
        "time-exceeded": ICMP6_TIME_EXCEEDED,
        "parameter-problem": ICMP6_PARAM_PROB,
        "echo-request": ICMP6_ECHO_REQUEST,
        "echo-reply": ICMP6_ECHO_REPLY,
        "mld-listener-query": MLD_LISTENER_QUERY,
        "mld-listener-report": MLD_LISTENER_REPORT,
        "mld-listener-done": MLD_LISTENER_REDUCTION,
        "mld-listener-reduction": MLD_LISTENER_REDUCTION,
        "nd-router-solicit": ND_ROUTER_SOLICIT,
        "nd-router-advert": ND_ROUTER_ADVERT,
        "nd-neighbor-solicit": ND_NEIGHBOR_SOLICIT,
        "nd-neighbor-advert": ND_NEIGHBOR_ADVERT,
        "nd-redirect": ND_REDIRECT,
        "router-renumbering": ICMP6_ROUTER_RENUMBERING,
        "ind-neighbor-solicit": IND_NEIGHBOR_SOLICIT,
        "ind-neighbor-advert": IND_NEIGHBOR_ADVERT,
        "mld2-listener-report": ICMPV6_MLD2_REPORT,
    }


class TchandleType(IntegerType):
    type = TYPE_CLASSID
    name = "classid"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32


class ArphdrType(IntegerType):
    type = TYPE_ARPHRD
    name = "iface_type"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 16
    symbols = {
        "ether": ARPHRD_ETHER,
        "ppp": ARPHRD_PPP,
        "ipip": ARPHRD_TUNNEL,
        "ipip6": ARPHRD_TUNNEL6,
        "loopback": ARPHRD_LOOPBACK,
        "sit": ARPHRD_SIT,
        "ipgre": ARPHRD_IPGRE,
    }


class UidType(IntegerType):
    type = TYPE_UID
    name = "uid"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32


class GidType(IntegerType):
    type = TYPE_GID
    name = "gid"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32


class PkttypeType(IntegerType):
    type = TYPE_PKTTYPE
    name = "pkt_type"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 8


class DevgroupType(IntegerType):
    type = TYPE_DEVGROUP
    name = "devgroup"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32
    flags = DTYPE_F_PREFIX


class CtEventType(IntegerType):
    type = TYPE_CT_EVENTBIT
    name = "ct_event"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32
    symbols = {
        "new": 1 << IPCT_NEW,
        "related": 1 << IPCT_RELATED,
        "destroy": 1 << IPCT_DESTROY,
        "reply": 1 << IPCT_REPLY,
        "assured": 1 << IPCT_ASSURED,
        "protoinfo": 1 << IPCT_PROTOINFO,
        "helper": 1 << IPCT_HELPER,
        "mark": 1 << IPCT_MARK,
        "seqadj": 1 << IPCT_SEQADJ,
        "secmark": 1 << IPCT_SECMARK,
        "label": 1 << IPCT_LABEL,
    }


class CtStatusType(IntegerType):
    type = TYPE_CT_STATUS
    name = "ct_status"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32
    symbols = {
        "expected": IPS_EXPECTED,
        "seen-reply": IPS_SEEN_REPLY,
        "assured": IPS_ASSURED,
        "confirmed": IPS_CONFIRMED,
        "snat": IPS_SRC_NAT,
        "dnat": IPS_DST_NAT,
        "dying": IPS_DYING,
    }


class FibAddrType(IntegerType):
    type = TYPE_FIB_ADDR
    name = "fib_addrtype"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 32
    symbols = {
        "unspec": RTN_UNSPEC,
        "unicast": RTN_UNICAST,
        "local": RTN_LOCAL,
        "broadcast": RTN_BROADCAST,
        "anycast": RTN_ANYCAST,
        "multicast": RTN_MULTICAST,
        "blackhole": RTN_BLACKHOLE,
        "unreachable": RTN_UNREACHABLE,
        "prohibit": RTN_PROHIBIT,

    }


class EthertypeType(IntegerType):
    type = TYPE_ETHERTYPE
    name = "ether_type"
    byteorder = BYTEORDER_BIG_ENDIAN
    size = 16
    symbols = {
        "ip": socket.htons(ETH_P_IP),
        "arp": socket.htons(ETH_P_ARP),
        "ip6": socket.htons(ETH_P_IPV6),
        "8021q": socket.htons(ETH_P_8021Q),
        "8021ad": socket.htons(ETH_P_8021AD),
        "vlan": socket.htons(ETH_P_8021Q),
    }


class ArpopType(IntegerType):
    type = TYPE_ARPOP
    name = "arp_op"
    byteorder = BYTEORDER_HOST_ENDIAN
    size = 16
    symbols = {
        "request": socket.htons(ARPOP_REQUEST),
        "reply": socket.htons(ARPOP_REPLY),
        "rrequest": socket.htons(ARPOP_RREQUEST),
        "rreply": socket.htons(ARPOP_RREPLY),
        "inrequest": socket.htons(ARPOP_InREQUEST),
        "inreply": socket.htons(ARPOP_InREPLY),
        "nak": socket.htons(ARPOP_NAK),
    }


# Custom types for convenience


class U8Type(IntegerType):
    size = 8


class U16BEType(IntegerType):
    size = 16
    byteorder = BYTEORDER_BIG_ENDIAN


class U32BEType(IntegerType):
    size = 32
    byteorder = BYTEORDER_BIG_ENDIAN


class U16HEType(IntegerType):
    size = 16
    byteorder = BYTEORDER_HOST_ENDIAN


class U32HEType(IntegerType):
    size = 32
    byteorder = BYTEORDER_HOST_ENDIAN
