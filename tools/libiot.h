#ifndef lib_pcap_pcap_h
#include <pcap.h>
#endif

#include <netdb.h>
#include <net/if.h>  /* For  IFNAMSIZ */

/* General constants */
#define SUCCESS		1
#define FAILURE		0
#define TRUE		1
#define FALSE		0

#define ADDR_AUTO	2


/* Constants used for Router Discovery */
#define MAX_PREFIXES_ONLINK		100
#define MAX_PREFIXES_AUTO		100
#define MAX_LOCAL_ADDRESSES		256


#define LUI		long unsigned int
#define	CHAR_CR			0x0d
#define CHAR_LF			0x0a
#define	DATA_BUFFER_LEN		1000
#define LINE_BUFFER_SIZE	80
#define MAX_STRING_SIZE			10 /* For limiting strncmp */
#define MAX_RANGE_STR_LEN		79 /* For function that check for address ranges in string */
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define	ETHERTYPE_IPV6	0x86dd		/* IP protocol version 6 */
#define	ETHER_ADDR_LEN	ETH_ALEN	/* size of ethernet addr */
#define	ETHER_HDR_LEN	ETH_HLEN	/* total octets in header */

#define ETHER_ADDR_PLEN	18		/* Includes termination byte */

#define ETHER_ALLNODES_LINK_ADDR	"33:33:00:00:00:01"
#define ETHER_ALLROUTERS_LINK_ADDR	"33:33:00:00:00:02"

#define	MIN_IPV6_HLEN			40
#define MIN_IPV6_MTU			1280
#define MIN_TCP_HLEN			20
#define MIN_UDP_HLEN			8
#define MIN_ICMP6_HLEN			8
#define MIN_HBH_LEN				8
#define	MIN_EXT_HLEN			8
#define IFACE_LENGTH			IFNAMSIZ



/* Constants used with the libcap functions */
#define PCAP_SNAP_LEN			65535
#define	PCAP_PROMISC			1
#define	PCAP_OPT				1
#ifndef PCAP_NETMASK_UNKNOWN
	#define PCAP_NETMASK_UNKNOWN	0xffffffff
#endif

#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__) || defined(sun) || defined(__sun)
	#define	PCAP_TIMEOUT			1
#else
	#define	PCAP_TIMEOUT			0
#endif


struct ether_addr{
  uint8_t a[ETHER_ADDR_LEN];
} __attribute__ ((__packed__));

/* For DLT_NULL encapsulation */
struct dlt_null
{
  uint32_t	family;	/* Protocol Family	*/
} __attribute__ ((__packed__));




/*
   Different OSes employ different constants for specifying the byte order.
   We employ the native Linux one, and if not available, map the BSD, Mac
   OS, or Solaris into the Linux one.
 */
#ifndef __BYTE_ORDER
	#define	__LITTLE_ENDIAN	1234
	#define	__BIG_ENDIAN	4321

	/* Mac OS */
	#if defined (__BYTE_ORDER__)
		# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			#define __BYTE_ORDER __LITTLE_ENDIAN
		#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			#define __BYTE_ORDER __BIG_ENDIAN
		#endif

	/* BSD */
	#elif defined(_BYTE_ORDER)
		#if _BYTE_ORDER == _LITTLE_ENDIAN
			#define __BYTE_ORDER __LITTLE_ENDIAN
		#elif _BYTE_ORDER == _BIG_ENDIAN
			#define __BYTE_ORDER __BIG_ENDIAN		
		#endif
	/* XXX: Solaris. There should be a better constant on which to check the byte order */
	#elif defined(sun) || defined (__sun)
		#if defined(_BIT_FIELDS_LTOH)
			#define __BYTE_ORDER __LITTLE_ENDIAN
		#else
			#define __BYTE_ORDER __IG_ENDIAN
		#endif
	#endif
#endif


/* 10Mb/s ethernet header */
struct ether_header{
  struct ether_addr dst;	/* destination eth addr	*/
  struct ether_addr src;	/* source ether addr	*/
  uint16_t ether_type;		/* packet type ID field	*/
} __attribute__ ((__packed__));


/* BSD definition */

/*
 * Structure of an internet header, naked of options.
 */
struct ip_hdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#endif
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;			/* total length */
    uint16_t ip_id;			/* identification */
    uint16_t ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
};


/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcp_hdr {
	uint16_t th_sport;		/* source port */
	uint16_t th_dport;		/* destination port */
	tcp_seq	  th_seq;		/* sequence number */
	tcp_seq	  th_ack;		/* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t th_x2:4,		/* (unused) */
		  th_off:4;		/* data offset */
#endif
#  if __BYTE_ORDER == __BIG_ENDIAN
	uint32_t th_off:4,		/* data offset */
		  th_x2:4;		/* (unused) */
#endif
	uint8_t  th_flags;
#define	TH_FIN	  0x01
#define	TH_SYN	  0x02
#define	TH_RST	  0x04
#define	TH_PUSH	  0x08
#define	TH_ACK	  0x10
#define	TH_URG	  0x20
#define	TH_ECE	  0x40
#define	TH_CWR	  0x80
	uint16_t th_win;			/* window */
	uint16_t th_sum;			/* checksum */
	uint16_t th_urp;			/* urgent pointer */
};

/*
  0      7 8     15 16    23 24    31  
 +--------+--------+--------+--------+ 
 |     Source      |   Destination   | 
 |      Port       |      Port       | 
 +--------+--------+--------+--------+ 
 |                 |                 | 
 |     Length      |    Checksum     | 
 +--------+--------+--------+--------+ 
 |                                     
 |          data octets ...            
 +---------------- ...                 

     User Datagram Header Format
*/

struct udp_hdr{
  uint16_t uh_sport;		/* source port */
  uint16_t uh_dport;		/* destination port */
  uint16_t uh_ulen;		/* udp length */
  uint16_t uh_sum;		/* udp checksum */
} __attribute__ ((__packed__));


struct pseudohdr{
	struct in_addr saddr;
	struct in_addr daddr;
	uint8_t mbz;
	uint8_t protocol;
	uint16_t length;
} __attribute__ ((__packed__));



/* Definition of the Authentication Header
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Header   |  Payload Len  |          RESERVED             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Security Parameters Index (SPI)               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Sequence Number Field                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                Integrity Check Value-ICV (variable)           |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ah_hdr{
	uint8_t ah_nxt;		/* Next Header */
	uint8_t ah_len;		/* Payload length */
	uint16_t ah_rsvd;	/* Reserved */
	uint32_t ah_spi;	/* Reserved */
	uint32_t ah_seq;	/* Reserved */
	uint32_t ah_icv;	/* Integrity Check Value - ICV */
} __attribute__ ((__packed__));


/* Definition of the Encapsulating Security Payload

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
 |               Security Parameters Index (SPI)                 | ^Int.
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
 |                      Sequence Number                          | |ered
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
 |                    Payload Data* (variable)                   | |   ^
 ~                                                               ~ |   |
 |                                                               | |Conf.
 +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
 |               |     Padding (0-255 bytes)                     | |ered*
 +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
 |                               |  Pad Length   | Next Header   | v   v
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
 |         Integrity Check Value-ICV   (variable)                |
 ~                                                               ~
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct esp_hdr{
	uint32_t esp_spi;	/* Reserved */
	uint32_t esp_seq;	/* Reserved */
	uint32_t ah_payload;	/* Integrity Check Value - ICV */
} __attribute__ ((__packed__));



#define	ARP_REQUEST		1
#define ARP_REPLY		2
#define RARP_REQUEST	3
#define RARP_REPLY		4

struct arp_hdr{
	struct ether_header		ether;	
	uint16_t				hard_type;		/* packet type ID field	*/
	uint16_t				prot_type;		/* packet type ID field	*/
	uint8_t				hard_size;
	uint8_t				prot_size;
	uint8_t				op;
	struct ether_addr		src_ether;
	struct in_addr			src_ip;
	struct ether_addr		tgt_ether;
	struct in_addr			tgt_ip;
} __attribute__ ((__packed__));


/* For obtaining an IPv6 target */
struct target_ipv6{
	struct in6_addr		ip6;	/* IPv6 address */
	char name			[NI_MAXHOST]; /* Name */
	char canonname		[NI_MAXHOST]; /* Canonic name */
	int					res;	/* Error code */
	unsigned int		flags;	/* Value-result: Whether the canonic name is required/obtained */
};

struct prefix_entry{
	struct in6_addr		ip6;
	unsigned char		len;
};

struct prefix_list{
	struct prefix_entry	**prefix;
	unsigned int		nprefix;
	unsigned int		maxprefix;
};


struct host_entry{
	struct in6_addr		ip6;
	struct ether_addr	ether;
	unsigned char		flag;
	struct host_entry	*next;
};

struct host_list{
	struct host_entry	**host;
	unsigned int		nhosts;
	unsigned int		maxhosts;
};

struct hostv4_entry{
	struct in_addr		ip;
	struct ether_addr	ether;
	unsigned char		flag;
};

struct hostv4_list{
	struct host_entry	*host;
	unsigned int		nhosts;
	unsigned int		maxhosts;
};


struct address_list{
	struct in6_addr		*addr;
	unsigned int		naddr;
	unsigned int		maxaddr;
};

struct prefixv4_entry{
	struct in_addr		ip;
	unsigned char		len;
};

struct prefixv4_list{
	struct prefixv4_entry	**prefix;
	unsigned int		nprefix;
	unsigned int		maxprefix;
};


#define MAX_IFACES		25
struct iface_entry{
	int					ifindex;
	char				iface[IFACE_LENGTH];	
	struct ether_addr	ether;
	unsigned char		ether_f;
	struct prefix_list	ip6_global;
	struct prefix_list  ip6_local;
	struct prefixv4_list  ip;
	int					flags;	
};

struct iface_list{
	struct iface_entry	*ifaces;
	unsigned int		nifaces;
	unsigned int		maxifaces;
};


/* Constants employed by decode_ipv6_address() */

#define IPV6_UNSPEC				1
#define IPV6_MULTICAST			2
#define IPV6_UNICAST			4

#define UCAST_V4MAPPED			1
#define UCAST_V4COMPAT			2
#define UCAST_LINKLOCAL			4
#define UCAST_SITELOCAL			8
#define UCAST_UNIQUELOCAL		16
#define UCAST_6TO4				32
#define UCAST_TEREDO			64
#define UCAST_GLOBAL			128
#define UCAST_LOOPBACK			256

#define MCAST_PERMANENT			512
#define MCAST_NONPERMANENT		1024
#define MCAST_INVALID			2048
#define MCAST_UNICASTBASED		4096
#define MCAST_EMBEDRP			8192
#define MCAST_UNKNOWN			16384

#define SCOPE_RESERVED			1
#define SCOPE_INTERFACE			2
#define SCOPE_LINK				4
#define SCOPE_ADMIN				8
#define SCOPE_SITE				16
#define SCOPE_ORGANIZATION		32
#define SCOPE_GLOBAL			64
#define SCOPE_UNASSIGNED		128
#define SCOPE_UNSPECIFIED		256

#define IID_MACDERIVED			1
#define IID_ISATAP				2
#define IID_EMBEDDEDIPV4		4
#define IID_EMBEDDEDIPV4_32		8192
#define IID_EMBEDDEDIPV4_64		64
#define IID_EMBEDDEDPORT		8
#define IID_EMBEDDEDPORTREV		16
#define IID_LOWBYTE				32
#define IID_PATTERN_BYTES		128
#define IID_RANDOM				256
#define IID_TEREDO_RFC4380		512
#define IID_TEREDO_RFC5991		1024
#define IID_TEREDO_UNKNOWN		2048
#define IID_UNSPECIFIED			4096



/* This struture is employed by decode_ipv6_address */
struct	decode6{
	struct in6_addr	ip6;
	unsigned int	type;
	unsigned int	subtype;
	unsigned int	scope;
	unsigned int	iidtype;
	unsigned int	iidsubtype;
};


/* Macros for IPv4 Addresses */
#ifndef IN_IS_ADDR_LOOPBACK
	#define IN_IS_ADDR_LOOPBACK(a) \
		(( *((uint32_t *) (a)) & htonl (0xff000000))		      \
		 == htonl (0x7f000000))
#endif


/* Macros for IPv6 Addresses */
#ifndef IN6_IS_ADDR_UNIQUELOCAL
	#define IN6_IS_ADDR_UNIQUELOCAL(a) \
		((((uint32_t *) (a))[0] & htonl (0xfe000000))		      \
		 == htonl (0xfc000000))
#endif

#ifndef IN6_IS_ADDR_6TO4
	#define IN6_IS_ADDR_6TO4(a) \
		((((uint32_t *) (a))[0] & htonl (0xffff0000))		      \
		 == htonl (0x20020000))
#endif

#ifndef IN6_IS_ADDR_TEREDO
	#define IN6_IS_ADDR_TEREDO(a) \
		(((uint32_t *) (a))[0] == htonl (0x20020000))
#endif

#ifndef IN6_IS_ADDR_TEREDO_LEGACY
	#define IN6_IS_ADDR_TEREDO_LEGACY(a) \
		(((uint32_t *) (a))[0] == htonl (0x3ffe831f))
#endif




#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
    #ifndef s6_addr16
	    #define s6_addr16	__u6_addr.__u6_addr16
    #endif

    #ifndef s6_addr
	    #define s6_addr		__u6_addr.__u6_addr8
    #endif

    #ifndef s6_addr8
	    #define s6_addr8	__u6_addr.__u6_addr8
    #endif

    #ifndef s6_addr32
	    #define s6_addr32	__u6_addr.__u6_addr32
    #endif
#elif defined __linux__ || ( !defined(__FreeBSD__) && defined(__FreeBSD_kernel__))
	#ifndef s6_addr16
		#define s6_addr16	__in6_u.__u6_addr16
	#endif

	#ifndef s6_addr32
		#define s6_addr32	__in6_u.__u6_addr32
	#endif
#elif defined(__sun) || defined(sun)
	#ifndef s6_addr8
		#define	s6_addr8	_S6_un._S6_u8
	#endif

	#ifndef s6_addr32
		#define	s6_addr32	_S6_un._S6_u32
	#endif
#endif


/* This causes Linux to use the BSD definition of the TCP and UDP header fields */
#ifndef __FAVOR_BSD
	#define __FAVOR_BSD
#endif


/* Names (DNS, NI) related constants and definitions */
#define MAX_DOMAIN_LEN			512
#define MAX_DNS_LABELS			50
#define MAX_DNS_CLABELS         5


/* RFC 4191 Router Advertisement Preference */
#define RTR_PREF_HIGH			0x01
#define RTR_PREF_LOW			0x03
#define RTR_PREF_MED			0x00
#define RTR_PREF_RSVD			0x02

/* ICMPv6 Types/Codes not defined in some OSes */
#ifndef ICMP6_DST_UNREACH_FAILEDPOLICY
	#define ICMP6_DST_UNREACH_FAILEDPOLICY	5
#endif

#ifndef ICMP6_DST_UNREACH_REJECTROUTE
	#define ICMP6_DST_UNREACH_REJECTROUTE	6
#endif


#if !(defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__))
/* Definitions for Linux */

	#ifndef _NETINET_ICMP6_H
	#include <netinet/icmp6.h>
	#endif

	#define ICMP6_NI_QUERY			139	/* node information request */
	#define ICMP6_NI_REPLY			140	/* node information reply */
	/*
	 * icmp6 namelookup
	 */

	struct icmp6_namelookup {
		struct icmp6_hdr 	icmp6_nl_hdr;
		uint8_t	icmp6_nl_nonce[8];
		int32_t		icmp6_nl_ttl;
	#if 0
		uint8_t	icmp6_nl_len;
		uint8_t	icmp6_nl_name[3];
	#endif
		/* could be followed by options */
	} __attribute__ ((__packed__));

	/*
	 * icmp6 node information
	 */
	struct icmp6_nodeinfo {
		struct icmp6_hdr icmp6_ni_hdr;
		uint8_t icmp6_ni_nonce[8];
		/* could be followed by reply data */
	} __attribute__ ((__packed__));

	#define ni_type		icmp6_ni_hdr.icmp6_type
	#define ni_code		icmp6_ni_hdr.icmp6_code
	#define ni_cksum	icmp6_ni_hdr.icmp6_cksum
	#define ni_qtype	icmp6_ni_hdr.icmp6_data16[0]
	#define ni_flags	icmp6_ni_hdr.icmp6_data16[1]

	#define NI_QTYPE_NOOP		0 /* NOOP  */
	#define NI_QTYPE_SUPTYPES	1 /* Supported Qtypes */
	#define NI_QTYPE_FQDN		2 /* FQDN (draft 04) */
	#define NI_QTYPE_DNSNAME	2 /* DNS Name */
	#define NI_QTYPE_NODEADDR	3 /* Node Addresses */
	#define NI_QTYPE_IPV4ADDR	4 /* IPv4 Addresses */

	#if __BYTE_ORDER == __BIG_ENDIAN
		#define NI_SUPTYPE_FLAG_COMPRESS	0x1
		#define NI_FQDN_FLAG_VALIDTTL		0x1
	#elif __BYTE_ORDER == __LITTLE_ENDIAN
		#define NI_SUPTYPE_FLAG_COMPRESS	0x0100
		#define NI_FQDN_FLAG_VALIDTTL		0x0100
	#endif

	#if __BYTE_ORDER == __BIG_ENDIAN
		#define NI_NODEADDR_FLAG_TRUNCATE	0x1
		#define NI_NODEADDR_FLAG_ALL		0x2
		#define NI_NODEADDR_FLAG_COMPAT		0x4
		#define NI_NODEADDR_FLAG_LINKLOCAL	0x8
		#define NI_NODEADDR_FLAG_SITELOCAL	0x10
		#define NI_NODEADDR_FLAG_GLOBAL		0x20
		#define NI_NODEADDR_FLAG_ANYCAST	0x40 /* just experimental. not in spec */
	#elif __BYTE_ORDER == __LITTLE_ENDIAN
		#define NI_NODEADDR_FLAG_TRUNCATE	0x0100
		#define NI_NODEADDR_FLAG_ALL		0x0200
		#define NI_NODEADDR_FLAG_COMPAT		0x0400
		#define NI_NODEADDR_FLAG_LINKLOCAL	0x0800
		#define NI_NODEADDR_FLAG_SITELOCAL	0x1000
		#define NI_NODEADDR_FLAG_GLOBAL		0x2000
		#define NI_NODEADDR_FLAG_ANYCAST	0x4000 /* just experimental. not in spec */
	#endif

	struct ni_reply_fqdn {
		uint32_t ni_fqdn_ttl;	/* TTL */
		uint8_t ni_fqdn_namelen; /* length in octets of the FQDN */
		uint8_t ni_fqdn_name[3]; /* XXX: alignment */
	} __attribute__ ((__packed__));

#endif


struct ni_reply_ip6 {
	uint32_t ni_ip6_ttl;	/* TTL */
	struct in6_addr ip6; /* IPv6 address */
} __attribute__ ((__packed__));


struct ni_reply_ip {
	uint32_t ni_ip_ttl;	/* TTL */
	struct in_addr ip; /* IPv6 address */
} __attribute__ ((__packed__));

struct ni_reply_name {
	uint32_t ni_name_ttl;	/* TTL */
	unsigned char	ni_name_name; /* IPv6 address */
} __attribute__ ((__packed__));


/* ICMPv6 Types/Codes not defined in some OSes */
#ifndef ICMP6_DST_UNREACH_FAILEDPOLICY
	#define ICMP6_DST_UNREACH_FAILEDPOLICY	5
#endif

#ifndef ICMP6_DST_UNREACH_REJECTROUTE
	#define ICMP6_DST_UNREACH_REJECTROUTE	6
#endif


struct packet{
	unsigned char	*link;
	unsigned char	*ipv6;
	unsigned char	*upper;
	unsigned long	maxsize;
};

struct iface_data{
	char				iface[IFACE_LENGTH];
	unsigned char		iface_f;
	pcap_t				*pfd;
	int					ifindex;
	unsigned char		ifindex_f;
	struct iface_list	iflist;
	unsigned int		type;
	unsigned int		flags;
	int					fd;
	unsigned int		pending_write_f;
	void				*pending_write_data;
	unsigned int		pending_write_size;
	fd_set				*rset;
	fd_set				*wset;
	fd_set				*eset;
	unsigned int		write_errors;
	struct ether_addr	ether;
	unsigned int		ether_flag;
	unsigned int		linkhsize;
	unsigned int		max_packet_size;
	struct in6_addr		ip6_local;
	unsigned int		ip6_local_flag;
	struct prefix_list	ip6_global;
	unsigned int		ip6_global_flag;
	struct in6_addr		router_ip6;
	struct ether_addr	router_ether;
	struct prefix_list	prefix_ac;
	struct prefix_list	prefix_ol;
	unsigned int		local_retrans;
	unsigned int		local_timeout;
	unsigned int		mtu;
	struct ether_addr	hsrcaddr;
	unsigned int		hsrcaddr_f;
	struct ether_addr	hdstaddr;
	unsigned int		hdstaddr_f;
	struct in_addr		srcaddr;
	unsigned int		src_f;      /* XXX Set when a source address has been selected (even if automatically) */
	unsigned int		srcaddr_f;
	unsigned char		srcpreflen;
	unsigned char		srcprefix_f;
	struct in_addr		dstaddr;
	unsigned int		dstaddr_f;
	unsigned int		verbose_f;
	unsigned char		listen_f;
	unsigned char		fragh_f;

	/* XXX
	   The next four variables are kind of a duplicate of router_ip6 and router_ether above.
       May remove them at some point
     */

	struct in6_addr		nhaddr;
	unsigned char		nhaddr_f;
	struct ether_addr	nhhaddr;
	unsigned char		nhhaddr_f;
	int					nhifindex;
	unsigned char		nhifindex_f;
	char				nhiface[IFACE_LENGTH];
	unsigned char		nh_f;
	uint16_t			srcport;
	uint16_t			dstport;
	char				srcport_f;
	char				dstport_f;
};


#ifdef __linux__
/* Consulting the routing table */
#define MAX_NLPAYLOAD 1024
#else
#define MAX_RTPAYLOAD 1024
#endif

#if defined(__linux__)

#define SLL_ADDRLEN 0

struct sll_linux{
        uint16_t sll_pkttype;          /* packet type */
        uint16_t sll_hatype;           /* link-layer address type */
        uint16_t sll_halen;            /* link-layer address length */
        uint8_t sll_addr[SLL_ADDRLEN]; /* link-layer address */
        uint16_t sll_protocol;         /* protocol */
} __attribute__ ((__packed__));
#endif


struct next_hop{
	struct in6_addr	srcaddr;
	unsigned char	srcaddr_f;
	struct in6_addr	dstaddr;
	unsigned char	dstaddr_f;
	struct in6_addr	nhaddr;
	unsigned char	nhaddr_f;
	struct ether_addr nhhaddr;
	unsigned char	nhhaddr_f;
	int				ifindex;
	unsigned char	ifindex_f;
};


/* Flags that specify what the load_dst_and_pcap() function should do */
#define LOAD_PCAP_ONLY		0x01
#define	LOAD_SRC_NXT_HOP	0x02

/* Constants to signal special interface types */
#define	IFACE_LOOPBACK			1
#define IFACE_TUNNEL			2

#ifndef SA_SIZE
#if defined(__APPLE__)
#define SA_SIZE(sa)                                            \
        (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?  \
           sizeof(long)         :                               \
           ((struct sockaddr *)(sa))->sa_len )
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__)
#define SA_SIZE(sa)                                            \
        (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?  \
           sizeof(long)         :                               \
           1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#else
	#define SA_SIZE(sa) sizeof(struct sockaddr)
#endif
#endif


#define MAX_JSON_ITEMS	150

struct json{
	unsigned int	nitem;
	unsigned int	maxitems; /* MAX_ITEMS */
	char			*key[MAX_JSON_ITEMS];
	unsigned int	key_l[MAX_JSON_ITEMS];
	char			*value[MAX_JSON_ITEMS];
	unsigned int	value_l[MAX_JSON_ITEMS];
};


struct json_value{
	char 			*value;
	unsigned int	len;
};


#define				IP_LIMITED_MULTICAST	"255.255.255.255"
#define				NULL_STRING	""
#define				TP_LINK_SMART_PORT	9999
/* XXX Should use different constant */
#define				MAX_TP_COMMAND_LENGTH	10000
#define				TP_LINK_IP_CAMERA_TDDP_PORT	1068


int					init_iface_data(struct iface_data *);
void				debug_print_iflist(struct iface_list *);
int					ether_ntop(const struct ether_addr *, char *, size_t);
int					ether_pton(const char *, struct ether_addr *, unsigned int);
void 				*find_iface_by_index(struct iface_list *, int);
void				*find_iface_by_name(struct iface_list *, char *);
void				*find_iface_by_addr(struct iface_list *, void *, sa_family_t);
void				*find_v4addr(struct iface_list *);
void				*find_v4addr_for_iface(struct iface_list *, char *);
int					get_local_addrs(struct iface_data *);
int					is_ip_in_prefix_list(struct in_addr *, struct prefixv4_list *);
int					is_ip6_in_prefix_list(struct in6_addr *, struct prefix_list *);
int					is_time_elapsed(struct timeval *, struct timeval *, unsigned long);
void				release_privileges(void);
size_t				Strnlen(const char *, size_t);
struct timeval		timeval_sub(struct timeval *, struct timeval *);
float				time_diff_ms(struct timeval *, struct timeval *);
void				tp_link_crypt(unsigned char *, size_t);
void				tp_link_decrypt(unsigned char *, size_t);
void				dump_hex(void *, size_t);
void				dump_text(void* ptr, size_t s);




int json_free_struct(struct json *);
void json_print_objects(struct json *);
unsigned int json_get_value(struct json *, struct json_value *, char *);
struct json * json_get_objects(char *, unsigned int);
unsigned int json_add_item(struct json *, char *, unsigned int, char *, unsigned int);
struct json * json_alloc_struct(void);
int is_valid_json_string(char *, unsigned int);
unsigned int json_remove_quotes(struct json *);
uint16_t in_chksum(uint16_t *, size_t);


