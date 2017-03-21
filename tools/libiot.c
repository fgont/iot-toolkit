/*
 * libiot : An IoT Library
 *
 * Copyright (C) 2017 Fernando Gont <fgont@si6networks.com>
 *
 * Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Build with: make libiot
 * 
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#ifdef __linux__
	#include <asm/types.h>
	#include <linux/netlink.h>
	#include <linux/rtnetlink.h>
	#include <netpacket/packet.h>   /* For datalink structure */
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__) || defined(__sun) || defined(sun)
	#include <net/if_dl.h>
	#include <net/route.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include <pcap.h>
#include <setjmp.h>
#include <pwd.h>

#include "libiot.h"
#include "iot-toolkit.h"


/* pcap variables */
char				errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program	pcap_filter;

#ifdef __linux__
/* Netlink requests */
struct nlrequest{
    struct nlmsghdr nl;
    struct rtmsg    rt;
    char   buf[MAX_NLPAYLOAD];
};
#endif




/*
 * Function: init_iface_data()
 *
 * Initializes the contents of "iface_data" structure
 */

int init_iface_data(struct iface_data *idata){
	unsigned int i;

	memset(idata, 0, sizeof(struct iface_data));

	idata->mtu= ETH_DATA_LEN;
	idata->local_retrans = 0;
	idata->local_timeout = 1;

	if( (idata->ip6_global.prefix= malloc(MAX_LOCAL_ADDRESSES * sizeof(struct prefix_entry *))) == NULL)
		return(FAILURE);

	idata->ip6_global.nprefix=0;
	idata->ip6_global.maxprefix= MAX_LOCAL_ADDRESSES;

	if( (idata->prefix_ol.prefix= malloc(MAX_PREFIXES_ONLINK * sizeof(struct prefix_entry *))) == NULL)
		return(FAILURE);

	idata->prefix_ol.nprefix= 0;
	idata->prefix_ol.maxprefix= MAX_PREFIXES_ONLINK;

	if( (idata->prefix_ac.prefix= malloc(MAX_PREFIXES_AUTO * sizeof(struct prefix_entry *))) == NULL)
		return(FAILURE);

	idata->prefix_ac.nprefix= 0;
	idata->prefix_ac.maxprefix= MAX_PREFIXES_AUTO;

	if( ((idata->iflist).ifaces= malloc(sizeof(struct iface_entry) * MAX_IFACES)) == NULL)
		return(FAILURE);

	memset((idata->iflist).ifaces, 0, sizeof(struct iface_entry) * MAX_IFACES);

	idata->iflist.nifaces=0;
	idata->iflist.maxifaces= MAX_IFACES;

	for(i=0; i<MAX_IFACES; i++){
		if(( (idata->iflist).ifaces[i].ip6_global.prefix= malloc( sizeof(struct prefix_entry *) * MAX_LOCAL_ADDRESSES)) == NULL){
			return(FAILURE);
		}

		(idata->iflist).ifaces[i].ip6_global.maxprefix= MAX_LOCAL_ADDRESSES;

		if( ((idata->iflist).ifaces[i].ip6_local.prefix= malloc( sizeof(struct prefix_entry *) * MAX_LOCAL_ADDRESSES)) == NULL){
			return(FAILURE);
		}

		(idata->iflist).ifaces[i].ip6_local.maxprefix= MAX_LOCAL_ADDRESSES;

		if( ((idata->iflist).ifaces[i].ip.prefix= malloc( sizeof(struct prefixv4_entry *) * MAX_LOCAL_ADDRESSES)) == NULL){
			return(FAILURE);
		}

		(idata->iflist).ifaces[i].ip.maxprefix= MAX_LOCAL_ADDRESSES;
	}

	return SUCCESS;
}




/*
 * Function: get_local_addrs()
 *
 * Obtains all local addresses (Ethernet and IPv6 addresses for all interfaces)
 */

int get_local_addrs(struct iface_data *idata){
	struct iface_entry		*cif;
	struct ifaddrs			*ifptr, *ptr;
	struct sockaddr_in6		*sockin6ptr;
	struct sockaddr_in		*sockinptr;

#ifdef __linux__
	struct sockaddr_ll	*sockpptr;
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
	struct sockaddr_dl	*sockpptr;
#endif

	if(getifaddrs(&ifptr) != 0){
		if(idata->verbose_f > 1){
			puts("Error in call to getifaddrs()");
		}
		return(FAILURE);
	}

	for(ptr=ifptr; ptr != NULL; ptr= ptr->ifa_next){
		if(ptr->ifa_addr == NULL){
			continue;
		}

		if(ptr->ifa_name == NULL){
#ifdef DEBUG
puts("DEBUG: ifa_name was null");
#endif
			continue;
		}

		if( (cif = find_iface_by_name( &(idata->iflist), ptr->ifa_name)) == NULL){
			if(idata->iflist.nifaces >= MAX_IFACES)
				continue;
			else{
				cif= &(idata->iflist.ifaces[idata->iflist.nifaces]);
				strncpy(cif->iface, ptr->ifa_name, IFACE_LENGTH-1);
				cif->iface[IFACE_LENGTH-1]=0;
				/* XXX: Cannot otherwise find the index for tun devices? */
				cif->ifindex= if_nametoindex(cif->iface);
				idata->iflist.nifaces++;
			}
		}

#ifdef __linux__
		if((ptr->ifa_addr)->sa_family == AF_PACKET){
			sockpptr = (struct sockaddr_ll *) (ptr->ifa_addr);

			if(sockpptr->sll_halen == ETHER_ADDR_LEN){
				memcpy(&(cif->ether), sockpptr->sll_addr, ETHER_ADDR_LEN);
				cif->ether_f= TRUE;
			}

			cif->ifindex= sockpptr->sll_ifindex;
		}
#elif defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
		if((ptr->ifa_addr)->sa_family == AF_LINK){
			sockpptr = (struct sockaddr_dl *) (ptr->ifa_addr);
			if(sockpptr->sdl_alen == ETHER_ADDR_LEN){
				memcpy(&(cif->ether), (sockpptr->sdl_data + sockpptr->sdl_nlen), ETHER_ADDR_LEN);
				cif->ether_f= TRUE;
			}

			cif->ifindex= sockpptr->sdl_index;
		}
#endif
		else if((ptr->ifa_addr)->sa_family == AF_INET){
			sockinptr= (struct sockaddr_in *) (ptr->ifa_addr);

			if(is_ip_in_prefix_list( &(sockinptr->sin_addr), &(cif->ip)))
				continue;

			if(IN_IS_ADDR_LOOPBACK(&(sockinptr->sin_addr)))
				cif->flags= IFACE_LOOPBACK;

			if(cif->ip.nprefix >= cif->ip6_global.maxprefix)
				continue;

			if( (cif->ip.prefix[cif->ip.nprefix] = \
											malloc(sizeof(struct prefixv4_entry))) == NULL){
				if(idata->verbose_f > 1)
					puts("Error while storing Source Address");

				freeifaddrs(ifptr);
				return(FAILURE);
			}

			(cif->ip.prefix[cif->ip.nprefix])->len = 32;
			(cif->ip.prefix[cif->ip.nprefix])->ip = sockinptr->sin_addr;
			cif->ip.nprefix++;	
		}

		else if((ptr->ifa_addr)->sa_family == AF_INET6){
			sockin6ptr= (struct sockaddr_in6 *) (ptr->ifa_addr);

			if(IN6_IS_ADDR_LINKLOCAL( &(sockin6ptr->sin6_addr))){
				if(cif->ip6_local.nprefix >= cif->ip6_local.maxprefix)
					continue;

				if(is_ip6_in_prefix_list( &(sockin6ptr->sin6_addr), &(cif->ip6_local)) == TRUE)
					continue;

				if( (cif->ip6_local.prefix[cif->ip6_local.nprefix] = malloc(sizeof(struct prefix_entry))) == NULL){
					if(idata->verbose_f > 1)
						puts("Error while storing Source Address");

					freeifaddrs(ifptr);
					return(FAILURE);
				}

				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->len = 128;
				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->ip6 = sockin6ptr->sin6_addr;

#if defined (__FreeBSD__) || defined(__NetBSD__) || defined (__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD_kernel__)
					/* BSDs store the interface index in s6_addr16[1], so we must clear it */
				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->ip6.s6_addr16[1] =0;
				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->ip6.s6_addr16[2] =0;
				(cif->ip6_local.prefix[cif->ip6_local.nprefix])->ip6.s6_addr16[3] =0;					
#endif

				cif->ip6_local.nprefix++;
			}
			else{
				if(is_ip6_in_prefix_list( &(sockin6ptr->sin6_addr), &(cif->ip6_global)))
					continue;

				if(IN6_IS_ADDR_LOOPBACK(&(sockin6ptr->sin6_addr)))
					cif->flags= IFACE_LOOPBACK;

				if(cif->ip6_global.nprefix >= cif->ip6_global.maxprefix)
					continue;

				if( (cif->ip6_global.prefix[cif->ip6_global.nprefix] = \
												malloc(sizeof(struct prefix_entry))) == NULL){
					if(idata->verbose_f > 1)
						puts("Error while storing Source Address");

					freeifaddrs(ifptr);
					return(FAILURE);
				}

				(cif->ip6_global.prefix[cif->ip6_global.nprefix])->len = 128;
				(cif->ip6_global.prefix[cif->ip6_global.nprefix])->ip6 = sockin6ptr->sin6_addr;
				cif->ip6_global.nprefix++;
			}
		}
	}

	freeifaddrs(ifptr);

#ifdef DEBUG
	debug_print_ifaces_data( &(idata->iflist));
#endif
	return(SUCCESS);
}




/*
 * Function: debug_print_ifaces_data()
 *
 * Prints the data correspoding to each interface
 */

void debug_print_iflist(struct iface_list *iflist){
	unsigned int		i, j;
	struct iface_entry	*iface;
	char 				plinkaddr[ETHER_ADDR_PLEN];
	char 				pv6addr[INET6_ADDRSTRLEN];
	char				pv4addr[16];  /* Space for xxx.xxx.xxx.xxx plus NULL */

	for(i=0; i< iflist->nifaces; i++){
		iface= iflist->ifaces +i;

		printf("DEBUG: Interface: %s (%d)\tFlags:%s%s\n", iface->iface, iface->ifindex, (iface->flags & IFACE_LOOPBACK)?" LOOPBACK":"",\
														 (iface->flags & IFACE_TUNNEL)?"TUNNEL":"");

		if(iface->ether_f){
			if(ether_ntop(&(iface->ether), plinkaddr, sizeof(plinkaddr)) == 0){
				puts("DEBUG: ether_ntop(): Error converting address");
				exit(EXIT_FAILURE);
			}

			printf("DEBUG: Link address: %s\n", plinkaddr);
		}

		if( (iface->ip6_global).nprefix){
			puts("DEBUG: Global addresses:");

			for(j=0; j<(iface->ip6_global.nprefix); j++){
				if(inet_ntop(AF_INET6, &((iface->ip6_global.prefix[j])->ip6), pv6addr, sizeof(pv6addr)) == NULL){
					puts("DEBUG: inet_ntop(): Error converting IPv6 Address to presentation format");
					exit(EXIT_FAILURE);
				}

				printf("DEBUG: %s\n", pv6addr);
			}
		}

		if( (iface->ip6_local).nprefix){
			puts("DEBUG: Local addresses:");

			for(j=0; j<(iface->ip6_local.nprefix); j++){
				if(inet_ntop(AF_INET6, &((iface->ip6_local.prefix[j])->ip6), pv6addr, sizeof(pv6addr)) == NULL){
					puts("DEBUG: inet_ntop(): Error converting IPv6 Address to presentation format");
					exit(EXIT_FAILURE);
				}

				printf("DEBUG: %s\n", pv6addr);
			}
		}

		if( (iface->ip).nprefix){
			puts("DEBUG: IPv4 addresses:");

			for(j=0; j<(iface->ip.nprefix); j++){
				if(inet_ntop(AF_INET, &((iface->ip.prefix[j])->ip), pv4addr, sizeof(pv4addr)) == NULL){
					puts("DEBUG: inet_ntop(): Error converting IPv4 Address to presentation format");
					exit(EXIT_FAILURE);
				}

				printf("DEBUG: %s\n", pv4addr);
			}
		}

		puts("");
	}
}



/*
 * Function: find_iface_by_name()
 *
 * Finds an Interface (by name) in an Interface list
 */

void *find_iface_by_name(struct iface_list *iflist, char *iface){
	unsigned int i;

	for(i=0; i < iflist->nifaces; i++){
		if(strncmp((iflist->ifaces[i]).iface, iface, IFACE_LENGTH) == 0)
			return(&(iflist->ifaces[i]));
	}

	return(NULL);
}


/*
 * Function: find_iface_by_index()
 *
 * Finds an Interface (by index) in an Interface list
 */

void *find_iface_by_index(struct iface_list *iflist, int ifindex){
	unsigned int i;

	for(i=0; i < iflist->nifaces; i++){
		if((iflist->ifaces[i]).ifindex == ifindex)
			return(&(iflist->ifaces[i]));
	}

	return(NULL);
}


/*
 * Function: find_iface_by_addr()
 *
 * Finds an Interface (by IPv6 address) in an Interface list
 */

void *find_iface_by_addr(struct iface_list *iflist, void *addr, sa_family_t family){
	unsigned int i;

	if(family == AF_INET6){
		for(i=0; i < iflist->nifaces; i++){
			if(is_ip6_in_prefix_list(addr, &((iflist->ifaces[i]).ip6_global)) || is_ip6_in_prefix_list(addr, &((iflist->ifaces[i]).ip6_local)))
				return(&(iflist->ifaces[i]));
		}

		return(NULL);
	}
	else if(family == AF_INET){
		for(i=0; i < iflist->nifaces; i++){
			if(is_ip_in_prefix_list(addr, &((iflist->ifaces[i]).ip)))
				return(&(iflist->ifaces[i]));
		}

		return(NULL);
	}
	else{
		return(NULL);
	}
}


/*
 * Function: find_v4addr_for_iface()
 *
 * Finds an IPv4 address for an interface (by name)
 */

void *find_v4addr_for_iface(struct iface_list *iflist, char *iface){
	unsigned int i;

	for(i=0; i < iflist->nifaces; i++){
		if(strncmp((iflist->ifaces[i]).iface, iface, IFACE_LENGTH) == 0){
			if( (iflist->ifaces[i]).ip.nprefix)
				return( &((iflist->ifaces[i]).ip.prefix[0])->ip);
			else
				return(NULL);
		}
	}

	return(NULL);
}


/*
 * Function: find_v4addr()
 *
 * Finds a non-loopback IPv4 address
 */

void *find_v4addr(struct iface_list *iflist){
	unsigned int i, j;

	for(i=0; i < iflist->nifaces; i++){
		for(j=0; j < iflist->ifaces[i].ip.nprefix; j++){
			if(!IN_IS_ADDR_LOOPBACK(&(((iflist->ifaces[i]).ip.prefix[j])->ip)))
				return( &(((iflist->ifaces[i]).ip.prefix[j])->ip));
		}
	}

	return(NULL);
}



/*
 * Function: Strnlen()
 *
 * Our own version of strnlen(), since some OSes do not support it.
 */

size_t Strnlen(const char *s, size_t maxlen){
	size_t i=0;

	while(i < maxlen && s[i] != 0)
		i++;

	if(i < maxlen)
		return(i);
	else
		return(maxlen);
}



/*
 * Function: is_ip_in_prefix_list()
 *
 * Checks whether an IPv4 address is present in a prefix list.
 */

int is_ip_in_prefix_list(struct in_addr *target, struct prefixv4_list *plist){
	unsigned int i;
	uint32_t	mask32;

	for(i=0; i < plist->nprefix; i++){
		mask32 = 0xffffffff << (32 - (plist->prefix[i])->len);

		if( (target->s_addr & htonl(mask32)) == ((plist->prefix[i])->ip.s_addr & htonl(mask32)))
			return TRUE;
	}

	return FALSE;
}


/*
 * Function: is_ip6_in_prefix_list()
 *
 * Checks whether an IPv6 address is present in an address list.
 */

int is_ip6_in_prefix_list(struct in6_addr *target, struct prefix_list *plist){
	unsigned int i, j, full32, rest32;
	uint32_t	mask32;

	for(i=0; i < plist->nprefix; i++){
		full32=(plist->prefix[i])->len / 32;
		rest32=(plist->prefix[i])->len % 32;
		mask32 = 0xffffffff;

		for(j=0; j < full32; j++)
			if(target->s6_addr32[j] != (plist->prefix[i])->ip6.s6_addr32[j])
				break;

		if(j == full32){
			if(rest32 == 0)
				return TRUE;
			else{
				mask32 = mask32 << (32 - rest32);

				if( (target->s6_addr32[full32] & htonl(mask32)) == ((plist->prefix[i])->ip6.s6_addr32[full32] & htonl(mask32)))
					return TRUE;
			}
		}
	}

	return FALSE;
}



/*
 * Function: ether_ntop()
 *
 * Convert binary Ethernet Address into printable foramt (an ASCII string)
 */

int ether_ntop(const struct ether_addr *ether, char *ascii, size_t s){
	unsigned int r;

	if(s < ETHER_ADDR_PLEN)
		return 0;

	r=snprintf(ascii, s, "%02x:%02x:%02x:%02x:%02x:%02x", ether->a[0], ether->a[1], ether->a[2], ether->a[3], \
											ether->a[4], ether->a[5]);

	if(r != 17)
		return 0;

	return 1;
}


/*
 * Function: ether_pton()
 *
 * Convert a string (printable Ethernet Address) into binary format
 */

int ether_pton(const char *ascii, struct ether_addr *etheraddr, unsigned int s){
	unsigned int i, a[6];

	if(s < ETHER_ADDR_LEN)
		return 0;
	
	if(ascii){
		if( sscanf(ascii,"%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) == 6){ 
			for(i=0;i<6;i++)
				etheraddr->a[i]= a[i];

			return 1;
		}
	}

	return 0;
}




/*
 * release_privileges()
 *
 * Releases superuser privileges by switching to the real uid and gid, or to nobody
 */

void release_privileges(void){
	uid_t			ruid;
	gid_t			rgid;
	struct passwd	*pwdptr;

	/* 
	   If the real UID is not root, we setuid() and setgid() to that user and group, releasing superuser
	   privileges. Otherwise, if the real UID is 0, we try to setuid() to "nobody", releasing superuser 
	   privileges.
	 */
	if( (ruid=getuid()) && (rgid=getgid())){
		if(setgid(rgid) == -1){
			puts("Error while releasing superuser privileges (changing to real GID)");
			exit(EXIT_FAILURE);
		}

		if(setuid(ruid) == -1){
			puts("Error while releasing superuser privileges (changing to real UID)");
			exit(EXIT_FAILURE);
		}
	}
	else{
		if((pwdptr=getpwnam("nobody"))){
			if(!pwdptr->pw_uid || !pwdptr->pw_gid){
				puts("User 'nobody' has incorrect privileges");
				exit(EXIT_FAILURE);
			}

			if(setgid(pwdptr->pw_gid) == -1){
				puts("Error while releasing superuser privileges (changing to nobody's group)");
				exit(EXIT_FAILURE);
			}

			if(setuid(pwdptr->pw_uid) == -1){
				puts("Error while releasing superuser privileges (changing to 'nobody')");
				exit(EXIT_FAILURE);
			}
		}
	}
}



/*
 * Function: tp_link_crypt()
 *
 * Releases memory allocated for holding IPv6 addresses and Ethernet addresses
 */

void tp_link_decrypt(unsigned char *p, size_t size){
	unsigned char	key= 171, c;
	unsigned int	i;

	if(p != NULL && size > 0){
		for(i=0; i<size; i++){
			c= key ^ p[i];
			key= p[i];
			p[i]= c;
		}
	}
}


/*
 * Function: tp_link_crypt()
 *
 * Releases memory allocated for holding IPv6 addresses and Ethernet addresses
 */

void tp_link_crypt(unsigned char *p, size_t size){
	unsigned char	key= 171;
	unsigned int	i;

	if(p != NULL && size > 0){
		for(i=0; i<size; i++){
			p[i]= p[i] ^ key;
			key= p[i];
		}
	}
}



/*
 * Function: dump_hex()
 *
 * Prints a buffer in hexadecimal (mostly for debugging purposes)
 */

void dump_hex(void* ptr, size_t s){
	unsigned int i;

	for(i=0; i < s; i++){
		printf("%02x ",  *( ((uint8_t *)ptr)+i) );
	}

	puts("");
}

/*
 * Function: dump_text()
 *
 * Prints a buffer in hexadecimal (mostly for debugging purposes)
 */

void dump_text(void* ptr, size_t s){
	unsigned int i;

	for(i=0; i < s; i++){
		printf("%c",  *( ((char *)ptr)+i) );
	}

	puts("");
}


/*
 * Function: is_time_elapsed()
 *
 * Checks whether a specific amount of time has elapsed. (i.e., whether curtime >= lastprobe + delta
 */

int is_time_elapsed(struct timeval *curtime, struct timeval *lastprobe, unsigned long delta){
		if( curtime->tv_sec > (lastprobe->tv_sec + delta / 1000000) ){
			return(1);
		}else if( curtime->tv_sec == (lastprobe->tv_sec + delta / 1000000)){
			if( curtime->tv_usec >= (lastprobe->tv_usec + delta % 1000000) ){
				return(1);
			}
		}

		return(0);
}




/*
 * Function: is_valid_json_string()
 *
 * Performs some minimum sanity checks on JSON strings
 */

int is_valid_json_string(char *s, unsigned int len){
	unsigned int i;
	int bracket_depth=0, curly_depth=0, quote_num=0, quoted_f=FALSE, openquote_f=FALSE;

	return(TRUE);

	if(s == NULL){
/*puts("string nulo");*/
		return(FALSE);
	}

	for(i=0; i< len; i++){
		if(s[i] == 0x00){
/*puts("Encontre 0x00");*/
			return(FALSE);
		}

		if(openquote_f){
			switch(s[i]){
				case '\\':
					quoted_f= TRUE;
					break;

				case '"':
					if(quoted_f){
						quoted_f= FALSE;
					}
					else{
						openquote_f= FALSE;
						quote_num++;
					}
	
					break;

				default:
					quoted_f= FALSE;
					break;
			}
		}
		else{
			switch(s[i]){
				case '\\':
					quoted_f= TRUE;
					break;

				case '[':
					bracket_depth++;
					quoted_f= FALSE;
					break;

				case ']':
					bracket_depth--;
					quoted_f= FALSE;

					if(bracket_depth < 0){
/*puts("curly_depth < 0");*/
						return(FALSE);
					}

					break;

				case '{':
					curly_depth++;
					quoted_f= FALSE;
					break;

				case '}':
					curly_depth--;
					quoted_f= FALSE;

					if(curly_depth < 0){
/*puts("curly_depth < 0"); */
						return(FALSE);
					}

					break;

				case '"':
					if(quoted_f){
						quoted_f= FALSE;
					}
					else{
						openquote_f= TRUE;
						quote_num++;
					}
	
					break;

				default:
					quoted_f= FALSE;
					break;
			}
		}

	}

/*
	if(quote_num % 2){
puts("quote num no es par");
	}

	if(curly_depth != 0){
puts("curly_depth != 0");
	}

	if(bracket_depth != 0){
puts("bracket_depth != 0");
	}
*/

	if(quote_num % 2 || curly_depth != 0 || bracket_depth != 0){
		return(FALSE);
	}

	return(TRUE);
}





/*
 * Function: get_json_objects()
 *
 * Obtains the first-level JSON objects
 */

struct json * json_get_objects(char *s, unsigned int len){
	struct json	*json;
	unsigned int i;
	char	*kstart=NULL, *kend=NULL, *vstart=NULL, *vend=NULL;
	char quoted_f=FALSE, open_quote_f=FALSE;
	int bracket_depth=0, curly_depth=0;

/*puts("Voy a chequear string");*/
	if(!is_valid_json_string(s, len)){
/*puts("String no valido");*/
		return(NULL);
	}

/*puts("String valido");*/

/*puts("Voy a hacer alloc");*/
	if( (json=json_alloc_struct()) == NULL){
/*puts("No pude hacer alloc");*/
		return(NULL);
	}

/*puts("hice alloc"); */

	for(i=0; i<	len; i++){
		if(open_quote_f){
			switch(s[i]){
				case '\\':
					quoted_f= TRUE;
					break;

				case '"':
					if(quoted_f){
						quoted_f= FALSE;
					}
					else{
						open_quote_f= FALSE;
/*
						if(curly_depth == 1 && kstart != NULL && kend==NULL){
							kend= s+i+1;
							vstart= s+i+1;
						}
*/
					}
	
					break;

				default:
					quoted_f= FALSE;
					break;
			}
		}
		else{
			switch(s[i]){
				case '\\':
					quoted_f= TRUE;
					break;

				case '[':
					bracket_depth++;
					quoted_f= FALSE;
					break;

				case ']':
					bracket_depth--;
					quoted_f= FALSE;

					if(bracket_depth < 0)
						return(FALSE);

					break;

				case '{':
					curly_depth++;
					if(curly_depth == 1 && kstart==NULL)
						kstart= s+i+1;

					quoted_f= FALSE;
					break;

				case ':':
					if(curly_depth == 1 && kstart != NULL && kend==NULL){
						kend= s+i;
						vstart= s+i+1;
					}

					quoted_f= FALSE;
					break;

				case ',':
					if(curly_depth == 1 && kstart != NULL && kend!=NULL && vstart!=NULL){
						vend= s+i;

						if(!json_add_item(json, kstart, kend-kstart, vstart, vend-vstart)){
							json_free_struct(json);
							return(FALSE);
						}

						kstart= s+i+1;
						kend= NULL;
						vstart= NULL;
						vend= NULL;
					}
					else if(curly_depth == 1 && kstart == NULL && kend==NULL && vstart==NULL && vend==NULL){
						kstart= s+i+1;
					}

					quoted_f= FALSE;
					break;

				case '}':
					curly_depth--;

					if(curly_depth <= 1 && curly_depth >= 0  && kstart != NULL && kend!=NULL && vstart!=NULL){
						vend= s+i+curly_depth;

						if(!json_add_item(json, kstart, kend-kstart, vstart, vend-vstart)){
							json_free_struct(json);
							return(FALSE);
						}

						kstart= NULL;
						kend= NULL;
						vstart= NULL;
						vend= NULL;
					}

					quoted_f= FALSE;

					if(curly_depth < 0)
						return(FALSE);

					break;

				case '"':
					if(quoted_f){
						quoted_f= FALSE;
					}
					else{
						open_quote_f=TRUE;
					}
	
					break;

				default:
					quoted_f= FALSE;
					break;
			}
		}
	}

	return(json);
}


/*
 * Function: json_alloc_struct()
 *
 * Obtains the first-level JSON objects
 */

struct json * json_alloc_struct(void){
	struct json *json;
	unsigned int i;

/*puts("entre a alloc");*/
	/* XXX: Minimal check on the size of struct json
		We have: 2 unsignet int, 2 arrays of MAX_ITEMS of unsigned in, 2 arrays of MAX_ITEMS of char *
	*/
/*printf("tam mem: %li\n", sizeof(struct json));*/

	if( (json= malloc(sizeof(struct json))) == NULL){
		return(NULL);
	}

/*
	if( (json= malloc(sizeof(struct json))) == NULL){
puts("no pude reservar memoria");
		return(NULL);
	}
*/

	if(sizeof(struct json) < ( ( (2 + 2 * MAX_JSON_ITEMS) * sizeof(unsigned int)) + (2 * MAX_JSON_ITEMS * sizeof(char *)))){
/*puts("Tamanio pequenio"); */
		free(json);
		return(NULL);
	}

/*puts("Voy a inicializar"); */
	json->nitem=0;
	json->maxitems= MAX_JSON_ITEMS;
	
	for(i=0; i<MAX_JSON_ITEMS; i++){
		json->key[i]=NULL;
		json->key_l[i]=0;
		json->value[i]=NULL;
		json->value_l[i]=0;
	}

/*puts("Ya vuelvo");*/
	return(json);
}



/*
 * Function: json_free_struct()
 *
 * Obtains the first-level JSON objects
 */

int json_free_struct(struct json *json){
	unsigned int i;

	/* XXX: Minimal check on the size of struct json
		We have: 2 unsignet int, 2 arrays of MAX_ITEMS of unsigned in, 2 arrays of MAX_ITEMS of char *
	*/

	if(sizeof(struct json) < (((2+ 2 * MAX_JSON_ITEMS) * sizeof(unsigned int)) + (2* MAX_JSON_ITEMS * sizeof(char *))))
		return(FALSE);

	json->nitem=0;
	json->maxitems= MAX_JSON_ITEMS;
	
	for(i=0; i<MAX_JSON_ITEMS; i++){
		if(json->key[i]==NULL){
			free(json->key[i]);
		}
		if(json->value[i]==NULL){
			free(json->value[i]);
		}
	}

	free(json);

	return(TRUE);
}




/*
 * Function: json_add_item()
 *
 * Add an item to a struct json
 */

unsigned int json_add_item(struct json *json, char *kstart, unsigned int klen, char *vstart, unsigned int vlen){
	if(json->nitem >= json->maxitems)
		return(FALSE);

	if(  (json->key[json->nitem]= malloc(klen+1)) == NULL){
		return(FALSE);
	}

	if(  (json->value[json->nitem]= malloc(vlen+1)) == NULL){
		free(json->key[json->nitem]);
		return(FALSE);
	}

	memcpy(json->key[json->nitem], kstart, klen);
	*(json->key[json->nitem]+klen)= 0x00;	/* Null terminate the string if we mean to print it */
	json->key_l[json->nitem]= klen;
	memcpy(json->value[json->nitem], vstart, vlen);
	json->value_l[json->nitem]= vlen;
	*(json->value[json->nitem]+vlen)= 0x00;	/* Null terminate the string if we mean to print it */
	json->nitem++;
	
	return(TRUE);
}




/*
 * Function: json_print_objects()
 *
 * Add an item to a struct json
 */

void json_print_objects(struct json *json){
	unsigned int i;

	for(i=0; i < json->nitem; i++){
		printf("%s: %s\n", json->key[i], json->value[i]);
	}
}


/*
 * Function: json_get_value()
 *
 * Obtain the value for a given key
 */

unsigned int json_get_value(struct json *json, struct json_value *json_value, char *key){
	unsigned int i, klen;

	klen= Strnlen(key, 50); /* 50 is an artificial length for the key */

	for(i=0; i < json->nitem; i++){
		if(strncmp(json->key[i], key, klen) == 0){
			json_value->value= json->value[i];
			json_value->len= json->value_l[i];
			return(TRUE);
		}
	}

	return(FALSE);
}


/*
 * Function: json_remove_quotes()
 *
 * Remove quotes in keys and values
 */

unsigned int json_remove_quotes(struct json *json){
	char *buff;
	unsigned int i;

	for(i=0; i<json->nitem;i++){

		/* We require opening and closing quotes in order to remove them */
		if(json->key_l[i] >= 2){
			if(*(json->key[i]) == '"' && *(json->key[i] + json->key_l[i] - 1) == '"'){
				/* In the speial case of an empty string, we do not really need to "copy" data */
				if(json->key_l[i] == 2){
					*(json->key[i])= 0x00;
					json->key_l[i]=0;
				}
				else{
					/* We are going to remove two characters, but need space for the NULL byte */
					if( (buff=malloc(json->key_l[i] - 1)) == NULL){
						return(FALSE);
					}

					/* Copy the string plus the NULL byte */
					memcpy(buff, (json->key[i]+1), json->key_l[i] - 2); /* 					memcpy(buff, (json->key[i]+1), json->key_l[i] - 1); */
					*(buff + json->key_l[i] - 2)= 0x00;
					/* Herewe copy the text string, minus the two quote signs, plus the null byte */

					memcpy(json->key[i], buff, json->key_l[i] - 1);
					json->key_l[i]= json->key_l[i]-2;
					free(buff);
				}
			}
		}  
           
		if(json->value_l[i] >= 2){
			if(*(json->value[i]) == '"' && *(json->value[i] + json->value_l[i] -1 ) == '"'){
				/* In the speial case of an empty string, we do not really need to "copy" data */
				if(json->value_l[i] == 2){
					*(json->value[i])= 0x00;
					json->value_l[i]=0;
				}
				else{
					if( (buff=malloc(json->value_l[i] - 1)) == NULL){
						return(FALSE);
					}

					memcpy(buff, (json->value[i]+1), json->value_l[i] - 2);
					*(buff + json->value_l[i] - 2)= 0x00;
					memcpy(json->value[i], buff, json->value_l[i] - 1);
					json->value_l[i]= json->value_l[i]-2;
					free(buff);
				}
			}
		}
	}

	return(TRUE);
}



/* 
 * Function: in_chksum()
 *
 * Calculate the 16-bit Internet checksum
 * The same algorithm is used for compute the UDP checksum and the
 * IP checksum
 */
uint16_t in_chksum(uint16_t *addr, size_t len){
	size_t nleft;
	unsigned int sum = 0;
	uint16_t *w;
	uint16_t answer = 0;

	nleft=len;
	w=addr;

	while(nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if(nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}

