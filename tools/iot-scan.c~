/*
 * iot-scan: An IoT Scanning Tool
 *
 * Copyright (C) 2017 Fernando Gont <fgont@si6networks.com>
 *
 * Programmed by Fernando Gont for SI6 Networks <https://www.si6networks.com>
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
 * Build with: make iot-scan
 *
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netdb.h>
#include <pcap.h>

#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <unistd.h>

#include "iot-scan.h"
#include "iot-toolkit.h"
#include "libiot.h"

/* #define DEBUG */

/* Function prototypes */
void				init_packet_data(struct iface_data *);
void				free_host_entries(struct host_list *);
int					host_scan_local(pcap_t *, struct iface_data *, struct in6_addr *, unsigned char, \
									struct host_entry *);
void				print_help(void);
int					print_host_entries(struct host_list *, unsigned char);
void				local_sig_alarm(int);
void				usage(void);
int					process_config_file(const char *);

/* Used for multiscan */
struct host_list			host_local, host_global, host_candidate;
struct host_entry			*host_locals[MAX_IPV6_ENTRIES], *host_globals[MAX_IPV6_ENTRIES];
struct host_entry			*host_candidates[MAX_IPV6_ENTRIES];

/* Used for router discovery */
struct iface_data			idata;

/* Variables used for learning the default router */
struct ether_addr			router_ether, rs_ether;
struct in6_addr				router_ipv6, rs_ipv6;

struct in6_addr				randprefix;
unsigned char				randpreflen;

bpf_u_int32				my_netmask;
bpf_u_int32				my_ip;
struct bpf_program		pcap_filter;
char 					dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char			buffer[BUFFER_SIZE], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
char			readbuff[BUFFER_SIZE], sendbuff[BUFFER_SIZE];
ssize_t					nreadbuff, nsendbuff;
char					line[LINE_BUFFER_SIZE];
unsigned char			*v6buffer, *ptr, *startofprefixes;
char					*pref;
    
struct ether_header		*ethernet;
unsigned int			ndst=0;

char					*lasts, *rpref;
char					*charptr;

size_t					nw;
unsigned long			ul_res, ul_val;
unsigned int			i, j, startrand;
unsigned int			skip;
unsigned char			dstpreflen;

uint16_t				mask;

char 					plinkaddr[ETHER_ADDR_PLEN], pv4addr[INET_ADDRSTRLEN];
char 					pv6addr[INET6_ADDRSTRLEN];
unsigned char 			verbose_f=FALSE;
unsigned char 			dstaddr_f=FALSE, timestamps_f=FALSE, scan_local_f=FALSE;



unsigned char			dst_f=FALSE, end_f=FALSE, endpscan_f=FALSE;
unsigned char			donesending_f=FALSE;
uint16_t				srcport, dstport;
uint32_t				scan_type;
char					scan_type_f=FALSE;
unsigned long			pktinterval, rate;
unsigned int			packetsize;

struct prefixv4_entry	prefix;

char					*charstart, *charend, *lastcolon;
unsigned int			nsleep;
int						sel;
fd_set					sset, rset, wset, eset;
struct timeval			curtime, pcurtime, lastprobe;
struct tm				pcurtimetm;
unsigned int			retrans=0;
char 					TP_LINK_SMART_DISCOVER[]="{\"system\":{\"get_sysinfo\":null},\"emeter\":{\"get_realtime\":null}}";
char 					TP_LINK_IP_CAMERA_DISCOVER[]={0x02, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x17, 0x00, \
						                               0x07, 0xd8, 0xa1, 0x4f, 0xc2, 0x90, 0x98, 0x93, 0xec, 0x5b, 0x80, 0x5e, \
						                               0xfa, 0xe2, 0x06, 0xd5, 0x63, 0x86, 0xb6, 0xdc, 0x3c, 0x8a, 0xff, 0x48, \
						                               0xce, 0x6c, 0xbd, 0x97, 0xb7, 0x1c, 0x21, 0xe9, 0xbd, 0x59, 0x30, 0xd7, \
						                               0x19, 0xd1, 0x22, 0x77, 0x6b, 0xd9, 0x43, 0x19, 0xd8, 0x87, 0x9f, 0xbb};

char					TP_LINK_IP_CAMERA_RESPONSE[]= {0x02, 0x03, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
						                               0x17, 0x00, 0x72, 0xa9, 0xa2, 0x32, 0xad, 0xd8, 0x65, 0xae, \
						                               0x78, 0x40, 0xad, 0x62, 0x08, 0xf9, 0x34, 0x16};

int main(int argc, char **argv){
	extern char				*optarg;
	int						r;
	struct addrinfo			hints, *res, *aiptr;
	struct target_ipv6		target;
	struct timeval			timeout;
	void					*voidptr;
	const int				on=1;
	struct sockaddr_in		sockaddr_in, sockaddr_from, sockaddr_to;
	socklen_t				sockaddrfrom_len;
	struct json				*json1, *json2, *json3;
	struct json_value		json_value;
	char					*alias, *dev_name, *type, *model;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"dst-address", required_argument, 0, 'd'},
		{"local-scan", no_argument, 0, 'L'},
		{"retrans", required_argument, 0, 'x'},
		{"timeout", required_argument, 0, 'O'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0,  0 }
	};

	char shortopts[]= "i:d:Lx:O:vh";

	char option;

	if(argc<=1){
		usage();
		exit(EXIT_FAILURE);
	}

	srandom(time(NULL));

	init_iface_data(&idata);


	while((r=getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		option= r;

		switch(option) {
			case 'i':  /* Interface */
				strncpy(idata.iface, optarg, IFACE_LENGTH-1);
				idata.iface[IFACE_LENGTH-1]=0;
				idata.ifindex= if_nametoindex(idata.iface);
				idata.iface_f=TRUE;
				break;

			case 'd':	/* IPv6 Destination Address/Prefix */
				/* The '-d' option contains a domain name */
				if((charptr = strtok_r(optarg, "/", &lasts)) == NULL){
					puts("Error in Destination Address");
					exit(EXIT_FAILURE);
				}

				strncpy(target.name, charptr, NI_MAXHOST);
				target.name[NI_MAXHOST-1]=0;

				if((charptr = strtok_r(NULL, " ", &lasts)) != NULL){
					prefix.len = atoi(charptr);
		
					if(prefix.len > 32){
						puts("Prefix length error in IP Destination Address");
						exit(EXIT_FAILURE);
					}
				}
				else{
					prefix.len= 32;
				}

				memset(&hints, 0, sizeof(hints));
				hints.ai_family= AF_INET;
				hints.ai_canonname = NULL;
				hints.ai_addr = NULL;
				hints.ai_next = NULL;
				hints.ai_socktype= SOCK_DGRAM;

				if( (target.res = getaddrinfo(target.name, NULL, &hints, &res)) != 0){
					printf("Unknown Destination '%s': %s\n", target.name, gai_strerror(target.res));
					exit(1);
				}

				for(aiptr=res; aiptr != NULL; aiptr=aiptr->ai_next){
					if(aiptr->ai_family != AF_INET)
							continue;

					if(aiptr->ai_addrlen != sizeof(struct sockaddr_in))
						continue;

					if(aiptr->ai_addr == NULL)
						continue;

					prefix.ip= ( (struct sockaddr_in *)aiptr->ai_addr)->sin_addr;
				}

				freeaddrinfo(res);

				idata.dstaddr= prefix.ip;				
				idata.dstaddr_f= TRUE;
				dst_f=TRUE;
				break;
	    
			case 'L':
				scan_local_f=TRUE;
				break;

			case 'x':
				idata.local_retrans=atoi(optarg);
				break;

			case 'O':
				idata.local_timeout=atoi(optarg);
				break;

			case 'v':	/* Be verbose */
				idata.verbose_f++;
				break;
		
			case 'h':	/* Help */
				print_help();
				exit(EXIT_FAILURE);
				break;

			default:
				usage();
				exit(EXIT_FAILURE);
				break;
		
		} /* switch */
	} /* while(getopt) */

	/*
	    XXX: This is rather ugly, but some local functions need to check for verbosity, and it was not warranted
	    to pass &idata as an argument
	 */
	verbose_f= idata.verbose_f;

	if(geteuid()){
		puts("iot-scan needs superuser privileges to run");
		exit(EXIT_FAILURE);
	}

	if(scan_local_f && !idata.iface_f){
		/* XXX This should later allow to just specify local scan and automatically choose an interface */
		puts("Must specify the network interface with the -i option when a local scan is selected");
/*		exit(EXIT_FAILURE); */
	}

	if(!dst_f && !scan_local_f){
		if(idata.verbose_f)
			puts("Must specify either a destination prefix ('-d'), or a local scan ('-L')");

		exit(EXIT_FAILURE);
	}

	release_privileges();

	if(get_local_addrs(&idata) == FAILURE){
		puts("Error obtaining list of local interfaces and addresses");
		exit(EXIT_FAILURE);
	}

/*	debug_print_iflist(&(idata.iflist)); */

	if(!scan_type_f){
		scan_type= IP_CAMERAS | SMART_PLUGS;
	}

	if(scan_local_f){
		host_local.nhosts=0;
		host_local.maxhosts= MAX_IPV6_ENTRIES;
		host_local.host= host_locals;

		/* If an interface was specified, we select an IPv4 address from such interface */
		if(idata.iface_f){
			if( (voidptr=find_v4addr_for_iface(&(idata.iflist), idata.iface)) == NULL){
				printf("No IPv4 address for interface %s\n", idata.iface);
				exit(EXIT_FAILURE);
			}

			idata.srcaddr= *((struct in_addr *) voidptr);
		}
		else{
			if( (voidptr=find_v4addr(&(idata.iflist))) == NULL){
				puts("No IPv4 address available on local host");
				exit(EXIT_FAILURE);
			}

			idata.srcaddr= *((struct in_addr *)voidptr);
		}

		if( (idata.fd=socket(AF_INET, SOCK_DGRAM, 0)) == -1){
			puts("Could not create socket");
			exit(EXIT_FAILURE);
		}

		if( setsockopt(idata.fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1){
			puts("Error while setting SO_BROADCAST socket option");
			exit(EXIT_FAILURE);
		}

		memset(&sockaddr_in, 0, sizeof(sockaddr_in));
		sockaddr_in.sin_family= AF_INET;
		sockaddr_in.sin_port= 0;  /* Allow Sockets API to set an ephemeral port */
		sockaddr_in.sin_addr= idata.srcaddr;

		if(bind(idata.fd, (struct sockaddr *) &sockaddr_in, sizeof(sockaddr_in)) == -1){
			puts("Error bind()ing socket to local address");
			exit(EXIT_FAILURE);
		}

if(scan_type | SMART_PLUGS){
		memset(&sockaddr_to, 0, sizeof(sockaddr_to));
		sockaddr_to.sin_family= AF_INET;
		sockaddr_to.sin_port= htons(TP_LINK_SMART_PORT);

		memset(&sockaddr_from, 0, sizeof(sockaddr_from));
		sockaddr_from.sin_family= AF_INET;
		sockaddrfrom_len=sizeof(sockaddr_from);


		if ( inet_pton(AF_INET, IP_LIMITED_MULTICAST, &(sockaddr_to.sin_addr)) <= 0){
			puts("inet_pton(): Error setting multicast address");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		lastprobe.tv_sec= 0;	
		lastprobe.tv_usec=0;
		idata.pending_write_f=TRUE;	

		/* The end_f flag is set after the last probe has been sent and a timeout period has elapsed.
		   That is, we give responses enough time to come back
		 */
		while(!end_f){
			rset= sset;
			wset= sset;
			eset= sset;

			if(!donesending_f){
				/* This is the retransmission timer */
				timeout.tv_sec= 1;
				timeout.tv_usec= 0;
			}
			else{
				/* XXX: This should use the parameter from command line */
				timeout.tv_sec= idata.local_timeout;
				timeout.tv_usec=0;
			}

			/*
				Check for readability and exceptions. We only check for writeability if there is pending data
				to send.
			 */
			if((sel=select(idata.fd+1, &rset, (idata.pending_write_f?&wset:NULL), &eset, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					perror("iot-scan:");
					exit(EXIT_FAILURE);
				}
			}

			if(gettimeofday(&curtime, NULL) == -1){
				if(idata.verbose_f)
					perror("iot-scan");

				exit(EXIT_FAILURE);
			}

			/* Check whether we have finished probing all targets */
			if(donesending_f){
				/*
				   Just wait for SELECT_TIMEOUT seconds for any incoming responses.
				*/

				if(is_time_elapsed(&curtime, &lastprobe, idata.local_timeout * 1000000)){
					end_f=TRUE;
				}
			}


			if(sel && FD_ISSET(idata.fd, &rset)){
				/* XXX: Process response packet */

				if( (nreadbuff = recvfrom(idata.fd, readbuff, sizeof(readbuff), 0, (struct sockaddr *)&sockaddr_from, &sockaddrfrom_len)) == -1){
					perror("iot-scan: ");
					exit(EXIT_FAILURE);
				}

				if(inet_ntop(AF_INET, &(sockaddr_from.sin_addr), pv4addr, sizeof(pv4addr)) == NULL){
					perror("iot-scan: ");
					exit(EXIT_FAILURE);
				}

				tp_link_decrypt((unsigned char *)readbuff, nreadbuff);

				alias= NULL_STRING;
				dev_name= NULL_STRING;
				type= NULL_STRING;
				model= NULL_STRING;

				/* Get to system:get_sysinfo */
				if( (json1=json_get_objects(readbuff, (nreadbuff))) != NULL){
					if( json_get_value(json1, &json_value, "\"system\"")){
						if( (json2=json_get_objects(json_value.value, json_value.len)) != NULL){
							if( json_get_value(json2, &json_value, "\"get_sysinfo\"")){
								if( (json3=json_get_objects(json_value.value, json_value.len)) != NULL){
									json_remove_quotes(json3);
									if( json_get_value(json3, &json_value, "type")){
										type=json_value.value;
									}
									if( json_get_value(json3, &json_value, "model")){
										model=json_value.value;
									}
									if( json_get_value(json3, &json_value, "dev_name")){
										dev_name=json_value.value;
									}
									if( json_get_value(json3, &json_value, "alias")){
										alias=json_value.value;
									}	
/*
									printf("%s: \"%s\" (\"%s\": %s %s)\n", pv4addr, alias, dev_name, type, model);
*/
									printf("%s # %s: TP-Link %s: %s: \"%s\"\n", pv4addr, type, model, dev_name, alias);
			
								}
							}
						}
					}
				}

			}


			if(!donesending_f && !idata.pending_write_f && is_time_elapsed(&curtime, &lastprobe, 1 * 1000000)){
				idata.pending_write_f=TRUE;
				continue;
			}

			if(!donesending_f && idata.pending_write_f && FD_ISSET(idata.fd, &wset)){
				idata.pending_write_f=FALSE;

				/* XXX: SEND PROBE PACKET */
				nsendbuff= Strnlen(TP_LINK_SMART_DISCOVER, MAX_TP_COMMAND_LENGTH);
				memcpy(sendbuff, TP_LINK_SMART_DISCOVER, nsendbuff);
				tp_link_crypt((unsigned char *)sendbuff, nsendbuff);
/*
				if( sendto(idata.fd, encrypted, sizeof(encrypted), 0, (struct sockaddr *) &sockaddr_to, sizeof(sockaddr_to)) == -1){
					perror("iot-scan: ");
					exit(EXIT_FAILURE);
				}
*/

				if( sendto(idata.fd, sendbuff, nsendbuff, 0, (struct sockaddr *) &sockaddr_to, sizeof(sockaddr_to)) == -1){
					perror("iot-scan: ");
					exit(EXIT_FAILURE);
				}

				if(gettimeofday(&lastprobe, NULL) == -1){
					if(idata.verbose_f)
						perror("iot-scan");

					exit(EXIT_FAILURE);
				}

				retrans++;

				if(retrans >= idata.local_retrans)
					donesending_f= 1;

			}


			if(FD_ISSET(idata.fd, &eset)){
				if(idata.verbose_f)
					puts("iot-scaner: Found exception on descriptor");

				exit(EXIT_FAILURE);
			}
		}

}
if(scan_type | IP_CAMERAS){
/* puts("Voy a escanear camaras"); */
donesending_f=FALSE;
end_f=FALSE;
		memset(&sockaddr_to, 0, sizeof(sockaddr_to));
		sockaddr_to.sin_family= AF_INET;
		sockaddr_to.sin_port= htons(TP_LINK_IP_CAMERA_TDDP_PORT);

		memset(&sockaddr_from, 0, sizeof(sockaddr_from));
		sockaddr_from.sin_family= AF_INET;
		sockaddrfrom_len=sizeof(sockaddr_from);


		if ( inet_pton(AF_INET, IP_LIMITED_MULTICAST, &(sockaddr_to.sin_addr)) <= 0){
			puts("inet_pton(): Error setting multicast address");
			exit(EXIT_FAILURE);
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		lastprobe.tv_sec= 0;	
		lastprobe.tv_usec=0;
		idata.pending_write_f=TRUE;	

		/* The end_f flag is set after the last probe has been sent and a timeout period has elapsed.
		   That is, we give responses enough time to come back
		 */
		while(!end_f){
			rset= sset;
			wset= sset;
			eset= sset;

			if(!donesending_f){
				/* This is the retransmission timer */
				timeout.tv_sec= 1;
				timeout.tv_usec= 0;
			}
			else{
				/* XXX: This should use the parameter from command line */
				timeout.tv_sec= idata.local_timeout;
				timeout.tv_usec=0;
			}

			/*
				Check for readability and exceptions. We only check for writeability if there is pending data
				to send.
			 */
			if((sel=select(idata.fd+1, &rset, (idata.pending_write_f?&wset:NULL), &eset, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					perror("iot-scan:");
					exit(EXIT_FAILURE);
				}
			}

			if(gettimeofday(&curtime, NULL) == -1){
				if(idata.verbose_f)
					perror("iot-scan");

				exit(EXIT_FAILURE);
			}

			/* Check whether we have finished probing all targets */
			if(donesending_f){
				/*
				   Just wait for SELECT_TIMEOUT seconds for any incoming responses.
				*/

				if(is_time_elapsed(&curtime, &lastprobe, idata.local_timeout * 1000000)){
					end_f=TRUE;
				}
			}


			if(sel && FD_ISSET(idata.fd, &rset)){
				/* XXX: Process response packet */

				if( (nreadbuff = recvfrom(idata.fd, readbuff, sizeof(readbuff), 0, (struct sockaddr *)&sockaddr_from, &sockaddrfrom_len)) == -1){
					perror("iot-scan: ");
					exit(EXIT_FAILURE);
				}
/* puts("Got response"); */

				if(inet_ntop(AF_INET, &(sockaddr_from.sin_addr), pv4addr, sizeof(pv4addr)) == NULL){
					perror("iot-scan: ");
					exit(EXIT_FAILURE);
				}

				/* Compare response with known one */
				if(nreadbuff == sizeof(TP_LINK_IP_CAMERA_RESPONSE)){
					if(memcmp(readbuff, TP_LINK_IP_CAMERA_RESPONSE, nreadbuff) == 0){
						printf("%s # camera: TP-Link IP camera\n", pv4addr);
					}
					else{
/* puts("Incorrect response"); */
					}
				}
				else{
/* puts("Incorrect size"); */
				}
			}


			if(!donesending_f && !idata.pending_write_f && is_time_elapsed(&curtime, &lastprobe, 1 * 1000000)){
				idata.pending_write_f=TRUE;
				continue;
			}

			if(!donesending_f && idata.pending_write_f && FD_ISSET(idata.fd, &wset)){
				idata.pending_write_f=FALSE;

				/* XXX: SEND PROBE PACKET */

				/* XXX: Will not happen, still check in case code is changed */
				if(sizeof(TP_LINK_IP_CAMERA_DISCOVER) > sizeof(sendbuff)){
					puts("Internal buffer too short");
					exit(EXIT_FAILURE);
				}

				nsendbuff= sizeof(TP_LINK_IP_CAMERA_DISCOVER);
				memcpy(sendbuff, TP_LINK_IP_CAMERA_DISCOVER, nsendbuff);

/*
				if( sendto(idata.fd, encrypted, sizeof(encrypted), 0, (struct sockaddr *) &sockaddr_to, sizeof(sockaddr_to)) == -1){
					perror("iot-scan: ");
					exit(EXIT_FAILURE);
				}
*/

				if( sendto(idata.fd, sendbuff, nsendbuff, 0, (struct sockaddr *) &sockaddr_to, sizeof(sockaddr_to)) == -1){
					perror("iot-scan: ");
					exit(EXIT_FAILURE);
				}

				if(gettimeofday(&lastprobe, NULL) == -1){
					if(idata.verbose_f)
						perror("iot-scan");

					exit(EXIT_FAILURE);
				}

				retrans++;

				if(retrans >= idata.local_retrans)
					donesending_f= 1;

			}


			if(FD_ISSET(idata.fd, &eset)){
				if(idata.verbose_f)
					puts("iot-scan: Found exception on descriptor");

				exit(EXIT_FAILURE);
			}
		}
}

	}

	exit(EXIT_SUCCESS);
}




/*
 * Function: match_strings()
 *
 * Checks whether one string "matches" within another string
 */

int match_strings(char *buscar, char *buffer){
	unsigned int buscars, buffers;
	unsigned int i=0, j=0;

	buscars= Strnlen(buscar, MAX_IEEE_OUIS_LINE_SIZE);
	buffers= Strnlen(buffer, MAX_IEEE_OUIS_LINE_SIZE);

	if(buscars > buffers)
		return(0);

	while(i <= (buffers - buscars)){
		j=0;

		while(j < buscars){
			if(toupper((int) ((unsigned char)buscar[j])) != toupper((int) ((unsigned char)buffer[i+j])))
				break;

			j++;
		}

		if(j >= buscars)
			return(1);

		i++;
	}

	return(0);
}





/*
 * Function: usage()
 *
 * Prints the syntax of the iot-scan tool
 */

void usage(void){
	puts("usage: iot-scan (-L | -d) [-i INTERFACE] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the iot-scan tool
 */

void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "iot-scan: An IoT scanning tool\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i             Network interface\n"
	     "  --dst-address, -d           IPv6 Destination Range or Prefix\n"
	     "  --retrans, -x               Number of retransmissions of each probe\n"
	     "  --timeout, -O               Timeout in seconds (default: 1 second)\n"
	     "  --local-scan, -L            Scan the local subnet\n"
	     "  --help, -h                  Print help for the iot-scan tool\n"
	     "  --verbose, -v               Be verbose\n"
	     "\n"
	     " Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>\n"
	     " Please send any bug reports to <fgont@si6networks.com>\n"
	);
}



/*
 * Function: print_host_entries()
 *
 * Prints the IPv6 addresses (and optionally the Ethernet addresses) in a list
 */

int print_host_entries(struct host_list *hlist, unsigned char flag){
	unsigned int i;

	for(i=0; i < (hlist->nhosts); i++){
		if(inet_ntop(AF_INET6, &((hlist->host[i])->ip6), pv6addr, sizeof(pv6addr)) == NULL){
			if(verbose_f>1)
				puts("inet_ntop(): Error converting IPv6 address to presentation format");

			return(-1);
		}

		if(flag == PRINT_ETHER_ADDR){
			if(ether_ntop( &((hlist->host[i])->ether), plinkaddr, sizeof(plinkaddr)) == 0){
				if(verbose_f>1)
					puts("ether_ntop(): Error converting address");

				return(-1);
			}

			printf("%s @ %s\n", pv6addr, plinkaddr);
		}
		else
			printf("%s\n", pv6addr);
	}

	return 0;
}



/*
 * Function: print_unique_host_entries()
 *
 * Prints only one IPv6 address (and optionally the Ethernet addresses) per Ethernet 
 * address in a list.
 */

int print_unique_host_entries(struct host_list *hlist, unsigned char flag){
	unsigned int i, j, k;

	for(i=0; i < (hlist->nhosts); i++){

		if(i){
			for(j=0; j < i; j++){
				for(k=0; k < ETH_ALEN; k++){
					if((hlist->host[i])->ether.a[k] != (hlist->host[j])->ether.a[k])
						break;
				}

				if(k == ETH_ALEN)
					break;
			}			

			if(j < i)
				continue;
		}
			
		if(inet_ntop(AF_INET6, &((hlist->host[i])->ip6), pv6addr, sizeof(pv6addr)) == NULL){
			if(verbose_f>1)
				puts("inet_ntop(): Error converting IPv6 address to presentation format");

			return(-1);
		}

		if(flag == PRINT_ETHER_ADDR){
			if(ether_ntop( &((hlist->host[i])->ether), plinkaddr, sizeof(plinkaddr)) == 0){
				if(verbose_f>1)
					puts("ether_ntop(): Error converting address");

				return(-1);
			}

			printf("%s @ %s\n", pv6addr, plinkaddr);
		}
		else
			printf("%s\n", pv6addr);
	}

	return 0;
}



/*
 * Function: free_host_entries()
 *
 * Releases memory allocated for holding IPv6 addresses and Ethernet addresses
 */

void free_host_entries(struct host_list *hlist){
	unsigned int i;

	for(i=0; i< hlist->nhosts; i++)
		free(hlist->host[i]);

	hlist->nhosts=0;	/* Set the number of entries to 0, to reflect the released memory */
	return;
}




