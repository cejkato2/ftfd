#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <err.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#ifndef ALARM_TIME
#define ALARM_TIME  300
#endif

pcap_t *pc = NULL;
uint64_t number = 0;

uint64_t synflag = 1, finflag = 1, synackflag = 1;
uint64_t pktdelta = 0;

char analyse_results = 0, process_traffic = 1;

void signal_handler(int s)
{
    switch (s) {
    case SIGINT:
        if (pc != NULL) {
            pcap_breakloop(pc);
        }
        process_traffic = 0;
        break;
    case SIGALRM:
        alarm(ALARM_TIME);
        analyse_results = 1;
        break;
    }
    signal(SIGINT, signal_handler);
    signal(SIGALRM, signal_handler);
}

char errbuf[PCAP_ERRBUF_SIZE];

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct ethhdr *eth = (struct ethhdr *) bytes;
    struct iphdr *ip = (struct iphdr *) (eth + 1);
    struct ip6_hdr *ip6 = (struct ip6_hdr *) (eth + 1);
    struct tcphdr *tcp = NULL;
    uint16_t *ethtype;
    u_short etht;
    int i = 0;
    number++;
    //printf("%i:%i accept packet: ", h->ts.tv_sec, h->ts.tv_usec);
    //for (i=0; i<16; ++i) {
    //    printf("%02X ", bytes[i]);
    //}
    //printf("\n");
    ethtype = &eth->h_proto;
    if (*ethtype == 0x0) {
        ethtype++;
    }
    if (*ethtype == 0x0008 /* ETH_P_IP */) {
        if (ip->protocol == IPPROTO_TCP) {
            tcp = (struct tcphdr *) (ip + 1);
        }
    } else if (*ethtype == 0xDD86 /* ETH_P_IPV6 */) {
        if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP) {
            tcp = (struct tcphdr *) (ip6+1);
        }
    }

    /* check if we found TCP */
    if (tcp != NULL) {
#ifdef __FAVOR_BSD
        //printf("%X", tcp->th_flags);
        if (tcp->th_flags & TH_SYN) {
            //printf("SYN ");
            //i = 1;
            if (tcp->th_flags & TH_ACK) {
                //printf("ACK ");
                synackflag++;
                //i = 1;
            } else {
                synflag++;
            }
        }
        if (tcp->th_flags & TH_FIN) {
            //printf("FIN ");
            finflag++;
            //i = 1;
        }
        //if (i == 1) {
        //    printf("\n");
        //}
#else
        if (tcp->syn) {
            //printf("SYN ");
            //i = 1;
            if (tcp->ack) {
                //printf("ACK ");
                synackflag++;
                //i = 1;
            } else {
                synflag++;
            }
        }
        if (tcp->fin) {
            //printf("FIN ");
            finflag++;
            //i = 1;
        }
        //if (i == 1) {
        //    printf("\n");
        //}
#endif
    }
    
}

void partial_results()
{
    printf("\n%d Accepted: %i packets\n", time(NULL), number);
    printf("S/F %llu/%llu = %f\n", synflag, finflag, (double) synflag / (double) finflag);
    printf("S/SA %llu/%llu = %f\n", synflag, synackflag, (double) synflag / (double) synackflag);
    printf("SA/F %llu/%llu = %f\n", synackflag, finflag, (double) synackflag / (double) finflag);
    synflag = finflag = synackflag = 1;
    analyse_results = 0;
}

int main(int argc, char **argv)
{
	int c;
	int digit_optind = 0;
	const char *source = NULL;
    struct bpf_program compprog;

	while (1) {
		int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] = {
			{"source",	required_argument, 0, 's'},
			{"help", no_argument, 0, 'h'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "s:h", long_options, &option_index);
		if (c == -1)
						 break;
		switch (c) {
		case 's':
			source = optarg;
			break;
		case 'h':
			printf("%s\t-h|--help\n\t-s|--source=any|eth0|...\n", argv[0]);
			exit(0);
			break;
		}
	}

	if (source == NULL) {
        warnx("You have not specified -s with interface, using \"any\", which probably does not work!!!");
		source = "any";
	}

	pc = pcap_create(source, errbuf);
	if (pc == NULL) {
		errx(1, "Initialization of libpcap failed.");
	}
		
    if (pcap_activate(pc) != 0) {
        errx(2, "%s", pcap_geterr(pc));
    }

    signal(SIGINT, signal_handler);
    signal(SIGALRM, signal_handler);

    if (pcap_compile(pc, &compprog, "tcp", 0,  PCAP_NETMASK_UNKNOWN) == -1) {
        errx(3, "Error: %s\n", pcap_geterr(pc));
    }

    if (pcap_setfilter(pc, &compprog) == -1) {
        errx(4, "Error: %s\n", pcap_geterr(pc));
    }

    alarm(ALARM_TIME);
    while (process_traffic) {
        pcap_dispatch(pc, 0, packet_handler, NULL);
        if (analyse_results) {
            partial_results();
        }
    }
    
    partial_results();
	return 0;
}

