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
uint32_t timeout = ALARM_TIME;
uint64_t synflag = 1, finflag = 1, synackflag = 1;
uint64_t pktdelta = 0;
FILE *output;

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
        alarm(timeout);
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
    fprintf(output, "%llu\t%llu\t%llu\t%llu\t%f\t%f\t%f\t%llu\t%llu\n",
            time(NULL),
            synflag, synackflag, finflag,
            (double) synflag / (double) finflag,
            (double) synflag / (double) synackflag,
            (double) synackflag / (double) finflag,
            number, number - pktdelta);
    pktdelta = number;
    synflag = finflag = synackflag = 1;
    analyse_results = 0;
}

int main(int argc, char **argv)
{
    int c;
    int digit_optind = 0;
    const char *source = NULL;
    const char *outputfile = NULL;
    struct bpf_program compprog;

    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
            {"source",	required_argument, 0, 's'},
            {"timeout", required_argument, 0, 't'},
            {"output", required_argument, 0, 'o'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "s:ht:o:", long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
        case 's':
            source = optarg;
            break;
        case 't':
            if (sscanf(optarg, "%u", &timeout) != 1) {
                timeout = ALARM_TIME;
            }
            break;
        case 'o':
            outputfile = optarg;
        case 'h':
            printf("%s\t-h|--help\n", argv[0]);
            printf("\t-o|--output=<output filepath>\n");
            printf("\t-s|--source=any|eth0|...\n");
            printf("\t-t|--timeout=<seconds>\n");
            exit(0);
            break;
        }
    }

    if (source == NULL) {
        warnx("You have not specified -s with interface, using \"any\", which probably does not work!!!");
        source = "any";
    }

    if (outputfile != NULL) {
        output = fopen(outputfile, "w");
        if (output == NULL) {
            fprintf(stderr, "Cannot open file (%s), using stdout.\n", outputfile);
            output = stdout;
        }
    } else {
        output = stdout;
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

    alarm(timeout);
    fprintf(output, "Time\tS\tSA\tF\tS/F\tS/SA\tSA/F\tpkts\tdeltapkts\n");
    while (process_traffic) {
        pcap_dispatch(pc, 0, packet_handler, NULL);
        if (analyse_results) {
            partial_results();
        }
    }

    partial_results();
    return 0;
}

