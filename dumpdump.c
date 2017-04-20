/**
 * This is a simple example of how to using pcap_dump
 * This example aims to rewrite a input pcap file and also can dump traffic from a network interface to a pcap file
 *
 * Required:
 *
 * apt-get install -y libpcap-dev
 *
 * Compile:
 * gcc -O3 -Wall -o dumpdump pcap_dump.c dumpdump.c -lpcap
 *
 * Test: 
 * Rewrite from a pcap file
 * ./dumpdump -i old_pcap.pcap -o newpcap.pcap
 *
 * Capture and save from an interface:
 * ./dumpdump -i eth0 -o online_capture.pcap
 *
 * That's it !
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "string.h"
#include "signal.h"
#include "pcap.h"
#include "pcap_dump.h"

// Define some constants
#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2

#ifndef VERSION
    #define VERSION "1.0.0.0"
#endif

#ifdef GIT_VERSION
    //GIT_VERSION is given by Makefile
    #define DUMPDUMP_VERSION VERSION " (" GIT_VERSION ")"
#else
    #define DUMPDUMP_VERSION VERSION
#endif

pcap_t *pcap; // Pcap handler
struct pcap_stat pcs; /* packet capture filter stats */
int pcap_bs = 0;

/**
 * Dump a packet into pcap file
 * @param data   packet data
 * @param header packet header
 * @param output output pcap file
 */
void dump_to_pcap(const u_char * data, const struct pcap_pkthdr *header, char * output){
    
    int fd = pd_open(output);

    if(fd){
        pd_write(fd,(char*)data,header->caplen,header->ts);
    }else{
        fprintf(stderr, "[error] Couldn't open output file %s\n", output);
        exit(0);
    }
}

/**
 * Initialize a pcap handler
 * @param  iname       interface name
 * @param  buffer_size buffer size (MB)
 * @param  snaplen     packet snaplen
 * @return             NULL if cannot create pcap handler
 *                     a pointer points to a new pcap handle
 */
pcap_t * init_pcap(char *iname, uint16_t buffer_size, uint16_t snaplen) {
    pcap_t * my_pcap;
    char errbuf[1024];
    my_pcap = pcap_create(iname, errbuf);
    if (my_pcap == NULL) {
        fprintf(stderr, "[error] Couldn't open device %s\n", errbuf);
        exit(0);
    }
    pcap_set_snaplen(my_pcap, snaplen);
    pcap_set_promisc(my_pcap, 1);
    pcap_set_timeout(my_pcap, 0);
    pcap_set_buffer_size(my_pcap, buffer_size * 1000 * 1000);
    pcap_activate(my_pcap);

    if (pcap_datalink(my_pcap) != DLT_EN10MB) {
        fprintf(stderr, "[error] %s is not an Ethernet (Make sure you run with administrator permission! )\n", iname);
        exit(0);
    }
    return my_pcap;
}

/**
 * Show help message
 * @param prg_name program name
 */
void usage(const char * prg_name) {
    printf("%s [<option>]\n", prg_name);
    printf("Option:\n");
    printf("\t-t <trace file>  : Gives the trace file to analyse.\n");
    printf("\t-i <interface>   : Gives the interface name for live traffic analysis.\n");
    printf("\t-o <output file> : Gives the output pcap file name.\n");
    printf("\t-b <buffer size> : Gives the buffer size of pcapHandler in online mode\n");
    printf("\t-h               : Prints this help.\n");
    exit(1);
}

/**
 * parser input parameter
 * @param argc     number of parameter
 * @param argv     parameter string
 * @param input input source -> file name or interaface name
 * @param type     TRACE_FILE or LIVE_INTERFACE
 */
void parseOptions(int argc, char ** argv, char * input, char * output, int * type) {
    int opt, optcount = 0;
    while ((opt = getopt(argc, argv, "t:i:b:o:h")) != EOF) {
        switch (opt) {
        case 't':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            strncpy((char *) input, optarg, MAX_FILENAME_SIZE);
            *type = TRACE_FILE;
            break;
        case 'i':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            strncpy((char *) input, optarg, MAX_FILENAME_SIZE);
            *type = LIVE_INTERFACE;
            break;
        case 'o':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            strncpy((char *) output, optarg, MAX_FILENAME_SIZE);
            break;
        case 'b':
            optcount++;
            if (optcount > 5) {
                usage(argv[0]);
            }
            pcap_bs = atoi(optarg);
            break;
        case 'h':
        default: usage(argv[0]);
        }
    }

    if (input == NULL || strcmp(input, "") == 0 || output == NULL || strcmp(output, "") == 0 ) {

        if (*type == TRACE_FILE) {
            fprintf(stderr, "[error] Missing trace file name\n");
        }

        if (*type == LIVE_INTERFACE) {
            fprintf(stderr, "[error] Missing network interface name\n");
        }

        if (output == NULL) {
            fprintf(stderr, "[error] Missing output file name\n");
        }
        usage(argv[0]);
    }
}

/**
 * Analyse from an interface
 * @param user     user argument
 * @param p_pkthdr pcap header
 * @param data     packet data
 */
void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
    char * output = (char*)user;
    dump_to_pcap(data, p_pkthdr, output);
}


/**
 * Clean resource when the program finished
 */
void clean() {
    printf("\n[info] Cleaning....\n");
    // Show pcap statistic if capture from an interface
    if (pcap_stats(pcap, &pcs) < 0) {
        printf("[info] pcap_stats does not exist\n");
        (void) printf("[info] pcap_stats: %s\n", pcap_geterr(pcap));
    } else {
        (void) printf("[info] \n%12d packets received by filter\n", pcs.ps_recv);
        (void) printf("[info] %12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
        (void) printf("[info] %12d packets dropped by driver (%3.2f%%)\n", pcs.ps_ifdrop, pcs.ps_ifdrop * 100.0 / pcs.ps_recv);
        fflush(stderr);
    }
    if (pcap != NULL) pcap_close(pcap);
    printf("[info] Finished cleaning....\n");
}

/**
 * Handler signals during excutation time
 * @param type signal type
 */
void signal_handler(int type) {
    printf("\n[info] reception of signal %d\n", type);
    fflush( stderr );
    clean();
}
/**
 * Main program start from here
 * @param  argc [description]
 * @param  argv [description]
 * @return      [description]
 */
int main(int argc, char ** argv) {
    printf("- - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("|\t\t DUMPDUMP\n");
    printf("|\t Version: %s\n", DUMPDUMP_VERSION);
    printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
    printf("|\t https://github.com/luongnv89/pcap_dump\n");
    printf("- - - - - - - - - - - - - - - - - - - - - - - - -\n");

    sigset_t signal_set;

    char error_buffer[1024];

    char input[MAX_FILENAME_SIZE + 1]; // interface name or path to pcap file
    char output[MAX_FILENAME_SIZE + 1]; // Output file name

    int type; // Online or offline mode

    // Parse option
    parseOptions(argc, argv, input, output, &type);

    // Handle signal
    sigfillset(&signal_set);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);

    if (type == TRACE_FILE) {
        // OFFLINE mode
        struct pcap_pkthdr p_pkthdr;
        pcap = pcap_open_offline(input, error_buffer);
        if (!pcap) {
            fprintf(stderr, "[error] pcap_open failed for the following reason: %s\n", error_buffer);
            return EXIT_FAILURE;
        }
        const u_char *data = NULL;
        while ((data = pcap_next(pcap, &p_pkthdr))) {
            dump_to_pcap(data, &p_pkthdr,output);
        }
    } else {
        if (pcap_bs == 0) {
            printf("[info] Use default buffer size: 50 (MB)\n");
        } else {
            printf("[info] Use buffer size: %d (MB)\n", pcap_bs);
        }
        // ONLINE MODE
        pcap = init_pcap(input, pcap_bs, 65535);

        if (!pcap) {
            fprintf(stderr, "[error] creating pcap failed for the following reason: %s\n", error_buffer);
            return EXIT_FAILURE;
        }
        (void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)output);
    }
    clean();

    return EXIT_SUCCESS;

}