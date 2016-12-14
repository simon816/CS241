#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include "dispatch.h"
#include <pthread.h>

// An Atomic Integer. Access is synchronized over the mutex lock.
struct atomic_int {
    int val;
    pthread_mutex_t lock;
};

int atomicint_get(struct atomic_int *aint) {
    if (pthread_mutex_lock(&aint->lock) != 0) {
        return -1;
    }
    int val = aint->val;
    pthread_mutex_unlock(&aint->lock);
    return val;
}

void atomicint_inc(struct atomic_int *aint) {
    if (pthread_mutex_lock(&aint->lock) != 0) {
        return;
    }
    aint->val++;
    pthread_mutex_unlock(&aint->lock);
}

static struct atomic_int susp_xmas;
static struct atomic_int susp_arp;
static struct atomic_int susp_url;

void print_report() {
    printf("Intrusion Detection Report:\n");
    printf("%d Xmas scans (host fingerprinting)\n", atomicint_get(&susp_xmas));
    printf("%d ARP responses (cache poisoning)\n", atomicint_get(&susp_arp));
    printf("%d URL Blacklist violations\n", atomicint_get(&susp_url));
}

void setup_signal() {
    void on_interrupt(int sig) {
        dispatch_teardown();
        print_report();
        exit(0);
    }
    signal(SIGINT, on_interrupt);
}

// Called from sniff.c on load
void analysis_init() {
    setup_signal();

    pthread_mutex_t lock1 = PTHREAD_MUTEX_INITIALIZER;
    susp_xmas.lock = lock1;
    susp_xmas.val = 0;

    pthread_mutex_t lock2 = PTHREAD_MUTEX_INITIALIZER;
    susp_arp.lock = lock2;
    susp_arp.val = 0;

    pthread_mutex_t lock3 = PTHREAD_MUTEX_INITIALIZER;
    susp_url.lock = lock3;
    susp_url.val = 0;
}

void analyse_ip(const unsigned char *data, int len);
void analyse_arp(const unsigned char *data, int len);

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    int hlen = sizeof(struct ether_header);
    packet += hlen;
    switch (ntohs(eth_header->ether_type)) {
        case ETHERTYPE_IP:
            analyse_ip(packet, header->len - hlen);
            break;
        case ETHERTYPE_ARP:
            analyse_arp(packet, header->len - hlen);
            break;
    }
}

void check_xmas(struct tcphdr *header) {
    if (header->urg && header->psh && header->fin) {
        atomicint_inc(&susp_xmas);
    }
}

int is_blocked(const char *host, int hostlen) {
    if (strncmp(host, "www.bbc.co.uk", hostlen) == 0) {
        return 1;
    }
    return 0;
}

void check_http(struct tcphdr *header, const char *data, int len) {
    if (ntohs(header->dest) != 80) {
        // Not HTTP traffic
        return;
    }
    if (len <= 0) {
        return;
    }
    char *host = NULL;
    int hostlen = -1;
    int first_header = 1;
    while (1) {
        // find position of the end of the line
        char *lineend = strstr(data, "\r\n");
        if (lineend == NULL) {
            break;
        }
        // If the end of the line is at the start of 'data'
        // then this must be the end of the headers
        if (data == lineend) {
            break;
        }
        if (first_header) {
            // First header is the URI request, skip this one
            first_header = 0;
        } else {
            // Headers are formatted as "Key: Value"
            // split by the colon
            char *colon = strchr(data, ':');
            if (colon != NULL) {
                // Find the key 'Host'
                char *hostidx = strstr(data, "Host");
                // if host is found and comes before the colon, proceed
                if (hostidx != NULL && hostidx < colon) {
                    // Find the position of the Value in the data
                    char *valstart = colon + 1;
                    while (valstart[0] == ' ') { // consume whitespace
                        valstart++;
                    }
                    host = valstart;
                    hostlen = lineend - valstart;
                }
            }
        }
        // Skip past \r\n
        data = lineend + 2;
    }
    if (host != NULL) {
        if (is_blocked(host, hostlen)) {
            atomicint_inc(&susp_url);
        }
    }
}

void analyse_tcp(const unsigned char *data, int len) {
    struct tcphdr *header = (struct tcphdr *) data;
    data += sizeof(struct tcphdr);
    int i;
    // skip past options. Same as analyse_ip
    for (i = 5; i < header->doff; i++) {
        data += 4;
    }

    check_xmas(header);
    check_http(header, (const char *) data, len - (i * 4));
}

void analyse_ip(const unsigned char *data, int len) {
    struct iphdr *header = (struct iphdr *) data;
    data += sizeof(struct iphdr);
    int i;
    // skip past options
    // IHL is length of the whole header in 4 byte blocks,
    // iphdr is a constant of 5 blocks
    // shift data pointer to end 
    for (i = 5; i < header->ihl; i++) {
        data += 4;
    }
    switch (header->protocol) {
        case SOL_TCP:
            analyse_tcp(data, len - (i * 4));
            break;
    }
}

void check_arp_poison(struct ether_arp *header) {
    if (ntohs(header->ea_hdr.ar_op) == 2) { // 2 = response
        atomicint_inc(&susp_arp);
    }
}

void analyse_arp(const unsigned char *data, int len) {
    struct ether_arp *header = (struct ether_arp *) data;

    check_arp_poison(header);
}

