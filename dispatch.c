#include "dispatch.h"

#include <pcap.h>

#include "analysis.h"

#include "threadpool.h"
#include <stdlib.h>
#include <string.h>

static struct threadpool *pool;

// Called from sniff.c on load
void dispatch_init() {
    pool = threadpool_create(8);
}

// Called from analysis.c when finishing
void dispatch_teardown() {
    threadpool_shutdown(pool);
    pool = NULL;
}

// Simple struct to hold function arguments
struct analysis_data {
    struct pcap_pkthdr *header;
    unsigned char *data;
    int verbose;
};

// The task the thread should run
void *dispatch_run(void *arg) {
    struct analysis_data *argdata = (struct analysis_data *) arg;
    analyse(argdata->header, argdata->data, argdata->verbose);
    free(argdata->header);
    free(argdata->data);
    free(argdata);
    return NULL;
}

// create an internal copy of the data to make sure it doesn't
// get free'd from somewhere else
struct analysis_data *copy_data(struct pcap_pkthdr *header, 
                                const unsigned char *packet,
                                int verbose) {
    struct analysis_data *data = malloc(sizeof(struct analysis_data));

    struct pcap_pkthdr *hcopy = malloc(sizeof(struct pcap_pkthdr));
    memcpy(hcopy, header, sizeof(struct pcap_pkthdr));

    unsigned char *pcopy = malloc(header->len);
    memcpy(pcopy, packet, header->len);

    data->header = hcopy;
    data->data = pcopy;
    data->verbose = verbose;

    return data;
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
    struct analysis_data *data = copy_data(header, packet, verbose);
    threadpool_submit(pool, &dispatch_run, data);
}

