#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <limits.h>
#include <GraphBLAS.h>
// #include <LAGraph.h>
#include <sys/syscall.h>
#include "cryptopANT.h"

// DPDK includes
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_regexdev.h>

#define SUBWINSIZE (1 << 17) // 131072
#define BSWAP(a) (pstate->swapped ? ntohl(a) : (a))
#define MAX_PATTERN_NUM 1
#define MAX_MATCH_NUM 1

struct px3_state {
    struct tm *f_tm;
    unsigned int save_trailing_packets;
    unsigned int anonymize;
    unsigned int swapped;
    unsigned int rec;
    int link_type;
    uint32_t files_per_window;
    uint32_t subwinsize;
    uint64_t total_packets, total_invalid;
    char *out_prefix;
    char f_name[1024];
    uint32_t findex;
    GrB_Index *R, *C;
    uint32_t *V;
    uint32_t *ip4cache;
};

struct px3_state *pstate; // global state

/// @brief 512-byte POSIX tar file header.
struct posix_tar_header
{                       /* byte offset */
    char name[100];     /*   0 - filename */
    char mode[8];       /* 100 - octal mode */
    char uid[8];        /* 108 - user ID */
    char gid[8];        /* 116 - group ID */
    char size[12];      /* 124 - file size */
    char mtime[12];     /* 136 - modification time */
    char chksum[8];     /* 148 - checksum */
    char typeflag;      /* 156 - type */
    char linkname[100]; /* 157 - link name */
    char magic[6];      /* 257 - tar magic, USTAR */
    char version[2];    /* 263 - tar version */
    char uname[32];     /* 265 - user name */
    char gname[32];     /* 297 - group name */
    char devmajor[8];   /* 329 - device major */
    char devminor[8];   /* 337 - device minor */
    char prefix[155];   /* 345 - prefix */
                        /* 500 */
    char padding1[12];  /* 512 - unused padding to fill 512 bytes */
};

#define TMAGIC   "ustar" /* ustar and a null */
#define TMAGLEN  6
#define TVERSION "00" /* 00 and no null */
#define TVERSLEN 2

struct px3_state *pstate; // global state

// If at first you don't succeed, just abort.
#define LAGRAPH_TRY_EXIT(method)                                                                                       \
    {                                                                                                                  \
        GrB_Info info = (method);                                                                                      \
        if (!(info == GrB_SUCCESS))                                                                                    \
        {                                                                                                              \
            fprintf(stderr, "LAGraph error: [%d]\nFile: %s Line: %d\n", info, __FILE__, __LINE__);                     \
            exit(5);                                                                                                   \
        }                                                                                                              \
    }

// Convenience macros to time code sections.
#ifndef NDEBUG
#define TIC(clocktype, msg)                                                                                            \
    {                                                                                                                  \
        double t_ts;                                                                                                   \
        pid_t _mytid = syscall(SYS_gettid);                                                                            \
        clock_gettime(clocktype, &ts_start);                                                                           \
        t_ts = ((ts_start.tv_sec * 1e9) + (ts_start.tv_nsec)) * 1e-9;                                                  \
        fprintf(stderr, "[%d] [%.2f] [%s] Section begin.\n", _mytid, t_ts, msg);                                       \
    }

#define TOC(clocktype, msg)                                                                                            \
    {                                                                                                                  \
        struct timespec ts_end, tsdiff;                                                                                \
        double t_ts;                                                                                                   \
        pid_t _mytid = syscall(SYS_gettid);                                                                            \
        clock_gettime(clocktype, &ts_end);                                                                             \
        timespec_diff(&ts_end, &ts_start, &tsdiff);                                                                    \
        t_ts      = ((ts_start.tv_sec * 1e9) + (ts_start.tv_nsec)) * 1e-9;                                             \
        t_elapsed = ((tsdiff.tv_sec * 1e9) + (tsdiff.tv_nsec)) * 1e-9;                                                 \
        fprintf(stderr, "[%d] [%.2f] [%s] elapsed %.2fs\n", _mytid, t_ts, msg, t_elapsed);                             \
    }
#else
#define TIC(clocktype, msg)
#define TOC(clocktype, msg)
#endif

/// @brief Calculate the delta time (as a struct timespec) between two struct timespec.
/// @param a Time #1
/// @param b Time #2
/// @param result struct timespec containing the elapsed time between them.
static inline void timespec_diff(struct timespec *a, struct timespec *b, struct timespec *result)
{
    result->tv_sec  = a->tv_sec - b->tv_sec;
    result->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (result->tv_nsec < 0)
    {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}

void usage(const char *name)
{
    fprintf(stderr,
            "usage: %s [-a anonymize.key] [-W FILES_PER_WINDOW] [-w SUBWINSIZE] [-O output_file_name] -i INPUT_FILE -o OUTPUT_DIRECTORY\n",
            name);
    fprintf(stderr, "    -a Anonymize using CryptopANT (https://ant.isi.edu/software/cryptopANT/index.html)\n");
    fprintf(stderr,
            "       If CryptoPAN anonymization keyfile does not exist, a random key will be generated and saved.\n");
    fprintf(stderr, "    -c Path to precomputed IPv4 anonymization table (generated with makecache).\n");
    fprintf(stderr, "    -W Number of GraphBLAS matrices to save in the output tar file.\n");
    fprintf(stderr, "    -w Window size (number of entries) in the saved GraphBLAS matrices.\n");
    fprintf(stderr, "    -O Single file mode - one tar file containing one GraphBLAS matrix..\n");
    fprintf(stderr, "    -i Input file (pcap format).\n");
    fprintf(stderr, "    -o Output directory.\n");
}

uint count = 0;

void set_output_filename(void)
{
    char timestr[128]   = { 0 };
    uint32_t windowsize = pstate->subwinsize * pstate->files_per_window;

    strftime(timestr, sizeof(timestr), "%Y%m%d-%H%M%S", pstate->f_tm);
    snprintf(pstate->f_name, sizeof(pstate->f_name), "%s/%s.%u.%u.tar", pstate->out_prefix, timestr, windowsize, count);
    count++;

    fprintf(stderr, "Setting output filename to %s.\n", pstate->f_name);

    if (access(pstate->f_name, F_OK) == 0)
    {
        fprintf(stderr, "ERR: Output file already exists in set_output_filename: %s\n", pstate->f_name);
        fprintf(stderr, "Not appending new data.\n");
        exit(EXIT_FAILURE);
    }

    pstate->findex = 0;
}

void add_blob_to_tar(void *blob_data, unsigned int blob_size)
{
    int tarfd;
    struct posix_tar_header th  = { 0 }; // let's make a tar file, or close enough
    const unsigned char *th_ptr = (const unsigned char *)&th;
    size_t tmp_chksum           = 0;
    size_t aligned;

    if ((tarfd = open(pstate->f_name, O_CREAT | O_WRONLY | O_APPEND, 0660)) == -1)
    {
        perror("open tar");
        exit(1);
    }

    sprintf(th.name, "%d.grb", pstate->findex);
    sprintf(th.uid, "%06o ", 0);
    sprintf(th.gid, "%06o ", 0);
    sprintf(th.size, "%011o", blob_size);
    sprintf(th.mode, "%06o", 0644);
    sprintf(th.magic, "%s", TMAGIC);
    sprintf(th.mtime, "%011o", (unsigned int)time(NULL));
    th.typeflag = '0';
    memset(th.chksum, ' ', 8); // or checksum computed below will be wrong!

    for (int b = 0; b < sizeof(struct posix_tar_header); b++)
        tmp_chksum += th_ptr[b];

    sprintf(th.chksum, "%06o ", (unsigned int)tmp_chksum);

    if (write(tarfd, &th, sizeof(th)) != sizeof(th))
    {
        perror("write tar error");
        exit(4);
    }

    if (write(tarfd, blob_data, blob_size) != blob_size)
    {
        perror("write tar error");
        exit(4);
    }

    aligned = (sizeof(th) + blob_size) % 512; // pad output file to 512 byte alignment
    if (aligned != 0)
    {
        const unsigned char padblock[512] = { 0 };

        if (write(tarfd, padblock, 512 - aligned) != 512 - aligned)
        {
            perror("write tar error");
            exit(4);
        }
    }

    close(tarfd);

    pstate->findex++;

    if (pstate->findex >= pstate->files_per_window && !(pstate->findex > 0 && pstate->files_per_window == 1))
    {
        set_output_filename();
    }
}


// DPDK regex init
struct rte_regexdev_info regexdev_info;
struct rte_regexdev_config regexdev_cfg;
struct rte_regexdev_qp_conf qconf;
uint16_t dev_id;
uint16_t qp_id;

// IP regex pattern
const char *ip_pattern = "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b";

int init_dpdk_regex(char *arg) {
    int ret;

    char *argv[1];
    argv[0] = arg;
    // EAL init
    fprintf(stderr, "Test\n");
    ret = rte_eal_init(1, argv);
    fprintf(stderr, "Test2\n");
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize EAL\n");
        return -1;
    }

    dev_id = 0; // using the first regex device for now
    ret = rte_regexdev_info_get(dev_id, &regexdev_info);
    if (ret != 0) {
        fprintf(stderr, "Failed to get RegEx device info\n");
        return -1;
    }

    memset(&regexdev_cfg, 0, sizeof(regexdev_cfg));
    regexdev_cfg.nb_max_matches = MAX_MATCH_NUM;
    regexdev_cfg.nb_queue_pairs = 1;
    regexdev_cfg.nb_rules_per_group = MAX_PATTERN_NUM;
    ret = rte_regexdev_configure(dev_id, &regexdev_cfg);
    if (ret != 0) {
        fprintf(stderr, "Failed to configure RegEx device\n");
        return -1;
    }

    struct rte_regexdev_rule rule = {
        .rule_id = 0,
        .pcre_rule = ip_pattern
    };
    // memset(rule_params, 0, sizeof(rule_params));
    // rule_params[0].rule_id = 0;
    // rule_params[0].rule_str = ip_pattern;

    ret = rte_regexdev_rule_db_update(dev_id, &rule, 1);
    if (ret != 0) {
        fprintf(stderr, "Failed to add rule to RegEx device\n");
        return -1;
    }

    memset(&qconf, 0, sizeof(qconf));
    qconf.nb_desc = 128;
    qp_id = 0;
    ret = rte_regexdev_queue_pair_setup(dev_id, qp_id, &qconf);
    if (ret != 0) {
        fprintf(stderr, "Failed to set up RegEx queue pair\n");
        return -1;
    }

    ret = rte_regexdev_start(dev_id);
    if (ret != 0) {
        fprintf(stderr, "Failed to start RegEx device\n");
        return -1;
    }

    return 0;
}

int extract_ips_with_regex(const uint8_t *packet, uint32_t *src_ip, uint32_t *dst_ip) {
    struct rte_mbuf *m;
    struct rte_regex_ops *ops;
    struct rte_regexdev_match *match;
    int ret;

    m = rte_pktmbuf_alloc(rte_pktmbuf_pool_create("MBUF_POOL", 8192, 250, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()));
    if (m == NULL) {
        fprintf(stderr, "Failed to allocate mbuf\n");
        return -1;
    }
    rte_memcpy(rte_pktmbuf_mtod(m, void *), packet, m->buf_len);


    ops = rte_malloc(NULL, sizeof(*ops), 0);
    if (ops == NULL) {
        fprintf(stderr, "Failed to allocate regex ops\n");
        rte_pktmbuf_free(m);
        return -1;
    }

    memset(ops, 0, sizeof(*ops));
    ops->mbuf = m;
    ops->group_id0 = 1; // Assuming we're using group 1

    ret = rte_regexdev_enqueue_burst(dev_id, qp_id, &ops, 1);
    if (ret != 1) {
        fprintf(stderr, "Failed to enqueue regex op\n");
        rte_free(ops);
        rte_pktmbuf_free(m);
        return -1;
    }

    ret = rte_regexdev_dequeue_burst(dev_id, qp_id, &ops, 1);
    if (ret != 1) {
        fprintf(stderr, "Failed to dequeue regex op\n");
        rte_free(ops);
        rte_pktmbuf_free(m);
        return -1;
    }

    if (ops->nb_matches >= 2) {
        match = &ops->matches[0];
        *src_ip = ntohl(*(uint32_t *)(packet + match->start_offset));
        match = &ops->matches[1];
        *dst_ip = ntohl(*(uint32_t *)(packet + match->start_offset));
    } else {
        fprintf(stderr, "Failed to extract both IPs\n");
        rte_free(ops);
        rte_pktmbuf_free(m);
        return -1;
    }

    rte_free(ops);
    rte_pktmbuf_free(m);
    return 0;
}

int main(int argc, char *argv[]) {
    FILE *in;
    char in_f[PATH_MAX] = {0}, anonkey[PATH_MAX] = {0}, cachefile[PATH_MAX] = {0};
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char *value = NULL;
    int c, ret, reqargs = 0;
    size_t filesize, filepos;
    struct timespec ts_start;
    double t_elapsed = 0;
    const uint8_t *buf_p;
    struct pcap_pkthdr *hdr_p;

    pstate = calloc(1, sizeof(struct px3_state));
    pstate->f_tm = NULL;
    pstate->subwinsize = SUBWINSIZE;
    pstate->files_per_window = 64;

    // Parse command line arguments
    while ((c = getopt(argc, argv, "SO:va:c:i:o:w:W:")) != -1) {
        switch (c)
        {
            case 'a':
                value             = optarg;
                pstate->anonymize = 1;
                snprintf(anonkey, sizeof(anonkey), "%s", value);
                break;
            case 'c':
                snprintf(cachefile, sizeof(cachefile) - 1, "%s", optarg);
                pstate->anonymize = 2;
                break;
            case 'i':
                // input
                value = optarg;
                reqargs++;
                snprintf(in_f, sizeof(in_f), "%s", value);
                break;
            case 'S':
                pstate->swapped = 1;
                break;
            case 'o':
                // output dir
                value = optarg;
                reqargs++;
                pstate->out_prefix = strdup(value);
                break;
            case 'O':
                pstate->files_per_window      = 1;
                pstate->subwinsize            = UINT_MAX;
                pstate->save_trailing_packets = 1;
                reqargs++;
                if (optarg != NULL)
                {
                    strncpy(pstate->f_name, optarg, sizeof(pstate->f_name) - 1);
                }
                break;
            case 'W':
                // files per window
                if (sscanf(optarg, "%u", &pstate->files_per_window) != 1)
                {
                    fprintf(stderr, "Invalid argument to option -%c.\n", optopt);
                    exit(EXIT_FAILURE);
                }
                if (pstate->files_per_window <= 0)
                {
                    fprintf(stderr, "Invalid value for window size: %u\n", pstate->files_per_window);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'w':
                // subwinsize
                if (sscanf(optarg, "%u", &pstate->subwinsize) != 1)
                {
                    fprintf(stderr, "Invalid argument to option -%c.\n", optopt);
                    exit(EXIT_FAILURE);
                }
                if (pstate->subwinsize <= 0)
                {
                    fprintf(stderr, "Invalid value for subwindow size: %u\n", pstate->subwinsize);
                    exit(EXIT_FAILURE);
                }
                break;
            case '?':
                if (optopt == 'i' || optopt == 'o' || optopt == 'a' || optopt == 'c' || optopt == 'w' ||
                    optopt == 'W' || optopt == 'O')
                {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                }
                else if (isprint(optopt))
                {
                    fprintf(stderr, "Unknown option: -%c.\n", optopt);
                }
                else
                {
                    fprintf(stderr, "Unrecognized option: -%c.\n", optopt);
                }
                usage(argv[0]);
                exit(1);
            default:
                exit(2);
        }
    }

    if (reqargs < 2 || in_f[0] == 0) {
        fprintf(stderr, "Invalid or insufficient arguments.\n");
        usage(argv[0]);
        exit(1);
    }


    if (init_dpdk_regex(argv[0]) != 0) {
        fprintf(stderr, "Failed to initialize DPDK RegEx\n");
        exit(1);
    }

    // Open input file
    if (!strcmp(in_f, "-")) {
        in = stdin;
    } else if ((in = fopen(in_f, "r")) == NULL) {
        perror("fopen in_f");
        return 1;
    }

    if (in != stdin) {
        fseek(in, 0L, SEEK_END);
        filesize = ftell(in);
        fseek(in, 0L, SEEK_SET);
        fprintf(stderr, "input pcap file is %ld bytes\n", filesize);
        fflush(stderr);
    }

    if ((pcap = pcap_fopen_offline(in, errbuf)) == NULL) {
        fprintf(stderr, "Error in opening pipefd for reading: %s\n", errbuf);
        fflush(stderr);
        return 1;
    }

    if (pstate->out_prefix == NULL)
        pstate->out_prefix = strdup(".");

    pstate->link_type = pcap_datalink(pcap);
    fprintf(stderr, "input pcap file is of type %s\n", pcap_datalink_val_to_name(pstate->link_type));

    GrB_init(GrB_NONBLOCKING);
    GrB_Matrix Gmat;
    GrB_Descriptor desc = NULL;

    if (pstate->subwinsize == UINT_MAX) {
        int packets_in_file = 0;
        long pos = ftell(pcap_file(pcap));
        while ((ret = pcap_next_ex(pcap, &hdr_p, &buf_p)) >= 0)
            packets_in_file++;
        fseek(pcap_file(pcap), pos, SEEK_SET);
        pstate->subwinsize = packets_in_file;
        fprintf(stderr, "Single file mode, %d packets in pcap file.\n", pstate->subwinsize);
    }

    fprintf(stderr, "Generating tar files with %u matrices of size: %u\n", pstate->files_per_window,
            pstate->subwinsize);

    pstate->R = malloc(sizeof(GrB_Index) * pstate->subwinsize);
    pstate->C = malloc(sizeof(GrB_Index) * pstate->subwinsize);
    pstate->V = malloc(sizeof(uint32_t) * pstate->subwinsize);

    GrB_Descriptor_new(&desc);
    GxB_Desc_set(desc, GxB_COMPRESSION, GxB_COMPRESSION_ZSTD + 1);

    clock_gettime(CLOCK_REALTIME, &ts_start);


    // TODO: still looping over packet by packet
    while ((ret = pcap_next_ex(pcap, &hdr_p, &buf_p)) >= 0) {
        pstate->total_packets++;

        uint32_t srcip, dstip;
        if (extract_ips_with_regex(buf_p, &srcip, &dstip) != 0) {
            pstate->total_invalid++;
            continue;
        }

        if (pstate->findex == 0 && pstate->rec == 0) {
            if (pstate->f_tm == NULL) {
                pstate->f_tm = localtime(&hdr_p->ts.tv_sec);
                if (pstate->f_name[0] == '\0') {
                    set_output_filename();
                }
            } else {
                pstate->f_tm = localtime(&hdr_p->ts.tv_sec);
            }
        }

        if (pstate->anonymize == 1) {
            srcip = scramble_ip4(BSWAP(srcip), 16);
            dstip = scramble_ip4(BSWAP(dstip), 16);
        } else if (pstate->anonymize == 2) {
            srcip = pstate->ip4cache[BSWAP(srcip)];
            dstip = pstate->ip4cache[BSWAP(dstip)];
        } else {
            srcip = BSWAP(srcip);
            dstip = BSWAP(dstip);
        }

        if (srcip > UINT_MAX - 1 || dstip > UINT_MAX - 1) {
            continue;
        }

        pstate->R[pstate->rec] = srcip;
        pstate->C[pstate->rec] = dstip;
        pstate->V[pstate->rec] = 1;
        pstate->rec++;

        if (pstate->rec == pstate->subwinsize) {
            void *blob = NULL;
            GrB_Index blob_size = 0;
            GrB_Matrix_new(&Gmat, GrB_UINT32, 4294967296, 4294967296);
            GrB_Matrix_build(Gmat, pstate->R, pstate->C, pstate->V, pstate->subwinsize, GrB_PLUS_UINT32);
            GxB_Matrix_serialize(&blob, &blob_size, Gmat, desc);
            add_blob_to_tar(blob, blob_size);
            free(blob);
            GrB_free(&Gmat);
            pstate->rec = 0;
        }
    }

    struct timespec ts_end, tsdiff;
    clock_gettime(CLOCK_REALTIME, &ts_end);
    timespec_diff(&ts_end, &ts_start, &tsdiff);
    t_elapsed = ((tsdiff.tv_sec * 1e9) + (tsdiff.tv_nsec)) * 1e-9;

    if (ret == -1) {
        fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pcap));
    }

    if (pstate->rec > 0) {
        if (pstate->save_trailing_packets != 0) {
            void *blob = NULL;
            GrB_Index blob_size = 0;
            LAGRAPH_TRY_EXIT(GrB_Matrix_new(&Gmat, GrB_UINT32, 4294967296, 4294967296));
            LAGRAPH_TRY_EXIT(GrB_Matrix_build(Gmat, pstate->R, pstate->C, pstate->V, pstate->rec, GrB_PLUS_UINT32));
            LAGRAPH_TRY_EXIT(GxB_Matrix_serialize(&blob, &blob_size, Gmat, desc));
            fprintf(stderr, "Adding trailing %u packets to tar file.\n", pstate->rec);
            add_blob_to_tar(blob, blob_size);
            free(blob);
            GrB_free(&Gmat);
        } else {
            fprintf(stderr, "INFO: Not processing %u remaining packets (less than matrix size of %u).\n", pstate->rec,
                    pstate->subwinsize);
        }
    }

    filepos = ftell(in);
    fprintf(stderr, "Done: %ld packets. (%.2f pps)\n", pstate->total_packets, pstate->total_packets / t_elapsed);
    fclose(in);
    free(pstate->R);
    free(pstate->C);
    free(pstate->V);

    // Clean up DPDK RegEx resources
    rte_regexdev_stop(dev_id);
    rte_regexdev_close(dev_id);
    rte_eal_cleanup();

    exit(0);
}