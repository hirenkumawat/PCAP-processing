#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_regex.h>
#include <doca_mmap.h>
#include "cryptopANT.h"

#define MAX_REGEX_JOBS 1024
#define MAX_FILE_NAME 255
#define IP_REGEX "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"

DOCA_LOG_REGISTER(PCAP_REGEX);

struct pcap_regex_config {
    char pci_address[DOCA_DEVINFO_PCI_ADDR_SIZE];
    char pcap_file[MAX_FILE_NAME];
    char rules_file[MAX_FILE_NAME];
    int anonymize;
    char anon_key_file[MAX_FILE_NAME];
};

struct pcap_regex_ctx {
    struct doca_dev *dev;
    struct doca_regex *doca_regex;
    struct doca_buf_inventory *buf_inv;
    struct doca_mmap *mmap;
    struct doca_workq *workq;
    void *pcap_data;
    size_t pcap_data_len;
    uint32_t *ip_matrix;
};

static doca_error_t
pcap_regex_init(struct pcap_regex_ctx *ctx, struct pcap_regex_config *cfg)
{
    doca_error_t result;

    result = open_doca_device_with_pci(cfg->pci_address, NULL, &ctx->dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to open DOCA device");
        return result;
    }

    result = doca_regex_create(&ctx->doca_regex);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create DOCA RegEx");
        return result;
    }

    result = doca_ctx_dev_add(doca_regex_as_ctx(ctx->doca_regex), ctx->dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add device to RegEx");
        return result;
    }

    result = doca_buf_inventory_create(NULL, MAX_REGEX_JOBS, DOCA_BUF_EXTENSION_NONE, &ctx->buf_inv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create buffer inventory");
        return result;
    }

    result = doca_mmap_create(NULL, &ctx->mmap);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create mmap");
        return result;
    }

    result = doca_mmap_set_memrange(ctx->mmap, ctx->pcap_data, ctx->pcap_data_len);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set memory range");
        return result;
    }

    result = doca_mmap_start(ctx->mmap);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start mmap");
        return result;
    }

    result = doca_workq_create(MAX_REGEX_JOBS, &ctx->workq);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create work queue");
        return result;
    }

    result = doca_ctx_workq_add(doca_regex_as_ctx(ctx->doca_regex), ctx->workq);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add work queue to RegEx context");
        return result;
    }

    return DOCA_SUCCESS;
}

static doca_error_t
pcap_regex_load_rules(struct pcap_regex_ctx *ctx, const char *rules_file)
{
    doca_error_t result;
    char *rules_buffer;
    size_t rules_size;

    result = read_file(rules_file, &rules_buffer, &rules_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to read rules file");
        return result;
    }

    result = doca_regex_set_hardware_compiled_rules(ctx->doca_regex, rules_buffer, rules_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set RegEx rules");
        free(rules_buffer);
        return result;
    }

    free(rules_buffer);
    return DOCA_SUCCESS;
}

static doca_error_t
pcap_regex_process(struct pcap_regex_ctx *ctx, struct pcap_regex_config *cfg)
{
    doca_error_t result;
    struct doca_buf *buf;
    struct doca_regex_job_search job;
    struct doca_event event;
    uint32_t remaining_bytes = ctx->pcap_data_len;
    uint32_t chunk_size = 65536; // Adjust as needed
    uint32_t src_ip, dst_ip;

    memset(&job, 0, sizeof(job));
    job.base.type = DOCA_REGEX_JOB_SEARCH;
    job.base.ctx = doca_regex_as_ctx(ctx->doca_regex);
    job.rule_group_ids[0] = 1; // Assuming rule group 1 for IP matching

    while (remaining_bytes > 0) {
        uint32_t job_size = (remaining_bytes < chunk_size) ? remaining_bytes : chunk_size;

        result = doca_buf_inventory_buf_by_addr(ctx->buf_inv, ctx->mmap, 
                                                ctx->pcap_data + (ctx->pcap_data_len - remaining_bytes),
                                                job_size, &buf);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to get buffer from inventory");
            return result;
        }

        job.buffer = buf;
        job.result = malloc(sizeof(struct doca_regex_search_result));
        if (job.result == NULL) {
            DOCA_LOG_ERR("Failed to allocate memory for search result");
            return DOCA_ERROR_NO_MEMORY;
        }

        result = doca_workq_submit(ctx->workq, (struct doca_job *)&job);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to submit RegEx job");
            free(job.result);
            return result;
        }

        do {
            result = doca_workq_progress_retrieve(ctx->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
            if (result == DOCA_SUCCESS) {
                struct doca_regex_search_result *search_result = (struct doca_regex_search_result *)event.result.ptr;
                struct doca_regex_match *match = search_result->matches;

                while (match != NULL) {
                    char ip_str[16];
                    strncpy(ip_str, ctx->pcap_data + match->match_start, match->length);
                    ip_str[match->length] = '\0';

                    uint32_t ip = inet_addr(ip_str);
                    if (cfg->anonymize) {
                        ip = scramble_ip4(ntohl(ip), 16);
                    }

                    if (src_ip == 0) {
                        src_ip = ip;
                    } else {
                        dst_ip = ip;
                        ctx->ip_matrix[src_ip * 256 + (dst_ip >> 24)]++;
                        src_ip = 0;
                    }

                    match = match->next;
                }

                free(search_result);
                doca_buf_refcount_rm(buf, NULL);
            } else if (result != DOCA_ERROR_AGAIN) {
                DOCA_LOG_ERR("Failed to retrieve RegEx job result");
                return result;
            }
        } while (result == DOCA_ERROR_AGAIN);

        remaining_bytes -= job_size;
    }

    return DOCA_SUCCESS;
}

static void
pcap_regex_cleanup(struct pcap_regex_ctx *ctx)
{
    if (ctx->workq != NULL) {
        doca_ctx_workq_rm(doca_regex_as_ctx(ctx->doca_regex), ctx->workq);
        doca_workq_destroy(ctx->workq);
    }
    if (ctx->doca_regex != NULL) {
        doca_ctx_stop(doca_regex_as_ctx(ctx->doca_regex));
        doca_regex_destroy(ctx->doca_regex);
    }
    if (ctx->mmap != NULL) {
        doca_mmap_destroy(ctx->mmap);
    }
    if (ctx->buf_inv != NULL) {
        doca_buf_inventory_destroy(ctx->buf_inv);
    }
    if (ctx->dev != NULL) {
        doca_dev_close(ctx->dev);
    }
    free(ctx->pcap_data);
    free(ctx->ip_matrix);
}

int main(int argc, char **argv)
{
    struct pcap_regex_config cfg = {0};
    struct pcap_regex_ctx ctx = {0};
    doca_error_t result;

    /* Register a logger backend */
    result = doca_log_create_standard_backend();
    if (result != DOCA_SUCCESS) {
        return EXIT_FAILURE;
    }

    /* Parse command line arguments */
    result = doca_argp_init("doca_pcap_regex", &cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init ARGP");
        return EXIT_FAILURE;
    }

    /* Add program-specific arguments */
    result = doca_argp_add_string_argument('p', "pci-addr", "PCI_ADDR", "DOCA device PCI address", &cfg.pci_address, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add PCI address argument");
        return EXIT_FAILURE;
    }

    result = doca_argp_add_string_argument('f', "pcap-file", "PCAP_FILE", "Path to PCAP file", &cfg.pcap_file, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add PCAP file argument");
        return EXIT_FAILURE;
    }

    result = doca_argp_add_string_argument('r', "rules-file", "RULES_FILE", "Path to RegEx rules file", &cfg.rules_file, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add rules file argument");
        return EXIT_FAILURE;
    }

    result = doca_argp_add_bool_argument('a', "anonymize", "Enable IP anonymization", &cfg.anonymize, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add anonymize argument");
        return EXIT_FAILURE;
    }

    result = doca_argp_add_string_argument('k', "anon-key", "ANON_KEY_FILE", "Path to anonymization key file", &cfg.anon_key_file, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add anonymization key file argument");
        return EXIT_FAILURE;
    }

    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse arguments");
        return EXIT_FAILURE;
    }

    /* Read PCAP file */
    result = read_file(cfg.pcap_file, &ctx.pcap_data, &ctx.pcap_data_len);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to read PCAP file");
        return EXIT_FAILURE;
    }

    /* Initialize DOCA RegEx */
    result = pcap_regex_init(&ctx, &cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to initialize DOCA RegEx");
        pcap_regex_cleanup(&ctx);
        return EXIT_FAILURE;
    }

    /* Load RegEx rules */
    result = pcap_regex_load_rules(&ctx, cfg.rules_file);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to load RegEx rules");
        pcap_regex_cleanup(&ctx);
        return EXIT_FAILURE;
    }

    /* Initialize IP matrix */
    ctx.ip_matrix = calloc(256 * 256, sizeof(uint32_t));
    if (ctx.ip_matrix == NULL) {
        DOCA_LOG_ERR("Failed to allocate IP matrix");
        pcap_regex_cleanup(&ctx);
        return EXIT_FAILURE;
    }

    /* Initialize anonymization if enabled */
    if (cfg.anonymize) {
        if (scramble_init_from_file(cfg.anon_key_file, SCRAMBLE_BLOWFISH, SCRAMBLE_BLOWFISH, NULL) < 0) {
            DOCA_LOG_ERR("Failed to initialize anonymization");
            pcap_regex_cleanup(&ctx);
            return EXIT_FAILURE;
        }
    }

    /* Process PCAP data */
    result = pcap_regex_process(&ctx, &cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to process PCAP data");
        pcap_regex_cleanup(&ctx);
        return EXIT_FAILURE;
    }

    /* Output results (you can modify this part to suit your needs) */
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 256; j++) {
            if (ctx.ip_matrix[i * 256 + j] > 0) {
                printf("%d.0.0.0 -> %d.0.0.0: %u\n", i, j, ctx.ip_matrix[i * 256 + j]);
            }
        }
    }

    /* Cleanup */
    pcap_regex_cleanup(&ctx);

    return EXIT_SUCCESS;
}
