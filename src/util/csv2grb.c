#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <csv.h>
#include <ctype.h>
#include <fcntl.h>
#include <malloc.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include <GraphBLAS.h>

#define BUFFERSIZE (1 << 17)

struct parse_state
{
    struct tm *f_tm;
    unsigned int skiprows, anonymize, swapped, at_eof;
    unsigned int current_row, current_col;
    unsigned int src, dst, val, rec;
    GrB_Index *R, *C, *V;
    GrB_Matrix Gmat;
};

struct _serialized_blob
{
    void *blob_data;
    GrB_Index blob_size;
};

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

void field_callback(void *s, size_t len, void *data)
{
    struct parse_state *ps = (struct parse_state *)data;
    struct in_addr tmp_inaddr;

    if (ps->current_row < ps->skiprows)
        return;

    switch (ps->current_col)
    {
        case 2:
        case 3:
            if (inet_aton(s, &tmp_inaddr) == 0)
            {
                fprintf(stderr, "Malformed input: %s\n", (char *)s);
                exit(2);
            }
            if (ps->current_col == 2)
                ps->src = tmp_inaddr.s_addr;
            else
                ps->dst = tmp_inaddr.s_addr;
            break;
        case 4:
            ps->val = atoi(s);
            break;
    }
    ps->current_col++;
    return;
}

void row_callback(int c, void *data)
{
    struct parse_state *ps = (struct parse_state *)data;

    ps->current_row++;
    ps->current_col = 0;

    if (ps->current_row <= ps->skiprows)
        return;

    ps->R[ps->rec] = ps->src;
    ps->C[ps->rec] = ps->dst;
    ps->V[ps->rec] = 1;

    ps->rec++;

    if (ps->rec == BUFFERSIZE)
    {
        GrB_Matrix tmpGmat, newGmat;

        LAGRAPH_TRY_EXIT(GrB_Matrix_new(&tmpGmat, GrB_UINT32, 4294967296, 4294967296));
        LAGRAPH_TRY_EXIT(GrB_Matrix_new(&newGmat, GrB_UINT32, 4294967296, 4294967296));

        LAGRAPH_TRY_EXIT(GrB_Matrix_build(tmpGmat, ps->R, ps->C, ps->V, ps->rec, GrB_PLUS_UINT32));
        LAGRAPH_TRY_EXIT(GrB_eWiseAdd(newGmat, GrB_NULL, GrB_NULL, GrB_PLUS_UINT32, ps->Gmat, tmpGmat, GrB_NULL));

        GrB_free(&(ps->Gmat));
        GrB_free(&tmpGmat);

        ps->Gmat = newGmat;
        ps->rec  = 0;
    }

    return;
}

int main(int argc, char *argv[])
{
    struct parse_state *ps = malloc(sizeof(*ps));
    GrB_Descriptor desc    = NULL;
    FILE *fp               = NULL;
    struct csv_parser p;
    int c = 0, nfiles = 0;
    size_t bytes_read = 0;
    char buf[4096]    = { 0 };

    if (argc < 2)
    {
        fprintf(stdout, "usage: %s [-f fieldspec] [-d delimiter] <file1.txt> ... <fileN.txt>\n", argv[0]);
        fprintf(stdout, "Input files should be newline-delimited lists of CIDR prefixes (e.g. 1.2.3.4/8)\n");
        fprintf(stdout, "    -S Produce big-endian (network byte order) output.\n");
        fprintf(stdout, "    -a Anonymize using CryptopANT (https://ant.isi.edu/software/cryptopANT/index.html)\n");
        fprintf(stdout, "       Requires a key generated by this library.\n");
        fprintf(stdout, "    -n Change the output filename prefix.  Default is LocalIPList-#FILES.tar\n");
        return 1;
    }

    while ((c = getopt(argc, argv, "f:d:")) != -1)
    {
        switch (c)
        {
            case 'f':
                break;
            case 'd':
                break;
            case '?':
                if (optopt == 'f')
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
                exit(1);
            default:
                exit(2);
        }
    }

    GrB_init(GrB_NONBLOCKING);
    csv_init(&p, CSV_APPEND_NULL);
    csv_set_delim(&p, '\t');
    nfiles = argc - optind;
    bzero(ps, sizeof(*ps));

    ps->R = malloc(sizeof(GrB_Index) * BUFFERSIZE);
    ps->C = malloc(sizeof(GrB_Index) * BUFFERSIZE);
    ps->V = malloc(sizeof(uint32_t) * BUFFERSIZE);

    ps->skiprows = 1;

    for (int index = optind, blob_index = 0; index < argc; index++, blob_index++)
    {
        LAGRAPH_TRY_EXIT(GrB_Matrix_new(&(ps->Gmat), GrB_UINT32, 4294967296, 4294967296));

        if ((fp = fopen(argv[index], "r")) == NULL)
        {
            perror("fopen");
            exit(2);
        }

        while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0)
        {
            if (csv_parse(&p, buf, bytes_read, field_callback, row_callback, ps) != bytes_read)
            {
                fprintf(stderr, "Error while parsing file: %s\n", csv_strerror(csv_error(&p)));
                exit(2);
            }
        }
        csv_fini(&p, field_callback, row_callback, ps);

        if (feof(fp))
        {
            GrB_Matrix tmpGmat, newGmat;
            GrB_Monoid sumMonoid;
            uint32_t vals = 0;

            if (ps->rec > 0)
            {
                LAGRAPH_TRY_EXIT(GrB_Matrix_new(&tmpGmat, GrB_UINT32, 4294967296, 4294967296));
                LAGRAPH_TRY_EXIT(GrB_Matrix_new(&newGmat, GrB_UINT32, 4294967296, 4294967296));

                LAGRAPH_TRY_EXIT(GrB_Matrix_build(tmpGmat, ps->R, ps->C, ps->V, ps->rec, GrB_PLUS_UINT32));
                LAGRAPH_TRY_EXIT(
                    GrB_eWiseAdd(newGmat, GrB_NULL, GrB_NULL, GrB_PLUS_UINT32, ps->Gmat, tmpGmat, GrB_NULL));

                GrB_free(&(ps->Gmat));
                GrB_free(&tmpGmat);

                ps->Gmat = newGmat;
            }

            GrB_Monoid_new(&sumMonoid, GrB_PLUS_UINT32, 0);

            GxB_Monoid_fprint(sumMonoid, "sumMonoid", 2, stderr);
            GxB_print(ps->Gmat, 2); // works
            GrB_reduce(&vals, GrB_NULL, sumMonoid, ps->Gmat, GrB_NULL);
            fprintf(stderr, "vals: %u\n", vals);

            ps->rec = 0;
        }

        fclose(fp);
    }
    free(ps);
}