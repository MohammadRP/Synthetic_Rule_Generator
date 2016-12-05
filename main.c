/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.c
 * Author: mrp
 *
 * Created on December 4, 2016, 1:38 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <string.h>

#include "main.h"

char *classbench_ruleset_filename = NULL;
char *synthetic_ruleset_filename = NULL;

float wildcard_ratio = -1;
float wildcard_threshold = -1;

int nb_rules;
rule_t *rules;

uint32_t *ingress_port_pool;
uint64_t *metadata_pool;
mac_t *eth_src_pool;
mac_t *eth_dst_pool;
uint16_t *ether_type_pool;
uint16_t *vid_pool;
uint8_t *vprty_pool;
uint8_t *tos_pool;
uint32_t *mpls_lbl_pool;
uint8_t *mpls_tfc_pool;

int nb_unique_ingress_port;
int nb_unique_metadata;
int nb_unique_eth_src;
int nb_unique_eth_dst;
int nb_unique_ether_type;
int nb_unique_vid;
int nb_unique_vprty;
int nb_unique_tos;
int nb_unique_mpls_lbl;
int nb_unique_mpls_tfc;


void usage(char *filename);
void parse_args(int argc, char** argv);
void init(void);
void load_classbench_five_tuples(void);
void generate_fileds_pool(void);
void generate_full_rules(void);
void dump_rules(void);

/*
 * 
 */
int main(int argc, char** argv) {
        parse_args(argc, argv);
        init();
        load_classbench_five_tuples();
        generate_fileds_pool();
        generate_full_rules();
        dump_rules();
        return (EXIT_SUCCESS);
}

void usage(char *filename) {
        printf("Usage: %s [OPTION] ...\n", filename);
        printf("  -i   input ClassBench file name\n");
        printf("  -o   output synthetic file name\n");
        printf("  -w   wildcard ratio\n");
        printf("  -h   print this help\n");
        exit(EXIT_FAILURE);
}

void parse_args(int argc, char** argv) {
        int c;
        opterr = 0;
        while ((c = getopt(argc, argv, "hi:o:w:")) != -1) {
                switch (c) {
                        case 'i': // input 5-tuple ClassBench rule set
                                classbench_ruleset_filename = strdup(optarg);
                                break;
                        case 'o': // output 15-tuple synthetic rule set
                                synthetic_ruleset_filename = strdup(optarg);
                                break;
                        case 'w': // wildcard ratio
                                wildcard_ratio = atof(optarg);
                                break;
                        case '?':
                        case 'h':
                                usage(argv[0]);
                                break;
                        default:
                                usage(argv[0]);
                                break;
                }
        }
        if (classbench_ruleset_filename == NULL) {
                printf("input ClassBench file name does not specified\n");
                usage(argv[0]);
        }
        if (synthetic_ruleset_filename == NULL) {
                printf("output synthetic file name does not specified\n");
                usage(argv[0]);
        }
        if (wildcard_ratio < 0) {
                printf("wildcard ratio does not specified\n");
                usage(argv[0]);
        }
}

void init(void) {

        // check availability of input rules file ------------------------------
        if (access(classbench_ruleset_filename, F_OK) != 0) {
                printf("%s does not exist\n", classbench_ruleset_filename);
                exit(1);
        }
        if (access(classbench_ruleset_filename, R_OK) != 0) {
                printf("Can not read %s\n", classbench_ruleset_filename);
                exit(1);
        }

        // check availability of output rules file -----------------------------
        if (access(synthetic_ruleset_filename, F_OK) == 0) {
                printf("%s already exist\n", synthetic_ruleset_filename);
                exit(1);
        }

        // initialize wildcard ratio
        wildcard_threshold = wildcard_ratio * 100;

        // initialize random
        srand(time(NULL));

        // initialize number of rules ------------------------------------------
        FILE * fp;
        char ch;
        int nb_lines = 0;
        fp = fopen(classbench_ruleset_filename, "r");
        while (!feof(fp)) {
                ch = fgetc(fp);
                if (ch == '\n') {
                        nb_lines++;
                }
        }
        nb_rules = nb_lines;
        rules = (rule_t *) malloc(nb_rules * sizeof (rule_t));
#ifdef DEBUG
        printf("NB_RULES : %d\n", nb_rules);
#endif

}

void load_classbench_five_tuples(void) {
        printf("\n\nLoading ClassBench Rules ...\n");
        sleep(1);

        FILE * rules_file;
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        int i = 0, j = 0;

        char *rule_format = (char *) "@" // start of rule
                "%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8 "/%" SCNu8 "%*[ \t]"// src ip
                "%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8 "/%" SCNu8 "%*[ \t]"// dest ip
                "%" SCNu16 " : %" SCNu16 "%*[ \t]"// src port
                "%" SCNu16 " : %" SCNu16 "%*[ \t]"// dest port
                "0x%" SCNx8 "/0x%" SCNx8 "%*[ \t]"// proto
                "0x%" SCNx16 "/0x%" SCNx16 "%*[ \t]"; // ext

        uint32_t src_ip, src_ip_bit_mask, dst_ip, dst_ip_bit_mask;
        uint8_t src_ip_byte1, src_ip_byte2, src_ip_byte3, src_ip_byte4, src_ip_mask;
        uint8_t dst_ip_byte1, dst_ip_byte2, dst_ip_byte3, dst_ip_byte4, dst_ip_mask;
        uint16_t src_port_lower_bound, src_port_upper_bound;
        uint16_t dst_port_lower_bound, dst_port_upper_bound;
        uint8_t proto, proto_mask;
        uint16_t ext, ext_mask;

        rules_file = fopen(classbench_ruleset_filename, "r");
        i = 0;
        while ((read = getline(&line, &len, rules_file)) != -1) {
#ifdef DUMP_LOADED_RULES
                printf("Rule %d:\n%s", i, line);
#endif
                sscanf(line, rule_format,
                        &src_ip_byte1, &src_ip_byte2, &src_ip_byte3, &src_ip_byte4, &src_ip_mask,
                        &dst_ip_byte1, &dst_ip_byte2, &dst_ip_byte3, &dst_ip_byte4, &dst_ip_mask,
                        &src_port_lower_bound, &src_port_upper_bound,
                        &dst_port_lower_bound, &dst_port_upper_bound,
                        &proto, &proto_mask,
                        &ext, &ext_mask);

                src_ip = (src_ip_byte1 << 24) | (src_ip_byte2 << 16) | (src_ip_byte3 << 8) | (src_ip_byte4);
                src_ip_bit_mask = 0;
                for (j = 0; j < src_ip_mask; j++) {
                        src_ip_bit_mask |= 1 << (32 - j - 1);
                }
                dst_ip = (dst_ip_byte1 << 24) | (dst_ip_byte2 << 16) | (dst_ip_byte3 << 8) | (dst_ip_byte4);
                dst_ip_bit_mask = 0;
                for (j = 0; j < dst_ip_mask; j++) {
                        dst_ip_bit_mask |= 1 << (32 - j - 1);
                }
#ifdef DUMP_LOADED_RULES
                printf("%hhu.%hhu.%hhu.%hhu/%hhu \t%u/0x%08x\n"
                        "%hhu.%hhu.%hhu.%hhu/%hhu\t%u/0x%08x\n"
                        "%hu : %hu\n"
                        "%hu : %hu\n"
                        "0x%02hhx/0x%02hhx\n"
                        "0x%04hx/0x%04hx\n\n",
                        src_ip_byte1, src_ip_byte2, src_ip_byte3, src_ip_byte4, src_ip_mask, src_ip, src_ip_bit_mask,
                        dst_ip_byte1, dst_ip_byte2, dst_ip_byte3, dst_ip_byte4, dst_ip_mask, dst_ip, dst_ip_bit_mask,
                        src_port_lower_bound, src_port_upper_bound,
                        dst_port_lower_bound, dst_port_upper_bound,
                        proto, proto_mask,
                        ext, ext_mask);
#endif

                rules[i].value.ip_src = src_ip;
                rules[i].value.ip_dst = dst_ip;
                rules[i].value.port_src.lower_bound = src_port_lower_bound;
                rules[i].value.port_src.upper_bound = src_port_upper_bound;
                rules[i].value.port_dst.lower_bound = dst_port_lower_bound;
                rules[i].value.port_dst.upper_bound = dst_port_upper_bound;
                rules[i].value.proto = proto;

                rules[i].mask.ip_src_mask = src_ip_bit_mask;
                rules[i].mask.ip_dst_mask = dst_ip_bit_mask;
                rules[i].mask.proto_mask = proto_mask;

                i++;
        }

        fclose(rules_file);

        printf("Done.\n\n");
}

void generate_fileds_pool(void) {

        printf("\nGenerating Fields Pool ...\n");
        sleep(1);

        int i, j;

        // ingress port --------------------------------------------------------
        nb_unique_ingress_port = nb_rules * UNIQUE_VALUE_RATIO_INGRESS_PORT;
        ingress_port_pool =
                (uint32_t *) malloc(nb_unique_ingress_port * sizeof (uint32_t));
#ifdef DUMP_POOLS
        printf("Generating %d ingress ports ...\n", nb_unique_ingress_port);
#endif
        for (i = 0; i < nb_unique_ingress_port;) {
                uint32_t new_ingress_port = rand() % MAX_UINT32;
                for (j = 0; j < i; j++) {
                        if (ingress_port_pool[j] == new_ingress_port)
                                break;
                }
                if (j < i)
                        continue;
                ingress_port_pool[i] = new_ingress_port;
#ifdef DUMP_POOLS
                printf("unique port %-3d --> 0x%08x\n", i, ingress_port_pool[i]);
#endif
                i++;
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif  

        // meta data -----------------------------------------------------------
        nb_unique_metadata = nb_rules * UNIQUE_VALUE_RATIO_METADATA;
        metadata_pool =
                (uint64_t *) malloc(nb_unique_metadata * sizeof (uint64_t));
#ifdef DUMP_POOLS
        printf("Generating %d metadata ...\n", nb_unique_metadata);
#endif
        for (i = 0; i < nb_unique_metadata;) {
                uint64_t new_metadata =
                        (((uint64_t) rand() % MAX_UINT32) << 32) |
                        (rand() % MAX_UINT32);
                for (j = 0; j < i; j++) {
                        if (metadata_pool[j] == new_metadata)
                                break;
                }
                if (j < i)
                        continue;
                metadata_pool[i] = new_metadata;
#ifdef DUMP_POOLS
                printf("unique metadata %-3d --> 0x%016lx\n", i, metadata_pool[i]);
#endif
                i++;
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif

        // eth src -------------------------------------------------------------
        nb_unique_eth_src = nb_rules * UNIQUE_VALUE_RATIO_ETH_SRC;
        eth_src_pool = (mac_t *) malloc(nb_unique_eth_src * sizeof (mac_t));
#ifdef DUMP_POOLS
        printf("Generating %d src mac address ... \n", nb_unique_eth_src);
#endif
        for (i = 0; i < nb_unique_eth_src;) {
                uint64_t new_eth_src =
                        (((uint64_t) rand() % MAX_UINT16) << 32) |
                        (rand() % MAX_UINT32);
                for (j = 0; j < i; j++) {
                        uint64_t tmp_eth_src =
                                (uint64_t) eth_src_pool[j].bytes[0] |
                                ((uint64_t) eth_src_pool[j].bytes[1] << 8) |
                                ((uint64_t) eth_src_pool[j].bytes[2] << 16) |
                                ((uint64_t) eth_src_pool[j].bytes[3] << 24) |
                                ((uint64_t) eth_src_pool[j].bytes[4] << 32) |
                                ((uint64_t) eth_src_pool[j].bytes[5] << 40);
                        if (tmp_eth_src == new_eth_src)
                                break;
                }
                if (j < i)
                        continue;
                eth_src_pool[i].bytes[0] = (new_eth_src >> 0) & 0xFF;
                eth_src_pool[i].bytes[1] = (new_eth_src >> 8) & 0xFF;
                eth_src_pool[i].bytes[2] = (new_eth_src >> 16) & 0xFF;
                eth_src_pool[i].bytes[3] = (new_eth_src >> 24) & 0xFF;
                eth_src_pool[i].bytes[4] = (new_eth_src >> 32) & 0xFF;
                eth_src_pool[i].bytes[5] = (new_eth_src >> 40) & 0xFF;
#ifdef DUMP_POOLS
                printf("unique src mac %-3d --> 0x%012lx\n", i, new_eth_src);
#endif
                i++;
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif

        // eth dst -------------------------------------------------------------
        nb_unique_eth_dst = nb_rules * UNIQUE_VALUE_RATIO_ETH_DST;
        eth_dst_pool = (mac_t *) malloc(nb_unique_eth_dst * sizeof (mac_t));
#ifdef DUMP_POOLS
        printf("Generating %d dst mac address ... \n", nb_unique_eth_dst);
#endif
        for (i = 0; i < nb_unique_eth_dst;) {
                uint64_t new_eth_dst =
                        (((uint64_t) rand() % MAX_UINT16) << 32) |
                        (rand() % MAX_UINT32);
                for (j = 0; j < i; j++) {
                        uint64_t tmp_eth_dst =
                                (uint64_t) eth_dst_pool[j].bytes[0] |
                                ((uint64_t) eth_dst_pool[j].bytes[1] << 8) |
                                ((uint64_t) eth_dst_pool[j].bytes[2] << 16) |
                                ((uint64_t) eth_dst_pool[j].bytes[3] << 24) |
                                ((uint64_t) eth_dst_pool[j].bytes[4] << 32) |
                                ((uint64_t) eth_dst_pool[j].bytes[5] << 40);
                        if (tmp_eth_dst == new_eth_dst)
                                break;
                }
                if (j < i)
                        continue;
                eth_dst_pool[i].bytes[0] = (new_eth_dst >> 0) & 0xFF;
                eth_dst_pool[i].bytes[1] = (new_eth_dst >> 8) & 0xFF;
                eth_dst_pool[i].bytes[2] = (new_eth_dst >> 16) & 0xFF;
                eth_dst_pool[i].bytes[3] = (new_eth_dst >> 24) & 0xFF;
                eth_dst_pool[i].bytes[4] = (new_eth_dst >> 32) & 0xFF;
                eth_dst_pool[i].bytes[5] = (new_eth_dst >> 40) & 0xFF;
#ifdef DUMP_POOLS
                printf("unique dst mac %-3d --> 0x%012lx\n", i, new_eth_dst);
#endif
                i++;
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif

        // ether type ----------------------------------------------------------
        nb_unique_ether_type = nb_rules * UNIQUE_VALUE_RATIO_ETH_TYPE;
        if (nb_unique_ether_type > MAX_NB_UNIQUE_VALUE_ETH_TYPE)
                nb_unique_ether_type = MAX_NB_UNIQUE_VALUE_ETH_TYPE;
        ether_type_pool = (uint16_t *) malloc(nb_unique_ether_type * sizeof (uint16_t));
#ifdef DUMP_POOLS
        printf("Generating %d ether type ... \n", nb_unique_ether_type);
#endif
        for (i = 0; i < nb_unique_ether_type;) {
                uint16_t new_ether_type = rand() % MAX_UINT16;
                for (j = 0; j < i; j++) {
                        if (ether_type_pool[j] == new_ether_type)
                                break;
                }
                if (j < i)
                        continue;
                ether_type_pool[i] = new_ether_type;
#ifdef DUMP_POOLS
                printf("unique ether type %-3d --> 0x%04x\n", i, ether_type_pool[i]);
#endif
                i++;
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif

        // vid -----------------------------------------------------------------
        nb_unique_vid = nb_rules * UNIQUE_VALUE_RATIO_VID;
        if (nb_unique_vid > MAX_NB_UNIQUE_VALUE_VID)
                nb_unique_vid = MAX_NB_UNIQUE_VALUE_VID;
        vid_pool = (uint16_t *) malloc(nb_unique_vid * sizeof (uint16_t));
#ifdef DUMP_POOLS
        printf("Generating %d vid ... \n", nb_unique_vid);
#endif
        for (i = 0; i < nb_unique_vid;) {
                uint16_t new_vid = rand() % MAX_UINT12;
                for (j = 0; j < i; j++) {
                        if (vid_pool[j] == new_vid)
                                break;
                }
                if (j < i)
                        continue;
                vid_pool[i] = new_vid;
#ifdef DUMP_POOLS
                printf("unique vid %-3d --> 0x%03x\n", i, vid_pool[i]);
#endif
                i++;
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif

        // vprty ---------------------------------------------------------------
        nb_unique_vprty = pow(2, 3);
        vprty_pool = (uint8_t *) malloc(nb_unique_vprty * sizeof (uint8_t));
#ifdef DUMP_POOLS
        printf("Generating %d vprty ... \n", nb_unique_vprty);
#endif
        for (i = 0; i < nb_unique_vprty; i++) {
                vprty_pool[i] = i;
#ifdef DUMP_POOLS
                printf("unique vprty %-3d --> 0x%1x\n", i, vprty_pool[i]);
#endif
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif

        // tos -----------------------------------------------------------------
        nb_unique_tos = pow(2, 6);
        tos_pool = (uint8_t *) malloc(nb_unique_tos * sizeof (uint8_t));
#ifdef DUMP_POOLS
        printf("Generating %d tos ... \n", nb_unique_tos);
#endif
        for (i = 0; i < nb_unique_tos; i++) {
                tos_pool[i] = i;
#ifdef DUMP_POOLS
                printf("unique tos %-3d --> 0x%02x\n", i, tos_pool[i]);
#endif
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif


        // mpls_lbl -----------------------------------------------------------
        nb_unique_mpls_lbl = nb_rules * UNIQUE_VALUE_RATIO_MPLS_LBL;
        if (nb_unique_mpls_lbl > MAX_NB_UNIQUE_VALUE_MPLS_LBL)
                nb_unique_mpls_lbl = MAX_NB_UNIQUE_VALUE_MPLS_LBL;
        mpls_lbl_pool =
                (uint32_t *) malloc(nb_unique_mpls_lbl * sizeof (uint32_t));
#ifdef DUMP_POOLS
        printf("Generating %d mpls lbl ...\n", nb_unique_mpls_lbl);
#endif
        for (i = 0; i < nb_unique_mpls_lbl;) {
                uint32_t new_mpls_lbl = rand() % MAX_UINT20;
                for (j = 0; j < i; j++) {
                        if (mpls_lbl_pool[j] == new_mpls_lbl)
                                break;
                }
                if (j < i)
                        continue;
                mpls_lbl_pool[i] = new_mpls_lbl;
#ifdef DUMP_POOLS
                printf("unique mpls lbl %-3d --> 0x%05x\n", i, mpls_lbl_pool[i]);
#endif
                i++;
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif


        // mpls_tfc -----------------------------------------------------------
        nb_unique_mpls_tfc = pow(2, 3);
        mpls_tfc_pool = (uint8_t *) malloc(nb_unique_mpls_tfc * sizeof (uint8_t));
#ifdef DUMP_POOLS
        printf("Generating %d mpls_tfc ... \n", nb_unique_mpls_tfc);
#endif
        for (i = 0; i < nb_unique_mpls_tfc; i++) {
                mpls_tfc_pool[i] = i;
#ifdef DUMP_POOLS
                printf("unique mpls_tfc type %-3d --> 0x%1x\n", i, mpls_tfc_pool[i]);
#endif
        }
#ifdef DUMP_POOLS
        printf("\n");
        getchar();
#endif
        printf("Done.\n\n");
}

void generate_full_rules(void) {

        printf("\nGenerating Full Rules ...\n");
        sleep(1);

        int i, random_wildcard, random_index;
        for (i = 0; i < nb_rules; i++) {
                // add ingress port
                random_wildcard = rand() % WILDCARD_UPPER_BOUND;
                if (random_wildcard < wildcard_threshold) {
                        rules[i].mask.ingress_ports_mask = 0;
                } else {
                        rules[i].mask.ingress_ports_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_ingress_port;
                        rules[i].value.ingress_port = ingress_port_pool[random_index];
                }

                // add metadata
                random_wildcard = rand() % WILDCARD_UPPER_BOUND;
                if (random_wildcard < wildcard_threshold) {
                        rules[i].mask.metadata_mask = 0;
                } else {
                        rules[i].mask.metadata_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_metadata;
                        rules[i].value.metadata = metadata_pool[random_index];

                }

                // add eth src
                random_wildcard = rand() % WILDCARD_UPPER_BOUND;
                if (random_wildcard < wildcard_threshold) {
                        rules[i].mask.eth_src_mask = 0;
                } else {
                        rules[i].mask.eth_src_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_eth_src;
                        rules[i].value.eth_src.bytes[0] =
                                eth_src_pool[random_index].bytes[0];
                        rules[i].value.eth_src.bytes[1] =
                                eth_src_pool[random_index].bytes[1];
                        rules[i].value.eth_src.bytes[2] =
                                eth_src_pool[random_index].bytes[2];
                        rules[i].value.eth_src.bytes[3] =
                                eth_src_pool[random_index].bytes[3];
                        rules[i].value.eth_src.bytes[4] =
                                eth_src_pool[random_index].bytes[4];
                        rules[i].value.eth_src.bytes[5] =
                                eth_src_pool[random_index].bytes[5];
                }

                // add eth dst
                random_wildcard = rand() % WILDCARD_UPPER_BOUND;
                if (random_wildcard < wildcard_threshold) {
                        rules[i].mask.eth_dst_mask = 0;
                } else {
                        rules[i].mask.eth_dst_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_eth_dst;
                        rules[i].value.eth_dst.bytes[0] =
                                eth_dst_pool[random_index].bytes[0];
                        rules[i].value.eth_dst.bytes[1] =
                                eth_dst_pool[random_index].bytes[1];
                        rules[i].value.eth_dst.bytes[2] =
                                eth_dst_pool[random_index].bytes[2];
                        rules[i].value.eth_dst.bytes[3] =
                                eth_dst_pool[random_index].bytes[3];
                        rules[i].value.eth_dst.bytes[4] =
                                eth_dst_pool[random_index].bytes[4];
                        rules[i].value.eth_dst.bytes[5] =
                                eth_dst_pool[random_index].bytes[5];
                }

                // add ether type
                random_wildcard = rand() % WILDCARD_UPPER_BOUND;
                if (random_wildcard < wildcard_threshold) {
                        rules[i].mask.ether_type_mask = 0;
                } else {
                        rules[i].mask.ether_type_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_ether_type;
                        rules[i].value.ether_type = ether_type_pool[random_index];
                }

                // add vid & vprty
                random_wildcard = rand() % WILDCARD_UPPER_BOUND;
                if (random_wildcard < wildcard_threshold) {
                        rules[i].mask.vid_mask = 0;
                        rules[i].mask.vprty_mask = 0;
                } else {
                        // vid
                        rules[i].mask.vid_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_vid;
                        rules[i].value.vid = vid_pool[random_index];
                        // vprty
                        rules[i].mask.vprty_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_vprty;
                        rules[i].value.vprty = vprty_pool[random_index];
                }

                // add tos
                random_wildcard = rand() % WILDCARD_UPPER_BOUND;
                if (random_wildcard < wildcard_threshold) {
                        rules[i].mask.tos_mask = 0;
                } else {
                        rules[i].mask.tos_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_tos;
                        rules[i].value.tos = tos_pool[random_index];
                }

                // add mpls_lbl & mpls_tfc
                random_wildcard = rand() % WILDCARD_UPPER_BOUND;
                if (random_wildcard < wildcard_threshold) {
                        rules[i].mask.mpls_lbl_mask = 0;
                        rules[i].mask.mpls_tfc_mask = 0;
                } else {
                        // mpls_lbl
                        rules[i].mask.mpls_lbl_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_mpls_lbl;
                        rules[i].value.mpls_lbl = mpls_lbl_pool[random_index];
                        // mpls_tfc
                        rules[i].mask.mpls_tfc_mask = MAX_UINT8;
                        random_index = rand() % nb_unique_mpls_tfc;
                        rules[i].value.mpls_tfc = mpls_tfc_pool[random_index];
                }
        }

        printf("Done.\n\n");
}

void dump_rules(void) {

        printf("\nDumping generated rules ...\n");
        sleep(1);

        int i;
        FILE *fp;
        fp = fopen(synthetic_ruleset_filename, "w");
        if (fp == NULL) {
                printf("Can not open file : %s\n", synthetic_ruleset_filename);
                exit(EXIT_FAILURE);
        }
        for (i = 0; i < nb_rules; i++) {
                // uint32_t ingress_port;
                fprintf(fp, "0x%08x/%d\t",
                        rules[i].value.ingress_port,
                        (rules[i].mask.ingress_ports_mask & 1) ? 1 : 0);
                // uint64_t metadata;
                fprintf(fp, "0x%016lx/%d\t",
                        rules[i].value.metadata,
                        (rules[i].mask.metadata_mask & 1) ? 1 : 0);
                // mac_t eth_src;
                fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x/%d\t",
                        rules[i].value.eth_src.bytes[0],
                        rules[i].value.eth_src.bytes[1],
                        rules[i].value.eth_src.bytes[2],
                        rules[i].value.eth_src.bytes[3],
                        rules[i].value.eth_src.bytes[4],
                        rules[i].value.eth_src.bytes[5],
                        (rules[i].mask.eth_src_mask & 1) ? 1 : 0);
                // mac_t eth_dst;
                fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x/%d\t",
                        rules[i].value.eth_dst.bytes[0],
                        rules[i].value.eth_dst.bytes[1],
                        rules[i].value.eth_dst.bytes[2],
                        rules[i].value.eth_dst.bytes[3],
                        rules[i].value.eth_dst.bytes[4],
                        rules[i].value.eth_dst.bytes[5],
                        (rules[i].mask.eth_dst_mask & 1) ? 1 : 0);
                // uint16_t ether_type;
                fprintf(fp, "0x%04x/%d\t",
                        rules[i].value.ether_type,
                        (rules[i].mask.ether_type_mask & 1) ? 1 : 0);
                // uint16_t vid;
                fprintf(fp, "0x%03x/%d\t",
                        rules[i].value.vid,
                        (rules[i].mask.vid_mask & 1) ? 1 : 0);
                // uint8_t vprty;
                fprintf(fp, "0x%1x/%d\t",
                        rules[i].value.vprty,
                        (rules[i].mask.vprty_mask & 1) ? 1 : 0);
                // uint8_t tos;
                fprintf(fp, "0x%02x/%d\t",
                        rules[i].value.tos,
                        (rules[i].mask.tos_mask & 1) ? 1 : 0);
                // uint32_t mpls_lbl;
                fprintf(fp, "0x%05x/%d\t",
                        rules[i].value.mpls_lbl,
                        (rules[i].mask.mpls_lbl_mask & 1) ? 1 : 0);
                // uint8_t mpls_tfc;
                fprintf(fp, "0x%1x/%d\t",
                        rules[i].value.mpls_tfc,
                        (rules[i].mask.mpls_tfc_mask & 1) ? 1 : 0);
                // uint32_t ip_src;
                fprintf(fp, "%hhu.%hhu.%hhu.%hhu/%08x\t",
                        (rules[i].value.ip_src >> 24) & 0xFF,
                        (rules[i].value.ip_src >> 16) & 0xFF,
                        (rules[i].value.ip_src >> 8) & 0xFF,
                        rules[i].value.ip_src & 0xFF,
                        rules[i].mask.ip_src_mask);
                // uint32_t ip_dst;
                fprintf(fp, "%hhu.%hhu.%hhu.%hhu/%08x\t",
                        (rules[i].value.ip_dst >> 24) & 0xFF,
                        (rules[i].value.ip_dst >> 16) & 0xFF,
                        (rules[i].value.ip_dst >> 8) & 0xFF,
                        rules[i].value.ip_dst & 0xFF,
                        rules[i].mask.ip_dst_mask);
                // uint8_t proto;
                fprintf(fp, "0x%02x/%d\t",
                        rules[i].value.proto,
                        (rules[i].mask.proto_mask & 1) ? 1 : 0);
                // port_t port_src;
                fprintf(fp, "%hu:%hu\t",
                        rules[i].value.port_src.lower_bound,
                        rules[i].value.port_src.upper_bound);
                // port_t port_dst;
                fprintf(fp, "%hu:%hu\n",
                        rules[i].value.port_dst.lower_bound,
                        rules[i].value.port_dst.upper_bound);
        }
        fclose(fp);
        printf("Done.\n\n");
}