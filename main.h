/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.h
 * Author: mrp
 *
 * Created on December 4, 2016, 1:47 PM
 */

#ifndef MAIN_H
#define MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define DEBUG
        //        #define DUMP_LOADED_RULES
#define DUMP_POOLS

#define WILDCARD_UPPER_BOUND    10000


#define UNIQUE_VALUE_RATIO_INGRESS_PORT 0.02
#define UNIQUE_VALUE_RATIO_METADATA     0.02
#define UNIQUE_VALUE_RATIO_ETH_SRC      0.25
#define UNIQUE_VALUE_RATIO_ETH_DST      0.25
#define UNIQUE_VALUE_RATIO_ETH_TYPE     0.01
#define UNIQUE_VALUE_RATIO_VID          0.2
#define UNIQUE_VALUE_RATIO_VPRTY        1
#define UNIQUE_VALUE_RATIO_TOS          1
#define UNIQUE_VALUE_RATIO_MPLS_LBL     0.02
#define UNIQUE_VALUE_RATIO_MPLS_TFC     1
#define UNIQUE_VALUE_RATIO_IP_SRC       0.25
#define UNIQUE_VALUE_RATIO_IP_DST       0.25
#define UNIQUE_VALUE_RATIO_PRTL         0.02
#define UNIQUE_VALUE_RATIO_PORT_SRC     0.1
#define UNIQUE_VALUE_RATIO_PORT_DST     0.1

#define MAX_NB_UNIQUE_VALUE_INGRESS_PORT (uint64_t)(pow(2,32)-1)
#define MAX_NB_UNIQUE_VALUE_METADATA     (uint64_t)(pow(2,64)-1)
#define MAX_NB_UNIQUE_VALUE_ETH_SRC      (uint64_t)(pow(2,48)-1)
#define MAX_NB_UNIQUE_VALUE_ETH_DST      (uint64_t)(pow(2,48)-1)
#define MAX_NB_UNIQUE_VALUE_ETH_TYPE     (uint64_t)(pow(2,16)-1)
#define MAX_NB_UNIQUE_VALUE_VID          (uint64_t)(pow(2,12)-1)
#define MAX_NB_UNIQUE_VALUE_VPRTY        (uint64_t)(pow(2,3)-1 )
#define MAX_NB_UNIQUE_VALUE_TOS          (uint64_t)(pow(2,6)-1 )
#define MAX_NB_UNIQUE_VALUE_MPLS_LBL     (uint64_t)(pow(2,20)-1)
#define MAX_NB_UNIQUE_VALUE_MPLS_TFC     (uint64_t)(pow(2,3)-1 )
#define MAX_NB_UNIQUE_VALUE_IP_SRC       (uint64_t)(pow(2,32)-1)
#define MAX_NB_UNIQUE_VALUE_IP_DST       (uint64_t)(pow(2,32)-1)
#define MAX_NB_UNIQUE_VALUE_PRTL         (uint64_t)(pow(2,8)-1 )
#define MAX_NB_UNIQUE_VALUE_PORT_SRC     (uint64_t)(pow(2,16)-1)
#define MAX_NB_UNIQUE_VALUE_PORT_DST     (uint64_t)(pow(2,16)-1)

#define MAX_UINT3       0x7
#define MAX_UINT6       0x3F
#define MAX_UINT8       0xFF
#define MAX_UINT12      0xFFF
#define MAX_UINT16      0xFFFF
#define MAX_UINT20      0xFFFFF
#define MAX_UINT32      0xFFFFFFFF
#define MAX_UINT48      0xFFFFFFFFFFFF
#define MAX_UINT64      0xFFFFFFFFFFFFFFFF

        typedef struct mac {
                uint8_t bytes[6];
        } mac_t;

        typedef struct port {
                uint16_t lower_bound;
                uint16_t upper_bound;
        } port_t;

        typedef struct rule_value {
                uint32_t ingress_port;
                uint64_t metadata;
                mac_t eth_src;
                mac_t eth_dst;
                uint16_t ether_type;
                uint16_t vid;
                uint8_t vprty;
                uint8_t tos;
                uint32_t mpls_lbl;
                uint8_t mpls_tfc;
                uint32_t ip_src;
                uint32_t ip_dst;
                uint8_t proto;
                port_t port_src;
                port_t port_dst;
        } value_t;

        typedef struct rule_mask {
                uint8_t ingress_ports_mask;
                uint8_t metadata_mask;
                uint8_t eth_src_mask;
                uint8_t eth_dst_mask;
                uint8_t ether_type_mask;
                uint8_t vid_mask;
                uint8_t vprty_mask;
                uint8_t tos_mask;
                uint8_t mpls_lbl_mask;
                uint8_t mpls_tfc_mask;
                uint32_t ip_src_mask;
                uint32_t ip_dst_mask;
                uint8_t proto_mask;
                uint16_t port_src_mask;
                uint16_t port_dst_mask;
        } mask_t;

        typedef struct rule {
                value_t value;
                mask_t mask;
                uint32_t pri;
                void *actionl;
        } rule_t;

#ifdef __cplusplus
}
#endif

#endif /* MAIN_H */

