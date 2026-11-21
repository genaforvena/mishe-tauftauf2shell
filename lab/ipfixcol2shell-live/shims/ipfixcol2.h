/* Minimal declarations needed to compile the TCP input plugin's real
 * Lz4Decoder.cpp / DecodeBuffer.cpp against the host, without libfds.
 * The struct layout is copied from CESNET/libfds master,
 * include/libfds/ipfix_structs.h:72-128 (16-byte packed IPFIX message header,
 * uint16 length at offset 2, network byte order). No logic is reimplemented.
 */
#pragma once
#include <arpa/inet.h>  // ntohs, used by DecodeBuffer.cpp via this core header
#include <cstdint>

struct __attribute__((__packed__)) fds_ipfix_msg_hdr {
    uint16_t version;
    uint16_t length;
    uint32_t export_time;
    uint32_t seq_num;
    uint32_t odid;
};

inline void ipx_strerror(int, const char *&out) { out = "shim-strerror"; }
