#pragma once
// Minimal API-shaped stand-in for <infiniband/verbs.h>.
// Only the types, constants and functions referenced by the pinned upstream
// ggml-rpc transport.cpp are declared. No real RDMA device or kernel verbs
// traffic is involved; the harness supplies stub implementations.
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <chrono>

#ifdef __cplusplus
extern "C" {
#endif

struct ibv_device { int unused; };
struct ibv_context { int unused; };
struct ibv_pd { int unused; };
struct ibv_cq { int kind; };
struct ibv_qp { uint32_t qp_num; int unused; };
struct ibv_comp_channel { int fd; };
struct ibv_mr { uint32_t lkey; uint32_t rkey; };

struct ibv_sge { uintptr_t addr; uint32_t length; uint32_t lkey; };
struct ibv_recv_wr { uint64_t wr_id; struct ibv_sge * sg_list; int num_sge; struct ibv_recv_wr * next; };
struct ibv_send_wr { uint64_t wr_id; struct ibv_sge * sg_list; int num_sge; int opcode; int send_flags; struct ibv_send_wr * next; };
struct ibv_wc { int status; uint32_t vendor_err; uint64_t wr_id; uint32_t byte_len; uint32_t imm_data; uint32_t qp_num; uint32_t opcode; };

struct ibv_gid { uint8_t raw[16]; };
struct ibv_gid_entry { struct ibv_gid gid; int gid_type; uint32_t gid_index; };
enum ibv_mtu { IBV_MTU_256=1, IBV_MTU_512=2, IBV_MTU_1024=3, IBV_MTU_2048=4, IBV_MTU_4096=5 };
struct ibv_port_attr { int gid_tbl_len; enum ibv_mtu active_mtu; };
enum ibv_qp_type { IBV_QPT_RC=2 };
enum ibv_qp_state { IBV_QPS_RESET=0, IBV_QPS_INIT=1, IBV_QPS_RTR=2, IBV_QPS_RTS=3 };
enum ibv_wc_status { IBV_WC_SUCCESS=0, IBV_WC_GENERAL_ERR=1 };
enum ibv_wc_opcode { IBV_WC_SEND=0, IBV_WC_RECV=1 };
enum ibv_gid_type { IBV_GID_TYPE_IB=0, IBV_GID_TYPE_ROCE_V1=1, IBV_GID_TYPE_ROCE_V2=2 };

struct ibv_grh { struct ibv_gid dgid; struct ibv_gid sgid; int hop_limit; int sgid_index; };
struct ibv_ah_attr { int is_global; struct ibv_grh grh; uint16_t dlid; uint8_t port_num; };
struct ibv_qp_attr {
    enum ibv_qp_state qp_state;
    uint8_t port_num;
    int pkey_index;
    int qp_access_flags;
    enum ibv_mtu path_mtu;
    uint32_t dest_qp_num;
    uint32_t rq_psn;
    int max_dest_rd_atomic;
    int min_rnr_timer;
    struct ibv_ah_attr ah_attr;
    int timeout;
    int retry_cnt;
    int rnr_retry;
    uint32_t sq_psn;
    int max_rd_atomic;
};
struct ibv_qp_cap { uint32_t max_send_wr, max_recv_wr, max_send_sge, max_recv_sge, max_inline_data; };
struct ibv_qp_init_attr { struct ibv_cq * send_cq; struct ibv_cq * recv_cq; enum ibv_qp_type qp_type; struct ibv_qp_cap cap; };

#define IBV_SEND_SIGNALED (1 << 2)
#define IBV_SEND_INLINE   (1 << 3)
#define IBV_WR_SEND 2
#define IBV_ACCESS_LOCAL_WRITE 1
#define IBV_ACCESS_REMOTE_WRITE 2
#define IBV_ACCESS_REMOTE_READ  4
#define IBV_QP_STATE          (1 << 0)
#define IBV_QP_ACCESS_FLAGS   (1 << 3)
#define IBV_QP_PKEY_INDEX     (1 << 4)
#define IBV_QP_PORT           (1 << 5)
#define IBV_QP_AV             (1 << 7)
#define IBV_QP_PATH_MTU       (1 << 8)
#define IBV_QP_TIMEOUT        (1 << 9)
#define IBV_QP_RETRY_CNT      (1 << 10)
#define IBV_QP_RNR_RETRY      (1 << 11)
#define IBV_QP_RQ_PSN         (1 << 12)
#define IBV_QP_MAX_QP_RD_ATOMIC (1 << 13)
#define IBV_QP_MIN_RNR_TIMER  (1 << 15)
#define IBV_QP_SQ_PSN         (1 << 16)
#define IBV_QP_MAX_DEST_RD_ATOMIC (1 << 17)
#define IBV_QP_DEST_QPN       (1 << 20)
int ibv_query_gid(struct ibv_context * context, uint8_t port_num, int index, struct ibv_gid * gid);

struct ibv_device ** ibv_get_device_list(int * num_devices);
void ibv_free_device_list(struct ibv_device ** list);
const char * ibv_get_device_name(struct ibv_device * device);
struct ibv_context * ibv_open_device(struct ibv_device * device);
int ibv_close_device(struct ibv_context * context);
int ibv_query_port(struct ibv_context * context, uint8_t port_num, struct ibv_port_attr * attr);

int ibv_query_gid_ex(struct ibv_context * context, uint32_t port_num, uint32_t gid_index, struct ibv_gid_entry * entry, uint32_t flags);
struct ibv_pd * ibv_alloc_pd(struct ibv_context * context);
int ibv_dealloc_pd(struct ibv_pd * pd);
struct ibv_comp_channel * ibv_create_comp_channel(struct ibv_context * context);
int ibv_destroy_comp_channel(struct ibv_comp_channel * channel);
struct ibv_cq * ibv_create_cq(struct ibv_context * context, int cqe, void * cq_context, struct ibv_comp_channel * channel, int comp_vector);
int ibv_destroy_cq(struct ibv_cq * cq);
int ibv_get_cq_event(struct ibv_comp_channel * channel, struct ibv_cq ** cq, void ** cq_context);
void ibv_ack_cq_events(struct ibv_cq * cq, unsigned int nevents);
struct ibv_qp * ibv_create_qp(struct ibv_pd * pd, struct ibv_qp_init_attr * attr);
int ibv_modify_qp(struct ibv_qp * qp, struct ibv_qp_attr * attr, int mask);
int ibv_destroy_qp(struct ibv_qp * qp);
struct ibv_mr * ibv_reg_mr(struct ibv_pd * pd, void * addr, size_t length, int access);
int ibv_dereg_mr(struct ibv_mr * mr);
int ibv_post_recv(struct ibv_qp * qp, struct ibv_recv_wr * wr, struct ibv_recv_wr ** bad);
int ibv_post_send(struct ibv_qp * qp, struct ibv_send_wr * wr, struct ibv_send_wr ** bad);
int ibv_poll_cq(struct ibv_cq * cq, int n, struct ibv_wc * wc);
int ibv_req_notify_cq(struct ibv_cq * cq, int solicited);
const char * ibv_wc_status_str(int status);

#ifdef __cplusplus
}
#endif
