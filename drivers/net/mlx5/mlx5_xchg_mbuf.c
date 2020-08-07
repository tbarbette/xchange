#include <rte_mbuf.h>
#include "mlx5_rxtx.h"
#include "mlx5_xchg.h"

#include "mlx5_rxtx_common.h"
#include "mlx5_rxtx_common.c"

    inline struct rte_mbuf* get_buf(struct xchg* x) {
        return (struct rte_mbuf*)x;
    }

    void xchg_set_buffer(struct xchg* xchg, void* buf) {
        (void)xchg;
        (void)buf;
    }

    void xchg_set_packet_type(struct xchg* xchg, uint32_t ptype) {
        get_buf(xchg)->packet_type = ptype;
    }

    void xchg_set_rss_hash(struct xchg* xchg, uint32_t rss) {
        get_buf(xchg)->hash.rss = rss;
    }

    void xchg_set_timestamp(struct xchg* xchg, uint64_t t) {
        get_buf(xchg)->timestamp = t;
    }

    void xchg_set_flag(struct xchg* xchg, uint64_t f) {
        get_buf(xchg)->ol_flags |= f;
    }

    uint64_t xchg_get_flags(struct xchg* xchg) {
        return get_buf(xchg)->ol_flags;
    }

    uint16_t xchg_get_outer_l2_len(struct xchg* xchg) {
        return get_buf(xchg)->outer_l2_len;
    }

    uint16_t xchg_get_outer_l3_len(struct xchg* xchg) {
        return get_buf(xchg)->outer_l3_len;
    }

// int xchg_has_flag(struct xchg* xchg, uint64_t f) {
//       return get_buf(xchg)->ol_flags & f;
//    }

    void xchg_clear_flag(struct xchg* xchg, uint64_t f) {
        get_buf(xchg)->ol_flags &= f;
    }

    void xchg_set_fdir_id(struct xchg* xchg, uint32_t mark) {
        get_buf(xchg)->hash.fdir.hi = mark;
    }

    void xchg_set_vlan(struct xchg* xchg, uint32_t vlan) {
        get_buf(xchg)->vlan_tci = vlan;
    }

    uint32_t xchg_get_vlan(struct xchg* xchg) {
        return get_buf(xchg)->vlan_tci;
    }


    void xchg_set_len(struct xchg* xchg, uint16_t len) {
        PKT_LEN(get_buf(xchg)) = len;
    }

    uint16_t xchg_get_data_len(struct xchg* xchg) {
        return DATA_LEN(get_buf(xchg));
    }

    void xchg_set_data_len(struct xchg* xchg, uint16_t len) {
        DATA_LEN(get_buf(xchg)) = len;
    }

    uint16_t xchg_get_len(struct xchg* xchg) {
        return PKT_LEN(get_buf(xchg));
    }

    void xchg_finish_packet(struct xchg* xchg) {
        (void)xchg;
    }

    /**
     * Take a packet from the ring and replace it by a new one
     */
    struct xchg* xchg_next(struct rte_mbuf** pkt, struct xchg** xchgs, struct rte_mempool* mp) {
        (void) xchgs; //Mbuf is set on advance
        struct rte_mbuf* xchg = *pkt; //Buffer in the ring
		rte_prefetch0(xchg);
        *pkt = rte_mbuf_raw_alloc(mp); //Allocate packet to put back in the ring 
        return (struct xchg*)xchg;
    }

    void xchg_cancel(struct xchg* xchg, struct rte_mbuf* pkt) {
        (void)xchg;
        rte_mbuf_raw_free(pkt);
    }

    void xchg_advance(struct xchg* xchg, struct xchg*** xchgs_p) {
        struct xchg** xchgs = *xchgs_p;
        *(xchgs++) = xchg; //Set in the user pointer the buffer from the ring
        *xchgs_p = xchgs;
    }
    void* xchg_buffer_from_elt(struct rte_mbuf* elt) {
        return rte_pktmbuf_mtod(elt, void*);
    }

    void xchg_tx_completed(struct rte_mbuf** elts, unsigned int part, unsigned int olx) {
        mlx5_tx_free_mbuf(elts, part, olx);
    }



    struct xchg* xchg_tx_next(struct xchg** xchgs) {
        struct rte_mbuf** pkts = (struct rte_mbuf**)xchgs;
        struct rte_mbuf* pkt = *(pkts);
        rte_prefetch0(pkt);
        return (struct xchg*)pkt;
    }

    int xchg_nb_segs(struct xchg* xchg) {
        struct rte_mbuf* pkt = (struct rte_mbuf*) xchg;
        return NB_SEGS(pkt);
    }

    bool xchg_do_tx_free = true;
 
    void xchg_tx_advance(struct xchg*** xchgs_p) { 
        struct rte_mbuf** pkts = (struct rte_mbuf**)(*xchgs_p);
        //printf("Advance : %p -> %p = %p\n", pkts, pkts+1, *(pkts+1));
        pkts += 1;
        *xchgs_p = (struct xchg**)pkts;

    }

    void* xchg_get_buffer_addr(struct xchg* xchg) {
        struct rte_mbuf* pkt = (struct rte_mbuf*) xchg;
        return pkt->buf_addr;
    }

    void* xchg_get_buffer(struct xchg* xchg) {
        struct rte_mbuf* pkt = (struct rte_mbuf*) xchg;
        return rte_pktmbuf_mtod(pkt, void *);
    }

    struct rte_mbuf* xchg_get_mbuf(struct xchg* xchg) {
        return get_buf(xchg);
    }

    void xchg_tx_sent_inline(struct xchg* xchg) { 
        struct rte_mbuf* pkt = (struct rte_mbuf*) xchg;

        //printf("INLINED %p\n", xchg);
        rte_pktmbuf_free_seg(pkt);
    }

    void xchg_tx_sent(struct rte_mbuf** elts, struct xchg** xchg) {
        //printf("SENT %p\n", *xchg);
        *elts= (struct rte_mbuf*)*xchg;
    }

    void xchg_tx_sent_vec(struct rte_mbuf** elts, struct xchg** xchg, unsigned n) {
//        for (unsigned i = 0; i < n; i++) 
            //printf("SENTV %p\n", ((struct rte_mbuf**)xchg)[i]);
        rte_memcpy((void *)elts, (void*) xchg, n * sizeof(struct rte_mbuf*));     
    }

    bool xchg_elts_vec = true;
    
