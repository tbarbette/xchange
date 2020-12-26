/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_xchg.h>

#include "main.h"

//RX and common

	/**
     * An internal helper to cast the xchg* pointer to the WritablePacket* pointer.
     */
    static inline struct my_xchg* get_buf(struct xchg* x) {
        return (struct my_xchg*)x;
    }

    //Set data_length (the actual packet length)
    void xchg_set_data_len(struct xchg* xchg, uint16_t len) {
        get_buf(xchg)->plen = len;
    }

    //Return the buffer length.
    uint16_t xchg_get_len(struct xchg* xchg) {
        (void)xchg;
        return RTE_MBUF_DEFAULT_BUF_SIZE;
    }

    //This functions is called "at the end of the for loop", when the driver has finished
    //with a packet, and will start reading the next one. It's a chance to wrap up what we
    //need to do.
    //In this case we prefetch the packet data, and set a few Click stuffs.
    void xchg_finish_packet(struct xchg* xchg) {
        rte_prefetch0(get_buf(xchg)->buffer);
    }

    /**
     * This function is called by the driver to advance in the RX ring.
     * Set a new buffer to replace in the ring if not canceled, and return the next descriptor
     */
    struct xchg* xchg_next(struct rte_mbuf** rep, struct xchg** xchgs, struct rte_mempool* mp) {
        struct my_xchg* first = (struct my_xchg*)*xchgs;
        //printf("First %p, xchgs* %p\n",first,xchgs);

        void* fresh_buf;
        if (unlikely(first->buffer == 0)) {
            //Sometime, the user does not give us a buffer to exchange, typically at initialization
            fresh_buf = rte_mbuf_raw_alloc(mp)->buf_addr;
        } else {
            //We'll take the address of the buffer and put that in the ring
            fresh_buf = ((uint8_t*)first->buffer) - RTE_PKTMBUF_HEADROOM;
        }

        //While the freshly received buffer with the new packet data
        unsigned char* buffer = ((uint8_t*)*rep) + sizeof(struct rte_mbuf);

        //We set the address in the ring
        *rep = (struct rte_mbuf*)(((unsigned char*)fresh_buf) - sizeof(struct rte_mbuf));

        //We set the address of the new buffer data in the Packet object
        first->buffer = buffer + RTE_PKTMBUF_HEADROOM;

        return (struct xchg*)first;
    }

    /**
     * Cancel the current receiving, this should cancel the last xchg_next.
     */
    void xchg_cancel(struct xchg* xchg, struct rte_mbuf* rep) {
        xchg->buffer = ((unsigned char*)rep) + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
    }

    /**
     * Pops the packet of the user provided buffers
     * Not much to do, the buffer have been already swapped above
     */
    void xchg_advance(struct xchg* xchg, struct xchg*** xchgs_p) {

        struct xchg** xchgs = *xchgs_p;
        //printf("Advance! %p = %p -> %p = %p\n",xchgs,*xchgs, xchgs+1,*(xchgs+1));
        xchgs++;

        *xchgs_p = xchgs;
    }

//TX
    //Little function to make the cast easier
    static inline struct my_xchg* get_tx_buf(struct xchg* x) {
        return (struct my_xchg*)x;
    }

    //Return the real data length (as opposed to the buffer length, which is probably a constant)
    uint16_t xchg_get_data_len(struct xchg* xchg) {
        return get_tx_buf(xchg)->plen;
    }

    //Nothing to do here
    void xchg_tx_completed(struct rte_mbuf** elts, unsigned int part, unsigned int olx) {
        //mlx5_tx_free_mbuf(elts, part, olx);
    }

    //This was a flag used for testing/research purpose, in XCHG we never "free" the transmitted user, we give it back to the application
    bool xchg_do_tx_free = false;

    //Peek the next packet to be sent, do not advance yet
    struct xchg* xchg_tx_next(struct xchg** xchgs) {
        struct my_xchg** p = (struct my_xchg**)xchgs;
        struct my_xchg* pkt = *p;
        rte_prefetch0(pkt);
        return (struct xchg*)pkt;
    }

    //Return the number of segments, 1 in this app
    int xchg_nb_segs(struct xchg* xchg) {
        //struct rte_mbuf* pkt = (struct rte_mbuf*) xchg;
        return 1; //NB_SEGS(pkt);
    }

    /* Advance in the list of packets, that is now permanently moved by one.*/
    void xchg_tx_advance(struct xchg*** xchgs_p) {
        struct my_xchg** pkts = (struct my_xchg**)(*xchgs_p);
        *xchgs_p = pkts + 1;

    }

    // Return the packet buffer address (not the data)
    void* xchg_get_buffer_addr(struct xchg* xchg) {
        struct my_xchg* p = get_tx_buf(xchg);
        return p->buffer - RTE_PKTMBUF_HEADROOM; //Beauty of this : this app is not changing the headroom. So we avoid some field
    }

    // Return the address of the packet buffer
    void* xchg_get_buffer(struct xchg* xchg) {
        return get_tx_buf(xchg)->buffer;
    }

    // Return the mbuf backing the buffer, try not to touch it! This function should be copy-pasted
    struct rte_mbuf* xchg_get_mbuf(struct xchg* xchg) {
        return (struct rte_mbuf*)(((uint8_t*)xchg_get_buffer_addr(xchg)) - sizeof(struct rte_mbuf));
    }

    // The packet was sent inline, therefore no buffer is set up in the ring to be recovered later
    void xchg_tx_sent_inline(struct xchg* xchg) {

    }

    // Normal sending of the packet the mbuf backing the buffer of xchg must be set in elts
    void xchg_tx_sent(struct rte_mbuf** elts, struct xchg** xchgs) {
        struct rte_mbuf* tmp = *elts;
        struct rte_mbuf* mbuf = xchg_get_mbuf(*xchgs);
        *elts = mbuf;
        if (tmp == 0) {
             get_tx_buf(*xchgs)->buffer = 0;
         }else
         {
            get_tx_buf(*xchgs)->buffer = ((uint8_t*)tmp) + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
         }
    }

    //This is a testing/research parameter, it should always be false as in a XCHG driver, there's no reason to wait before doing the exchange of buffers
    bool xchg_elts_vec = false;

    void xchg_tx_sent_vec(struct rte_mbuf** elts, struct xchg** xchg, unsigned n) {
        assert(false);
    }

/**
 * All the unused stuffs we don't use, let the compiler remove that and inline the default case!
 */

    void xchg_set_packet_type(struct xchg* xchg, uint32_t ptype) {};

    void xchg_set_rss_hash(struct xchg* xchg, uint32_t rss) {};

    void xchg_set_timestamp(struct xchg* xchg, uint64_t t) {};

    void xchg_set_flag(struct xchg* xchg, uint64_t f) {};

    void xchg_clear_flag(struct xchg* xchg, uint64_t f) {};

    void xchg_set_fdir_id(struct xchg* xchg, uint32_t mark) {};

    void xchg_set_vlan(struct xchg* xchg, uint32_t vlan) {};

    void xchg_set_len(struct xchg* xchg, uint16_t len) {};

    //Author say this should not change, so this should not change
    void* xchg_buffer_from_elt(struct rte_mbuf* buf) {
        return ((unsigned char*)buf) + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
    };
