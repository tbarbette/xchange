#include "mlx5_rxtx.h"
#include <rte_xchg.h>

#include "mlx5_rxtx_common.h"
#include "mlx5_rxtx_common.c"


__extension__
struct mlx5_txq_xchg_local {
	struct mlx5_wqe *wqe_last; /* last sent WQE pointer. */
    struct xchg** xchgs;
	struct xchg *next; /* first mbuf to process. */
	uint16_t pkts_copy; /* packets copied to elts. */
	uint16_t pkts_sent; /* packets sent. */
	uint16_t pkts_loop; /* packets sent on loop entry. */
	uint16_t elts_free; /* available elts remain. */
	uint16_t wqe_free; /* available wqe remain. */
	uint16_t mbuf_off; /* data offset in current mbuf. */
	uint16_t mbuf_nseg; /* number of remaining mbuf. */
};



/**
 * Fill in xchg fields from RX completion flags.
 * Note that pkt->ol_flags should be initialized outside of this function.
 *
 * @param rxq
 *   Pointer to RX queue.
 * @param pkt
 *   xchg to fill.
 * @param cqe
 *   CQE to process.
 * @param rss_hash_res
 *   Packet RSS Hash result.
 */
static inline void
rxq_cq_to_xchg(struct mlx5_rxq_data *rxq, struct xchg *xchg,
	       volatile struct mlx5_cqe *cqe, uint32_t rss_hash_res)
{
	/* Update packet information. */
	xchg_set_packet_type(xchg, rxq_cq_to_pkt_type(rxq, cqe));
	if (rss_hash_res && rxq->rss_hash) {
		xchg_set_rss_hash(xchg, rss_hash_res);
		xchg_set_flag(xchg, PKT_RX_RSS_HASH);
	}
	if (rxq->mark && MLX5_FLOW_MARK_IS_VALID(cqe->sop_drop_qpn)) {
		xchg_set_flag(xchg, PKT_RX_FDIR);
		if (cqe->sop_drop_qpn !=
		    rte_cpu_to_be_32(MLX5_FLOW_MARK_DEFAULT)) {
			uint32_t mark = cqe->sop_drop_qpn;

    		xchg_set_flag(xchg, PKT_RX_FDIR_ID);
			xchg_set_fdir_id(xchg, mlx5_flow_mark_get(mark));
		}
	}
/*	if (rte_flow_dynf_metadata_avail() && cqe->flow_table_metadata) {
		pkt->ol_flags |= PKT_RX_DYNF_METADATA;
		*RTE_FLOW_DYNF_METADATA(pkt) = cqe->flow_table_metadata;
	}*/
	if (rxq->csum)
    	xchg_set_flag(xchg, rxq_cq_to_ol_flags(cqe));
	if (rxq->vlan_strip &&
	    (cqe->hdr_type_etc & rte_cpu_to_be_16(MLX5_CQE_VLAN_STRIPPED))) {
//		pkt->ol_flags |= 
        xchg_set_flag(xchg, PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED);
		xchg_set_vlan(xchg, rte_be_to_cpu_16(cqe->vlan_info));
	}
	if (rxq->hw_timestamp) {
		xchg_set_timestamp(xchg, rte_be_to_cpu_64(cqe->timestamp));
    	xchg_set_flag(xchg, PKT_RX_TIMESTAMP);
	}
}


/**
 * DPDK callback for RX.
 *
 * @param dpdk_rxq
 *   Generic pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= pkts_n).
 */
uint16_t
mlx5_rx_burst_xchg(void *dpdk_rxq, struct xchg **xchgs, uint16_t pkts_n)
{
	struct mlx5_rxq_data *rxq = (struct mlx5_rxq_data*)dpdk_rxq;
	const unsigned int wqe_cnt = (1 << rxq->elts_n) - 1;
	const unsigned int cqe_cnt = (1 << rxq->cqe_n) - 1;
	const unsigned int sges_n = rxq->sges_n;

	volatile struct mlx5_cqe *cqe =
		&(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
	unsigned int i = 0;
	unsigned int rq_ci = rxq->rq_ci << sges_n;
	int len = 0; /* keep its value across iterations. */

	while (pkts_n) {
		unsigned int idx = rq_ci & wqe_cnt;
		volatile struct mlx5_wqe_data_seg *wqe =
			&((volatile struct mlx5_wqe_data_seg *)rxq->wqes)[idx];
		volatile struct mlx5_mini_cqe8 *mcqe = NULL;
		uint32_t rss_hash_res;
        struct rte_mbuf* rep = (*rxq->elts)[idx];
        struct xchg* xchg = xchg_next(&rep, xchgs, rxq->mp);
		rte_prefetch0(cqe);
		rte_prefetch0(wqe);
		if (unlikely(xchg == NULL)) {
			++rxq->stats.rx_nombuf;
			break;
		}
        cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
        len = mlx5_rx_poll_len(rxq, cqe, cqe_cnt, &mcqe);
        if (!len) {
            xchg_cancel(xchg, rep);
            break;
        }
        xchg_advance(xchg, &xchgs);
        MLX5_ASSERT(len >= (rxq->crc_present << 2));
        xchg_clear_flag(xchg, EXT_ATTACHED_MBUF);
        /* If compressed, take hash result from mini-CQE. */
        rss_hash_res = rte_be_to_cpu_32(mcqe == NULL ?
                        cqe->rx_hash_res :
                        mcqe->rx_hash_result);
        rxq_cq_to_xchg(rxq, xchg, cqe, rss_hash_res);
        if (rxq->crc_present)
            len -= RTE_ETHER_CRC_LEN;
        xchg_set_len(xchg, len);
/*        if (cqe->lro_num_seg > 1) {
            mlx5_lro_update_hdr
                (rte_pktmbuf_mtod(pkt, uint8_t *), cqe,
                 len);
            xchg->ol_flags |= PKT_RX_LRO;
            xchg->tso_segsz = len / cqe->lro_num_seg;
        }*/
//		struct rte_mbuf* seg = (struct rte_mbuf*)xchg;
//		DATA_LEN(rep) = DATA_LEN(seg);
//		PKT_LEN(rep) = PKT_LEN(seg);
//		SET_DATA_OFF(rep, DATA_OFF(seg));
//		PORT(rep) = PORT(seg);
        /*
		 * Fill NIC descriptor with the new buffer.  The lkey and size
		 * of the buffers are already known, only the buffer address
		 * changes.
		 */
        (*rxq->elts)[idx] = rep;
	    wqe->addr = rte_cpu_to_be_64((uintptr_t)xchg_buffer_from_elt(rep));

		/* If there's only one MR, no need to replace LKey in WQE. */
		if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1))
            assert(false);
//			wqe->lkey = mlx5_rx_mb2mr(rxq, rep);
		xchg_set_data_len(xchg, len);
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Increment bytes counter. */
		rxq->stats.ibytes += xchg_get_len(xchg);
#endif
        xchg_finish_packet(xchg);
		/* Return packet. */
		--pkts_n;
		++i;
		/* Align consumer index to the next stride. */
		rq_ci >>= sges_n;
		++rq_ci;
		rq_ci <<= sges_n;
	}
	if (unlikely((i == 0) && ((rq_ci >> sges_n) == rxq->rq_ci)))
		return 0;
	/* Update the consumer index. */
	rxq->rq_ci = rq_ci >> sges_n;
	rte_cio_wmb();
	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	rte_cio_wmb();
	*rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Increment packets counter. */
	rxq->stats.ipackets += i;
#endif
	return i;
}


/**
 * DPDK callback for RX.
 *
 * @param dpdk_rxq
 *   Generic pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 *
 * @return
 *   Number of packets successfully received (<= pkts_n).
 */
uint16_t
mlx5_rx_burst_stripped(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n)
{
	struct mlx5_rxq_data *rxq = (struct mlx5_rxq_data*)dpdk_rxq;
	const unsigned int wqe_cnt = (1 << rxq->elts_n) - 1;
	const unsigned int cqe_cnt = (1 << rxq->cqe_n) - 1;
	const unsigned int sges_n = rxq->sges_n;
	struct rte_mbuf *pkt = NULL;
	struct rte_mbuf *seg = NULL;
	volatile struct mlx5_cqe *cqe =
		&(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
	unsigned int i = 0;
	unsigned int rq_ci = rxq->rq_ci << sges_n;
	int len = 0; /* keep its value across iterations. */

	while (pkts_n) {
		unsigned int idx = rq_ci & wqe_cnt;
		volatile struct mlx5_wqe_data_seg *wqe =
			&((volatile struct mlx5_wqe_data_seg *)rxq->wqes)[idx];
		struct rte_mbuf *rep = (*rxq->elts)[idx];
		volatile struct mlx5_mini_cqe8 *mcqe = NULL;
		uint32_t rss_hash_res;
#ifdef MLX5_PMD_MULTISEG
		if (pkt)
			NEXT(seg) = rep;
#endif
		seg = rep;
		rte_prefetch0(seg);
		rte_prefetch0(cqe);
		rte_prefetch0(wqe);
		rep = rte_mbuf_raw_alloc(rxq->mp);
		if (unlikely(rep == NULL)) {
			++rxq->stats.rx_nombuf;
#ifdef MLX5_PMD_MULTISEG
			if (!pkt) {
				/*
				 * no buffers before we even started,
				 * bail out silently.
				 */
				break;
			}
			while (pkt != seg) {
				MLX5_ASSERT(pkt != (*rxq->elts)[idx]);
				rep = NEXT(pkt);
				NEXT(pkt) = NULL;
				NB_SEGS(pkt) = 1;
				rte_mbuf_raw_free(pkt);
				pkt = rep;
			}
#endif
			break;
		}
		if (!pkt) {
			cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
			len = mlx5_rx_poll_len(rxq, cqe, cqe_cnt, &mcqe);
			if (!len) {
				rte_mbuf_raw_free(rep);
				break;
			}
			pkt = seg;
			MLX5_ASSERT(len >= (rxq->crc_present << 2));
			pkt->ol_flags &= EXT_ATTACHED_MBUF;
			/* If compressed, take hash result from mini-CQE. */
			rss_hash_res = rte_be_to_cpu_32(mcqe == NULL ?
							cqe->rx_hash_res :
							mcqe->rx_hash_result);
			rxq_cq_to_mbuf(rxq, pkt, cqe, rss_hash_res);
			if (rxq->crc_present)
				len -= RTE_ETHER_CRC_LEN;
			PKT_LEN(pkt) = len;
/*			if (cqe->lro_num_seg > 1) {
				mlx5_lro_update_hdr
					(rte_pktmbuf_mtod(pkt, uint8_t *), cqe,
					 len);
				pkt->ol_flags |= PKT_RX_LRO;
				pkt->tso_segsz = len / cqe->lro_num_seg;
			}*/
		}
		DATA_LEN(rep) = DATA_LEN(seg);
		PKT_LEN(rep) = PKT_LEN(seg);
		SET_DATA_OFF(rep, DATA_OFF(seg));
		PORT(rep) = PORT(seg);
		(*rxq->elts)[idx] = rep;
		/*
		 * Fill NIC descriptor with the new buffer.  The lkey and size
		 * of the buffers are already known, only the buffer address
		 * changes.
		 */
		wqe->addr = rte_cpu_to_be_64(rte_pktmbuf_mtod(rep, uintptr_t));
		/* If there's only one MR, no need to replace LKey in WQE. */
		if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1))
			wqe->lkey = mlx5_rx_mb2mr(rxq, rep);
#ifdef MLX5_PMD_MULTISEG
		if (len > DATA_LEN(seg)) {
			len -= DATA_LEN(seg);
			++NB_SEGS(pkt);
			++rq_ci;
			continue;
i		}
#endif
		DATA_LEN(seg) = len;
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Increment bytes counter. */
		rxq->stats.ibytes += PKT_LEN(pkt);
#endif
		/* Return packet. */
		*(pkts++) = pkt;
#ifdef MLX5_PMD_MULTISEG
		pkt = NULL;
#endif
		--pkts_n;
		++i;
		/* Align consumer index to the next stride. */
		rq_ci >>= sges_n;
		++rq_ci;
		rq_ci <<= sges_n;
	}
	if (unlikely((i == 0) && ((rq_ci >> sges_n) == rxq->rq_ci)))
		return 0;
	/* Update the consumer index. */
	rxq->rq_ci = rq_ci >> sges_n;
	rte_cio_wmb();
	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	rte_cio_wmb();
	*rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Increment packets counter. */
	rxq->stats.ipackets += i;
#endif
	return i;
}

/**
 * Analyze the packet and select the best method to send.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param loc
 *   Pointer to burst routine local context.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 * @param newp
 *   The predefined flag whether do complete check for
 *   multi-segment packets and TSO.
 *
 * @return
 *  MLX5_TXCMP_CODE_MULTI - multi-segment packet encountered.
 *  MLX5_TXCMP_CODE_TSO - TSO required, use TSO/LSO.
 *  MLX5_TXCMP_CODE_SINGLE - single-segment packet, use SEND.
 *  MLX5_TXCMP_CODE_EMPW - single-segment packet, use MPW.
 */
static __rte_always_inline enum mlx5_txcmp_code
mlx5_tx_xchg_able_to_empw(struct mlx5_txq_data *restrict txq,
		     struct mlx5_txq_xchg_local *restrict loc,
		     unsigned int olx,
		     bool newp)
{
	/* Check for multi-segment packet. */
	if (newp &&
	    MLX5_TXOFF_CONFIG(MULTI) &&
	    unlikely(xchg_nb_segs(loc->next) > 1))
		return MLX5_TXCMP_CODE_MULTI;
	/* Check for TSO packet. */
	if (newp &&
	    MLX5_TXOFF_CONFIG(TSO) &&
	    unlikely(xchg_has_flag(loc->next, PKT_TX_TCP_SEG)))
		return MLX5_TXCMP_CODE_TSO;
	/* Check if eMPW is enabled at all. */
	if (!MLX5_TXOFF_CONFIG(EMPW))
		return MLX5_TXCMP_CODE_SINGLE;
	/* Check if eMPW can be engaged. */
	if (MLX5_TXOFF_CONFIG(VLAN) &&
	    unlikely(xchg_has_flag(loc->next, PKT_TX_VLAN_PKT)) &&
		(!MLX5_TXOFF_CONFIG(INLINE) ||
		 unlikely((xchg_get_data_len(loc->next) +
			   sizeof(struct rte_vlan_hdr)) > txq->inlen_empw))) {
		/*
		 * eMPW does not support VLAN insertion offload,
		 * we have to inline the entire packet but
		 * packet is too long for inlining.
		 */
		return MLX5_TXCMP_CODE_SINGLE;
	}
	return MLX5_TXCMP_CODE_EMPW;
}

/**
 * Set Software Parser flags and offsets in Ethernet Segment of WQE.
 * Flags must be preliminary initialized to zero.
 *
 * @param loc
 *   Pointer to burst routine local context.
 * @param swp_flags
 *   Pointer to store Software Parser flags
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 *
 * @return
 *   Software Parser offsets packed in dword.
 *   Software Parser flags are set by pointer.
 */
static __rte_always_inline uint32_t
txq_xchg_to_swp(struct mlx5_txq_xchg_local *restrict loc,
		uint8_t *swp_flags,
		unsigned int olx)
{
	uint64_t ol, tunnel;
	unsigned int idx, off;
	uint32_t set;

	if (!MLX5_TXOFF_CONFIG(SWP))
		return 0;
	ol = xchg_get_flags(loc->next);
	tunnel = ol & PKT_TX_TUNNEL_MASK;
	/*
	 * Check whether Software Parser is required.
	 * Only customized tunnels may ask for.
	 */
	if (likely(tunnel != PKT_TX_TUNNEL_UDP && tunnel != PKT_TX_TUNNEL_IP))
		return 0;
	/*
	 * The index should have:
	 * bit[0:1] = PKT_TX_L4_MASK
	 * bit[4] = PKT_TX_IPV6
	 * bit[8] = PKT_TX_OUTER_IPV6
	 * bit[9] = PKT_TX_OUTER_UDP
	 */
	idx = (ol & (PKT_TX_L4_MASK | PKT_TX_IPV6 | PKT_TX_OUTER_IPV6)) >> 52;
	idx |= (tunnel == PKT_TX_TUNNEL_UDP) ? (1 << 9) : 0;
	*swp_flags = mlx5_swp_types_table[idx];
	/*
	 * Set offsets for SW parser. Since ConnectX-5, SW parser just
	 * complements HW parser. SW parser starts to engage only if HW parser
	 * can't reach a header. For the older devices, HW parser will not kick
	 * in if any of SWP offsets is set. Therefore, all of the L3 offsets
	 * should be set regardless of HW offload.
	 */
	off = xchg_get_outer_l2_len(loc->next);
	if (MLX5_TXOFF_CONFIG(VLAN) && ol & PKT_TX_VLAN_PKT)
		off += sizeof(struct rte_vlan_hdr);
	set = (off >> 1) << 8; /* Outer L3 offset. */
	off += xchg_get_outer_l3_len(loc->next);
	if (tunnel == PKT_TX_TUNNEL_UDP)
		set |= off >> 1; /* Outer L4 offset. */
	if (ol & (PKT_TX_IPV4 | PKT_TX_IPV6)) { /* Inner IP. */
		const uint64_t csum = ol & PKT_TX_L4_MASK;
			off += xchg_get_outer_l2_len(loc->next);
		set |= (off >> 1) << 24; /* Inner L3 offset. */
		if (csum == PKT_TX_TCP_CKSUM ||
		    csum == PKT_TX_UDP_CKSUM ||
		    (MLX5_TXOFF_CONFIG(TSO) && ol & PKT_TX_TCP_SEG)) {
			off += xchg_get_outer_l3_len(loc->next);
			set |= (off >> 1) << 16; /* Inner L4 offset. */
		}
	}
	set = rte_cpu_to_le_32(set);
	return set;
}

/**
 * Build the Ethernet Segment without inlined data.
 * Supports Software Parser, Checksums and VLAN
 * insertion Tx offload features.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param loc
 *   Pointer to burst routine local context.
 * @param wqe
 *   Pointer to WQE to fill with built Ethernet Segment.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 */
static __rte_always_inline void
mlx5_tx_xchg_eseg_none(struct mlx5_txq_data *restrict txq __rte_unused,
		  struct mlx5_txq_xchg_local *restrict loc,
		  struct mlx5_wqe *restrict wqe,
		  unsigned int olx)
{
	struct mlx5_wqe_eseg *restrict es = &wqe->eseg;
	uint32_t csum;

	/*
	 * Calculate and set check sum flags first, dword field
	 * in segment may be shared with Software Parser flags.
	 */
	csum = MLX5_TXOFF_CONFIG(CSUM) ? txq_ol_cksum_to_cs(xchg_get_flags(loc->next)) : 0;
	es->flags = rte_cpu_to_le_32(csum);
	/*
	 * Calculate and set Software Parser offsets and flags.
	 * These flags a set for custom UDP and IP tunnel packets.
	 */
	es->swp_offs = txq_xchg_to_swp(loc, &es->swp_flags, olx);
	/* Fill metadata field if needed. */
	/*es->metadata = MLX5_TXOFF_CONFIG(METADATA) ?
		       xchg_get_flags(loc->next) & PKT_TX_DYNF_METADATA ?
		       *RTE_FLOW_DYNF_METADATA(loc->mbuf) : 0 : 0;*/
	/* Engage VLAN tag insertion feature if requested. */
	if (MLX5_TXOFF_CONFIG(VLAN) &&
	    xchg_get_flags(loc->next) & PKT_TX_VLAN_PKT) {
		/*
		 * We should get here only if device support
		 * this feature correctly.
		 */
		MLX5_ASSERT(txq->vlan_en);
		es->inline_hdr = rte_cpu_to_be_32(MLX5_ETH_WQE_VLAN_INSERT |
						  xchg_get_vlan(loc->next));
	} else {
		es->inline_hdr = RTE_BE32(0);
	}
}

/**
 * Build the Ethernet Segment with minimal inlined data
 * of MLX5_ESEG_MIN_INLINE_SIZE bytes length. This is
 * used to fill the gap in single WQEBB WQEs.
 * Supports Software Parser, Checksums and VLAN
 * insertion Tx offload features.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param loc
 *   Pointer to burst routine local context.
 * @param wqe
 *   Pointer to WQE to fill with built Ethernet Segment.
 * @param vlan
 *   Length of VLAN tag insertion if any.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 */
static __rte_always_inline void
mlx5_tx_eseg_dmin(struct mlx5_txq_data *restrict txq __rte_unused,
		  struct mlx5_txq_xchg_local *restrict loc,
		  struct mlx5_wqe *restrict wqe,
		  unsigned int vlan,
		  unsigned int olx)
{
	struct mlx5_wqe_eseg *restrict es = &wqe->eseg;
	uint32_t csum;
	uint8_t *psrc, *pdst;

	/*
	 * Calculate and set check sum flags first, dword field
	 * in segment may be shared with Software Parser flags.
	 */
	csum = MLX5_TXOFF_CONFIG(CSUM) ? txq_ol_cksum_to_cs(xchg_get_flags(loc->next)) : 0;
	es->flags = rte_cpu_to_le_32(csum);
	/*
	 * Calculate and set Software Parser offsets and flags.
	 * These flags a set for custom UDP and IP tunnel packets.
	 */
	es->swp_offs = txq_xchg_to_swp(loc, &es->swp_flags, olx);
	/* Fill metadata field if needed. */
	/*es->metadata = MLX5_TXOFF_CONFIG(METADATA) ?
		       xchg_get_flags(loc->next) & PKT_TX_DYNF_METADATA ?
		       *RTE_FLOW_DYNF_METADATA(loc->mbuf) : 0 : 0;*/
	static_assert(MLX5_ESEG_MIN_INLINE_SIZE ==
				(sizeof(uint16_t) +
				 sizeof(rte_v128u32_t)),
		      "invalid Ethernet Segment data size");
	static_assert(MLX5_ESEG_MIN_INLINE_SIZE ==
				(sizeof(uint16_t) +
				 sizeof(struct rte_vlan_hdr) +
				 2 * RTE_ETHER_ADDR_LEN),
		      "invalid Ethernet Segment data size");
	psrc = xchg_get_buffer(loc->next);
	es->inline_hdr_sz = RTE_BE16(MLX5_ESEG_MIN_INLINE_SIZE);
	es->inline_data = *(unaligned_uint16_t *)psrc;
	psrc +=	sizeof(uint16_t);
	pdst = (uint8_t *)(es + 1);
	if (MLX5_TXOFF_CONFIG(VLAN) && vlan) {
		/* Implement VLAN tag insertion as part inline data. */
		memcpy(pdst, psrc, 2 * RTE_ETHER_ADDR_LEN - sizeof(uint16_t));
		pdst += 2 * RTE_ETHER_ADDR_LEN - sizeof(uint16_t);
		psrc +=	2 * RTE_ETHER_ADDR_LEN - sizeof(uint16_t);
		/* Insert VLAN ethertype + VLAN tag. */
		*(unaligned_uint32_t *)pdst = rte_cpu_to_be_32
						((RTE_ETHER_TYPE_VLAN << 16) |
						 xchg_get_vlan(loc->next));
		pdst += sizeof(struct rte_vlan_hdr);
		/* Copy the rest two bytes from packet data. */
		MLX5_ASSERT(pdst == RTE_PTR_ALIGN(pdst, sizeof(uint16_t)));
		*(uint16_t *)pdst = *(unaligned_uint16_t *)psrc;
	} else {
		/* Fill the gap in the title WQEBB with inline data. */
		rte_mov16(pdst, psrc);
	}
}

/**
 * Build the Ethernet Segment with entire packet
 * data inlining. Checks the boundary of WQEBB and
 * ring buffer wrapping, supports Software Parser,
 * Checksums and VLAN insertion Tx offload features.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param loc
 *   Pointer to burst routine local context.
 * @param wqe
 *   Pointer to WQE to fill with built Ethernet Segment.
 * @param vlan
 *   Length of VLAN tag insertion if any.
 * @param inlen
 *   Length of data to inline (VLAN included, if any).
 * @param tso
 *   TSO flag, set mss field from the packet.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 *
 * @return
 *   Pointer to the next Data Segment (aligned and wrapped around).
 */
static __rte_always_inline struct mlx5_wqe_dseg *
mlx5_tx_eseg_data(struct mlx5_txq_data *restrict txq,
		  struct mlx5_txq_xchg_local *restrict loc,
		  struct mlx5_wqe *restrict wqe,
		  unsigned int vlan,
		  unsigned int inlen,
		  unsigned int tso,
		  unsigned int olx)
{
	struct mlx5_wqe_eseg *restrict es = &wqe->eseg;
	uint32_t csum;
	uint8_t *psrc, *pdst;
	unsigned int part;

	/*
	 * Calculate and set check sum flags first, dword field
	 * in segment may be shared with Software Parser flags.
	 */
	csum = MLX5_TXOFF_CONFIG(CSUM) ? txq_ol_cksum_to_cs(xchg_get_flags(loc->next)) : 0;
	if (tso) {
		csum <<= 24;
		csum |= xchg_get_tsosz(loc->next);
		es->flags = rte_cpu_to_be_32(csum);
	} else {
		es->flags = rte_cpu_to_le_32(csum);
	}
	/*
	 * Calculate and set Software Parser offsets and flags.
	 * These flags a set for custom UDP and IP tunnel packets.
	 */
	es->swp_offs = txq_xchg_to_swp(loc, &es->swp_flags, olx);
	/* Fill metadata field if needed. */
	/*es->metadata = MLX5_TXOFF_CONFIG(METADATA) ?
		       xchg_get_flags(loc->next) & PKT_TX_DYNF_METADATA ?
		       *RTE_FLOW_DYNF_METADATA(loc->mbuf) : 0 : 0;*/
	static_assert(MLX5_ESEG_MIN_INLINE_SIZE ==
				(sizeof(uint16_t) +
				 sizeof(rte_v128u32_t)),
		      "invalid Ethernet Segment data size");
	static_assert(MLX5_ESEG_MIN_INLINE_SIZE ==
				(sizeof(uint16_t) +
				 sizeof(struct rte_vlan_hdr) +
				 2 * RTE_ETHER_ADDR_LEN),
		      "invalid Ethernet Segment data size");
	psrc = (uint8_t*)xchg_get_buffer(loc->next);
	es->inline_hdr_sz = rte_cpu_to_be_16(inlen);
	es->inline_data = *(unaligned_uint16_t *)psrc;
	psrc +=	sizeof(uint16_t);
	pdst = (uint8_t *)(es + 1);
	if (MLX5_TXOFF_CONFIG(VLAN) && vlan) {
		/* Implement VLAN tag insertion as part inline data. */
		memcpy(pdst, psrc, 2 * RTE_ETHER_ADDR_LEN - sizeof(uint16_t));
		pdst += 2 * RTE_ETHER_ADDR_LEN - sizeof(uint16_t);
		psrc +=	2 * RTE_ETHER_ADDR_LEN - sizeof(uint16_t);
		/* Insert VLAN ethertype + VLAN tag. */
		*(unaligned_uint32_t *)pdst = rte_cpu_to_be_32
						((RTE_ETHER_TYPE_VLAN << 16) |
						 xchg_get_vlan(loc->next));
		pdst += sizeof(struct rte_vlan_hdr);
		/* Copy the rest two bytes from packet data. */
		MLX5_ASSERT(pdst == RTE_PTR_ALIGN(pdst, sizeof(uint16_t)));
		*(uint16_t *)pdst = *(unaligned_uint16_t *)psrc;
		psrc += sizeof(uint16_t);
	} else {
		/* Fill the gap in the title WQEBB with inline data. */
		rte_mov16(pdst, psrc);
		psrc += sizeof(rte_v128u32_t);
	}
	pdst = (uint8_t *)(es + 2);
	MLX5_ASSERT(inlen >= MLX5_ESEG_MIN_INLINE_SIZE);
	MLX5_ASSERT(pdst < (uint8_t *)txq->wqes_end);
	inlen -= MLX5_ESEG_MIN_INLINE_SIZE;
	if (!inlen) {
		MLX5_ASSERT(pdst == RTE_PTR_ALIGN(pdst, MLX5_WSEG_SIZE));
		return (struct mlx5_wqe_dseg *)pdst;
	}
	/*
	 * The WQEBB space availability is checked by caller.
	 * Here we should be aware of WQE ring buffer wraparound only.
	 */
	part = (uint8_t *)txq->wqes_end - pdst;
	part = RTE_MIN(part, inlen);
	do {
		rte_memcpy(pdst, psrc, part);
		inlen -= part;
		if (likely(!inlen)) {
			/*
			 * If return value is not used by the caller
			 * the code below will be optimized out.
			 */
			pdst += part;
			pdst = RTE_PTR_ALIGN(pdst, MLX5_WSEG_SIZE);
			if (unlikely(pdst >= (uint8_t *)txq->wqes_end))
				pdst = (uint8_t *)txq->wqes;
			return (struct mlx5_wqe_dseg *)pdst;
		}
		pdst = (uint8_t *)txq->wqes;
		psrc += part;
		part = inlen;
	} while (true);
}


/**
 * Query LKey from a packet buffer for Tx. If not found, add the mempool.
 *
 * @param txq
 *   Pointer to Tx queue structure.
 * @param addr
 *   Address to search.
 *
 * @return
 *   Searched LKey on success, UINT32_MAX on no match.
 */
static __rte_always_inline uint32_t
mlx5_tx_xchg_mb2mr(struct mlx5_txq_data *txq, struct xchg *xchg)
{
	struct mlx5_mr_ctrl *mr_ctrl = &txq->mr_ctrl;
	uintptr_t addr = (uintptr_t)xchg_get_buffer_addr(xchg);
	uint32_t lkey;

	/* Check generation bit to see if there's any change on existing MRs. */
	if (unlikely(*mr_ctrl->dev_gen_ptr != mr_ctrl->cur_gen))
		mlx5_mr_flush_local_cache(mr_ctrl);
	/* Linear search on MR cache array. */
	lkey = mlx5_mr_lookup_cache(mr_ctrl->cache, &mr_ctrl->mru,
				    MLX5_MR_CACHE_N, addr);
	if (likely(lkey != UINT32_MAX))
		return lkey;
	
    /* Take slower bottom-half on miss. */
	return mlx5_tx_mb2mr_bh(txq, xchg_get_mbuf(xchg));
}
/**
 * Build the Data Segment of pointer type.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param loc
 *   Pointer to burst routine local context.
 * @param dseg
 *   Pointer to WQE to fill with built Data Segment.
 * @param buf
 *   Data buffer to point.
 * @param len
 *   Data buffer length.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 */
static __rte_always_inline void
mlx5_tx_xchg_dseg_ptr(struct mlx5_txq_data *restrict txq,
		 struct mlx5_txq_xchg_local *restrict loc,
		 struct mlx5_wqe_dseg *restrict dseg,
		 uint8_t *buf,
		 unsigned int len,
		 unsigned int olx __rte_unused)

{
	MLX5_ASSERT(len);
	dseg->bcount = rte_cpu_to_be_32(len);
	dseg->lkey = mlx5_tx_xchg_mb2mr(txq, loc->next);
	dseg->pbuf = rte_cpu_to_be_64((uintptr_t)buf);
}



/**
 * The routine sends packets with ordinary MLX5_OPCODE_SEND.
 * Data inlining and VLAN insertion are supported.
 */
static __rte_always_inline enum mlx5_txcmp_code
mlx5_tx_burst_xchg_single_send(struct mlx5_txq_data *restrict txq,

		     unsigned int pkts_n,
			  struct mlx5_txq_xchg_local *restrict loc,
			  unsigned int olx)
{
    assert(false);
    //printf("SINGLESEND pkts %d, xchgs %p, xchg %p\n", pkts_n, loc->xchgs, *loc->xchgs);
	/*
	 * Subroutine is the part of mlx5_tx_burst_xchg_single()
	 * and sends single-segment packet with SEND opcode.
	 */
	MLX5_ASSERT(loc->elts_free && loc->wqe_free);
	MLX5_ASSERT(pkts_n > loc->pkts_sent);
	//xchg_tx_advance((struct xchg***)&xchgs, loc->pkts_sent + 1);
    pkts_n -= loc->pkts_sent;
	for (;;) {
		struct mlx5_wqe *restrict wqe;
		enum mlx5_txcmp_code ret;

		//MLX5_ASSERT(NB_SEGS(loc->mbuf) == 1);
		if (MLX5_TXOFF_CONFIG(INLINE)) {
			unsigned int inlen, vlan = 0;

			inlen = xchg_get_data_len(loc->next);
			if (MLX5_TXOFF_CONFIG(VLAN) &&
			    xchg_has_flag(loc->next, PKT_TX_VLAN_PKT)) {
				vlan = sizeof(struct rte_vlan_hdr);
				inlen += vlan;
				static_assert((sizeof(struct rte_vlan_hdr) +
					       sizeof(struct rte_ether_hdr)) ==
					       MLX5_ESEG_MIN_INLINE_SIZE,
					       "invalid min inline data size");
			}
			/*
			 * If inlining is enabled at configuration time
			 * the limit must be not less than minimal size.
			 * Otherwise we would do extra check for data
			 * size to avoid crashes due to length overflow.
			 */
			MLX5_ASSERT(txq->inlen_send >=
				    MLX5_ESEG_MIN_INLINE_SIZE);
			if (inlen <= txq->inlen_send) {
				unsigned int seg_n, wqe_n;

				rte_prefetch0(xchg_get_buffer(loc->next));
				/* Check against minimal length. */
				if (inlen <= MLX5_ESEG_MIN_INLINE_SIZE)
					return MLX5_TXCMP_CODE_ERROR;
				if (xchg_has_flag(loc->next, PKT_TX_DYNF_NOINLINE)) {
					/*
					 * The hint flag not to inline packet
					 * data is set. Check whether we can
					 * follow the hint.
					 */
					if ((!MLX5_TXOFF_CONFIG(EMPW) &&
					      txq->inlen_mode) ||
					    (MLX5_TXOFF_CONFIG(MPW) &&
					     txq->inlen_mode)) {
						/*
						 * The hardware requires the
						 * minimal inline data header.
						 */
						goto single_min_inline;
					}
					if (MLX5_TXOFF_CONFIG(VLAN) &&
					    vlan && !txq->vlan_en) {
						/*
						 * We must insert VLAN tag
						 * by software means.
						 */
						goto single_part_inline;
					}
					goto single_no_inline;
				}
				/*
				 * Completely inlined packet data WQE:
				 * - Control Segment, SEND opcode
				 * - Ethernet Segment, no VLAN insertion
				 * - Data inlined, VLAN optionally inserted
				 * - Alignment to MLX5_WSEG_SIZE
				 * Have to estimate amount of WQEBBs
				 */
				seg_n = (inlen + 3 * MLX5_WSEG_SIZE -
					 MLX5_ESEG_MIN_INLINE_SIZE +
					 MLX5_WSEG_SIZE - 1) / MLX5_WSEG_SIZE;
				/* Check if there are enough WQEBBs. */
				wqe_n = (seg_n + 3) / 4;
				if (wqe_n > loc->wqe_free)
					return MLX5_TXCMP_CODE_EXIT;
				wqe = txq->wqes + (txq->wqe_ci & txq->wqe_m);
				loc->wqe_last = wqe;
				mlx5_tx_cseg_init(txq, wqe, seg_n,
						  MLX5_OPCODE_SEND, olx);
				mlx5_tx_eseg_data(txq, loc, wqe,
						  vlan, inlen, 0, olx);
				txq->wqe_ci += wqe_n;
				loc->wqe_free -= wqe_n;
				/*
				 * Packet data are completely inlined,
				 * free the packet immediately.
				 */
                xchg_tx_sent_inline(loc->next);
			} else if ((!MLX5_TXOFF_CONFIG(EMPW) ||
				     MLX5_TXOFF_CONFIG(MPW)) &&
					txq->inlen_mode) {
				/*
				 * If minimal inlining is requested the eMPW
				 * feature should be disabled due to data is
				 * inlined into Ethernet Segment, which can
				 * not contain inlined data for eMPW due to
				 * segment shared for all packets.
				 */
				struct mlx5_wqe_dseg *restrict dseg;
				unsigned int ds;
				uint8_t *dptr;

				/*
				 * The inline-mode settings require
				 * to inline the specified amount of
				 * data bytes to the Ethernet Segment.
				 * We should check the free space in
				 * WQE ring buffer to inline partially.
				 */
single_min_inline:
				MLX5_ASSERT(txq->inlen_send >= txq->inlen_mode);
				MLX5_ASSERT(inlen > txq->inlen_mode);
				MLX5_ASSERT(txq->inlen_mode >=
					    MLX5_ESEG_MIN_INLINE_SIZE);
				/*
				 * Check whether there are enough free WQEBBs:
				 * - Control Segment
				 * - Ethernet Segment
				 * - First Segment of inlined Ethernet data
				 * - ... data continued ...
				 * - Finishing Data Segment of pointer type
				 */
				ds = (MLX5_WQE_CSEG_SIZE +
				      MLX5_WQE_ESEG_SIZE +
				      MLX5_WQE_DSEG_SIZE +
				      txq->inlen_mode -
				      MLX5_ESEG_MIN_INLINE_SIZE +
				      MLX5_WQE_DSEG_SIZE +
				      MLX5_WSEG_SIZE - 1) / MLX5_WSEG_SIZE;
				if (loc->wqe_free < ((ds + 3) / 4))
					return MLX5_TXCMP_CODE_EXIT;
				/*
				 * Build the ordinary SEND WQE:
				 * - Control Segment
				 * - Ethernet Segment, inline inlen_mode bytes
				 * - Data Segment of pointer type
				 */
				wqe = txq->wqes + (txq->wqe_ci & txq->wqe_m);
				loc->wqe_last = wqe;
				mlx5_tx_cseg_init(txq, wqe, ds,
						  MLX5_OPCODE_SEND, olx);
				dseg = mlx5_tx_eseg_data(txq, loc, wqe, vlan,
							 txq->inlen_mode,
							 0, olx);

				dptr = (uint8_t*)xchg_get_buffer(loc->next) +
				       txq->inlen_mode - vlan;
				inlen -= txq->inlen_mode;
				//printf("Min inline %p",loc->next);
				mlx5_tx_xchg_dseg_ptr(txq, loc, dseg,
						 dptr, inlen, olx);
                /*
				 * WQE is built, update the loop parameters
				 * and got to the next packet.
				 */
				txq->wqe_ci += (ds + 3) / 4;
				loc->wqe_free -= (ds + 3) / 4;
				/* We have to store mbuf in elts.*/
				MLX5_ASSERT(MLX5_TXOFF_CONFIG(INLINE));
				--loc->elts_free;
			} else {
				uint8_t *dptr;
				unsigned int dlen;

				/*
				 * Partially inlined packet data WQE, we have
				 * some space in title WQEBB, we can fill it
				 * with some packet data. It takes one WQEBB,
				 * it is available, no extra space check:
				 * - Control Segment, SEND opcode
				 * - Ethernet Segment, no VLAN insertion
				 * - MLX5_ESEG_MIN_INLINE_SIZE bytes of Data
				 * - Data Segment, pointer type
				 *
				 * We also get here if VLAN insertion is not
				 * supported by HW, the inline is enabled.
				 */
single_part_inline:
				wqe = txq->wqes + (txq->wqe_ci & txq->wqe_m);
				loc->wqe_last = wqe;
				mlx5_tx_cseg_init(txq,  wqe, 4,
						  MLX5_OPCODE_SEND, olx);
				mlx5_tx_eseg_dmin(txq, loc, wqe, vlan, olx);
				dptr = (uint8_t*)xchg_get_buffer(loc->next) +
				       MLX5_ESEG_MIN_INLINE_SIZE - vlan;
				/*
				 * The length check is performed above, by
				 * comparing with txq->inlen_send. We should
				 * not get overflow here.
				 */
				MLX5_ASSERT(inlen > MLX5_ESEG_MIN_INLINE_SIZE);
				dlen = inlen - MLX5_ESEG_MIN_INLINE_SIZE;
				//printf("Par inline %p\n",loc->next);
				mlx5_tx_xchg_dseg_ptr(txq, loc, &wqe->dseg[1],
						 dptr, dlen, olx);
				++txq->wqe_ci;
				--loc->wqe_free;
				/* We have to store mbuf in elts.*/
				MLX5_ASSERT(MLX5_TXOFF_CONFIG(INLINE));
				--loc->elts_free;
			}
#ifdef MLX5_PMD_SOFT_COUNTERS
			/* Update sent data bytes counter. */
			txq->stats.obytes += vlan + xchg_get_data_len(loc->next);
#endif
            xchg_tx_sent(&txq->elts[txq->elts_head++ & txq->elts_m], loc->xchgs);
		} else {
			/*
			 * No inline at all, it means the CPU cycles saving
			 * is prioritized at configuration, we should not
			 * copy any packet data to WQE.
			 *
			 * SEND WQE, one WQEBB:
			 * - Control Segment, SEND opcode
			 * - Ethernet Segment, optional VLAN, no inline
			 * - Data Segment, pointer type
			 */
single_no_inline:
			wqe = txq->wqes + (txq->wqe_ci & txq->wqe_m);
			loc->wqe_last = wqe;
			mlx5_tx_cseg_init(txq, wqe, 3,
					  MLX5_OPCODE_SEND, olx);
			mlx5_tx_xchg_eseg_none(txq, loc, wqe, olx);
			//printf("Next %p\n",loc->next);

			//printf("Next buffer %p\n",xchg_get_buffer(loc->next));
            mlx5_tx_xchg_dseg_ptr
				(txq, loc, &wqe->dseg[0],
				 (uint8_t*)xchg_get_buffer(loc->next),
				 xchg_get_data_len(loc->next), olx);
			++txq->wqe_ci;
			--loc->wqe_free;

			/*
			 * We should not store mbuf pointer in elts
			 * if no inlining is configured, this is done
			 * by calling routine in a batch copy.
			 */
			MLX5_ASSERT(!MLX5_TXOFF_CONFIG(INLINE));
			--loc->elts_free;
#ifdef MLX5_PMD_SOFT_COUNTERS
			/* Update sent data bytes counter. */
			txq->stats.obytes += xchg_get_data_len(loc->next);
			if (MLX5_TXOFF_CONFIG(VLAN) &&
			    xchg_get_flags(loc->next) & PKT_TX_VLAN_PKT)
				txq->stats.obytes +=
					sizeof(struct rte_vlan_hdr);
#endif
            if (!xchg_elts_vec) {
                xchg_tx_sent(&txq->elts[txq->elts_head++ & txq->elts_m], loc->xchgs);
            }
		}
		++loc->pkts_sent;

//        printf("SentH %d += %d\n", loc->pkts_sent, 1);
		--pkts_n;
        //printf("END - PKTS N %d\n", pkts_n);
		if (unlikely(!pkts_n || !loc->elts_free || !loc->wqe_free))
			return MLX5_TXCMP_CODE_EXIT;

		xchg_tx_advance(&loc->xchgs);
		loc->next = xchg_tx_next(loc->xchgs);
		//printf("3 Advanced, next is %p\n",loc->next);
		ret = mlx5_tx_xchg_able_to_empw(txq, loc, olx, true);
		if (unlikely(ret != MLX5_TXCMP_CODE_SINGLE))
			return ret;
	}
	MLX5_ASSERT(false);
}

/**
 * Check the next packet attributes to match with the eMPW batch ones.
 * In addition, for legacy MPW the packet length is checked either.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param es
 *   Pointer to Ethernet Segment of eMPW batch.
 * @param loc
 *   Pointer to burst routine local context.
 * @param dlen
 *   Length of previous packet in MPW descriptor.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 *
 * @return
 *  true - packet match with eMPW batch attributes.
 *  false - no match, eMPW should be restarted.
 */
static __rte_always_inline bool
mlx5_tx_xchg_match_empw(struct mlx5_txq_data *restrict txq __rte_unused,
		   struct mlx5_wqe_eseg *restrict es,
		   struct mlx5_txq_xchg_local *restrict loc,
		   uint32_t dlen,
		   unsigned int olx)
{
	uint8_t swp_flags = 0;

	/* Compare the checksum flags, if any. */
	if (MLX5_TXOFF_CONFIG(CSUM) &&
	    txq_ol_cksum_to_cs(xchg_get_flags(loc->next)) != es->cs_flags)
		return false;
	/* Compare the Software Parser offsets and flags. */
	if (MLX5_TXOFF_CONFIG(SWP) &&
	    (es->swp_offs != txq_xchg_to_swp(loc, &swp_flags, olx) ||
	     es->swp_flags != swp_flags))
		return false;
	/* Fill metadata field if needed. */
	/*if (MLX5_TXOFF_CONFIG(METADATA) &&
		es->metadata != (xchg_has_flag(loc->next, PKT_TX_DYNF_METADATA) ?
				 *RTE_FLOW_DYNF_METADATA(loc->mbuf) : 0))
		return false;*/
	/* Legacy MPW can send packets with the same lengt only. */
	if (MLX5_TXOFF_CONFIG(MPW) &&
	    dlen != xchg_get_data_len(loc->next))
		return false;
	/* There must be no VLAN packets in eMPW loop. */
	if (MLX5_TXOFF_CONFIG(VLAN))
		MLX5_ASSERT(!(xchg_has_flag(xchg->next, PKT_TX_VLAN_PKT)));
	return true;
}

/*
 * Update send loop variables and WQE for eMPW loop
 * without data inlining. Number of Data Segments is
 * equal to the number of sent packets.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param loc
 *   Pointer to burst routine local context.
 * @param ds
 *   Number of packets/Data Segments/Packets.
 * @param slen
 *   Accumulated statistics, bytes sent
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 *
 * @return
 *  true - packet match with eMPW batch attributes.
 *  false - no match, eMPW should be restarted.
 */
static __rte_always_inline void
mlx5_tx_xchg_sdone_empw(struct mlx5_txq_data *restrict txq,
		   struct mlx5_txq_xchg_local *restrict loc,
		   unsigned int ds,
		   unsigned int slen,
		   unsigned int olx __rte_unused)
{
	MLX5_ASSERT(!MLX5_TXOFF_CONFIG(INLINE));
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Update sent data bytes counter. */
	 txq->stats.obytes += slen;
#else
	(void)slen;
#endif
	loc->elts_free -= ds;
	loc->pkts_sent += ds;

//        printf("SentR %d += %d\n", loc->pkts_sent, ds);
	ds += 2;
	loc->wqe_last->cseg.sq_ds = rte_cpu_to_be_32(txq->qp_num_8s | ds);
	txq->wqe_ci += (ds + 3) / 4;
	loc->wqe_free -= (ds + 3) / 4;
}


/**
 * The set of Tx burst functions for single-segment packets
 * without TSO and with Multi-Packet Writing feature support.
 * Supports all types of Tx offloads, except multi-packets
 * and TSO.
 *
 * Uses MLX5_OPCODE_EMPW to build WQEs if possible and sends
 * as many packet per WQE as it can. If eMPW is not configured
 * or packet can not be sent with eMPW (VLAN insertion) the
 * ordinary SEND opcode is used and only one packet placed
 * in WQE.
 *
 * Functions stop sending if it encounters the multi-segment
 * packet or packet with TSO requested.
 *
 * The routines are responsible for storing processed mbuf
 * into elts ring buffer and update elts_head if inlining
 * offload is requested. Otherwise the copying mbufs to elts
 * can be postponed and completed at the end of burst routine.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param[in] pkts
 *   Packets to transmit.
 * @param pkts_n
 *   Number of packets in array.
 * @param loc
 *   Pointer to burst routine local context.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 *
 * @return
 *   MLX5_TXCMP_CODE_EXIT - sending is done or impossible.
 *   MLX5_TXCMP_CODE_ERROR - some unrecoverable error occurred.
 *   MLX5_TXCMP_CODE_MULTI - multi-segment packet encountered.
 *   MLX5_TXCMP_CODE_TSO - TSO packet encountered.
 *   MLX5_TXCMP_CODE_SINGLE - used inside functions set.
 *   MLX5_TXCMP_CODE_EMPW - used inside functions set.
 *
 * Local context variables updated.
 *
 *
 * The routine sends packets with MLX5_OPCODE_EMPW
 * without inlining, this is dedicated optimized branch.
 * No VLAN insertion is supported.
 */
static __rte_always_inline enum mlx5_txcmp_code
mlx5_tx_burst_xchg_empw_simple(struct mlx5_txq_data *restrict txq,
			  unsigned int pkts_n,
			  struct mlx5_txq_xchg_local *restrict loc,
			  unsigned int olx)
{
	/*
	 * Subroutine is the part of mlx5_tx_burst_single()
	 * and sends single-segment packet with eMPW opcode
	 * without data inlining.
	 */
	MLX5_ASSERT(!MLX5_TXOFF_CONFIG(INLINE));
	MLX5_ASSERT(MLX5_TXOFF_CONFIG(EMPW));
	MLX5_ASSERT(loc->elts_free && loc->wqe_free);
	MLX5_ASSERT(pkts_n > loc->pkts_sent);
	static_assert(MLX5_EMPW_MIN_PACKETS >= 2, "invalid min size");
	pkts_n -= loc->pkts_sent;


//    printf("EMPWSINGLESEND pkts %d, xchgs %p, xchg %p, sent %d\n", pkts_n, loc->xchgs, *loc->xchgs, loc->pkts_sent);
	for (;;) {
		struct mlx5_wqe_dseg *restrict dseg;
		struct mlx5_wqe_eseg *restrict eseg;
		enum mlx5_txcmp_code ret;
		unsigned int part, loop;
		unsigned int slen = 0;

next_empw:
		MLX5_ASSERT(xchg_nb_segs(loc->next) == 1);
		part = RTE_MIN(pkts_n, MLX5_TXOFF_CONFIG(MPW) ?
				       MLX5_MPW_MAX_PACKETS :
				       MLX5_EMPW_MAX_PACKETS);
		if (unlikely(loc->elts_free < part)) {
			/* We have no enough elts to save all mbufs. */
			if (unlikely(loc->elts_free < MLX5_EMPW_MIN_PACKETS))
				return MLX5_TXCMP_CODE_EXIT;
			/* But we still able to send at least minimal eMPW. */
			part = loc->elts_free;
		}
		/* Check whether we have enough WQEs */
		if (unlikely(loc->wqe_free < ((2 + part + 3) / 4))) {
			if (unlikely(loc->wqe_free <
				((2 + MLX5_EMPW_MIN_PACKETS + 3) / 4)))
				return MLX5_TXCMP_CODE_EXIT;
			part = (loc->wqe_free * 4) - 2;
		}
/*Old code, this has been prefetched long ago
 * if (likely(part > 1))
			rte_prefetch0(xchg_tx_next(loc->xchgs));*/
		loc->wqe_last = txq->wqes + (txq->wqe_ci & txq->wqe_m);
		/*
		 * Build eMPW title WQEBB:
		 * - Control Segment, eMPW opcode
		 * - Ethernet Segment, no inline
		 */
		mlx5_tx_cseg_init(txq, loc->wqe_last, part + 2,
				  MLX5_OPCODE_ENHANCED_MPSW, olx);
		mlx5_tx_xchg_eseg_none(txq, loc, loc->wqe_last,
				  olx & ~MLX5_TXOFF_CONFIG_VLAN);
		eseg = &loc->wqe_last->eseg;
		dseg = &loc->wqe_last->dseg[0];
		loop = part;
        //unsigned ns = 0;
		/* Store the packet length for legacy MPW. */
		if (MLX5_TXOFF_CONFIG(MPW))
			eseg->mss = rte_cpu_to_be_16
					(xchg_get_data_len(loc->next));
		for (;;) {
			uint32_t dlen = xchg_get_data_len(loc->next);
#ifdef MLX5_PMD_SOFT_COUNTERS
			/* Update sent data bytes counter. */
			slen += dlen;
#endif

            //printf("Sending %p, buffer %p",loc->next, xchg_get_buffer(loc->next));
			mlx5_tx_xchg_dseg_ptr
				(txq, loc, dseg,
				 xchg_get_buffer(loc->next),
				 dlen, olx);

			//--loc->elts_free;
            if (!xchg_elts_vec)  {
/*                	struct rte_mbuf **elts = (struct rte_mbuf **)txq->elts;
	                unsigned partr = txq->elts_s - (txq->elts_head & txq->elts_m);
	                assert(partr);
                    unsigned n = RTE_MIN(partr, (unsigned)1);
                    assert(n == 1);
                    xchg_tx_sent_vec(elts + ((txq->elts_head + loc->pkts_sent + ns  ) & txq->elts_m),
            		   loc->xchgs,
            		   n);
                    ns++;
//                    txq->elts_head += 1;

            assert(*loc->xchgs == (struct xchg*) 0x87);
            }*/

                 xchg_tx_sent(&txq->elts[txq->elts_head++ & txq->elts_m], loc->xchgs);
		}

			xchg_tx_advance(&loc->xchgs); //Advances pointer, so the top is always pointing to the "next to be sent"
			//printf("Advanced, next is %p\n", *loc->xchgs);
			loc->next = xchg_tx_next(loc->xchgs); //Takes the pointer on top
			if (unlikely(--loop == 0)) {
				//printf("End of loop\n");
				break;
			}



            //assert(loc->next != 0);
            //printf("Advanced, NEXT %p XCHGS %p",loc->next, loc->xchgs);
/*			if (likely(loop > 1))
				rte_prefetch0(xchg_tx_next(loc->xchgs));*/
			ret = mlx5_tx_xchg_able_to_empw(txq, loc, olx, true);
			/*
			 * Unroll the completion code to avoid
			 * returning variable value - it results in
			 * unoptimized sequent checking in caller.
			 */
			if (ret == MLX5_TXCMP_CODE_MULTI) {
				part -= loop;
				mlx5_tx_xchg_sdone_empw(txq, loc, part, slen, olx);
				if (unlikely(!loc->elts_free ||
					     !loc->wqe_free)) {
                    assert(false);
					return MLX5_TXCMP_CODE_EXIT;
                }
                assert(false);
				return MLX5_TXCMP_CODE_MULTI;
			}
			MLX5_ASSERT(NB_SEGS(loc->mbuf) == 1);
			if (ret == MLX5_TXCMP_CODE_TSO) {
                assert(false);
				part -= loop;
				mlx5_tx_xchg_sdone_empw(txq, loc, part, slen, olx);
				if (unlikely(!loc->elts_free ||
					     !loc->wqe_free))
					return MLX5_TXCMP_CODE_EXIT;
				return MLX5_TXCMP_CODE_TSO;
			}
			if (ret == MLX5_TXCMP_CODE_SINGLE) {
                assert(false);
				part -= loop;
				mlx5_tx_xchg_sdone_empw(txq, loc, part, slen, olx);
				if (unlikely(!loc->elts_free ||
					     !loc->wqe_free))
					return MLX5_TXCMP_CODE_EXIT;
				return MLX5_TXCMP_CODE_SINGLE;
			}
			if (ret != MLX5_TXCMP_CODE_EMPW) {
				MLX5_ASSERT(false);
				part -= loop;
				mlx5_tx_xchg_sdone_empw(txq, loc, part, slen, olx);
                printf("ERROR\n");
				return MLX5_TXCMP_CODE_ERROR;
			}
			/*
			 * Check whether packet parameters coincide
			 * within assumed eMPW batch:
			 * - check sum settings
			 * - metadata value
			 * - software parser settings
			 * - packets length (legacy MPW only)
			 */
			if (!mlx5_tx_xchg_match_empw(txq, eseg, loc, dlen, olx)) {
				MLX5_ASSERT(loop);
				part -= loop;
				mlx5_tx_xchg_sdone_empw(txq, loc, part, slen, olx);
				if (unlikely(!loc->elts_free ||
					     !loc->wqe_free))
					return MLX5_TXCMP_CODE_EXIT;
				pkts_n -= part;
				goto next_empw;
			}
			/* Packet attributes match, continue the same eMPW. */
			++dseg;
			if ((uintptr_t)dseg >= (uintptr_t)txq->wqes_end)
				dseg = (struct mlx5_wqe_dseg *)txq->wqes;
		}
		/* eMPW is built successfully, update loop parameters. */
		MLX5_ASSERT(!loop);
		MLX5_ASSERT(pkts_n >= part);
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Update sent data bytes counter. */
		txq->stats.obytes += slen;
#endif
		loc->elts_free -= part;
//        printf("Sent %d += %d\n", loc->pkts_sent, part);
		loc->pkts_sent += part;
		txq->wqe_ci += (2 + part + 3) / 4;
		loc->wqe_free -= (2 + part + 3) / 4;
		pkts_n -= part;
		if (unlikely(!pkts_n || !loc->elts_free || !loc->wqe_free))
			return MLX5_TXCMP_CODE_EXIT;
		//loc->next = xchg_tx_advance(&loc->xchgs);
        ret = mlx5_tx_xchg_able_to_empw(txq, loc, olx, true);
		if (unlikely(ret != MLX5_TXCMP_CODE_EMPW))
			return ret;
		/* Continue sending eMPW batches. */
	}
	MLX5_ASSERT(false);
}

static __rte_always_inline enum mlx5_txcmp_code
mlx5_tx_burst_xchg_single(struct mlx5_txq_data *restrict txq,
		     unsigned int pkts_n,
		     struct mlx5_txq_xchg_local *restrict loc,
		     unsigned int olx)
{
	enum mlx5_txcmp_code ret;
	//printf("XCHG SINGLE\n");
    ret = mlx5_tx_xchg_able_to_empw(txq, loc, olx, false);
	if (ret == MLX5_TXCMP_CODE_SINGLE) {
        printf("All ordinary?\n");
		goto ordinary_send;
    }
	MLX5_ASSERT(ret == MLX5_TXCMP_CODE_EMPW);
	for (;;) {
		/* Optimize for inline/no inline eMPW send. */
		ret = /*(MLX5_TXOFF_CONFIG(INLINE)) ?
			mlx5_tx_burst_xchg_empw_inline
				(txq, xchgs, pkts_n, loc, olx) :*/
			mlx5_tx_burst_xchg_empw_simple
				(txq, pkts_n, loc, olx);
		if (ret != MLX5_TXCMP_CODE_SINGLE)
			return ret;
		/* The resources to send one packet should remain. */
		MLX5_ASSERT(loc->elts_free && loc->wqe_free);
ordinary_send:
        assert(false);
		ret = mlx5_tx_burst_xchg_single_send(txq, pkts_n, loc, olx);
		MLX5_ASSERT(ret != MLX5_TXCMP_CODE_SINGLE);
		if (ret != MLX5_TXCMP_CODE_EMPW)
			return ret;
		/* The resources to send one packet should remain. */
		MLX5_ASSERT(loc->elts_free && loc->wqe_free);
	}
}


/**
 * Free the mbuf from the elts ring buffer till new tail.
 *
 * @param txq
 *   Pointer to Tx queue structure.
 * @param tail
 *   Index in elts to free up to, becomes new elts tail.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 */
static __rte_always_inline void
mlx5_tx_xchg_free_elts(struct mlx5_txq_data *restrict txq,
		  uint16_t tail,
		  unsigned int olx __rte_unused)
{
	uint16_t n_elts = tail - txq->elts_tail;

	MLX5_ASSERT(n_elts);
	MLX5_ASSERT(n_elts <= txq->elts_s);
	/*
	 * Implement a loop to support ring buffer wraparound
     * with single inlining of mlx5_tx_free_mbuf().
	 */
    if (xchg_do_tx_free) {
        do {
            unsigned int part;

            part = txq->elts_s - (txq->elts_tail & txq->elts_m);
            part = RTE_MIN(part, n_elts);
            MLX5_ASSERT(part);
            MLX5_ASSERT(part <= txq->elts_s);
            xchg_tx_completed(&txq->elts[txq->elts_tail & txq->elts_m],
                      part, olx);
            txq->elts_tail += part;
            n_elts -= part;
        } while (n_elts);
    } else {
        txq->elts_tail += n_elts;
    }
}
/**
 * Update completion queue consuming index via doorbell
 * and flush the completed data buffers.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param valid CQE pointer
 *   if not NULL update txq->wqe_pi and flush the buffers
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 */
static __rte_always_inline void
mlx5_tx_xchg_comp_flush(struct mlx5_txq_data *restrict txq,
		   volatile struct mlx5_cqe *last_cqe,
		   unsigned int olx __rte_unused)
{
	if (likely(last_cqe != NULL)) {
		uint16_t tail;

		txq->wqe_pi = rte_be_to_cpu_16(last_cqe->wqe_counter);
		tail = txq->fcqs[(txq->cq_ci - 1) & txq->cqe_m];
		if (likely(tail != txq->elts_tail)) {
			mlx5_tx_xchg_free_elts(txq, tail, olx);
			MLX5_ASSERT(tail == txq->elts_tail);
		}
	}
}

/**
 * Manage TX completions. This routine checks the CQ for
 * arrived CQEs, deduces the last accomplished WQE in SQ,
 * updates SQ producing index and frees all completed mbufs.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 *
 * NOTE: not inlined intentionally, it makes tx_burst
 * routine smaller, simple and faster - from experiments.
 */
static void
mlx5_tx_xchg_handle_completion(struct mlx5_txq_data *restrict txq,
			  unsigned int olx __rte_unused)
{
	unsigned int count = MLX5_TX_COMP_MAX_CQE;
	volatile struct mlx5_cqe *last_cqe = NULL;
	uint16_t ci = txq->cq_ci;
	int ret;

	static_assert(MLX5_CQE_STATUS_HW_OWN < 0, "Must be negative value");
	static_assert(MLX5_CQE_STATUS_SW_OWN < 0, "Must be negative value");
	do {
		volatile struct mlx5_cqe *cqe;

		cqe = &txq->cqes[ci & txq->cqe_m];
		ret = check_cqe(cqe, txq->cqe_s, ci);
		if (unlikely(ret != MLX5_CQE_STATUS_SW_OWN)) {
			if (likely(ret != MLX5_CQE_STATUS_ERR)) {
				/* No new CQEs in completion queue. */
				MLX5_ASSERT(ret == MLX5_CQE_STATUS_HW_OWN);
				break;
			}
			/*
			 * Some error occurred, try to restart.
			 * We have no barrier after WQE related Doorbell
			 * written, make sure all writes are completed
			 * here, before we might perform SQ reset.
			 */
			rte_wmb();
			txq->cq_ci = ci;
			ret = mlx5_tx_error_cqe_handle
				(txq, (volatile struct mlx5_err_cqe *)cqe);
			if (unlikely(ret < 0)) {
				/*
				 * Some error occurred on queue error
				 * handling, we do not advance the index
				 * here, allowing to retry on next call.
				 */
				return;
			}
			/*
			 * We are going to fetch all entries with
			 * MLX5_CQE_SYNDROME_WR_FLUSH_ERR status.
			 * The send queue is supposed to be empty.
			 */
			++ci;
			txq->cq_pi = ci;
			last_cqe = NULL;
			continue;
		}
		/* Normal transmit completion. */
		MLX5_ASSERT(ci != txq->cq_pi);
		MLX5_ASSERT((txq->fcqs[ci & txq->cqe_m] >> 16) ==
			    cqe->wqe_counter);
		++ci;
		last_cqe = cqe;
		/*
		 * We have to restrict the amount of processed CQEs
		 * in one tx_burst routine call. The CQ may be large
		 * and many CQEs may be updated by the NIC in one
		 * transaction. Buffers freeing is time consuming,
		 * multiple iterations may introduce significant
		 * latency.
		 */
		if (likely(--count == 0))
			break;
	} while (true);
	if (likely(ci != txq->cq_ci)) {
		/*
		 * Update completion queue consuming index
		 * and ring doorbell to notify hardware.
		 */
		rte_compiler_barrier();
		txq->cq_ci = ci;
		*txq->cq_db = rte_cpu_to_be_32(ci);
		mlx5_tx_xchg_comp_flush(txq, last_cqe, olx);
	}
}

/**
 * Check if the completion request flag should be set in the last WQE.
 * Both pushed mbufs and WQEs are monitored and the completion request
 * flag is set if any of thresholds is reached.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param loc
 *   Pointer to burst routine local context.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 */
static __rte_always_inline void
mlx5_tx_xchg_request_completion(struct mlx5_txq_data *restrict txq,
			   struct mlx5_txq_xchg_local *restrict loc,
			   unsigned int olx)
{
	uint16_t head = txq->elts_head;
	unsigned int part;

    part = MLX5_TXOFF_CONFIG(INLINE) || !xchg_elts_vec ?
	       0 : loc->pkts_sent - loc->pkts_copy;
	head += part;
	if ((uint16_t)(head - txq->elts_comp) >= MLX5_TX_COMP_THRESH ||
	     ((MLX5_TXOFF_CONFIG(INLINE) || !xchg_elts_vec) &&
	     (uint16_t)(txq->wqe_ci - txq->wqe_comp) >= txq->wqe_thres)) {
		volatile struct mlx5_wqe *last = loc->wqe_last;

		MLX5_ASSERT(last);
		txq->elts_comp = head;
		if (MLX5_TXOFF_CONFIG(INLINE) || !xchg_elts_vec)
			txq->wqe_comp = txq->wqe_ci;
		/* Request unconditional completion on last WQE. */
		last->cseg.flags = RTE_BE32(MLX5_COMP_ALWAYS <<
					    MLX5_COMP_MODE_OFFSET);
		/* Save elts_head in dedicated free on completion queue. */
#ifdef RTE_LIBRTE_MLX5_DEBUG
		txq->fcqs[txq->cq_pi++ & txq->cqe_m] = head |
			  (last->cseg.opcode >> 8) << 16;
#else
		txq->fcqs[txq->cq_pi++ & txq->cqe_m] = head;
#endif
		/* A CQE slot must always be available. */
		MLX5_ASSERT((txq->cq_pi - txq->cq_ci) <= txq->cqe_s);
	}
}


/**
 * Store the mbuf being sent into elts ring buffer.
 * On Tx completion these mbufs will be freed.
 *
 * @param txq
 *   Pointer to Tx queue structure.
 * @param pkts
 *   Pointer to array of packets to be stored.
 * @param pkts_n
 *   Number of packets to be stored.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 */
static __rte_always_inline void
mlx5_tx_xchg_copy_elts(struct mlx5_txq_data *restrict txq,
		  struct xchg **restrict xchgs,
		  unsigned int pkts_n,
		  unsigned int olx __rte_unused)
{
	unsigned int part;
	struct rte_mbuf **elts = (struct rte_mbuf **)txq->elts;

	MLX5_ASSERT(pkts);
	MLX5_ASSERT(pkts_n);
	part = txq->elts_s - (txq->elts_head & txq->elts_m);
	MLX5_ASSERT(part);
	MLX5_ASSERT(part <= txq->elts_s);
	/* This code is a good candidate for vectorizing with SIMD. */
	//TODO : get_mbuf
    //and swap ELTS to XCHG!
    unsigned n = RTE_MIN(part, pkts_n);
    xchg_tx_sent_vec(elts + (txq->elts_head & txq->elts_m),
		   xchgs,
		   n);
	txq->elts_head += pkts_n;
	if (unlikely(part < pkts_n))
		/* The copy is wrapping around the elts array. */
        xchg_tx_sent_vec(elts,
		   xchgs + part,
		   pkts_n - part);
}



/**
 * DPDK Tx callback template. This is configured template
 * used to generate routines optimized for specified offload setup.
 * One of this generated functions is chosen at SQ configuration
 * time.
 *
 * @param txq
 *   Generic pointer to TX queue structure.
 * @param[in] pkts
 *   Packets to transmit.
 * @param pkts_n
 *   Number of packets in array.
 * @param olx
 *   Configured offloads mask, presents the bits of MLX5_TXOFF_CONFIG_xxx
 *   values. Should be static to take compile time static configuration
 *   advantages.
 *
 * @return
 *   Number of packets successfully transmitted (<= pkts_n).
 */
static __rte_always_inline uint16_t
mlx5_tx_burst_xchg_tmpl(struct mlx5_txq_data *restrict txq,
		   struct xchg **restrict xchgs_arg,
		   uint16_t pkts_n,
		   unsigned int olx)
{
	struct mlx5_txq_xchg_local loc;
	enum mlx5_txcmp_code ret;
	unsigned int part;

	MLX5_ASSERT(txq->elts_s >= (uint16_t)(txq->elts_head - txq->elts_tail));
	MLX5_ASSERT(txq->wqe_s >= (uint16_t)(txq->wqe_ci - txq->wqe_pi));
	if (unlikely(!pkts_n))
		return 0;
    loc.xchgs = xchgs_arg;
	loc.pkts_loop = 0;
    loc.pkts_sent = 0;
	loc.pkts_copy = 0;
	loc.wqe_last = NULL;
    //printf("TX BURST - xchgs %p xchg %p, n %d\n",loc.xchgs, *loc.xchgs, pkts_n);

send_loop:
	loc.pkts_loop = loc.pkts_sent;
	/*
	 * Check if there are some CQEs, if any:
	 * - process an encountered errors
	 * - process the completed WQEs
	 * - free related mbufs
	 * - doorbell the NIC about processed CQEs
	 */

    loc.next = xchg_tx_next(loc.xchgs);

    //printf("First advance xchgs %p xchg %p, n %d, next %p\n",loc.xchgs, *loc.xchgs, pkts_n, loc.next);
	mlx5_tx_xchg_handle_completion(txq, olx);
	/*
	 * Calculate the number of available resources - elts and WQEs.
	 * There are two possible different scenarios:
	 * - no data inlining into WQEs, one WQEBB may contains upto
	 *   four packets, in this case elts become scarce resource
	 * - data inlining into WQEs, one packet may require multiple
	 *   WQEBBs, the WQEs become the limiting factor.
	 */
	MLX5_ASSERT(txq->elts_s >= (uint16_t)(txq->elts_head - txq->elts_tail));
	loc.elts_free = txq->elts_s -
				(uint16_t)(txq->elts_head - txq->elts_tail);
	MLX5_ASSERT(txq->wqe_s >= (uint16_t)(txq->wqe_ci - txq->wqe_pi));
	loc.wqe_free = txq->wqe_s -
				(uint16_t)(txq->wqe_ci - txq->wqe_pi);
	if (unlikely(!loc.elts_free || !loc.wqe_free))
		goto burst_exit;
	for (;;) {
		//printf("TMPL loop, xchgs %p, next %p\n", loc.xchgs, *loc.xchgs);
		/*
		 * Fetch the packet from array. Usually this is
		 * the first packet in series of multi/single
		 * segment packets.
		 */
		
        /* Dedicated branch for multi-segment packets. */
		/*if (MLX5_TXOFF_CONFIG(MULTI) &&
		    unlikely(NB_SEGS(loc.mbuf) > 1)) {
			 * Multi-segment packet encountered.
			 * Hardware is able to process it only
			 * with SEND/TSO opcodes, one packet
			 * per WQE, do it in dedicated routine.
			 
enter_send_multi:
			MLX5_ASSERT(loc.pkts_sent >= loc.pkts_copy);
			part = loc.pkts_sent - loc.pkts_copy;
			if (!MLX5_TXOFF_CONFIG(INLINE) && part) {
				
				 * There are some single-segment mbufs not
				 * stored in elts. The mbufs must be in the
				 * same order as WQEs, so we must copy the
				 * mbufs to elts here, before the coming
				 * multi-segment packet mbufs is appended.
				 
				mlx5_tx_copy_elts(txq, pkts + loc.pkts_copy,
						  part, olx);
				loc.pkts_copy = loc.pkts_sent;
			}
			MLX5_ASSERT(pkts_n > loc.pkts_sent);
			ret = mlx5_tx_burst_mseg(txq, pkts, pkts_n, &loc, olx);
			if (!MLX5_TXOFF_CONFIG(INLINE))
				loc.pkts_copy = loc.pkts_sent;
			
			 * These returned code checks are supposed
			 * to be optimized out due to routine inlining.
			
			if (ret == MLX5_TXCMP_CODE_EXIT) {
				
				 * The routine returns this code when
				 * all packets are sent or there is no
				 * enough resources to complete request.
				 
				break;
			}
			if (ret == MLX5_TXCMP_CODE_ERROR) {
				*
				 * The routine returns this code when
				 * some error in the incoming packets
				 * format occurred.
				 *
				txq->stats.oerrors++;
				break;
			}
			if (ret == MLX5_TXCMP_CODE_SINGLE) {
				*
				 * The single-segment packet was encountered
				 * in the array, try to send it with the
				 * best optimized way, possible engaging eMPW.
				 *
				goto enter_send_single;
			}
			if (MLX5_TXOFF_CONFIG(TSO) &&
			    ret == MLX5_TXCMP_CODE_TSO) {
				
				 * The single-segment TSO packet was
				 * encountered in the array.
				 *
				goto enter_send_tso;
			}
			* We must not get here. Something is going wrong. *
			MLX5_ASSERT(false);
			txq->stats.oerrors++;
			break;
		}*/ // No mseg
		/* Dedicated branch for single-segment TSO packets. */
		if (MLX5_TXOFF_CONFIG(TSO) &&
		    unlikely(xchg_has_flag(loc.next, PKT_TX_TCP_SEG))) {
			/*
			 * TSO might require special way for inlining
			 * (dedicated parameters) and is sent with
			 * MLX5_OPCODE_TSO opcode only, provide this
			 * in dedicated branch.
			 */
enter_send_tso:
assert(false);
			//MLX5_ASSERT(NB_SEGS(loc.mbuf) == 1);
			MLX5_ASSERT(pkts_n > loc.pkts_sent);
			//ret = mlx5_tx_burst_tso(txq, pkts, pkts_n, &loc, olx);
			/*
			 * These returned code checks are supposed
			 * to be optimized out due to routine inlining.
			 */
			if (ret == MLX5_TXCMP_CODE_EXIT)
				break;
			if (ret == MLX5_TXCMP_CODE_ERROR) {
				txq->stats.oerrors++;
				break;
			}
			if (ret == MLX5_TXCMP_CODE_SINGLE)
				goto enter_send_single;
			if (MLX5_TXOFF_CONFIG(MULTI) &&
			    ret == MLX5_TXCMP_CODE_MULTI) {
				/*
				 * The multi-segment packet was
				 * encountered in the array.
				 */
                assert(false);
				//goto enter_send_multi;
			}
			/* We must not get here. Something is going wrong. */
			MLX5_ASSERT(false);
			txq->stats.oerrors++;
			break;
		}
		/*
		 * The dedicated branch for the single-segment packets
		 * without TSO. Often these ones can be sent using
		 * MLX5_OPCODE_EMPW with multiple packets in one WQE.
		 * The routine builds the WQEs till it encounters
		 * the TSO or multi-segment packet (in case if these
		 * offloads are requested at SQ configuration time).
		 */
enter_send_single:
		MLX5_ASSERT(pkts_n > loc.pkts_sent);
		ret = mlx5_tx_burst_xchg_single(txq, pkts_n, &loc, olx);

		/*
		 * These returned code checks are supposed
		 * to be optimized out due to routine inlining.
		 */
		if (ret == MLX5_TXCMP_CODE_EXIT)
			break;
		if (ret == MLX5_TXCMP_CODE_ERROR) {
			txq->stats.oerrors++;
			break;
		}
		if (MLX5_TXOFF_CONFIG(MULTI) &&
		    ret == MLX5_TXCMP_CODE_MULTI) {
			/*
			 * The multi-segment packet was
			 * encountered in the array.
			 */
            assert(false);
			//goto enter_send_multi;
		}
		if (MLX5_TXOFF_CONFIG(TSO) &&
		    ret == MLX5_TXCMP_CODE_TSO) {
			/*
			 * The single-segment TSO packet was
			 * encountered in the array.
			 */
			goto enter_send_tso;
		}
		/* We must not get here. Something is going wrong. */
		MLX5_ASSERT(false);
		txq->stats.oerrors++;
		break;
	}
	/*
	 * Main Tx loop is completed, do the rest:
	 * - set completion request if thresholds are reached
	 * - doorbell the hardware
	 * - copy the rest of mbufs to elts (if any)
	 */
	MLX5_ASSERT(MLX5_TXOFF_CONFIG(INLINE) ||
		    loc.pkts_sent >= loc.pkts_copy);
	/* Take a shortcut if nothing is sent. */
	if (unlikely(loc.pkts_sent == loc.pkts_loop))
		goto burst_exit;
	/* Request CQE generation if limits are reached. */
	mlx5_tx_xchg_request_completion(txq, &loc, olx);
	/*
	 * Ring QP doorbell immediately after WQE building completion
	 * to improve latencies. The pure software related data treatment
	 * can be completed after doorbell. Tx CQEs for this SQ are
	 * processed in this thread only by the polling.
	 *
	 * The rdma core library can map doorbell register in two ways,
	 * depending on the environment variable "MLX5_SHUT_UP_BF":
	 *
	 * - as regular cached memory, the variable is either missing or
	 *   set to zero. This type of mapping may cause the significant
	 *   doorbell register writing latency and requires explicit
	 *   memory write barrier to mitigate this issue and prevent
	 *   write combining.
	 *
	 * - as non-cached memory, the variable is present and set to
	 *   not "0" value. This type of mapping may cause performance
	 *   impact under heavy loading conditions but the explicit write
	 *   memory barrier is not required and it may improve core
	 *   performance.
	 *
	 * - the legacy behaviour (prior 19.08 release) was to use some
	 *   heuristics to decide whether write memory barrier should
	 *   be performed. This behavior is supported with specifying
	 *   tx_db_nc=2, write barrier is skipped if application
	 *   provides the full recommended burst of packets, it
	 *   supposes the next packets are coming and the write barrier
	 *   will be issued on the next burst (after descriptor writing,
	 *   at least).
	 */
	mlx5_tx_dbrec_cond_wmb(txq, loc.wqe_last, !txq->db_nc &&
			(!txq->db_heu || pkts_n % MLX5_TX_DEFAULT_BURST));
	/* Not all of the mbufs may be stored into elts yet. */
	part = (MLX5_TXOFF_CONFIG(INLINE) || !xchg_elts_vec)? 0 : loc.pkts_sent - loc.pkts_copy;
	if (!(MLX5_TXOFF_CONFIG(INLINE) || !xchg_elts_vec) && part) {
		/*
		 * There are some single-segment mbufs not stored in elts.
		 * It can be only if the last packet was single-segment.
		 * The copying is gathered into one place due to it is
		 * a good opportunity to optimize that with SIMD.
		 * Unfortunately if inlining is enabled the gaps in
		 * pointer array may happen due to early freeing of the
		 * inlined mbufs.
		 */
        if (xchg_elts_vec) {
            mlx5_tx_xchg_copy_elts(txq, xchgs_arg + loc.pkts_copy, part, olx);
        } else {
	 //       txq->elts_head += part;
        }
		loc.pkts_copy = loc.pkts_sent;
	}
	MLX5_ASSERT(txq->elts_s >= (uint16_t)(txq->elts_head - txq->elts_tail));
	MLX5_ASSERT(txq->wqe_s >= (uint16_t)(txq->wqe_ci - txq->wqe_pi));
	if (pkts_n > loc.pkts_sent) {
		/*
		 * If burst size is large there might be no enough CQE
		 * fetched from completion queue and no enough resources
		 * freed to send all the packets.
		 */
		goto send_loop;
	}
burst_exit:
#ifdef MLX5_PMD_SOFT_COUNTERS
	/* Increment sent packets counter. */
	txq->stats.opackets += loc.pkts_sent;
#endif
	return loc.pkts_sent;
}


#define MLX5_TXOFF_XCHG_DECL(func, olx) \
static uint16_t mlx5_tx_xchg_burst_##func(void *txq, \
				     struct xchg **xchgs, \
				    uint16_t pkts_n) \
{ \
	return mlx5_tx_burst_xchg_tmpl((struct mlx5_txq_data *)txq, \
		    xchgs, pkts_n, (olx)); \
}

MLX5_TXOFF_XCHG_DECL(none_empw,
		MLX5_TXOFF_CONFIG_NONE | MLX5_TXOFF_CONFIG_EMPW)

/*MLX5_TXOFF_XCHG_DECL(inline_empw,
		MLX5_TXOFF_CONFIG_INLINE | MLX5_TXOFF_CONFIG_EMPW)*/

//MLX5_TXOFF_XCHG_DECL(none,
//		MLX5_TXOFF_CONFIG_NONE)


uint16_t
rte_mlx5_rx_burst_xchg(uint16_t port_id, uint16_t queue_id,
	 struct xchg **xchgs, const uint16_t nb_pkts)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	uint16_t nb_rx;

	nb_rx = mlx5_rx_burst_xchg(dev->data->rx_queues[queue_id],
				     xchgs, nb_pkts);
	return nb_rx;
}


uint16_t
rte_mlx5_rx_burst_xchg_vec(uint16_t port_id, uint16_t queue_id,
	 struct xchg **xchgs, const uint16_t nb_pkts)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	uint16_t nb_rx;

	nb_rx = mlx5_rx_burst_xchg_vec(dev->data->rx_queues[queue_id],
				     xchgs, nb_pkts);
	return nb_rx;
}


uint16_t
rte_mlx5_rx_burst_xchg_vec_comp(uint16_t port_id, uint16_t queue_id,
	 struct xchg **xchgs, const uint16_t nb_pkts)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	uint16_t nb_rx;

	nb_rx = mlx5_rx_burst_xchg_vec(dev->data->rx_queues[queue_id],
				     xchgs, nb_pkts);
	return nb_rx;
}



uint16_t
rte_mlx5_tx_burst_xchg(uint16_t port_id, uint16_t queue_id,
		 struct xchg **tx_pkts, uint16_t nb_pkts)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	return mlx5_tx_xchg_burst_none_empw(dev->data->tx_queues[queue_id], tx_pkts, nb_pkts);
}

uint16_t
rte_mlx5_rx_burst_stripped(uint16_t port_id, uint16_t queue_id,
		 struct rte_mbuf **rx_pkts, const uint16_t nb_pkts)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	uint16_t nb_rx;

	nb_rx = mlx5_rx_burst_stripped(dev->data->rx_queues[queue_id],
				     rx_pkts, nb_pkts);
	return nb_rx;
}

uint16_t
mlx5_tx_burst_xchg(void *dpdk_txq,
		 struct xchg **tx_pkts, uint16_t nb_pkts)
{
	return mlx5_tx_xchg_burst_none_empw(dpdk_txq, tx_pkts, nb_pkts);
}
