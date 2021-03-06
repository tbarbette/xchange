/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 6WIND S.A.
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_RXTX_VEC_SSE_H_
#define RTE_PMD_MLX5_RXTX_VEC_SSE_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <smmintrin.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>

#include <mlx5_prm.h>

#include "mlx5_defs.h"
#include "mlx5.h"
#include "mlx5_utils.h"
#include "mlx5_rxtx.h"
#include "mlx5_rxtx_vec.h"
#include "mlx5_autoconf.h"

#ifndef __INTEL_COMPILER
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

/**
 * Store free buffers to RX SW ring.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param pkts
 *   Pointer to array of packets to be stored.
 * @param pkts_n
 *   Number of packets to be stored.
 */
static inline void
rxq_copy_mbuf_v(struct mlx5_rxq_data *rxq, struct rte_mbuf **pkts, uint16_t n)
{
	const uint16_t q_mask = (1 << rxq->elts_n) - 1;
	struct rte_mbuf **elts = &(*rxq->elts)[rxq->rq_pi & q_mask];
	unsigned int pos;
	uint16_t p = n & -2;

	for (pos = 0; pos < p; pos += 2) {
		__m128i mbp;

		mbp = _mm_loadu_si128((__m128i *)&elts[pos]);
		_mm_storeu_si128((__m128i *)&pkts[pos], mbp);
	}
	if (n & 1)
		pkts[pos] = elts[pos];
}

/**
 * Decompress a compressed completion and fill in mbufs in RX SW ring with data
 * extracted from the title completion descriptor.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param cq
 *   Pointer to completion array having a compressed completion at first.
 * @param elts
 *   Pointer to SW ring to be filled. The first mbuf has to be pre-built from
 *   the title completion descriptor to be copied to the rest of mbufs.
 *
 * @return
 *   Number of mini-CQEs successfully decompressed.
 */
static inline uint16_t
rxq_cq_decompress_v(struct mlx5_rxq_data *rxq, volatile struct mlx5_cqe *cq,
		    struct rte_mbuf **elts)
{
	volatile struct mlx5_mini_cqe8 *mcq = (void *)(cq + 1);
	struct rte_mbuf *t_pkt = elts[0]; /* Title packet is pre-built. */
	unsigned int pos;
	unsigned int i;
	unsigned int inv = 0;
	/* Mask to shuffle from extracted mini CQE to mbuf. */
	const __m128i shuf_mask1 =
		_mm_set_epi8(0,  1,  2,  3, /* rss, bswap32 */
			    -1, -1,         /* skip vlan_tci */
			     6,  7,         /* data_len, bswap16 */
			    -1, -1,  6,  7, /* pkt_len, bswap16 */
			    -1, -1, -1, -1  /* skip packet_type */);
	const __m128i shuf_mask2 =
		_mm_set_epi8(8,  9, 10, 11, /* rss, bswap32 */
			    -1, -1,         /* skip vlan_tci */
			    14, 15,         /* data_len, bswap16 */
			    -1, -1, 14, 15, /* pkt_len, bswap16 */
			    -1, -1, -1, -1  /* skip packet_type */);
	/* Restore the compressed count. Must be 16 bits. */
	const uint16_t mcqe_n = t_pkt->data_len +
				(rxq->crc_present * RTE_ETHER_CRC_LEN);
	const __m128i rearm =
		_mm_loadu_si128((__m128i *)&t_pkt->rearm_data);
	const __m128i rxdf =
		_mm_loadu_si128((__m128i *)&t_pkt->rx_descriptor_fields1);
	const __m128i crc_adj =
		_mm_set_epi16(0, 0, 0,
			      rxq->crc_present * RTE_ETHER_CRC_LEN,
			      0,
			      rxq->crc_present * RTE_ETHER_CRC_LEN,
			      0, 0);
	const uint32_t flow_tag = t_pkt->hash.fdir.hi;
#ifdef MLX5_PMD_SOFT_COUNTERS
	const __m128i zero = _mm_setzero_si128();
	const __m128i ones = _mm_cmpeq_epi32(zero, zero);
	uint32_t rcvd_byte = 0;
	/* Mask to shuffle byte_cnt to add up stats. Do bswap16 for all. */
	const __m128i len_shuf_mask =
		_mm_set_epi8(-1, -1, -1, -1,
			     -1, -1, -1, -1,
			     14, 15,  6,  7,
			     10, 11,  2,  3);
#endif

	/*
	 * A. load mCQEs into a 128bit register.
	 * B. store rearm data to mbuf.
	 * C. combine data from mCQEs with rx_descriptor_fields1.
	 * D. store rx_descriptor_fields1.
	 * E. store flow tag (rte_flow mark).
	 */
	for (pos = 0; pos < mcqe_n; ) {
		__m128i mcqe1, mcqe2;
		__m128i rxdf1, rxdf2;
#ifdef MLX5_PMD_SOFT_COUNTERS
		__m128i byte_cnt, invalid_mask;
#endif

		if (!(pos & 0x7) && pos + 8 < mcqe_n)
			rte_prefetch0((void *)(cq + pos + 8));
		/* A.1 load mCQEs into a 128bit register. */
		mcqe1 = _mm_loadu_si128((__m128i *)&mcq[pos % 8]);
		mcqe2 = _mm_loadu_si128((__m128i *)&mcq[pos % 8 + 2]);
		/* B.1 store rearm data to mbuf. */
		_mm_storeu_si128((__m128i *)&elts[pos]->rearm_data, rearm);
		_mm_storeu_si128((__m128i *)&elts[pos + 1]->rearm_data, rearm);
		/* C.1 combine data from mCQEs with rx_descriptor_fields1. */
		rxdf1 = _mm_shuffle_epi8(mcqe1, shuf_mask1);
		rxdf2 = _mm_shuffle_epi8(mcqe1, shuf_mask2);
		rxdf1 = _mm_sub_epi16(rxdf1, crc_adj);
		rxdf2 = _mm_sub_epi16(rxdf2, crc_adj);
		rxdf1 = _mm_blend_epi16(rxdf1, rxdf, 0x23);
		rxdf2 = _mm_blend_epi16(rxdf2, rxdf, 0x23);
		/* D.1 store rx_descriptor_fields1. */
		_mm_storeu_si128((__m128i *)
				  &elts[pos]->rx_descriptor_fields1,
				 rxdf1);
		_mm_storeu_si128((__m128i *)
				  &elts[pos + 1]->rx_descriptor_fields1,
				 rxdf2);
		/* B.1 store rearm data to mbuf. */
		_mm_storeu_si128((__m128i *)&elts[pos + 2]->rearm_data, rearm);
		_mm_storeu_si128((__m128i *)&elts[pos + 3]->rearm_data, rearm);
		/* C.1 combine data from mCQEs with rx_descriptor_fields1. */
		rxdf1 = _mm_shuffle_epi8(mcqe2, shuf_mask1);
		rxdf2 = _mm_shuffle_epi8(mcqe2, shuf_mask2);
		rxdf1 = _mm_sub_epi16(rxdf1, crc_adj);
		rxdf2 = _mm_sub_epi16(rxdf2, crc_adj);
		rxdf1 = _mm_blend_epi16(rxdf1, rxdf, 0x23);
		rxdf2 = _mm_blend_epi16(rxdf2, rxdf, 0x23);
		/* D.1 store rx_descriptor_fields1. */
		_mm_storeu_si128((__m128i *)
				  &elts[pos + 2]->rx_descriptor_fields1,
				 rxdf1);
		_mm_storeu_si128((__m128i *)
				  &elts[pos + 3]->rx_descriptor_fields1,
				 rxdf2);
#ifdef MLX5_PMD_SOFT_COUNTERS
		invalid_mask = _mm_set_epi64x(0,
					      (mcqe_n - pos) *
					      sizeof(uint16_t) * 8);
		invalid_mask = _mm_sll_epi64(ones, invalid_mask);
		mcqe1 = _mm_srli_si128(mcqe1, 4);
		byte_cnt = _mm_blend_epi16(mcqe1, mcqe2, 0xcc);
		byte_cnt = _mm_shuffle_epi8(byte_cnt, len_shuf_mask);
		byte_cnt = _mm_andnot_si128(invalid_mask, byte_cnt);
		byte_cnt = _mm_hadd_epi16(byte_cnt, zero);
		rcvd_byte += _mm_cvtsi128_si64(_mm_hadd_epi16(byte_cnt, zero));
#endif
		if (rxq->mark) {
			/* E.1 store flow tag (rte_flow mark). */
			elts[pos]->hash.fdir.hi = flow_tag;
			elts[pos + 1]->hash.fdir.hi = flow_tag;
			elts[pos + 2]->hash.fdir.hi = flow_tag;
			elts[pos + 3]->hash.fdir.hi = flow_tag;
		}
		pos += MLX5_VPMD_DESCS_PER_LOOP;
		/* Move to next CQE and invalidate consumed CQEs. */
		if (!(pos & 0x7) && pos < mcqe_n) {
			mcq = (void *)(cq + pos);
			for (i = 0; i < 8; ++i)
				cq[inv++].op_own = MLX5_CQE_INVALIDATE;
		}
	}
	/* Invalidate the rest of CQEs. */
	for (; inv < mcqe_n; ++inv)
		cq[inv].op_own = MLX5_CQE_INVALIDATE;
#ifdef MLX5_PMD_SOFT_COUNTERS
	rxq->stats.ipackets += mcqe_n;
	rxq->stats.ibytes += rcvd_byte;
#endif
	rxq->cq_ci += mcqe_n;
	return mcqe_n;
}

/**
 * Calculate packet type and offload flag for mbuf and store it.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param cqes[4]
 *   Array of four 16bytes completions extracted from the original completion
 *   descriptor.
 * @param op_err
 *   Opcode vector having responder error status. Each field is 4B.
 * @param pkts
 *   Pointer to array of packets to be filled.
 */
static inline void
rxq_cq_to_ptype_oflags_v(struct mlx5_rxq_data *rxq, __m128i cqes[4],
			 __m128i op_err, struct rte_mbuf **pkts)
{
	__m128i pinfo0, pinfo1;
	__m128i pinfo, ptype;
	__m128i ol_flags = _mm_set1_epi32(rxq->rss_hash * PKT_RX_RSS_HASH |
					  rxq->hw_timestamp * PKT_RX_TIMESTAMP);
	__m128i cv_flags;
	const __m128i zero = _mm_setzero_si128();
	const __m128i ptype_mask =
		_mm_set_epi32(0xfd06, 0xfd06, 0xfd06, 0xfd06);
	const __m128i ptype_ol_mask =
		_mm_set_epi32(0x106, 0x106, 0x106, 0x106);
	const __m128i pinfo_mask =
		_mm_set_epi32(0x3, 0x3, 0x3, 0x3);
	const __m128i cv_flag_sel =
		_mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0,
			     (uint8_t)((PKT_RX_IP_CKSUM_GOOD |
					PKT_RX_L4_CKSUM_GOOD) >> 1),
			     0,
			     (uint8_t)(PKT_RX_L4_CKSUM_GOOD >> 1),
			     0,
			     (uint8_t)(PKT_RX_IP_CKSUM_GOOD >> 1),
			     (uint8_t)(PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED),
			     0);
	const __m128i cv_mask =
		_mm_set_epi32(PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD |
			      PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED,
			      PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD |
			      PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED,
			      PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD |
			      PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED,
			      PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD |
			      PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED);
	const __m128i mbuf_init =
		_mm_load_si128((__m128i *)&rxq->mbuf_initializer);
	__m128i rearm0, rearm1, rearm2, rearm3;
	uint8_t pt_idx0, pt_idx1, pt_idx2, pt_idx3;

	/* Extract pkt_info field. */
	pinfo0 = _mm_unpacklo_epi32(cqes[0], cqes[1]);
	pinfo1 = _mm_unpacklo_epi32(cqes[2], cqes[3]);
	pinfo = _mm_unpacklo_epi64(pinfo0, pinfo1);
	/* Extract hdr_type_etc field. */
	pinfo0 = _mm_unpackhi_epi32(cqes[0], cqes[1]);
	pinfo1 = _mm_unpackhi_epi32(cqes[2], cqes[3]);
	ptype = _mm_unpacklo_epi64(pinfo0, pinfo1);
	if (rxq->mark) {
		const __m128i pinfo_ft_mask =
			_mm_set_epi32(0xffffff00, 0xffffff00,
				      0xffffff00, 0xffffff00);
		const __m128i fdir_flags = _mm_set1_epi32(PKT_RX_FDIR);
		__m128i fdir_id_flags = _mm_set1_epi32(PKT_RX_FDIR_ID);
		__m128i flow_tag, invalid_mask;

		flow_tag = _mm_and_si128(pinfo, pinfo_ft_mask);
		/* Check if flow tag is non-zero then set PKT_RX_FDIR. */
		invalid_mask = _mm_cmpeq_epi32(flow_tag, zero);
		ol_flags = _mm_or_si128(ol_flags,
					_mm_andnot_si128(invalid_mask,
							 fdir_flags));
		/* Mask out invalid entries. */
		fdir_id_flags = _mm_andnot_si128(invalid_mask, fdir_id_flags);
		/* Check if flow tag MLX5_FLOW_MARK_DEFAULT. */
		ol_flags = _mm_or_si128(ol_flags,
					_mm_andnot_si128(
						_mm_cmpeq_epi32(flow_tag,
								pinfo_ft_mask),
						fdir_id_flags));
	}
	/*
	 * Merge the two fields to generate the following:
	 * bit[1]     = l3_ok
	 * bit[2]     = l4_ok
	 * bit[8]     = cv
	 * bit[11:10] = l3_hdr_type
	 * bit[14:12] = l4_hdr_type
	 * bit[15]    = ip_frag
	 * bit[16]    = tunneled
	 * bit[17]    = outer_l3_type
	 */
	ptype = _mm_and_si128(ptype, ptype_mask);
	pinfo = _mm_and_si128(pinfo, pinfo_mask);
	pinfo = _mm_slli_epi32(pinfo, 16);
	/* Make pinfo has merged fields for ol_flags calculation. */
	pinfo = _mm_or_si128(ptype, pinfo);
	ptype = _mm_srli_epi32(pinfo, 10);
	ptype = _mm_packs_epi32(ptype, zero);
	/* Errored packets will have RTE_PTYPE_ALL_MASK. */
	op_err = _mm_srli_epi16(op_err, 8);
	ptype = _mm_or_si128(ptype, op_err);
	pt_idx0 = _mm_extract_epi8(ptype, 0);
	pt_idx1 = _mm_extract_epi8(ptype, 2);
	pt_idx2 = _mm_extract_epi8(ptype, 4);
	pt_idx3 = _mm_extract_epi8(ptype, 6);
	pkts[0]->packet_type = mlx5_ptype_table[pt_idx0] |
			       !!(pt_idx0 & (1 << 6)) * rxq->tunnel;
	pkts[1]->packet_type = mlx5_ptype_table[pt_idx1] |
			       !!(pt_idx1 & (1 << 6)) * rxq->tunnel;
	pkts[2]->packet_type = mlx5_ptype_table[pt_idx2] |
			       !!(pt_idx2 & (1 << 6)) * rxq->tunnel;
	pkts[3]->packet_type = mlx5_ptype_table[pt_idx3] |
			       !!(pt_idx3 & (1 << 6)) * rxq->tunnel;
	/* Fill flags for checksum and VLAN. */
	pinfo = _mm_and_si128(pinfo, ptype_ol_mask);
	pinfo = _mm_shuffle_epi8(cv_flag_sel, pinfo);
	/* Locate checksum flags at byte[2:1] and merge with VLAN flags. */
	cv_flags = _mm_slli_epi32(pinfo, 9);
	cv_flags = _mm_or_si128(pinfo, cv_flags);
	/* Move back flags to start from byte[0]. */
	cv_flags = _mm_srli_epi32(cv_flags, 8);
	/* Mask out garbage bits. */
	cv_flags = _mm_and_si128(cv_flags, cv_mask);
	/* Merge to ol_flags. */
	ol_flags = _mm_or_si128(ol_flags, cv_flags);
	/* Merge mbuf_init and ol_flags. */
	rearm0 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(ol_flags, 8), 0x30);
	rearm1 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(ol_flags, 4), 0x30);
	rearm2 = _mm_blend_epi16(mbuf_init, ol_flags, 0x30);
	rearm3 = _mm_blend_epi16(mbuf_init, _mm_srli_si128(ol_flags, 4), 0x30);
	/* Write 8B rearm_data and 8B ol_flags. */
	_mm_store_si128((__m128i *)&pkts[0]->rearm_data, rearm0);
	_mm_store_si128((__m128i *)&pkts[1]->rearm_data, rearm1);
	_mm_store_si128((__m128i *)&pkts[2]->rearm_data, rearm2);
	_mm_store_si128((__m128i *)&pkts[3]->rearm_data, rearm3);
}

/**
 * Receive burst of packets. An errored completion also consumes a mbuf, but the
 * packet_type is set to be RTE_PTYPE_ALL_MASK. Marked mbufs should be freed
 * before returning to application.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 * @param[out] err
 *   Pointer to a flag. Set non-zero value if pkts array has at least one error
 *   packet to handle.
 *
 * @return
 *   Number of packets received including errors (<= pkts_n).
 */
static inline uint16_t
rxq_burst_v(struct mlx5_rxq_data *rxq, struct rte_mbuf **pkts, uint16_t pkts_n,
	    uint64_t *err)
{
	const uint16_t q_n = 1 << rxq->cqe_n;
	const uint16_t q_mask = q_n - 1;
	volatile struct mlx5_cqe *cq;
	struct rte_mbuf **elts;
	unsigned int pos;
	uint64_t n;
	uint16_t repl_n;
	uint64_t comp_idx = MLX5_VPMD_DESCS_PER_LOOP;
	uint16_t nocmp_n = 0;
	uint16_t rcvd_pkt = 0;
	unsigned int cq_idx = rxq->cq_ci & q_mask;
	unsigned int elts_idx;
	unsigned int ownership = !!(rxq->cq_ci & (q_mask + 1));
	const __m128i owner_check =
		_mm_set_epi64x(0x0100000001000000LL, 0x0100000001000000LL);
	const __m128i opcode_check =
		_mm_set_epi64x(0xf0000000f0000000LL, 0xf0000000f0000000LL);
	const __m128i format_check =
		_mm_set_epi64x(0x0c0000000c000000LL, 0x0c0000000c000000LL);
	const __m128i resp_err_check =
		_mm_set_epi64x(0xe0000000e0000000LL, 0xe0000000e0000000LL);
#ifdef MLX5_PMD_SOFT_COUNTERS
	uint32_t rcvd_byte = 0;
	/* Mask to shuffle byte_cnt to add up stats. Do bswap16 for all. */
	const __m128i len_shuf_mask =
		_mm_set_epi8(-1, -1, -1, -1,
			     -1, -1, -1, -1,
			     12, 13,  8,  9,
			      4,  5,  0,  1);
#endif

    // Mask to shuffle from extracted CQE to mbuf.
	const __m128i shuf_mask =
		_mm_set_epi8(-1,  3,  2,  1, /* fdir.hi */
			     12, 13, 14, 15, /* rss, bswap32 */
			     10, 11,         /* vlan_tci, bswap16 */
			      4,  5,         /* data_len, bswap16 */
			     -1, -1,         /* zero out 2nd half of pkt_len */
			      4,  5          /* pkt_len, bswap16 */);
	/* Mask to blend from the last Qword to the first DQword. */
	const __m128i blend_mask =
		_mm_set_epi8(-1, -1, -1, -1,
			     -1, -1, -1, -1,
			      0,  0,  0,  0,
			      0,  0,  0, -1);
	const __m128i zero = _mm_setzero_si128();
	const __m128i ones = _mm_cmpeq_epi32(zero, zero);
	const __m128i crc_adj =
		_mm_set_epi16(0, 0, 0, 0, 0,
			      rxq->crc_present * RTE_ETHER_CRC_LEN,
			      0,
			      rxq->crc_present * RTE_ETHER_CRC_LEN);
	const __m128i flow_mark_adj = _mm_set_epi32(rxq->mark * (-1), 0, 0, 0);

	MLX5_ASSERT(rxq->sges_n == 0);
	MLX5_ASSERT(rxq->cqe_n == rxq->elts_n);
	cq = &(*rxq->cqes)[cq_idx];
	rte_prefetch0(cq);
	rte_prefetch0(cq + 1);
	rte_prefetch0(cq + 2);
	rte_prefetch0(cq + 3);
	pkts_n = RTE_MIN(pkts_n, MLX5_VPMD_RX_MAX_BURST);
	repl_n = q_n - (rxq->rq_ci - rxq->rq_pi);
	if (repl_n >= rxq->rq_repl_thresh)
		mlx5_rx_replenish_bulk_mbuf(rxq, repl_n);
	/* See if there're unreturned mbufs from compressed CQE. */
	rcvd_pkt = rxq->decompressed;
	if (rcvd_pkt > 0) {
		rcvd_pkt = RTE_MIN(rcvd_pkt, pkts_n);
		rxq_copy_mbuf_v(rxq, pkts, rcvd_pkt);
		rxq->rq_pi += rcvd_pkt;
		rxq->decompressed -= rcvd_pkt;
		pkts += rcvd_pkt;
	}
	elts_idx = rxq->rq_pi & q_mask;
	elts = &(*rxq->elts)[elts_idx];
	/* Not to overflow pkts array. */
	pkts_n = RTE_ALIGN_FLOOR(pkts_n - rcvd_pkt, MLX5_VPMD_DESCS_PER_LOOP);
	/* Not to cross queue end. */
	pkts_n = RTE_MIN(pkts_n, q_n - elts_idx);
	pkts_n = RTE_MIN(pkts_n, q_n - cq_idx);
	if (!pkts_n)
		return rcvd_pkt;
	/* At this point, there shouldn't be any remained packets. */
	MLX5_ASSERT(rxq->decompressed == 0);
	/*
	 * A. load first Qword (8bytes) in one loop.
	 * B. copy 4 mbuf pointers from elts ring to returing pkts.
	 * C. load remained CQE data and extract necessary fields.
	 *    Final 16bytes cqes[] extracted from original 64bytes CQE has the
	 *    following structure:
	 *        struct {
	 *          uint8_t  pkt_info;
	 *          uint8_t  flow_tag[3];
	 *          uint16_t byte_cnt;
	 *          uint8_t  rsvd4;
	 *          uint8_t  op_own;
	 *          uint16_t hdr_type_etc;
	 *          uint16_t vlan_info;
	 *          uint32_t rx_has_res;
	 *        } c;
	 * D. fill in mbuf.
	 * E. get valid CQEs.
	 * F. find compressed CQE.
	 */
	for (pos = 0;
	     pos < pkts_n;
	     pos += MLX5_VPMD_DESCS_PER_LOOP) {
		__m128i cqes[MLX5_VPMD_DESCS_PER_LOOP];
		__m128i cqe_tmp1, cqe_tmp2;
		__m128i pkt_mb0, pkt_mb1, pkt_mb2, pkt_mb3;
		__m128i op_own, op_own_tmp1, op_own_tmp2;
		__m128i opcode, owner_mask, invalid_mask;
		__m128i comp_mask;
		__m128i mask;
#ifdef MLX5_PMD_SOFT_COUNTERS
		__m128i byte_cnt;
#endif
		__m128i mbp1, mbp2;
		__m128i p = _mm_set_epi16(0, 0, 0, 0, 3, 2, 1, 0);
		unsigned int p1, p2, p3;

		/* Prefetch next 4 CQEs. */
		if (pkts_n - pos >= 2 * MLX5_VPMD_DESCS_PER_LOOP) {
			rte_prefetch0(&cq[pos + MLX5_VPMD_DESCS_PER_LOOP]);
			rte_prefetch0(&cq[pos + MLX5_VPMD_DESCS_PER_LOOP + 1]);
			rte_prefetch0(&cq[pos + MLX5_VPMD_DESCS_PER_LOOP + 2]);
			rte_prefetch0(&cq[pos + MLX5_VPMD_DESCS_PER_LOOP + 3]);
		}
		/* A.0 do not cross the end of CQ. */
		mask = _mm_set_epi64x(0, (pkts_n - pos) * sizeof(uint16_t) * 8);
		mask = _mm_sll_epi64(ones, mask);
		p = _mm_andnot_si128(mask, p);
		/* A.1 load cqes. */
		p3 = _mm_extract_epi16(p, 3);
		cqes[3] = _mm_loadl_epi64((__m128i *)
					   &cq[pos + p3].sop_drop_qpn);
		rte_compiler_barrier();
		p2 = _mm_extract_epi16(p, 2);
		cqes[2] = _mm_loadl_epi64((__m128i *)
					   &cq[pos + p2].sop_drop_qpn);
		rte_compiler_barrier();
		/* B.1 load mbuf pointers. */
		mbp1 = _mm_loadu_si128((__m128i *)&elts[pos]);
		mbp2 = _mm_loadu_si128((__m128i *)&elts[pos + 2]);
		/* A.1 load a block having op_own. */
		p1 = _mm_extract_epi16(p, 1);
		cqes[1] = _mm_loadl_epi64((__m128i *)
					   &cq[pos + p1].sop_drop_qpn);
		rte_compiler_barrier();
		cqes[0] = _mm_loadl_epi64((__m128i *)
					   &cq[pos].sop_drop_qpn);
		/* B.2 copy mbuf pointers. */
		_mm_storeu_si128((__m128i *)&pkts[pos], mbp1);
		_mm_storeu_si128((__m128i *)&pkts[pos + 2], mbp2);
		rte_cio_rmb();
		/* C.1 load remained CQE data and extract necessary fields. */
		cqe_tmp2 = _mm_load_si128((__m128i *)&cq[pos + p3]);
		cqe_tmp1 = _mm_load_si128((__m128i *)&cq[pos + p2]);
		cqes[3] = _mm_blendv_epi8(cqes[3], cqe_tmp2, blend_mask);
		cqes[2] = _mm_blendv_epi8(cqes[2], cqe_tmp1, blend_mask);
		cqe_tmp2 = _mm_loadu_si128((__m128i *)&cq[pos + p3].csum);
		cqe_tmp1 = _mm_loadu_si128((__m128i *)&cq[pos + p2].csum);
		cqes[3] = _mm_blend_epi16(cqes[3], cqe_tmp2, 0x30);
		cqes[2] = _mm_blend_epi16(cqes[2], cqe_tmp1, 0x30);
		cqe_tmp2 = _mm_loadl_epi64((__m128i *)&cq[pos + p3].rsvd4[2]);
		cqe_tmp1 = _mm_loadl_epi64((__m128i *)&cq[pos + p2].rsvd4[2]);
		cqes[3] = _mm_blend_epi16(cqes[3], cqe_tmp2, 0x04);
		cqes[2] = _mm_blend_epi16(cqes[2], cqe_tmp1, 0x04);
		/* C.2 generate final structure for mbuf with swapping bytes. */
		pkt_mb3 = _mm_shuffle_epi8(cqes[3], shuf_mask);
		pkt_mb2 = _mm_shuffle_epi8(cqes[2], shuf_mask);
		/* C.3 adjust CRC length. */
		pkt_mb3 = _mm_sub_epi16(pkt_mb3, crc_adj);
		pkt_mb2 = _mm_sub_epi16(pkt_mb2, crc_adj);
		/* C.4 adjust flow mark. */
		pkt_mb3 = _mm_add_epi32(pkt_mb3, flow_mark_adj);
		pkt_mb2 = _mm_add_epi32(pkt_mb2, flow_mark_adj);
		/* D.1 fill in mbuf - rx_descriptor_fields1. */
		_mm_storeu_si128((void *)&pkts[pos + 3]->pkt_len, pkt_mb3);
		_mm_storeu_si128((void *)&pkts[pos + 2]->pkt_len, pkt_mb2);
		/* E.1 extract op_own field. */
		op_own_tmp2 = _mm_unpacklo_epi32(cqes[2], cqes[3]);
		/* C.1 load remained CQE data and extract necessary fields. */
		cqe_tmp2 = _mm_load_si128((__m128i *)&cq[pos + p1]);
		cqe_tmp1 = _mm_load_si128((__m128i *)&cq[pos]);
		cqes[1] = _mm_blendv_epi8(cqes[1], cqe_tmp2, blend_mask);
		cqes[0] = _mm_blendv_epi8(cqes[0], cqe_tmp1, blend_mask);
		cqe_tmp2 = _mm_loadu_si128((__m128i *)&cq[pos + p1].csum);
		cqe_tmp1 = _mm_loadu_si128((__m128i *)&cq[pos].csum);
		cqes[1] = _mm_blend_epi16(cqes[1], cqe_tmp2, 0x30);
		cqes[0] = _mm_blend_epi16(cqes[0], cqe_tmp1, 0x30);
		cqe_tmp2 = _mm_loadl_epi64((__m128i *)&cq[pos + p1].rsvd4[2]);
		cqe_tmp1 = _mm_loadl_epi64((__m128i *)&cq[pos].rsvd4[2]);
		cqes[1] = _mm_blend_epi16(cqes[1], cqe_tmp2, 0x04);
		cqes[0] = _mm_blend_epi16(cqes[0], cqe_tmp1, 0x04);
		/* C.2 generate final structure for mbuf with swapping bytes. */
		pkt_mb1 = _mm_shuffle_epi8(cqes[1], shuf_mask);
		pkt_mb0 = _mm_shuffle_epi8(cqes[0], shuf_mask);
		/* C.3 adjust CRC length. */
		pkt_mb1 = _mm_sub_epi16(pkt_mb1, crc_adj);
		pkt_mb0 = _mm_sub_epi16(pkt_mb0, crc_adj);
		/* C.4 adjust flow mark. */
		pkt_mb1 = _mm_add_epi32(pkt_mb1, flow_mark_adj);
		pkt_mb0 = _mm_add_epi32(pkt_mb0, flow_mark_adj);
		/* E.1 extract op_own byte. */
		op_own_tmp1 = _mm_unpacklo_epi32(cqes[0], cqes[1]);
		op_own = _mm_unpackhi_epi64(op_own_tmp1, op_own_tmp2);
		/* D.1 fill in mbuf - rx_descriptor_fields1. */
		_mm_storeu_si128((void *)&pkts[pos + 1]->pkt_len, pkt_mb1);
		_mm_storeu_si128((void *)&pkts[pos]->pkt_len, pkt_mb0);
		/* E.2 flip owner bit to mark CQEs from last round. */
		owner_mask = _mm_and_si128(op_own, owner_check);
		if (ownership)
			owner_mask = _mm_xor_si128(owner_mask, owner_check);
		owner_mask = _mm_cmpeq_epi32(owner_mask, owner_check);
		owner_mask = _mm_packs_epi32(owner_mask, zero);
		/* E.3 get mask for invalidated CQEs. */
		opcode = _mm_and_si128(op_own, opcode_check);
		invalid_mask = _mm_cmpeq_epi32(opcode_check, opcode);
		invalid_mask = _mm_packs_epi32(invalid_mask, zero);
		/* E.4 mask out beyond boundary. */
		invalid_mask = _mm_or_si128(invalid_mask, mask);
		/* E.5 merge invalid_mask with invalid owner. */
		invalid_mask = _mm_or_si128(invalid_mask, owner_mask);
		/* F.1 find compressed CQE format. */
		comp_mask = _mm_and_si128(op_own, format_check);
		comp_mask = _mm_cmpeq_epi32(comp_mask, format_check);
		comp_mask = _mm_packs_epi32(comp_mask, zero);
		/* F.2 mask out invalid entries. */
		comp_mask = _mm_andnot_si128(invalid_mask, comp_mask);
		comp_idx = _mm_cvtsi128_si64(comp_mask);
		/* F.3 get the first compressed CQE. */
		comp_idx = comp_idx ?
				__builtin_ctzll(comp_idx) /
					(sizeof(uint16_t) * 8) :
				MLX5_VPMD_DESCS_PER_LOOP;
		/* E.6 mask out entries after the compressed CQE. */
		mask = _mm_set_epi64x(0, comp_idx * sizeof(uint16_t) * 8);
		mask = _mm_sll_epi64(ones, mask);
		invalid_mask = _mm_or_si128(invalid_mask, mask);
		/* E.7 count non-compressed valid CQEs. */
		n = _mm_cvtsi128_si64(invalid_mask);
		n = n ? __builtin_ctzll(n) / (sizeof(uint16_t) * 8) :
			MLX5_VPMD_DESCS_PER_LOOP;
		nocmp_n += n;
		/* D.2 get the final invalid mask. */
		mask = _mm_set_epi64x(0, n * sizeof(uint16_t) * 8);
		mask = _mm_sll_epi64(ones, mask);
		invalid_mask = _mm_or_si128(invalid_mask, mask);
		/* D.3 check error in opcode. */
		opcode = _mm_cmpeq_epi32(resp_err_check, opcode);
		opcode = _mm_packs_epi32(opcode, zero);
		opcode = _mm_andnot_si128(invalid_mask, opcode);
		/* D.4 mark if any error is set */
		*err |= _mm_cvtsi128_si64(opcode);
		/* D.5 fill in mbuf - rearm_data and packet_type. */
		rxq_cq_to_ptype_oflags_v(rxq, cqes, opcode, &pkts[pos]);
		if (rxq->hw_timestamp) {
			pkts[pos]->timestamp =
				rte_be_to_cpu_64(cq[pos].timestamp);
			pkts[pos + 1]->timestamp =
				rte_be_to_cpu_64(cq[pos + p1].timestamp);
			pkts[pos + 2]->timestamp =
				rte_be_to_cpu_64(cq[pos + p2].timestamp);
			pkts[pos + 3]->timestamp =
				rte_be_to_cpu_64(cq[pos + p3].timestamp);
		}
		if (rte_flow_dynf_metadata_avail()) {
			/* This code is subject for futher optimization. */
			*RTE_FLOW_DYNF_METADATA(pkts[pos]) =
				cq[pos].flow_table_metadata;
			*RTE_FLOW_DYNF_METADATA(pkts[pos + 1]) =
				cq[pos + p1].flow_table_metadata;
			*RTE_FLOW_DYNF_METADATA(pkts[pos + 2]) =
				cq[pos + p2].flow_table_metadata;
			*RTE_FLOW_DYNF_METADATA(pkts[pos + 3]) =
				cq[pos + p3].flow_table_metadata;
			if (*RTE_FLOW_DYNF_METADATA(pkts[pos]))
				pkts[pos]->ol_flags |= PKT_RX_DYNF_METADATA;
			if (*RTE_FLOW_DYNF_METADATA(pkts[pos + 1]))
				pkts[pos + 1]->ol_flags |= PKT_RX_DYNF_METADATA;
			if (*RTE_FLOW_DYNF_METADATA(pkts[pos + 2]))
				pkts[pos + 2]->ol_flags |= PKT_RX_DYNF_METADATA;
			if (*RTE_FLOW_DYNF_METADATA(pkts[pos + 3]))
				pkts[pos + 3]->ol_flags |= PKT_RX_DYNF_METADATA;
		}
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Add up received bytes count. */
		byte_cnt = _mm_shuffle_epi8(op_own, len_shuf_mask);
		byte_cnt = _mm_andnot_si128(invalid_mask, byte_cnt);
		byte_cnt = _mm_hadd_epi16(byte_cnt, zero);
		rcvd_byte += _mm_cvtsi128_si64(_mm_hadd_epi16(byte_cnt, zero));
#endif
		/*
		 * Break the loop unless more valid CQE is expected, or if
		 * there's a compressed CQE.
		 */
		if (n != MLX5_VPMD_DESCS_PER_LOOP)
			break;
	}
	/* If no new CQE seen, return without updating cq_db. */
	if (unlikely(!nocmp_n && comp_idx == MLX5_VPMD_DESCS_PER_LOOP))
		return rcvd_pkt;
	/* Update the consumer indexes for non-compressed CQEs. */
	MLX5_ASSERT(nocmp_n <= pkts_n);
	rxq->cq_ci += nocmp_n;
	rxq->rq_pi += nocmp_n;
	rcvd_pkt += nocmp_n;
#ifdef MLX5_PMD_SOFT_COUNTERS
	rxq->stats.ipackets += nocmp_n;
	rxq->stats.ibytes += rcvd_byte;
#endif
	/* Decompress the last CQE if compressed. */
	if (comp_idx < MLX5_VPMD_DESCS_PER_LOOP && comp_idx == n) {
		MLX5_ASSERT(comp_idx == (nocmp_n % MLX5_VPMD_DESCS_PER_LOOP));
		rxq->decompressed = rxq_cq_decompress_v(rxq, &cq[nocmp_n],
							&elts[nocmp_n]);
		/* Return more packets if needed. */
		if (nocmp_n < pkts_n) {
			uint16_t n = rxq->decompressed;

			n = RTE_MIN(n, pkts_n - nocmp_n);
			rxq_copy_mbuf_v(rxq, &pkts[nocmp_n], n);
			rxq->rq_pi += n;
			rcvd_pkt += n;
			rxq->decompressed -= n;
		}
	}
	rte_compiler_barrier();
	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	return rcvd_pkt;
}

#ifdef RTE_LIBRTE_XCHG
#include <rte_xchg.h>

/**
 * Calculate packet type and offload flag for mbuf and store it.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param cqes[4]
 *   Array of four 16bytes completions extracted from the original completion
 *   descriptor.
 * @param op_err
 *   Opcode vector having responder error status. Each field is 4B.
 * @param pkts
 *   Pointer to array of packets to be filled.
 */
static inline void
rxq_cq_to_ptype_oflags_v_xchg(struct mlx5_rxq_data *rxq, __m128i cqes[4],
			 __m128i op_err, struct xchg **xchgs)
{
	__m128i pinfo0, pinfo1;
	__m128i pinfo, ptype;
	__m128i ol_flags = _mm_set1_epi32(rxq->rss_hash * PKT_RX_RSS_HASH |
					  rxq->hw_timestamp * PKT_RX_TIMESTAMP);

	__m128i cv_flags;
	const __m128i zero = _mm_setzero_si128();
	const __m128i ptype_mask =
		_mm_set_epi32(0xfd06, 0xfd06, 0xfd06, 0xfd06);
	const __m128i ptype_ol_mask =
		_mm_set_epi32(0x106, 0x106, 0x106, 0x106);
	const __m128i pinfo_mask =
		_mm_set_epi32(0x3, 0x3, 0x3, 0x3);
	const __m128i cv_flag_sel =
		_mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0,
			     (uint8_t)((PKT_RX_IP_CKSUM_GOOD |
					PKT_RX_L4_CKSUM_GOOD) >> 1),
			     0,
			     (uint8_t)(PKT_RX_L4_CKSUM_GOOD >> 1),
			     0,
			     (uint8_t)(PKT_RX_IP_CKSUM_GOOD >> 1),
			     (uint8_t)(PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED),
			     0);
	const __m128i cv_mask =
		_mm_set_epi32(PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD |
			      PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED,
			      PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD |
			      PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED,
			      PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD |
			      PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED,
			      PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD |
			      PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED);
	/*const __m128i mbuf_init =
		_mm_load_si128((__m128i *)&rxq->mbuf_initializer);
	__m128i rearm0, rearm1, rearm2, rearm3;*/
	uint8_t pt_idx0, pt_idx1, pt_idx2, pt_idx3;

	/* Extract pkt_info field. */
	pinfo0 = _mm_unpacklo_epi32(cqes[0], cqes[1]);
	pinfo1 = _mm_unpacklo_epi32(cqes[2], cqes[3]);
	pinfo = _mm_unpacklo_epi64(pinfo0, pinfo1);
	/* Extract hdr_type_etc field. */
	pinfo0 = _mm_unpackhi_epi32(cqes[0], cqes[1]);
	pinfo1 = _mm_unpackhi_epi32(cqes[2], cqes[3]);
	ptype = _mm_unpacklo_epi64(pinfo0, pinfo1);
	if (rxq->mark) {
		const __m128i pinfo_ft_mask =
			_mm_set_epi32(0xffffff00, 0xffffff00,
				      0xffffff00, 0xffffff00);
		const __m128i fdir_flags = _mm_set1_epi32(PKT_RX_FDIR);
		__m128i fdir_id_flags = _mm_set1_epi32(PKT_RX_FDIR_ID);
		__m128i flow_tag, invalid_mask;

		flow_tag = _mm_and_si128(pinfo, pinfo_ft_mask);
		/* Check if flow tag is non-zero then set PKT_RX_FDIR. */
		invalid_mask = _mm_cmpeq_epi32(flow_tag, zero);
		ol_flags = _mm_or_si128(ol_flags,
					_mm_andnot_si128(invalid_mask,
							 fdir_flags));
		/* Mask out invalid entries. */
		fdir_id_flags = _mm_andnot_si128(invalid_mask, fdir_id_flags);
		/* Check if flow tag MLX5_FLOW_MARK_DEFAULT. */
		ol_flags = _mm_or_si128(ol_flags,
					_mm_andnot_si128(
						_mm_cmpeq_epi32(flow_tag,
								pinfo_ft_mask),
						fdir_id_flags));
	}
	/*
	 * Merge the two fields to generate the following:
	 * bit[1]     = l3_ok
	 * bit[2]     = l4_ok
	 * bit[8]     = cv
	 * bit[11:10] = l3_hdr_type
	 * bit[14:12] = l4_hdr_type
	 * bit[15]    = ip_frag
	 * bit[16]    = tunneled
	 * bit[17]    = outer_l3_type
	 */
	ptype = _mm_and_si128(ptype, ptype_mask);
	pinfo = _mm_and_si128(pinfo, pinfo_mask);
	pinfo = _mm_slli_epi32(pinfo, 16);
	/* Make pinfo has merged fields for ol_flags calculation. */
	pinfo = _mm_or_si128(ptype, pinfo);
	ptype = _mm_srli_epi32(pinfo, 10);
	ptype = _mm_packs_epi32(ptype, zero);
	/* Errored packets will have RTE_PTYPE_ALL_MASK. */
	op_err = _mm_srli_epi16(op_err, 8);
	ptype = _mm_or_si128(ptype, op_err);
	pt_idx0 = _mm_extract_epi8(ptype, 0);
	pt_idx1 = _mm_extract_epi8(ptype, 2);
	pt_idx2 = _mm_extract_epi8(ptype, 4);
	pt_idx3 = _mm_extract_epi8(ptype, 6);
	xchg_set_packet_type(xchgs[0], mlx5_ptype_table[pt_idx0] |
			       !!(pt_idx0 & (1 << 6)) * rxq->tunnel);
	xchg_set_packet_type(xchgs[1], mlx5_ptype_table[pt_idx1] |
			       !!(pt_idx1 & (1 << 6)) * rxq->tunnel);
	xchg_set_packet_type(xchgs[2], mlx5_ptype_table[pt_idx2] |
			       !!(pt_idx2 & (1 << 6)) * rxq->tunnel);
	xchg_set_packet_type(xchgs[3], mlx5_ptype_table[pt_idx3] |
			       !!(pt_idx3 & (1 << 6)) * rxq->tunnel);
	/* Fill flags for checksum and VLAN. */
	pinfo = _mm_and_si128(pinfo, ptype_ol_mask);
	pinfo = _mm_shuffle_epi8(cv_flag_sel, pinfo);
	/* Locate checksum flags at byte[2:1] and merge with VLAN flags. */
	cv_flags = _mm_slli_epi32(pinfo, 9);
	cv_flags = _mm_or_si128(pinfo, cv_flags);
	/* Move back flags to start from byte[0]. */
	cv_flags = _mm_srli_epi32(cv_flags, 8);
	/* Mask out garbage bits. */
	cv_flags = _mm_and_si128(cv_flags, cv_mask);
	/* Merge to ol_flags. */
	ol_flags = _mm_or_si128(ol_flags, cv_flags);
	/* Merge mbuf_init and ol_flags. */
	/*rearm0 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(ol_flags, 8), 0x30);
	rearm1 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(ol_flags, 4), 0x30);
	rearm2 = _mm_blend_epi16(mbuf_init, ol_flags, 0x30);
	rearm3 = _mm_blend_epi16(mbuf_init, _mm_srli_si128(ol_flags, 4), 0x30);*/
	/* Write 8B rearm_data and 8B ol_flags. */
	/*_mm_store_si128((__m128i *)&xchgs[0]->rearm_data, rearm0);
	_mm_store_si128((__m128i *)&xchgs[1]->rearm_data, rearm1);
	_mm_store_si128((__m128i *)&xchgs[2]->rearm_data, rearm2);
	_mm_store_si128((__m128i *)&xchgs[3]->rearm_data, rearm3);*/
	xchg_set_flag(xchgs[0], _mm_extract_epi32 (ol_flags, 0));
	xchg_set_flag(xchgs[1], _mm_extract_epi32 (ol_flags, 1));
	xchg_set_flag(xchgs[2], _mm_extract_epi32 (ol_flags, 2));
	xchg_set_flag(xchgs[3], _mm_extract_epi32 (ol_flags, 3));

}


/***
 * Compressed CQE allow to write 8 mini CQE in one CQE. Then, 7 CQEs are skipped, so that
 * ease PCIe and memory.
 *
 * A compressed CQE has the last field (MLX5_CQE_FORMAT(op_own)) set to a specific value, MLX5_COMPRESSED
 *
 * The number of actual  total number mini cqes is set as the byte count of the normal CQEs
 * zip->cqe_cnt = rte_be_to_cpu_32(cqe->byte_cnt);
 * Then one, knows there are up to 8 "mini" CQEs (mlx5_mini_cqe8) to find in the next CQE.
 * Then 6 empty CQE.
 * Then, if cqe was bigger than 8, up to 8 mini CQE again.
 *
 * Therefore, all miniCQE are not always at the same place, as for the first one one
 * must pass the "header" CQE.
 *
 * Also, it appears CQE never wraps around the queue. So if the NIC says there's 48 mini CQE
 * then we know we don't have to mask the index up to the end. This explains why this function is MUCH
 * more simple than the generic one.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param cq
 *   Pointer to completion array having a compressed completion at first.
 * @param elts
 *   Pointer to SW ring to be filled. The first mbuf has to be pre-built from
 *   the title completion descriptor to be copied to the rest of mbufs.
 *
 * @return
 *   Number of mini-CQEs successfully decompressed.
 */
static __rte_always_inline uint16_t
rxq_cq_decompress_v_xchg(struct mlx5_rxq_data *rxq, volatile struct mlx5_cqe *cq,
		    struct rte_mbuf** elts, volatile struct mlx5_wqe_data_seg * wq, struct xchg ***xchgs, uint16_t pkts_n)
{
	unsigned int pos;
	unsigned int i;
	unsigned int inv = 0;
	/* Mask to shuffle from extracted mini CQE to mbuf. */
	#if 0
	const __m128i shuf_mask1 =
		_mm_set_epi8(0,  1,  2,  3, /* rss, bswap32 */
			    -1, -1,         /* skip vlan_tci */
			     6,  7,         /* data_len, bswap16 */
			    -1, -1,  6,  7, /* pkt_len, bswap16 */
			    -1, -1, -1, -1  /* skip packet_type */);
	const __m128i shuf_mask2 =
		_mm_set_epi8(8,  9, 10, 11, /* rss, bswap32 */
			    -1, -1,         /* skip vlan_tci */
			    14, 15,         /* data_len, bswap16 */
			    -1, -1, 14, 15, /* pkt_len, bswap16 */
			    -1, -1, -1, -1  /* skip packet_type */);
				#endif
	/* Restore the compressed count. Must be 16 bits. */
	//const uint16_t mcqe_n = xchg_get_data_len(x_pkt) +
	//(rxq->crc_present * RTE_ETHER_CRC_LEN);
	const uint16_t mcqe_n = rxq->decompressed;
	//fprintf( stderr,"Have mcqe_n %d or %d, xchg %p, current %d, cq %p, rq %d, max pkts %d\n",mcqe_n,rte_be_to_cpu_32(cq->byte_cnt), *xchgs, rxq->current, cq, rxq->rq_ci,pkts_n);
	/*const __m128i rearm =
		_mm_loadu_si128((__m128i *)&t_pkt->rearm_data);
	const __m128i rxdf =
		_mm_loadu_si128((__m128i *)&t_pkt->rx_descriptor_fields1);
	const __m128i crc_adj =
		_mm_set_epi16(0, 0, 0,
			      rxq->crc_present * RTE_ETHER_CRC_LEN,
			      0,
			      rxq->crc_present * RTE_ETHER_CRC_LEN,
			      0, 0);
	const uint32_t flow_tag = t_pkt->hash.fdir.hi;*/
	uint32_t rcvd_byte = 0;
#ifdef MLX5_PMD_SOFT_COUNTERS
/*	const __m128i zero = _mm_setzero_si128();
	const __m128i ones = _mm_cmpeq_epi32(zero, zero);

	// Mask to shuffle byte_cnt to add up stats. Do bswap16 for all.
	const __m128i len_shuf_mask =
		_mm_set_epi8(-1, -1, -1, -1,
			     -1, -1, -1, -1,
			     14, 15,  6,  7,
			     10, 11,  2,  3);*/
#endif
	/*(void)zero;
	(void)ones;
	(void)len_shuf_mask;*/


	/*(void)shuf_mask1;
	(void)shuf_mask2;*/

	volatile struct mlx5_mini_cqe8 *mcq;
	if (rxq->current) {
		mcq = (void *)(cq) ;
	} else
		mcq = (void *)(cq + 1);

	//Don't eat more than we can
	if (pkts_n >= mcqe_n) {
		pkts_n = mcqe_n;
		rxq->decompressed = 0;
		rxq->current = 0;
	} else {
		pkts_n = pkts_n & ~7; //We cannot leave a hole in the MCQE
		//fprintf( stderr,"Will receive only %d out of %d\n", pkts_n, mcqe_n);
		rxq->decompressed = mcqe_n - pkts_n;
		rxq->current += pkts_n;
	}


	/*
	 * A. load mCQEs into a 128bit register.
	 * B. store rearm data to mbuf.
	 * C. combine data from mCQEs with rx_descriptor_fields1.
	 * D. store rx_descriptor_fields1.
	 * E. store flow tag (rte_flow mark).
	 */

	struct xchg* xchg_last = 0;
	pos = 0;
	while (pos < pkts_n) {

		//__m128i mcqe1, mcqe2;
		struct xchg* xchgs_vec[MLX5_VPMD_DESCS_PER_LOOP];
		//__m128i rxdf1, rxdf2;
#ifdef MLX5_PMD_SOFT_COUNTERS
		//__m128i byte_cnt, invalid_mask;
#endif

		if (!(pos & 0x7) && pos + 8 < mcqe_n)
			rte_prefetch0((void *)(cq + pos + 8));
		/* A.1 load mCQEs into a 128bit register. */
		/*mcqe1 = _mm_loadu_si128((__m128i *)&mcq[pos % 8]);
		mcqe2 = _mm_loadu_si128((__m128i *)&mcq[pos % 8 + 2]);
		(void)mcqe1;
		(void)mcqe2;
*/

		#if defined(__clang__)
		#pragma unroll MLX5_VPMD_DESCS_PER_LOOP
		#elif __GNUC_PREREQ(8,0)
		#pragma GCC unroll 4
		#endif
		for (int i = 0; i < MLX5_VPMD_DESCS_PER_LOOP; i++) {
			//fprintf( stderr,"Size %d for pos %d, xchg top %p\n", rte_be_to_cpu_32(mcq[pos % 8 + i].byte_cnt), pos +i, *xchgs);
			if (pos + i == pkts_n) {
				xchg_last = xchgs_vec[i - 1];
				goto split;
			}

			// pos is accumulated in elts at the end of the loop
			struct xchg* next = xchg_rx_next(elts + pos + i, *xchgs, rxq->mp);

			//fprintf(stderr, "CQ Next have now buffer %p:%p -> %x, elts is %p\n",next, xchg_get_buffer_addr(next), *(((unsigned char*)xchg_get_buffer_addr(next)) + 128), ((unsigned char*)elts[pos + i]) +128 );
			xchgs_vec[i] = next;
			xchg_rx_advance(next, xchgs);

			uint32_t b = rte_be_to_cpu_32(mcq[pos % 8 + i].byte_cnt);
			xchg_set_data_len(xchgs_vec[i], b);
			rcvd_byte+= b;


			xchg_rx_finish_packet(xchgs_vec[i]);
			wq[pos + i].addr = rte_cpu_to_be_64((uintptr_t)xchg_buffer_from_elt(elts[pos + i]));
			if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1)) {
					//fprintf( stderr,"slow\n");
					wq->lkey = mlx5_rx_mb2mr(rxq, elts[pos + i]);
			}


		}
		xchg_last = xchgs_vec[3];
		split:


		#if 0
		/* B.1 store rearm data to mbuf. */
		_mm_storeu_si128((__m128i *)&elts[pos]->rearm_data, rearm);
		_mm_storeu_si128((__m128i *)&elts[pos + 1]->rearm_data, rearm);
		/* C.1 combine data from mCQEs with rx_descriptor_fields1. */
		rxdf1 = _mm_shuffle_epi8(mcqe1, shuf_mask1);
		rxdf2 = _mm_shuffle_epi8(mcqe1, shuf_mask2);
		rxdf1 = _mm_sub_epi16(rxdf1, crc_adj);
		rxdf2 = _mm_sub_epi16(rxdf2, crc_adj);
		rxdf1 = _mm_blend_epi16(rxdf1, rxdf, 0x23);
		rxdf2 = _mm_blend_epi16(rxdf2, rxdf, 0x23);
		/* D.1 store rx_descriptor_fields1. */
		_mm_storeu_si128((__m128i *)
				  &elts[pos]->rx_descriptor_fields1,
				 rxdf1);
		_mm_storeu_si128((__m128i *)
				  &elts[pos + 1]->rx_descriptor_fields1,
				 rxdf2);
		/* B.1 store rearm data to mbuf. */
		//_mm_storeu_si128((__m128i *)&elts[pos + 2]->rearm_data, rearm);
		//_mm_storeu_si128((__m128i *)&elts[pos + 3]->rearm_data, rearm);
		/* C.1 combine data from mCQEs with rx_descriptor_fields1. */
		rxdf1 = _mm_shuffle_epi8(mcqe2, shuf_mask1);
		rxdf2 = _mm_shuffle_epi8(mcqe2, shuf_mask2);
		rxdf1 = _mm_sub_epi16(rxdf1, crc_adj);
		rxdf2 = _mm_sub_epi16(rxdf2, crc_adj);
		rxdf1 = _mm_blend_epi16(rxdf1, rxdf, 0x23);
		rxdf2 = _mm_blend_epi16(rxdf2, rxdf, 0x23);
		/* D.1 store rx_descriptor_fields1. */
		_mm_storeu_si128((__m128i *)
				  &elts[pos + 2]->rx_descriptor_fields1,
				 rxdf1);
		_mm_storeu_si128((__m128i *)
				  &elts[pos + 3]->rx_descriptor_fields1,
				 rxdf2);
#ifdef MLX5_PMD_SOFT_COUNTERS
		invalid_mask = _mm_set_epi64x(0,
					      (mcqe_n - pos) *
					      sizeof(uint16_t) * 8);
		invalid_mask = _mm_sll_epi64(ones, invalid_mask);
		mcqe1 = _mm_srli_si128(mcqe1, 4);
		byte_cnt = _mm_blend_epi16(mcqe1, mcqe2, 0xcc);
		byte_cnt = _mm_shuffle_epi8(byte_cnt, len_shuf_mask);
		byte_cnt = _mm_andnot_si128(invalid_mask, byte_cnt);
		byte_cnt = _mm_hadd_epi16(byte_cnt, zero);
		rcvd_byte += _mm_cvtsi128_si64(_mm_hadd_epi16(byte_cnt, zero));
#endif
#endif
		/*if (rxq->mark) {
			// E.1 store flow tag (rte_flow mark).
			elts[pos]->hash.fdir.hi = flow_tag;
			elts[pos + 1]->hash.fdir.hi = flow_tag;
			elts[pos + 2]->hash.fdir.hi = flow_tag;
			elts[pos + 3]->hash.fdir.hi = flow_tag;
		}*/
		pos += MLX5_VPMD_DESCS_PER_LOOP;
		/* Move to next CQE and invalidate consumed CQEs. */
		if (!(pos & 0x7) && pos < pkts_n) {
		//	fprintf( stderr,"NOT FINISHED\n");
			mcq = (void *)(cq + pos);
			for (i = 0; i < 8; ++i)
				cq[inv++].op_own = MLX5_CQE_INVALIDATE;
		}
	}

	xchg_rx_last_packet(xchg_last, *xchgs);

	/* Invalidate the rest of CQEs. */
	for (; inv < pkts_n; ++inv)
		cq[inv].op_own = MLX5_CQE_INVALIDATE;

//	fprintf( stderr,"Next CQ should be %p\n", cq + pos);
#ifdef MLX5_PMD_SOFT_COUNTERS
	rxq->stats.ipackets += pkts_n;
	rxq->stats.ibytes += rcvd_byte;
#endif
	rxq->cq_ci += pkts_n;
	rxq->rq_ci += pkts_n;

	if (rxq->decompressed == 0) {
		rte_compiler_barrier();
		*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
		rte_cio_wmb();
		*rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);
	}
	return pkts_n;

}


/**
 * Receive burst of packets. An errored completion also consumes a mbuf, but the
 * packet_type is set to be RTE_PTYPE_ALL_MASK. Marked mbufs should be freed
 * before returning to application.
 *
 * @param rxq
 *   Pointer to RX queue structure.
 * @param[out] pkts
 *   Array to store received packets.
 * @param pkts_n
 *   Maximum number of packets in array.
 * @param[out] err
 *   Pointer to a flag. Set non-zero value if pkts array has at least one error
 *   packet to handle.
 *
 * @return
 *   Number of packets received including errors (<= pkts_n).
 */
static __rte_always_inline uint16_t
rxq_burst_v_xchg(struct mlx5_rxq_data *rxq, struct xchg **xchgs, uint16_t pkts_n,
	    uint64_t *err, int comp_enabled)
{
	//fprintf( stderr,"Entering XCHG with %p\n",*xchgs);
	struct rte_mbuf **elts;
	const uint16_t q_n = 1 << rxq->cqe_n;
	const uint16_t q_mask = q_n - 1;
	unsigned int cq_idx ;
	unsigned int elts_idx;
	uint16_t rcvd_pkt = 0;
	volatile struct mlx5_cqe *cq;
	volatile struct mlx5_wqe_data_seg *wq;
decomp:
	elts_idx = rxq->rq_ci & q_mask;
	elts = &(*rxq->elts)[elts_idx];
	cq_idx = rxq->cq_ci & q_mask;
	cq = &(*rxq->cqes)[cq_idx];
	wq =&((volatile struct mlx5_wqe_data_seg *)rxq->wqes)[elts_idx];

	if (comp_enabled && rxq->decompressed) {
		//fprintf( stderr,"Should recover %d, can receive %d\n", rxq->decompressed, pkts_n);

		//assert((rxq->rq_ci & q_mask) + (pkts_n<rxq->decompressed?pkts_n:rxq->decompressed) <= q_n);
		unsigned dec = rxq_cq_decompress_v_xchg(rxq, cq ,
								elts,wq,&xchgs,pkts_n);
		//fprintf(stderr, "Received from deq %d\n", dec);
		rcvd_pkt += dec;
		pkts_n -= dec;
		//We continue if we don't have any compressed packets left, and if there is room for at least 4 packets
		if (!rxq->decompressed && pkts_n >= MLX5_VPMD_DESCS_PER_LOOP) {
			//fprintf(stderr, "Still have some space for %d packets\n",pkts_n);
			elts_idx = rxq->rq_ci & q_mask;
			elts = &(*rxq->elts)[elts_idx];
			cq_idx = rxq->cq_ci & q_mask;
			cq = &(*rxq->cqes)[cq_idx];
			wq =&((volatile struct mlx5_wqe_data_seg *)rxq->wqes)[elts_idx];
		} else {
			return rcvd_pkt;
		}
	}
	unsigned int pos;
	uint64_t n;
	//uint16_t repl_n;
	uint64_t comp_idx = MLX5_VPMD_DESCS_PER_LOOP;
	uint16_t nocmp_n = 0;

	struct xchg** xchgs_vec;
	struct xchg* xchgs_vec_novec[MLX5_VPMD_DESCS_PER_LOOP];
	if (!xchg_is_vec)
		xchgs_vec = xchgs_vec_novec;
	else
		xchgs_vec = xchgs;

	unsigned int ownership = !!(rxq->cq_ci & (q_mask + 1));
	const __m128i owner_check =
		_mm_set_epi64x(0x0100000001000000LL, 0x0100000001000000LL);
	const __m128i opcode_check =
		_mm_set_epi64x(0xf0000000f0000000LL, 0xf0000000f0000000LL);
	const __m128i format_check =
		_mm_set_epi64x(0x0c0000000c000000LL, 0x0c0000000c000000LL);
	const __m128i resp_err_check =
		_mm_set_epi64x(0xe0000000e0000000LL, 0xe0000000e0000000LL);
#ifdef MLX5_PMD_SOFT_COUNTERS
	uint32_t rcvd_byte = 0;
	/* Mask to shuffle byte_cnt to add up stats. Do bswap16 for all. */
	const __m128i len_shuf_mask =
		_mm_set_epi8(-1, -1, -1, -1,
			     -1, -1, -1, -1,
			     12, 13,  8,  9,
			      4,  5,  0,  1);
#endif

	/* Mask to shuffle from extracted CQE to mbuf. */
	#if 0
	//Not yet done... A bit more thinking to do :p
	const __m128i shuf_mask =
		_mm_set_epi8(-1,  xchg_fdir_off()>-1?xchg_fdir_off() + 2:-1,  xchg_fdir_off()>-1?xchg_fdir_off() + 1:-1,  xchg_fdir_off(), /* fdir.hi */
			    xchg_rss_off(), xchg_rss_off()> -1?xchg_rss_off() + 1 : -1, xchg_rss_off()> -1?xchg_rss_off() + 2 : -1, xchg_rss_off()> -1?xchg_rss_off() + 3 : -1, /* rss, bswap32 */
			    xchg_vlan_off(),  xchg_vlan_off()> -1?xchg_vlan_off() + 1 : -1,         /* vlan_tci, bswap16 */
			    xchg_pkt_len_off(),  xchg_pkt_len_off()> -1?xchg_pkt_len_off() + 1 : -1,         /* data_len, bswap16 */
			    -1, -1,         /* zero out 2nd half of pkt_len */
			    xchg_pkt_len_off(),  xchg_pkt_len_off()> -1?xchg_pkt_len_off() + 1 : -1          /* pkt_len, bswap16 */);
				#endif
	/* Mask to blend from the last Qword to the first DQword. */
	const __m128i blend_mask =
		_mm_set_epi8(-1, -1, -1, -1,
			     -1, -1, -1, -1,
			      0,  0,  0,  0,
			      0,  0,  0, -1);
	const __m128i zero = _mm_setzero_si128();
	const __m128i ones = _mm_cmpeq_epi32(zero, zero);
	#if 0
	const __m128i crc_adj =
		_mm_set_epi16(0, 0, 0, 0, 0,
			      rxq->crc_present * RTE_ETHER_CRC_LEN,
			      0,
			      rxq->crc_present * RTE_ETHER_CRC_LEN);
	const __m128i flow_mark_adj = _mm_set_epi32(rxq->mark * (-1), 0, 0, 0);
	#endif

	MLX5_ASSERT(rxq->sges_n == 0);
	MLX5_ASSERT(rxq->cqe_n == rxq->elts_n);

	rte_prefetch0(cq);
	rte_prefetch0(cq + 1);
	rte_prefetch0(cq + 2);
	rte_prefetch0(cq + 3);
	pkts_n = RTE_MIN(pkts_n, MLX5_VPMD_RX_MAX_BURST);

	/* Not to overflow pkts array. */
	pkts_n = RTE_ALIGN_FLOOR(pkts_n, MLX5_VPMD_DESCS_PER_LOOP);
	/* Not to cross queue end. */
	pkts_n = RTE_MIN(pkts_n, q_n - elts_idx);
	pkts_n = RTE_MIN(pkts_n, q_n - cq_idx);
	if (!pkts_n)
		return rcvd_pkt;

	/*
	 * A. load first Qword (8bytes) in one loop.
	 * B. copy 4 mbuf pointers from elts ring to returing pkts. --> swap 4 buffers from user to elts
	 * C. load remained CQE data and extract necessary fields.
	 *    Final 16bytes cqes[] extracted from original 64bytes CQE has the
	 *    following structure:
	 *        struct {
	 *          uint8_t  pkt_info;
	 *          uint8_t  flow_tag[3];
	 *          uint16_t byte_cnt;
	 *          uint8_t  rsvd4;
	 *          uint8_t  op_own;
	 *          uint16_t hdr_type_etc;
	 *          uint16_t vlan_info;
	 *          uint32_t rx_has_res;
	 *        } c;
	 * D. fill in xchgs.
	 * E. get valid CQEs.
	 * F. find compressed CQE.
	 */
	//fprintf( stderr,"Normal CQs\n");

	struct xchg* xchg_last = 0;
	for (pos = 0;
	     pos < pkts_n;
	     pos += MLX5_VPMD_DESCS_PER_LOOP) {
		//fprintf( stderr,"Received %d/%d, elts idx %d\n",pos, pkts_n, elts_idx);
		__m128i cqes[MLX5_VPMD_DESCS_PER_LOOP];
		__m128i cqe_tmp1, cqe_tmp2;
		//__m128i pkt_mb0, pkt_mb1, pkt_mb2, pkt_mb3;
		__m128i op_own, op_own_tmp1, op_own_tmp2;
		__m128i opcode, owner_mask, invalid_mask;
		__m128i comp_mask;
		__m128i mask;
#ifdef MLX5_PMD_SOFT_COUNTERS
		__m128i byte_cnt;
#endif
		//__m128i mbp1, mbp2;
		__m128i p = _mm_set_epi16(0, 0, 0, 0, 3, 2, 1, 0);
		unsigned int p1, p2, p3;

		/* Prefetch next 4 CQEs. */
		if (pkts_n - pos >= 2 * MLX5_VPMD_DESCS_PER_LOOP) {
			rte_prefetch0(&cq[pos + MLX5_VPMD_DESCS_PER_LOOP]);
			rte_prefetch0(&cq[pos + MLX5_VPMD_DESCS_PER_LOOP + 1]);
			rte_prefetch0(&cq[pos + MLX5_VPMD_DESCS_PER_LOOP + 2]);
			rte_prefetch0(&cq[pos + MLX5_VPMD_DESCS_PER_LOOP + 3]);
		}
		/* A.0 do not cross the end of CQ. */
		mask = _mm_set_epi64x(0, (pkts_n - pos) * sizeof(uint16_t) * 8);
		mask = _mm_sll_epi64(ones, mask);
		p = _mm_andnot_si128(mask, p);
		/* A.1 load cqes. */
		p3 = _mm_extract_epi16(p, 3);
		cqes[3] = _mm_loadl_epi64((__m128i *)
					   &cq[pos + p3].sop_drop_qpn);
		rte_compiler_barrier();
		p2 = _mm_extract_epi16(p, 2);
		cqes[2] = _mm_loadl_epi64((__m128i *)
					   &cq[pos + p2].sop_drop_qpn);
		rte_compiler_barrier();
		/* B.1 load mbuf pointers. */
		/*mbp1 = _mm_loadu_si128((__m128i *)&elts[pos]);
		mbp2 = _mm_loadu_si128((__m128i *)&elts[pos + 2]);*/


		#if defined(__clang__)
		#pragma unroll MLX5_VPMD_DESCS_PER_LOOP
		#elif __GNUC_PREREQ(8,0)
		#pragma GCC unroll 4
		#endif
		for (int i = 0; i < MLX5_VPMD_DESCS_PER_LOOP; i++) {
			// pos is accumulated in elts at the end of the loop
			struct xchg* next = xchg_rx_next(elts + i, xchgs, rxq->mp);
			//fprintf(stderr, "Next have now buffer %p:%p -> %x, elts is %p\n",next, xchg_get_buffer_addr(next), *(((unsigned char*)xchg_get_buffer_addr(next)) + 128), ((unsigned char*)elts[i]) +128 );
			if (!xchg_is_vec)
				xchgs_vec[i] = next;
			xchg_rx_advance(next, &xchgs);
		}
		/* A.1 load a block having op_own. */
		p1 = _mm_extract_epi16(p, 1);
		cqes[1] = _mm_loadl_epi64((__m128i *)
					   &cq[pos + p1].sop_drop_qpn);
		rte_compiler_barrier();
		cqes[0] = _mm_loadl_epi64((__m128i *)
					   &cq[pos].sop_drop_qpn);
		/* B.2 copy mbuf pointers. */
		/*_mm_storeu_si128((__m128i *)&pkts[pos], mbp1);
		_mm_storeu_si128((__m128i *)&pkts[pos + 2], mbp2);*/
		rte_cio_rmb();
		/* C.1 load remained CQE data and extract necessary fields. */
		cqe_tmp2 = _mm_load_si128((__m128i *)&cq[pos + p3]);
		cqe_tmp1 = _mm_load_si128((__m128i *)&cq[pos + p2]);
		cqes[3] = _mm_blendv_epi8(cqes[3], cqe_tmp2, blend_mask);
		cqes[2] = _mm_blendv_epi8(cqes[2], cqe_tmp1, blend_mask);
		cqe_tmp2 = _mm_loadu_si128((__m128i *)&cq[pos + p3].csum);
		cqe_tmp1 = _mm_loadu_si128((__m128i *)&cq[pos + p2].csum);
		cqes[3] = _mm_blend_epi16(cqes[3], cqe_tmp2, 0x30);
		cqes[2] = _mm_blend_epi16(cqes[2], cqe_tmp1, 0x30);
		cqe_tmp2 = _mm_loadl_epi64((__m128i *)&cq[pos + p3].rsvd4[2]);
		cqe_tmp1 = _mm_loadl_epi64((__m128i *)&cq[pos + p2].rsvd4[2]);
		cqes[3] = _mm_blend_epi16(cqes[3], cqe_tmp2, 0x04);
		cqes[2] = _mm_blend_epi16(cqes[2], cqe_tmp1, 0x04);
		#if 0
		/* C.2 generate final structure for mbuf with swapping bytes. */
		pkt_mb3 = _mm_shuffle_epi8(cqes[3], shuf_mask);
		pkt_mb2 = _mm_shuffle_epi8(cqes[2], shuf_mask);
		/* C.3 adjust CRC length. */
		pkt_mb3 = _mm_sub_epi16(pkt_mb3, crc_adj);
		pkt_mb2 = _mm_sub_epi16(pkt_mb2, crc_adj);
		/* C.4 adjust flow mark. */
		pkt_mb3 = _mm_add_epi32(pkt_mb3, flow_mark_adj);
		pkt_mb2 = _mm_add_epi32(pkt_mb2, flow_mark_adj);
		#endif
		xchg_set_data_len(xchgs_vec[3],rte_be_to_cpu_32(cq[pos + p3].byte_cnt));
		//fprintf( stderr,"DL3 %d xchg %p", rte_be_to_cpu_32(cq[pos + p3].byte_cnt), xchgs_vec[3]);
		xchg_set_data_len(xchgs_vec[2],rte_be_to_cpu_32(cq[pos + p2].byte_cnt));
		//fprintf( stderr,"DL2 %d xchg %p", rte_be_to_cpu_32(cq[pos + p2].byte_cnt), xchgs_vec[2]);
		/* D.1 fill in mbuf - rx_descriptor_fields1. */
		//_mm_storeu_si128((void *)&pkts[pos + 3]->pkt_len, pkt_mb3);
		//_mm_storeu_si128((void *)&pkts[pos + 2]->pkt_len, pkt_mb2);
		/* E.1 extract op_own field. */
		op_own_tmp2 = _mm_unpacklo_epi32(cqes[2], cqes[3]);
		/* C.1 load remained CQE data and extract necessary fields. */
		cqe_tmp2 = _mm_load_si128((__m128i *)&cq[pos + p1]);
		cqe_tmp1 = _mm_load_si128((__m128i *)&cq[pos]);
		cqes[1] = _mm_blendv_epi8(cqes[1], cqe_tmp2, blend_mask);
		cqes[0] = _mm_blendv_epi8(cqes[0], cqe_tmp1, blend_mask);
		cqe_tmp2 = _mm_loadu_si128((__m128i *)&cq[pos + p1].csum);
		cqe_tmp1 = _mm_loadu_si128((__m128i *)&cq[pos].csum);
		cqes[1] = _mm_blend_epi16(cqes[1], cqe_tmp2, 0x30);
		cqes[0] = _mm_blend_epi16(cqes[0], cqe_tmp1, 0x30);
		cqe_tmp2 = _mm_loadl_epi64((__m128i *)&cq[pos + p1].rsvd4[2]);
		cqe_tmp1 = _mm_loadl_epi64((__m128i *)&cq[pos].rsvd4[2]);
		cqes[1] = _mm_blend_epi16(cqes[1], cqe_tmp2, 0x04);
		cqes[0] = _mm_blend_epi16(cqes[0], cqe_tmp1, 0x04);
		/* C.2 generate final structure for mbuf with swapping bytes. */
		#if 0
		pkt_mb1 = _mm_shuffle_epi8(cqes[1], shuf_mask);
		pkt_mb0 = _mm_shuffle_epi8(cqes[0], shuf_mask);
		/* C.3 adjust CRC length. */
		pkt_mb1 = _mm_sub_epi16(pkt_mb1, crc_adj);
		pkt_mb0 = _mm_sub_epi16(pkt_mb0, crc_adj);
		/* C.4 adjust flow mark. */
		pkt_mb1 = _mm_add_epi32(pkt_mb1, flow_mark_adj);
		pkt_mb0 = _mm_add_epi32(pkt_mb0, flow_mark_adj);
		#endif
		/* E.1 extract op_own byte. */
		op_own_tmp1 = _mm_unpacklo_epi32(cqes[0], cqes[1]);
		op_own = _mm_unpackhi_epi64(op_own_tmp1, op_own_tmp2);
		/* D.1 fill in mbuf - rx_descriptor_fields1. */
		//_mm_storeu_si128((void *)&pkts[pos + 1]->pkt_len, pkt_mb1);
		//_mm_storeu_si128((void *)&pkts[pos]->pkt_len, pkt_mb0);
		xchg_set_data_len(xchgs_vec[1],rte_be_to_cpu_32(cq[pos + p1].byte_cnt));
		xchg_set_data_len(xchgs_vec[0],rte_be_to_cpu_32(cq[pos + 0].byte_cnt));
		//fprintf( stderr,"DL1 %d xchg %p", rte_be_to_cpu_32(cq[pos + p1].byte_cnt), xchgs_vec[1]);

		//fprintf( stderr,"DL0 %d xchg %p", rte_be_to_cpu_32(cq[pos + 0].byte_cnt), xchgs_vec[0]);
		/* E.2 flip owner bit to mark CQEs from last round. */
		owner_mask = _mm_and_si128(op_own, owner_check);
		if (ownership)
			owner_mask = _mm_xor_si128(owner_mask, owner_check);
		owner_mask = _mm_cmpeq_epi32(owner_mask, owner_check);
		owner_mask = _mm_packs_epi32(owner_mask, zero);
		/* E.3 get mask for invalidated CQEs. */
		opcode = _mm_and_si128(op_own, opcode_check);
		invalid_mask = _mm_cmpeq_epi32(opcode_check, opcode);
		invalid_mask = _mm_packs_epi32(invalid_mask, zero);
		/* E.4 mask out beyond boundary. */
		invalid_mask = _mm_or_si128(invalid_mask, mask);
		/* E.5 merge invalid_mask with invalid owner. */
		invalid_mask = _mm_or_si128(invalid_mask, owner_mask);
		/* F.1 find compressed CQE format. */
		comp_mask = _mm_and_si128(op_own, format_check);
		comp_mask = _mm_cmpeq_epi32(comp_mask, format_check);
		comp_mask = _mm_packs_epi32(comp_mask, zero);
		/* F.2 mask out invalid entries. */
		comp_mask = _mm_andnot_si128(invalid_mask, comp_mask);
		comp_idx = _mm_cvtsi128_si64(comp_mask);
		/* F.3 get the first compressed CQE. */
		comp_idx = comp_idx ?
				__builtin_ctzll(comp_idx) /
					(sizeof(uint16_t) * 8) :
				MLX5_VPMD_DESCS_PER_LOOP;
		/* E.6 mask out entries after the compressed CQE. */
		mask = _mm_set_epi64x(0, comp_idx * sizeof(uint16_t) * 8);
		mask = _mm_sll_epi64(ones, mask);
		invalid_mask = _mm_or_si128(invalid_mask, mask);
		/* E.7 count non-compressed valid CQEs. */
		n = _mm_cvtsi128_si64(invalid_mask);
		n = n ? __builtin_ctzll(n) / (sizeof(uint16_t) * 8) :
			MLX5_VPMD_DESCS_PER_LOOP;
		nocmp_n += n;
		/* D.2 get the final invalid mask. */
		mask = _mm_set_epi64x(0, n * sizeof(uint16_t) * 8);
		mask = _mm_sll_epi64(ones, mask);
		invalid_mask = _mm_or_si128(invalid_mask, mask);
		/* D.3 check error in opcode. */
		opcode = _mm_cmpeq_epi32(resp_err_check, opcode);
		opcode = _mm_packs_epi32(opcode, zero);
		opcode = _mm_andnot_si128(invalid_mask, opcode);
		/* D.4 mark if any error is set */
		*err |= _mm_cvtsi128_si64(opcode);
		/* D.5 fill in mbuf - rearm_data and packet_type. */
		rxq_cq_to_ptype_oflags_v_xchg(rxq, cqes, opcode, xchgs_vec);
		if (rxq->hw_timestamp) {
			xchg_set_timestamp(xchgs_vec[0],
				rte_be_to_cpu_64(cq[pos].timestamp));
			xchg_set_timestamp(xchgs_vec[1],
				rte_be_to_cpu_64(cq[pos + p1].timestamp));
			xchg_set_timestamp(xchgs_vec[2],
				rte_be_to_cpu_64(cq[pos + p2].timestamp));
			xchg_set_timestamp(xchgs_vec[3],
				rte_be_to_cpu_64(cq[pos + p3].timestamp));
		}
		/*if (rte_flow_dynf_metadata_avail()) {
			// This code is subject for futher optimization.
			*RTE_FLOW_DYNF_METADATA(pkts[pos]) =
				cq[pos].flow_table_metadata;
			*RTE_FLOW_DYNF_METADATA(pkts[pos + 1]) =
				cq[pos + p1].flow_table_metadata;
			*RTE_FLOW_DYNF_METADATA(pkts[pos + 2]) =
				cq[pos + p2].flow_table_metadata;
			*RTE_FLOW_DYNF_METADATA(pkts[pos + 3]) =
				cq[pos + p3].flow_table_metadata;
			if (*RTE_FLOW_DYNF_METADATA(pkts[pos]))
				pkts[pos]->ol_flags |= PKT_RX_DYNF_METADATA;
			if (*RTE_FLOW_DYNF_METADATA(pkts[pos + 1]))
				pkts[pos + 1]->ol_flags |= PKT_RX_DYNF_METADATA;
			if (*RTE_FLOW_DYNF_METADATA(pkts[pos + 2]))
				pkts[pos + 2]->ol_flags |= PKT_RX_DYNF_METADATA;
			if (*RTE_FLOW_DYNF_METADATA(pkts[pos + 3]))
				pkts[pos + 3]->ol_flags |= PKT_RX_DYNF_METADATA;
		}*/
#ifdef MLX5_PMD_SOFT_COUNTERS
		/* Add up received bytes count. */
		byte_cnt = _mm_shuffle_epi8(op_own, len_shuf_mask);
		byte_cnt = _mm_andnot_si128(invalid_mask, byte_cnt);
		byte_cnt = _mm_hadd_epi16(byte_cnt, zero);
		rcvd_byte += _mm_cvtsi128_si64(_mm_hadd_epi16(byte_cnt, zero));
#endif

		/*
		 * Break the loop unless more valid CQE is expected, or if
		 * there's a compressed CQE.
		 */

		if (unlikely(n != MLX5_VPMD_DESCS_PER_LOOP)) {
			if (unlikely(n > 0)) { //We could send some of the packets
				#if defined(__clang__)
				#pragma unroll MLX5_VPMD_DESCS_PER_LOOP - 1
				#elif __GNUC_PREREQ(8,0)
				#pragma GCC unroll 3
				#endif
				for (unsigned i = 0; i < n; i++) {
					//fprintf( stderr,"Validate %p->%p %d/%lu/%d idx %d,%u,%u\n",xchgs_vec[i],xchg_get_buffer_addr(xchgs_vec[i]), i,n,nocmp_n,elts_idx,rxq->rq_ci&q_mask,rxq->cq_ci&q_mask);

					wq[i].addr = rte_cpu_to_be_64((uintptr_t)xchg_buffer_from_elt(elts[i]));
					if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1)) {
							fprintf( stderr,"slow\n");
							wq->lkey = mlx5_rx_mb2mr(rxq, elts[i]);
					}
					xchg_rx_finish_packet(xchgs_vec[i]);
				}
				wq+=n;
				xchg_last = xchgs_vec[n - 1];
				if (xchg_is_vec)
					xchgs = &xchgs_vec[n];
				else
					*xchgs = xchgs_vec[n];
			} else
				if (xchg_is_vec)
					xchgs = &xchgs_vec[0];
				else
					*xchgs = xchgs_vec[0];

			//The packets we received were actually not ready... Rollback!
			#if defined(__clang__)
			#pragma unroll MLX5_VPMD_DESCS_PER_LOOP
			#elif __GNUC_PREREQ(8,0)
			#pragma GCC unroll 4
			#endif
			for (int i = n; i < MLX5_VPMD_DESCS_PER_LOOP; i++) {
				//if (n > 0)

				struct rte_mbuf* tmp = xchg_get_mbuf(xchgs_vec[i]); //Tmp is the buffer where we should receive something
				//fprintf( stderr,"Cancel %p %d/%lu/%d idx %d,%u,%u. Elts back to %p (%x), buf back to %p(%x)\n",xchgs_vec[i], i,n,nocmp_n,elts_idx,rxq->rq_ci & q_mask,rxq->cq_ci &q_mask,((unsigned char*)tmp) + 128,*(((unsigned char*)tmp)+256),xchg_get_buffer_addr(xchgs_vec[i]),*((unsigned char*)xchg_get_buffer_addr(xchgs_vec[i])+128));
				xchg_rx_cancel(xchgs_vec[i], elts[i]);
				elts[i] = tmp;
				//fprintf( stderr,"Elts %d back to %p\n",elts_idx+pos+i,((unsigned char*)tmp)+128);

			}
			break;
		}
		//All 4 packets are good to go!
		//fprintf( stderr,"Received 4, idx %d!\n",elts_idx + pos);
		#if defined(__clang__)
		#pragma unroll MLX5_VPMD_DESCS_PER_LOOP
		#elif __GNUC_PREREQ(8,0)
		#pragma GCC unroll 4
		#endif
		for (unsigned i = 0; i < MLX5_VPMD_DESCS_PER_LOOP; i++) {
			//fprintf( stderr,"%p -> %p\n", xchgs_vec[i], xchg_get_buffer(xchgs_vec[i]));
			wq->addr = rte_cpu_to_be_64((uintptr_t)xchg_buffer_from_elt(*elts));
			if (unlikely(mlx5_mr_btree_len(&rxq->mr_ctrl.cache_bh) > 1)) {
					fprintf( stderr,"slow\n");
					wq->lkey = mlx5_rx_mb2mr(rxq, *elts);
			}
			assert((((unsigned char*)xchg_get_buffer_addr(xchgs_vec[i])) - 128) != (unsigned char*)&rxq->fake_mbuf);
			//fprintf( stderr,"Finish %p -> %x",xchgs_vec[i], *(((unsigned char*)xchg_get_buffer_addr(xchgs_vec[i])) + 128));
			xchg_rx_finish_packet(xchgs_vec[i]);
			++elts;
			++wq;
		}
		xchg_last = xchgs_vec[3];
		if (xchg_is_vec)
			xchgs_vec+=MLX5_VPMD_DESCS_PER_LOOP;
	}


	/* If no new CQE seen, return without updating cq_db. */
	if (unlikely(!nocmp_n && comp_idx == MLX5_VPMD_DESCS_PER_LOOP))
		return rcvd_pkt;


	/* Update the consumer indexes for non-compressed CQEs. */
	MLX5_ASSERT(nocmp_n <= pkts_n);
	rxq->cq_ci += nocmp_n;
	rxq->rq_ci += nocmp_n;
	//rxq->rq_pi += nocmp_n;
	rcvd_pkt += nocmp_n;



	/* Prevent overflowing into consumed mbufs. */
/*	elts_idx = rxq->rq_ci & q_mask;
	for (i = 0; i < MLX5_VPMD_DESCS_PER_LOOP; ++i)
		(*rxq->elts)[elts_idx + i] = &rxq->fake_mbuf;
*/



#ifdef MLX5_PMD_SOFT_COUNTERS
	rxq->stats.ipackets += nocmp_n;
	rxq->stats.ibytes += rcvd_byte;
#endif
	if (comp_enabled && comp_idx < MLX5_VPMD_DESCS_PER_LOOP && comp_idx == n) {
			pkts_n -= nocmp_n;
			//fprintf( stderr,"Decompressing CQs... CQ %d, max %d\n",nocmp_n, pkts_n);
			rxq->decompressed = rte_be_to_cpu_32(cq[nocmp_n].byte_cnt);
			if (likely(pkts_n > 7 || pkts_n >= rxq->decompressed))
				goto decomp;
	}
	/*
	else {
		if (nocmp_n > 0)
			fprintf( stderr,"Received %d, no compressed\n",nocmp_n);
	}*/

	if (likely(nocmp_n))
		xchg_rx_last_packet(xchg_last, xchgs);

	rte_compiler_barrier();
	*rxq->cq_db = rte_cpu_to_be_32(rxq->cq_ci);
	rte_cio_wmb();
	*rxq->rq_db = rte_cpu_to_be_32(rxq->rq_ci);

	return rcvd_pkt;
}
#endif

#endif /* RTE_PMD_MLX5_RXTX_VEC_SSE_H_ */
