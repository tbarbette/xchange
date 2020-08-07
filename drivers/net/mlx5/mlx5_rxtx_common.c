/**
 * Fill in mbuf fields from RX completion flags.
 * Note that pkt->ol_flags should be initialized outside of this function.
 *
 * @param rxq
 *   Pointer to RX queue.
 * @param pkt
 *   mbuf to fill.
 * @param cqe
 *   CQE to process.
 * @param rss_hash_res
 *   Packet RSS Hash result.
 */
static inline void
rxq_cq_to_mbuf(struct mlx5_rxq_data *rxq, struct rte_mbuf *pkt,
	       volatile struct mlx5_cqe *cqe, uint32_t rss_hash_res)
{
	/* Update packet information. */
	pkt->packet_type = rxq_cq_to_pkt_type(rxq, cqe);
	if (rss_hash_res && rxq->rss_hash) {
		pkt->hash.rss = rss_hash_res;
		pkt->ol_flags |= PKT_RX_RSS_HASH;
	}
	if (rxq->mark && MLX5_FLOW_MARK_IS_VALID(cqe->sop_drop_qpn)) {
		pkt->ol_flags |= PKT_RX_FDIR;
		if (cqe->sop_drop_qpn !=
		    rte_cpu_to_be_32(MLX5_FLOW_MARK_DEFAULT)) {
			uint32_t mark = cqe->sop_drop_qpn;

			pkt->ol_flags |= PKT_RX_FDIR_ID;
			pkt->hash.fdir.hi = mlx5_flow_mark_get(mark);
		}
	}
	if (rte_flow_dynf_metadata_avail() && cqe->flow_table_metadata) {
		pkt->ol_flags |= PKT_RX_DYNF_METADATA;
		*RTE_FLOW_DYNF_METADATA(pkt) = cqe->flow_table_metadata;
	}
	if (rxq->csum)
		pkt->ol_flags |= rxq_cq_to_ol_flags(cqe);
	if (rxq->vlan_strip &&
	    (cqe->hdr_type_etc & rte_cpu_to_be_16(MLX5_CQE_VLAN_STRIPPED))) {
		pkt->ol_flags |= PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED;
		pkt->vlan_tci = rte_be_to_cpu_16(cqe->vlan_info);
	}
	if (rxq->hw_timestamp) {
		pkt->timestamp = rte_be_to_cpu_64(cqe->timestamp);
		pkt->ol_flags |= PKT_RX_TIMESTAMP;
	}
}

/**
 * Translate RX completion flags to packet type.
 *
 * @param[in] rxq
 *   Pointer to RX queue structure.
 * @param[in] cqe
 *   Pointer to CQE.
 *
 * @note: fix mlx5_dev_supported_ptypes_get() if any change here.
 *
 * @return
 *   Packet type for struct rte_mbuf.
 */
static inline uint32_t
rxq_cq_to_pkt_type(struct mlx5_rxq_data *rxq, volatile struct mlx5_cqe *cqe)
{
	uint8_t idx;
	uint8_t pinfo = cqe->pkt_info;
	uint16_t ptype = cqe->hdr_type_etc;

	/*
	 * The index to the array should have:
	 * bit[1:0] = l3_hdr_type
	 * bit[4:2] = l4_hdr_type
	 * bit[5] = ip_frag
	 * bit[6] = tunneled
	 * bit[7] = outer_l3_type
	 */
	idx = ((pinfo & 0x3) << 6) | ((ptype & 0xfc00) >> 10);
	return mlx5_ptype_table[idx] | rxq->tunnel * !!(idx & (1 << 6));
}

/**
 * Translate RX completion flags to offload flags.
 *
 * @param[in] cqe
 *   Pointer to CQE.
 *
 * @return
 *   Offload flags (ol_flags) for struct rte_mbuf.
 */
static inline uint32_t
rxq_cq_to_ol_flags(volatile struct mlx5_cqe *cqe)
{
	uint32_t ol_flags = 0;
	uint16_t flags = rte_be_to_cpu_16(cqe->hdr_type_etc);

	ol_flags =
		TRANSPOSE(flags,
			  MLX5_CQE_RX_L3_HDR_VALID,
			  PKT_RX_IP_CKSUM_GOOD) |
		TRANSPOSE(flags,
			  MLX5_CQE_RX_L4_HDR_VALID,
			  PKT_RX_L4_CKSUM_GOOD);
	return ol_flags;
}


/**
 * Get size of the next packet for a given CQE. For compressed CQEs, the
 * consumer index is updated only once all packets of the current one have
 * been processed.
 *
 * @param rxq
 *   Pointer to RX queue.
 * @param cqe
 *   CQE to process.
 * @param[out] mcqe
 *   Store pointer to mini-CQE if compressed. Otherwise, the pointer is not
 *   written.
 *
 * @return
 *   0 in case of empty CQE, otherwise the packet size in bytes.
 */
static inline int
mlx5_rx_poll_len(struct mlx5_rxq_data *rxq, volatile struct mlx5_cqe *cqe,
		 uint16_t cqe_cnt, volatile struct mlx5_mini_cqe8 **mcqe)
{
	struct rxq_zip *zip = &rxq->zip;
	uint16_t cqe_n = cqe_cnt + 1;
	int len;
	uint16_t idx, end;

	do {
		len = 0;
		/* Process compressed data in the CQE and mini arrays. */
		if (zip->ai) {
			volatile struct mlx5_mini_cqe8 (*mc)[8] =
				(volatile struct mlx5_mini_cqe8 (*)[8])
				(uintptr_t)(&(*rxq->cqes)[zip->ca &
							  cqe_cnt].pkt_info);

			len = rte_be_to_cpu_32((*mc)[zip->ai & 7].byte_cnt);
			*mcqe = &(*mc)[zip->ai & 7];
			if ((++zip->ai & 7) == 0) {
				/* Invalidate consumed CQEs */
				idx = zip->ca;
				end = zip->na;
				while (idx != end) {
					(*rxq->cqes)[idx & cqe_cnt].op_own =
						MLX5_CQE_INVALIDATE;
					++idx;
				}
				/*
				 * Increment consumer index to skip the number
				 * of CQEs consumed. Hardware leaves holes in
				 * the CQ ring for software use.
				 */
				zip->ca = zip->na;
				zip->na += 8;
			}
			if (unlikely(rxq->zip.ai == rxq->zip.cqe_cnt)) {
				/* Invalidate the rest */
				idx = zip->ca;
				end = zip->cq_ci;

				while (idx != end) {
					(*rxq->cqes)[idx & cqe_cnt].op_own =
						MLX5_CQE_INVALIDATE;
					++idx;
				}
				rxq->cq_ci = zip->cq_ci;
				zip->ai = 0;
			}
		/*
		 * No compressed data, get next CQE and verify if it is
		 * compressed.
		 */
		} else {
			int ret;
			int8_t op_own;

			ret = check_cqe(cqe, cqe_n, rxq->cq_ci);
			if (unlikely(ret != MLX5_CQE_STATUS_SW_OWN)) {
				if (unlikely(ret == MLX5_CQE_STATUS_ERR ||
					     rxq->err_state)) {
					ret = mlx5_rx_err_handle(rxq, 0);
					if (ret == MLX5_CQE_STATUS_HW_OWN ||
					    ret == -1)
						return 0;
				} else {
					return 0;
				}
			}
			++rxq->cq_ci;
			op_own = cqe->op_own;
			if (MLX5_CQE_FORMAT(op_own) == MLX5_COMPRESSED) {
				volatile struct mlx5_mini_cqe8 (*mc)[8] =
					(volatile struct mlx5_mini_cqe8 (*)[8])
					(uintptr_t)(&(*rxq->cqes)
						[rxq->cq_ci &
						 cqe_cnt].pkt_info);

				/* Fix endianness. */
				zip->cqe_cnt = rte_be_to_cpu_32(cqe->byte_cnt);
				/*
				 * Current mini array position is the one
				 * returned by check_cqe64().
				 *
				 * If completion comprises several mini arrays,
				 * as a special case the second one is located
				 * 7 CQEs after the initial CQE instead of 8
				 * for subsequent ones.
				 */
				zip->ca = rxq->cq_ci;
				zip->na = zip->ca + 7;
				/* Compute the next non compressed CQE. */
				--rxq->cq_ci;
				zip->cq_ci = rxq->cq_ci + zip->cqe_cnt;
				/* Get packet size to return. */
				len = rte_be_to_cpu_32((*mc)[0].byte_cnt);
				*mcqe = &(*mc)[0];
				zip->ai = 1;
				/* Prefetch all to be invalidated */
				idx = zip->ca;
				end = zip->cq_ci;
				while (idx != end) {
					rte_prefetch0(&(*rxq->cqes)[(idx) &
								    cqe_cnt]);
					++idx;
				}
			} else {
				len = rte_be_to_cpu_32(cqe->byte_cnt);
			}
		}
		if (unlikely(rxq->err_state)) {
			cqe = &(*rxq->cqes)[rxq->cq_ci & cqe_cnt];
			++rxq->stats.idropped;
		} else {
			return len;
		}
	} while (1);
}

/* TX burst subroutines return codes. */
enum mlx5_txcmp_code {
	MLX5_TXCMP_CODE_EXIT = 0,
	MLX5_TXCMP_CODE_ERROR,
	MLX5_TXCMP_CODE_SINGLE,
	MLX5_TXCMP_CODE_MULTI,
	MLX5_TXCMP_CODE_TSO,
	MLX5_TXCMP_CODE_EMPW,
};


/*
 * These defines are used to configure Tx burst routine option set
 * supported at compile time. The not specified options are optimized out
 * out due to if conditions can be explicitly calculated at compile time.
 * The offloads with bigger runtime check (require more CPU cycles to
 * skip) overhead should have the bigger index - this is needed to
 * select the better matching routine function if no exact match and
 * some offloads are not actually requested.
 */
#define MLX5_TXOFF_CONFIG_MULTI (1u << 0) /* Multi-segment packets.*/
#define MLX5_TXOFF_CONFIG_TSO (1u << 1) /* TCP send offload supported.*/
#define MLX5_TXOFF_CONFIG_SWP (1u << 2) /* Tunnels/SW Parser offloads.*/
#define MLX5_TXOFF_CONFIG_CSUM (1u << 3) /* Check Sums offloaded. */
#define MLX5_TXOFF_CONFIG_INLINE (1u << 4) /* Data inlining supported. */
#define MLX5_TXOFF_CONFIG_VLAN (1u << 5) /* VLAN insertion supported.*/
#define MLX5_TXOFF_CONFIG_METADATA (1u << 6) /* Flow metadata. */
#define MLX5_TXOFF_CONFIG_EMPW (1u << 8) /* Enhanced MPW supported.*/
#define MLX5_TXOFF_CONFIG_MPW (1u << 9) /* Legacy MPW supported.*/

/* The most common offloads groups. */
#define MLX5_TXOFF_CONFIG_NONE 0
#define MLX5_TXOFF_CONFIG_FULL (MLX5_TXOFF_CONFIG_MULTI | \
				MLX5_TXOFF_CONFIG_TSO | \
				MLX5_TXOFF_CONFIG_SWP | \
				MLX5_TXOFF_CONFIG_CSUM | \
				MLX5_TXOFF_CONFIG_INLINE | \
				MLX5_TXOFF_CONFIG_VLAN | \
				MLX5_TXOFF_CONFIG_METADATA)

#define MLX5_TXOFF_CONFIG(mask) (olx & MLX5_TXOFF_CONFIG_##mask)

uint64_t rte_net_mlx5_dynf_inline_mask;
#define PKT_TX_DYNF_NOINLINE rte_net_mlx5_dynf_inline_mask

/**
 * Convert the Checksum offloads to Verbs.
 *
 * @param buf
 *   Pointer to the mbuf.
 *
 * @return
 *   Converted checksum flags.
 */
static __rte_always_inline uint8_t
txq_ol_cksum_to_cs(uint64_t ol_flags)
{
	uint32_t idx;
	uint8_t is_tunnel = !!(ol_flags & PKT_TX_TUNNEL_MASK);
	const uint64_t ol_flags_mask = PKT_TX_TCP_SEG | PKT_TX_L4_MASK |
				       PKT_TX_IP_CKSUM | PKT_TX_OUTER_IP_CKSUM;

	/*
	 * The index should have:
	 * bit[0] = PKT_TX_TCP_SEG
	 * bit[2:3] = PKT_TX_UDP_CKSUM, PKT_TX_TCP_CKSUM
	 * bit[4] = PKT_TX_IP_CKSUM
	 * bit[8] = PKT_TX_OUTER_IP_CKSUM
	 * bit[9] = tunnel
	 */
	idx = ((ol_flags & ol_flags_mask) >> 50) | (!!is_tunnel << 9);
	return mlx5_cksum_table[idx];
}


/**
 * Build the Control Segment with specified opcode:
 * - MLX5_OPCODE_SEND
 * - MLX5_OPCODE_ENHANCED_MPSW
 * - MLX5_OPCODE_TSO
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param loc
 *   Pointer to burst routine local context.
 * @param wqe
 *   Pointer to WQE to fill with built Control Segment.
 * @param ds
 *   Supposed length of WQE in segments.
 * @param opcode
 *   SQ WQE opcode to put into Control Segment.
 * @param olx
 *   Configured Tx offloads mask. It is fully defined at
 *   compile time and may be used for optimization.
 */
static __rte_always_inline void
mlx5_tx_cseg_init(struct mlx5_txq_data *restrict txq,
		  struct mlx5_wqe *restrict wqe,
		  unsigned int ds,
		  unsigned int opcode,
		  unsigned int olx __rte_unused)
{
	struct mlx5_wqe_cseg *restrict cs = &wqe->cseg;

	/* For legacy MPW replace the EMPW by TSO with modifier. */
	if (MLX5_TXOFF_CONFIG(MPW) && opcode == MLX5_OPCODE_ENHANCED_MPSW)
		opcode = MLX5_OPCODE_TSO | MLX5_OPC_MOD_MPW << 24;
	cs->opcode = rte_cpu_to_be_32((txq->wqe_ci << 8) | opcode);
	cs->sq_ds = rte_cpu_to_be_32(txq->qp_num_8s | ds);
	cs->flags = RTE_BE32(MLX5_COMP_ONLY_FIRST_ERR <<
			     MLX5_COMP_MODE_OFFSET);
	cs->misc = RTE_BE32(0);
}

/* Return 1 if the error CQE is signed otherwise, sign it and return 0. */
static int
check_err_cqe_seen(volatile struct mlx5_err_cqe *err_cqe)
{
	static const uint8_t magic[] = "seen";
	int ret = 1;
	unsigned int i;

	for (i = 0; i < sizeof(magic); ++i)
		if (!ret || err_cqe->rsvd1[i] != magic[i]) {
			ret = 0;
			err_cqe->rsvd1[i] = magic[i];
		}
	return ret;
}

int
mlx5_queue_state_modify(struct rte_eth_dev *dev,
			struct mlx5_mp_arg_queue_state_modify *sm);

/**
 * Move QP from error state to running state and initialize indexes.
 *
 * @param txq_ctrl
 *   Pointer to TX queue control structure.
 *
 * @return
 *   0 on success, else -1.
 */
static int
tx_recover_qp(struct mlx5_txq_ctrl *txq_ctrl)
{
	struct mlx5_mp_arg_queue_state_modify sm = {
			.is_wq = 0,
			.queue_id = txq_ctrl->txq.idx,
	};

	if (mlx5_queue_state_modify(ETH_DEV(txq_ctrl->priv), &sm))
		return -1;
	txq_ctrl->txq.wqe_ci = 0;
	txq_ctrl->txq.wqe_pi = 0;
	txq_ctrl->txq.elts_comp = 0;
	return 0;
}

static int
mlx5_tx_error_cqe_handle(struct mlx5_txq_data *restrict txq,
			 volatile struct mlx5_err_cqe *err_cqe) __attribute__((unused));

/**
 * Handle error CQE.
 *
 * @param txq
 *   Pointer to TX queue structure.
 * @param error_cqe
 *   Pointer to the error CQE.
 *
 * @return
 *   Negative value if queue recovery failed, otherwise
 *   the error completion entry is handled successfully.
 */
static int
mlx5_tx_error_cqe_handle(struct mlx5_txq_data *restrict txq,
			 volatile struct mlx5_err_cqe *err_cqe)
{
	if (err_cqe->syndrome != MLX5_CQE_SYNDROME_WR_FLUSH_ERR) {
		const uint16_t wqe_m = ((1 << txq->wqe_n) - 1);
		struct mlx5_txq_ctrl *txq_ctrl =
				container_of(txq, struct mlx5_txq_ctrl, txq);
		uint16_t new_wqe_pi = rte_be_to_cpu_16(err_cqe->wqe_counter);
		int seen = check_err_cqe_seen(err_cqe);

		if (!seen && txq_ctrl->dump_file_n <
		    txq_ctrl->priv->config.max_dump_files_num) {
			MKSTR(err_str, "Unexpected CQE error syndrome "
			      "0x%02x CQN = %u SQN = %u wqe_counter = %u "
			      "wq_ci = %u cq_ci = %u", err_cqe->syndrome,
			      txq->cqe_s, txq->qp_num_8s >> 8,
			      rte_be_to_cpu_16(err_cqe->wqe_counter),
			      txq->wqe_ci, txq->cq_ci);
			MKSTR(name, "dpdk_mlx5_port_%u_txq_%u_index_%u_%u",
			      PORT_ID(txq_ctrl->priv), txq->idx,
			      txq_ctrl->dump_file_n, (uint32_t)rte_rdtsc());
			mlx5_dump_debug_information(name, NULL, err_str, 0);
			mlx5_dump_debug_information(name, "MLX5 Error CQ:",
						    (const void *)((uintptr_t)
						    txq->cqes),
						    sizeof(*err_cqe) *
						    (1 << txq->cqe_n));
			mlx5_dump_debug_information(name, "MLX5 Error SQ:",
						    (const void *)((uintptr_t)
						    txq->wqes),
						    MLX5_WQE_SIZE *
						    (1 << txq->wqe_n));
			txq_ctrl->dump_file_n++;
		}
		if (!seen)
			/*
			 * Count errors in WQEs units.
			 * Later it can be improved to count error packets,
			 * for example, by SQ parsing to find how much packets
			 * should be counted for each WQE.
			 */
			txq->stats.oerrors += ((txq->wqe_ci & wqe_m) -
						new_wqe_pi) & wqe_m;
		if (tx_recover_qp(txq_ctrl)) {
			/* Recovering failed - retry later on the same WQE. */
			return -1;
		}
		/* Release all the remaining buffers. */
		txq_free_elts(txq_ctrl);
	}
	return 0;
}
