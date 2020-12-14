/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 KTH
 */

#ifndef _RTE_XCHG_H_
#define _RTE_XCHG_H_

#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ethdev_core.h>

struct rte_mempool;

/**
 * The struct xchg is only a wrapper to the user's packet descriptor. It is never implemented for real, only casted.
 */
struct xchg {
};


/**
 * Warning : this file contains a lot of functions, but someone seeking to implement its efficient application using X-Change do not need to implement them all, certain functions are just to allow a backward compatible behavior. Use one of the simple implementation, eg l2fwd-xchg and start from there.
 */

//Buffer management

//Set the data buffer address in the descriptor
void xchg_set_buffer(struct xchg*, void*);
//Set the packet length
void xchg_set_len(struct xchg*, uint16_t);
//Return the packet length
uint16_t xchg_get_len(struct xchg*);
//Set the packet data length (see rte_mbuf.h if you wonder about the difference)
void xchg_set_data_len(struct xchg*, uint16_t);
//Get the data len
uint16_t xchg_get_data_len(struct xchg* xchg);

//Clears all flags of the packet
void xchg_clear_flag(struct xchg*, uint64_t);
//Set a flag
void xchg_set_flag(struct xchg*, uint64_t);
//Tells if a flag is set
int xchg_has_flag(struct xchg* xchg, uint64_t f);


//Set the packet type (DPDK convention)
void xchg_set_packet_type(struct xchg*, uint32_t);
//Set he RSS hash
void xchg_set_rss_hash(struct xchg*, uint32_t);
//Set the timestamp
void xchg_set_timestamp(struct xchg*, uint64_t);
//Set the fdir mark, if provided
void xchg_set_fdir_id(struct xchg*, uint32_t);
//Set the VLAN TCI
void xchg_set_vlan(struct xchg*, uint32_t);


//Descriptor advancement (advancing in the list/array provided by the user)

//Give the next descriptor pointer of the user list. One must also set in *buf the pointer to the rte_mbuf backing a buffer to receive new data
struct xchg* xchg_next(struct rte_mbuf** buf, struct xchg** xchgs, struct rte_mempool* mp);
//Cancel the last xchg_next (it's how mlx5 works)
void xchg_cancel(struct xchg*, struct rte_mbuf*);
//Advance in the user list, one can see next as a "peek()" function and advance as a "pop" function.
void xchg_advance(struct xchg*, struct xchg*** xchgs_p);
//Convert a rte_mbuf buffer in the ring to its buffer pointer. As only the user manages those, one usually do a constant shift between the buffer pointer and the size of the rte_mbuf structure
void* xchg_buffer_from_elt(struct rte_mbuf* buf);

//An array of packets has been sent, free them. Only called if xchg_do_tx_sent_vec is true.
//The goal of XCHG is to avoid this kind of double-looping.
void xchg_tx_sent_vec(struct rte_mbuf** elts, struct xchg** xchg, unsigned n);

//A packet has been fully received, all flags set, data written, etc. Anything else to do before going to the next one?
void xchg_finish_packet(struct xchg* xchg);


//Read from packet metadata, the name gives it out
uint32_t xchg_get_vlan(struct xchg* xchg);
uint64_t xchg_get_flags(struct xchg* xchg);
uint16_t xchg_get_outer_l2_len(struct xchg* xchg);
uint16_t xchg_get_outer_l3_len(struct xchg* xchg);
uint8_t xchg_get_tsosz(struct xchg* xchg);


//Peek the next descriptor to be sent.
struct xchg* xchg_tx_next(struct xchg** xchgs);
//Returns the number of segments in the packet
int xchg_nb_segs(struct xchg* xchg);
//Advance xchgs by one
void xchg_tx_advance(struct xchg*** xchgs);
//Return the pointer of the packet buffer data (the real beginning of the packet) from the descriptor
void* xchg_get_buffer(struct xchg* xchg);
//Return the buffer address of the pointer
void* xchg_get_buffer_addr(struct xchg* xchg);

//Returns the rte_mbuf backing the buffer of the descriptor
struct rte_mbuf* xchg_get_mbuf(struct xchg* xchg);
//A packet has been sent. One must free the elements in elts
void xchg_tx_completed(struct rte_mbuf** elts, unsigned int part, unsigned int olx);

//The packet has been sent inline, so there is no buffer to recover
void xchg_tx_sent_inline(struct xchg* xchg);
//The packet has been sent, one should set in elts the mbuf associated to the buffer put in the ring
void xchg_tx_sent(struct rte_mbuf** elts, struct xchg** xchg);

/**
 * Flags describing how the driver should behave regarding a few mechanisms that can use multiple methods.
 * One may wonder if adding a lot of booleans everywhere would not harm the performance? The answer is no, LTO will inline them all. Similarly, all those simple functions above will be inlined.
 */

//Should the driver free all sent buffers at once? Default yes
extern bool xchg_elts_vec;
//Should the driver free the transmitted buffers, default to yes
extern bool xchg_do_tx_free;


//External API for MLX5, if XCHG is standardized this should be pushed to the mlx5 driver itself
uint16_t rte_mlx5_tx_burst_xchg(uint16_t port_id, uint16_t queue_id,
		 struct xchg **tx_pkts, uint16_t nb_pkts);
uint16_t
mlx5_rx_burst_xchg(void *dpdk_rxq, struct xchg **xchgs, uint16_t pkts_n);

uint16_t
mlx5_rx_burst_stripped(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n);

static inline uint16_t
rte_mlx5_rx_burst_stripped(uint16_t port_id, uint16_t queue_id,
		 struct rte_mbuf **rx_pkts, const uint16_t nb_pkts)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	uint16_t nb_rx;

	nb_rx = mlx5_rx_burst_stripped(dev->data->rx_queues[queue_id],
				     rx_pkts, nb_pkts);
	return nb_rx;
}


static inline uint16_t
rte_mlx5_rx_burst_xchg(uint16_t port_id, uint16_t queue_id,
	 struct xchg **xchgs, const uint16_t nb_pkts)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	uint16_t nb_rx;

	nb_rx = mlx5_rx_burst_xchg(dev->data->rx_queues[queue_id],
				     xchgs, nb_pkts);
	return nb_rx;
}

#endif
