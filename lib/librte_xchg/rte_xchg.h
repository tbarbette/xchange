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
struct xchg;


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
//The goal of XCHG is to avoid this kind of double-looping. This is only for backward compatibility, XCHG exchange buffers so we never free the buffer, and especially don't wait to do it in buffer
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


//----
// Implementation of the tx_buffer API for XCHG



/**
 * Structure used to buffer packets for future TX
 * Used by APIs rte_eth_tx_buffer and rte_eth_tx_buffer_flush
 */
struct rte_eth_dev_tx_buffer_xchg {
	//buffer_tx_error_fn error_callback;
	//void *error_userdata;
	uint16_t size;           /**< Size of buffer for buffered tx */
	uint16_t length;         /**< Number of packets in the array */
	struct xchg *pkts[];
	/**< Pending packets to be sent on explicit flush or when full */
};


static inline uint16_t
rte_eth_tx_burst_xchg(uint16_t port_id, uint16_t queue_id,
		 struct xchg **tx_pkts, uint16_t nb_pkts);

static inline uint16_t
rte_eth_tx_buffer_flush_xchg(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_dev_tx_buffer_xchg *buffer);

static inline uint16_t
rte_eth_tx_buffer_xchg(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_dev_tx_buffer_xchg *buffer, struct xchg *tx_pkt);

static inline int
rte_eth_tx_buffer_init_xchg(struct rte_eth_dev_tx_buffer_xchg *buffer, uint16_t size);

/**
 * Send a burst of output packets on a transmit queue of an Ethernet device.
 *
 * The rte_eth_tx_burst() function is invoked to transmit output packets
 * on the output queue *queue_id* of the Ethernet device designated by its
 * *port_id*.
 * The *nb_pkts* parameter is the number of packets to send which are
 * supplied in the *tx_pkts* array of *rte_mbuf* structures, each of them
 * allocated from a pool created with rte_pktmbuf_pool_create().
 * The rte_eth_tx_burst() function loops, sending *nb_pkts* packets,
 * up to the number of transmit descriptors available in the TX ring of the
 * transmit queue.
 * For each packet to send, the rte_eth_tx_burst() function performs
 * the following operations:
 *
 * - Pick up the next available descriptor in the transmit ring.
 *
 * - Free the network buffer previously sent with that descriptor, if any.
 *
 * - Initialize the transmit descriptor with the information provided
 *   in the *rte_mbuf data structure.
 *
 * In the case of a segmented packet composed of a list of *rte_mbuf* buffers,
 * the rte_eth_tx_burst() function uses several transmit descriptors
 * of the ring.
 *
 * The rte_eth_tx_burst() function returns the number of packets it
 * actually sent. A return value equal to *nb_pkts* means that all packets
 * have been sent, and this is likely to signify that other output packets
 * could be immediately transmitted again. Applications that implement a
 * "send as many packets to transmit as possible" policy can check this
 * specific case and keep invoking the rte_eth_tx_burst() function until
 * a value less than *nb_pkts* is returned.
 *
 * It is the responsibility of the rte_eth_tx_burst() function to
 * transparently free the memory buffers of packets previously sent.
 * This feature is driven by the *tx_free_thresh* value supplied to the
 * rte_eth_dev_configure() function at device configuration time.
 * When the number of free TX descriptors drops below this threshold, the
 * rte_eth_tx_burst() function must [attempt to] free the *rte_mbuf*  buffers
 * of those packets whose transmission was effectively completed.
 *
 * If the PMD is DEV_TX_OFFLOAD_MT_LOCKFREE capable, multiple threads can
 * invoke this function concurrently on the same tx queue without SW lock.
 * @see rte_eth_dev_info_get, struct rte_eth_txconf::offloads
 *
 * @see rte_eth_tx_prepare to perform some prior checks or adjustments
 * for offloads.
 *
 * @param port_id
 *   The port identifier of the Ethernet device.
 * @param queue_id
 *   The index of the transmit queue through which output packets must be
 *   sent.
 *   The value must be in the range [0, nb_tx_queue - 1] previously supplied
 *   to rte_eth_dev_configure().
 * @param tx_pkts
 *   The address of an array of *nb_pkts* pointers to *rte_mbuf* structures
 *   which contain the output packets.
 * @param nb_pkts
 *   The maximum number of packets to transmit.
 * @return
 *   The number of output packets actually stored in transmit descriptors of
 *   the transmit ring. The return value can be less than the value of the
 *   *tx_pkts* parameter when the transmit ring is full or has been filled up.
 */
static inline uint16_t
rte_eth_tx_burst_xchg(uint16_t port_id, uint16_t queue_id,
		 struct xchg **tx_pkts, uint16_t nb_pkts)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, 0);
	RTE_FUNC_PTR_OR_ERR_RET(*dev->tx_pkt_burst, 0);

	if (queue_id >= dev->data->nb_tx_queues) {
		RTE_ETHDEV_LOG(ERR, "Invalid TX queue_id=%u\n", queue_id);
		return 0;
	}
#endif

#ifdef RTE_ETHDEV_RXTX_CALLBACKS
	struct rte_eth_rxtx_callback *cb = dev->pre_tx_burst_cbs[queue_id];

	if (unlikely(cb != NULL)) {
		do {
			nb_pkts = cb->fn.tx(port_id, queue_id, (struct rte_mbuf**)tx_pkts, nb_pkts,
					cb->param);
			cb = cb->next;
		} while (cb != NULL);
	}
#endif

	return (*dev->tx_pkt_burst_xchg)(dev->data->tx_queues[queue_id],  tx_pkts, nb_pkts);
}


static inline int
rte_eth_tx_buffer_init_xchg(struct rte_eth_dev_tx_buffer_xchg *buffer, uint16_t size)
{
	int ret = 0;

	if (buffer == NULL)
		return -EINVAL;

	buffer->size = size;
	/*if (buffer->error_callback == NULL) {
		ret = rte_eth_tx_buffer_set_err_callback_xchg(
			buffer, rte_eth_tx_buffer_drop_callback, NULL);
	}*/

	return ret;
}

/**
 * Send any packets queued up for transmission on a port and HW queue
 *
 * This causes an explicit flush of packets previously buffered via the
 * rte_eth_tx_buffer() function. It returns the number of packets successfully
 * sent to the NIC, and calls the error callback for any unsent packets. Unless
 * explicitly set up otherwise, the default callback simply frees the unsent
 * packets back to the owning mempool.
 *
 * @param port_id
 *   The port identifier of the Ethernet device.
 * @param queue_id
 *   The index of the transmit queue through which output packets must be
 *   sent.
 *   The value must be in the range [0, nb_tx_queue - 1] previously supplied
 *   to rte_eth_dev_configure().
 * @param buffer
 *   Buffer of packets to be transmit.
 * @return
 *   The number of packets successfully sent to the Ethernet device. The error
 *   callback is called for any packets which could not be sent.
 */
static inline uint16_t
rte_eth_tx_buffer_flush_xchg(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_dev_tx_buffer_xchg *buffer)
{
	uint16_t sent;
	uint16_t to_send = buffer->length;

	if (to_send == 0)
		return 0;

	sent = rte_eth_tx_burst_xchg(port_id, queue_id, buffer->pkts, to_send);

	buffer->length = 0;

	/* All packets sent, or to be dealt with by callback below */
/*	if (unlikely(sent != to_send))
		buffer->error_callback(&buffer->pkts[sent],
				       (uint16_t)(to_send - sent),
				       buffer->error_userdata);
					   */

	return sent;
}

/**
 * Buffer a single packet for future transmission on a port and queue
 *
 * This function takes a single mbuf/packet and buffers it for later
 * transmission on the particular port and queue specified. Once the buffer is
 * full of packets, an attempt will be made to transmit all the buffered
 * packets. In case of error, where not all packets can be transmitted, a
 * callback is called with the unsent packets as a parameter. If no callback
 * is explicitly set up, the unsent packets are just freed back to the owning
 * mempool. The function returns the number of packets actually sent i.e.
 * 0 if no buffer flush occurred, otherwise the number of packets successfully
 * flushed
 *
 * @param port_id
 *   The port identifier of the Ethernet device.
 * @param queue_id
 *   The index of the transmit queue through which output packets must be
 *   sent.
 *   The value must be in the range [0, nb_tx_queue - 1] previously supplied
 *   to rte_eth_dev_configure().
 * @param buffer
 *   Buffer used to collect packets to be sent.
 * @param tx_pkt
 *   Pointer to the packet mbuf to be sent.
 * @return
 *   0 = packet has been buffered for later transmission
 *   N > 0 = packet has been buffered, and the buffer was subsequently flushed,
 *     causing N packets to be sent, and the error callback to be called for
 *     the rest.
 */
static __rte_always_inline uint16_t
rte_eth_tx_buffer_xchg(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_dev_tx_buffer_xchg *buffer, struct xchg *tx_pkt)
{
	buffer->pkts[buffer->length++] = tx_pkt;
	if (buffer->length < buffer->size)
		return 0;

	return rte_eth_tx_buffer_flush_xchg(port_id, queue_id, buffer);
}


/**
 *
 * Retrieve a burst of input packets from a receive queue of an Ethernet
 * device. The retrieved packets are stored in *rte_mbuf* structures whose
 * pointers are supplied in the *rx_pkts* array.
 *
 * The rte_eth_rx_burst() function loops, parsing the RX ring of the
 * receive queue, up to *nb_pkts* packets, and for each completed RX
 * descriptor in the ring, it performs the following operations:
 *
 * - Initialize the *rte_mbuf* data structure associated with the
 *   RX descriptor according to the information provided by the NIC into
 *   that RX descriptor.
 *
 * - Store the *rte_mbuf* data structure into the next entry of the
 *   *rx_pkts* array.
 *
 * - Replenish the RX descriptor with a new *rte_mbuf* buffer
 *   allocated from the memory pool associated with the receive queue at
 *   initialization time.
 *
 * When retrieving an input packet that was scattered by the controller
 * into multiple receive descriptors, the rte_eth_rx_burst() function
 * appends the associated *rte_mbuf* buffers to the first buffer of the
 * packet.
 *
 * The rte_eth_rx_burst() function returns the number of packets
 * actually retrieved, which is the number of *rte_mbuf* data structures
 * effectively supplied into the *rx_pkts* array.
 * A return value equal to *nb_pkts* indicates that the RX queue contained
 * at least *rx_pkts* packets, and this is likely to signify that other
 * received packets remain in the input queue. Applications implementing
 * a "retrieve as much received packets as possible" policy can check this
 * specific case and keep invoking the rte_eth_rx_burst() function until
 * a value less than *nb_pkts* is returned.
 *
 * This receive method has the following advantages:
 *
 * - It allows a run-to-completion network stack engine to retrieve and
 *   to immediately process received packets in a fast burst-oriented
 *   approach, avoiding the overhead of unnecessary intermediate packet
 *   queue/dequeue operations.
 *
 * - Conversely, it also allows an asynchronous-oriented processing
 *   method to retrieve bursts of received packets and to immediately
 *   queue them for further parallel processing by another logical core,
 *   for instance. However, instead of having received packets being
 *   individually queued by the driver, this approach allows the caller
 *   of the rte_eth_rx_burst() function to queue a burst of retrieved
 *   packets at a time and therefore dramatically reduce the cost of
 *   enqueue/dequeue operations per packet.
 *
 * - It allows the rte_eth_rx_burst() function of the driver to take
 *   advantage of burst-oriented hardware features (CPU cache,
 *   prefetch instructions, and so on) to minimize the number of CPU
 *   cycles per packet.
 *
 * To summarize, the proposed receive API enables many
 * burst-oriented optimizations in both synchronous and asynchronous
 * packet processing environments with no overhead in both cases.
 *
 * The rte_eth_rx_burst() function does not provide any error
 * notification to avoid the corresponding overhead. As a hint, the
 * upper-level application might check the status of the device link once
 * being systematically returned a 0 value for a given number of tries.
 *
 * @param port_id
 *   The port identifier of the Ethernet device.
 * @param queue_id
 *   The index of the receive queue from which to retrieve input packets.
 *   The value must be in the range [0, nb_rx_queue - 1] previously supplied
 *   to rte_eth_dev_configure().
 * @param rx_pkts
 *   The address of an array of pointers to *rte_mbuf* structures that
 *   must be large enough to store *nb_pkts* pointers in it.
 * @param nb_pkts
 *   The maximum number of packets to retrieve.
 * @return
 *   The number of packets actually retrieved, which is the number
 *   of pointers to *rte_mbuf* structures effectively supplied to the
 *   *rx_pkts* array.
 */
static inline uint16_t
rte_eth_rx_burst_xchg(uint16_t port_id, uint16_t queue_id,
		 struct xchg **rx_pkts, const uint16_t nb_pkts)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	uint16_t nb_rx;

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, 0);
	RTE_FUNC_PTR_OR_ERR_RET(*dev->rx_pkt_burst, 0);

	if (queue_id >= dev->data->nb_rx_queues) {
		RTE_ETHDEV_LOG(ERR, "Invalid RX queue_id=%u\n", queue_id);
		return 0;
	}
#endif
	nb_rx = (*dev->rx_pkt_burst_xchg)(dev->data->rx_queues[queue_id],
				     rx_pkts, nb_pkts);

#ifdef RTE_ETHDEV_RXTX_CALLBACKS
/*	if (unlikely(dev->post_rx_burst_cbs[queue_id] != NULL)) {
		struct rte_eth_rxtx_callback *cb =
				dev->post_rx_burst_cbs[queue_id];

		do {
			nb_rx = cb->fn.rx(port_id, queue_id, rx_pkts, nb_rx,
						nb_pkts, cb->param);
			cb = cb->next;
		} while (cb != NULL);
	}*/
#endif

	return nb_rx;
}


//---- Functions exported for testing of direct call
//
#ifdef RTE_LIBRTE_XCHG
uint16_t rte_mlx5_tx_burst_xchg(uint16_t port_id, uint16_t queue_id,
		 struct xchg **tx_pkts, uint16_t nb_pkts);
uint16_t
rte_mlx5_rx_burst_xchg(uint16_t port_id, uint16_t queue_id,
	 struct xchg **xchgs, const uint16_t nb_pkts);
uint16_t
rte_mlx5_rx_burst_xchg_vec(uint16_t port_id, uint16_t queue_id,
	 struct xchg **xchgs, const uint16_t nb_pkts);
uint16_t
rte_mlx5_rx_burst_xchg_vec_comp(uint16_t port_id, uint16_t queue_id,
	 struct xchg **xchgs, const uint16_t nb_pkts);
uint16_t
rte_mlx5_rx_burst_stripped(uint16_t port_id, uint16_t queue_id,
		 struct rte_mbuf **rx_pkts, const uint16_t nb_pkts);
#endif
#endif
