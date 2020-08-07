#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ethdev_core.h>

struct rte_mempool;

struct xchg {
};

    extern bool xchg_elts_vec;
    extern bool xchg_do_tx_free;

    void xchg_set_buffer(struct xchg*, void*);
    void xchg_set_packet_type(struct xchg*, uint32_t);
    void xchg_set_rss_hash(struct xchg*, uint32_t);
    void xchg_set_timestamp(struct xchg*, uint64_t);

    void xchg_clear_flag(struct xchg*, uint64_t);
    void xchg_set_flag(struct xchg*, uint64_t);
    void xchg_set_fdir_id(struct xchg*, uint32_t);
    void xchg_set_vlan(struct xchg*, uint32_t);
    void xchg_set_len(struct xchg*, uint16_t);
    void xchg_set_data_len(struct xchg*, uint16_t);

    uint16_t xchg_get_len(struct xchg*);

    void xchg_finish_packet(struct xchg* xchg);
    struct xchg* xchg_next(struct rte_mbuf** buf, struct xchg** xchgs, struct rte_mempool* mp);
    void xchg_cancel(struct xchg*, struct rte_mbuf*);
    void xchg_advance(struct xchg*, struct xchg*** xchgs_p);
    void* xchg_buffer_from_elt(struct rte_mbuf* buf);

    void xchg_tx_sent_vec(struct rte_mbuf** elts, struct xchg** xchg, unsigned n);

    
    uint32_t xchg_get_vlan(struct xchg* xchg);
    uint64_t xchg_get_flags(struct xchg* xchg);

    uint16_t xchg_get_outer_l2_len(struct xchg* xchg);

    uint16_t xchg_get_outer_l3_len(struct xchg* xchg);
    uint8_t xchg_get_tsosz(struct xchg* xchg);


    struct xchg* xchg_tx_next(struct xchg** xchgs);
    int xchg_nb_segs(struct xchg* xchg);
    //Advance xchgs by one
    void xchg_tx_advance(struct xchg*** xchgs);
    void* xchg_get_buffer(struct xchg* xchg);

    struct rte_mbuf* xchg_get_mbuf(struct xchg* xchg);
    void xchg_tx_completed(struct rte_mbuf** elts, unsigned int part, unsigned int olx);
    void* xchg_get_buffer_addr(struct xchg* xchg);
    void xchg_tx_sent_inline(struct xchg* xchg);
    void xchg_tx_sent(struct rte_mbuf** elts, struct xchg** xchg);
    int xchg_has_flag(struct xchg* xchg, uint64_t f);
uint16_t xchg_get_data_len(struct xchg* xchg);

//External API for MLX5
uint16_t rte_mlx5_tx_burst_xchg(uint16_t port_id, uint16_t queue_id,
		 struct xchg **tx_pkts, uint16_t nb_pkts);
uint16_t
mlx5_rx_burst_xchg(void *dpdk_rxq, struct xchg **xchgs, uint16_t pkts_n);
//uint16_t mlx5_rx_burst(void *dpdk_rxq, struct rte_mbuf **pkts, uint16_t pkts_n);
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


