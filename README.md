# X-Change: Efficient Metadata Management Model for Packet Processing

X-Change model is an optimization to Data Plane Development Kit ([DPDK][dpdk-page]) that provides custom buffers to drivers; thus, metadata can be directly written into the applications' buffers rather than using an intermediate DPDK buffer. X-Change uses conversion functions instead of direct assignment to set the metadata fields. The X-Change API (i.e., the different conversion functions) is dependent on the driver's features, as some NICs provide more metadata. For more information, please refer to PacketMill's [paper][packetmill-paper] and [main repository][packetmill-repo]. 

**Note: Currently, X-Change only supports the MLX5 driver used by Mellanox NICs. However, X-Change is applicable to other drivers, as other (e.g., Intel) drivers are implemented similarly and have the same inefficiencies.**


## Why X-Change?

X-Change provides an efficient metadata management model for packet processing. More specifically, it addresses the three main problems associated with current DPDK-based metadata management models:

1. DPDK uses a distinct metadata buffer (i.e. the rte\_mbuf) for every packet, but these extra metadata buffers reduce cache locality. In contrast, we only need a limited number of metadata buffers, as packet processing frameworks use batching.

2. DPDK uses a generic buffer for metadata management. Consequently, different applications have to copy and/or transform the metadata fields in order to process packets.

3. All applications use one standard data structure for all kinds of packet processing. However, different network functions require different fields, resulting in carrying unused information during processing; again, reducing cache locality.

X-Change results in the following improvements:

* Enables applications to use their tailored metadata and to bypass the generic `rte_mbuf`, thus avoiding unnecessary copy/transform operations and cache evictions;

* Pushes down part of the application's RX/TX loops to initialize packet annotations into the Poll Mode Driver (PMD), thereby simplifying the application's processing path;

* Limits the amount of metadata used to the application's requirement (i.e., proportional to the RX burst size + the number of packets enqueued in software), keeping metadata cache lines warmer;

* Skips buffer allocation/release operations through DPDK buffer pools, which is inefficient due to supporting/maintaining many (unnecessary) features; and

* Makes it possible for the application to easily use different packet chaining models (e.g., vector, linked list, or a combination of both) to better fit their needs.

## Advantage over Other Approaches

* [Pirelli et al.][tinynf-link] [OSDI'20][osdi-20-page] accelerates DPDK model by removing the need for dynamic packet metadata. However, it also prevents buffering of packets, such as switching packets between cores, reordering packets, and stream processing; even a DPI would need to copy packets. Hence, it comes with a lot of drawbacks. X-Change also reduces the number of metadata buffers, but without imposing those restrictions. Furthermore, X-Change is more generic, as it brings programmability inside the driver, which makes it possible to implement buffer exchanging, or the model proposed by Pirelli et al., without even re-compiling DPDK.

## Building X-Change

You can compile/build X-Change via `usertools/dpdk-setup.sh`. We have tested X-Change with both `gcc` and `clang`.

**Please make sure that `CONFIG_RTE_LIBRTE_XCHG=y` and `CONFIG_RTE_LIBRTE_XCHG_MBUF=n` are set in `config/common_base`.**

To make the most out of X-Change, it is essential to use Link-Time Optimization (LTO). Using LTO allows the compiler to perform "whole program" optimizations during link time and inline the conversion functions introduced by X-Change, thereby achieving zero-overhead flexibility.



### LTO (gcc)

As the default DPDK's build system supports LTO for gcc, you only need to make sure that `CONFIG_RTE_ENABLE_LTO=y` is set in the `config/common_base`, and then build DPDK as before (e.g., via the following command).


```bash
make install T=x86_64-native-linux-gcc
```

### LTO (clang)

We have extended DPDK's build system to support LTO for clang. To compile DPDK/X-Change with LTO (clang), we have introduced a new toolchain (`clanglto`). You can either use `dpdk-setup.sh` or use the following command to compile with LTO (clang).

```bash
make install T=x86_64-native-linux-clanglto
```

 **Note: Please install the LLVM Toolchain and Clang (10.0). You can check PacketMill's [repo][packetmill-repo] for more information.**


## Using X-Change (xchg library)

As X-Change is only implemented in the MLX5 driver for now, one has to call `mlx5_rx_burst_xchg` instead of `rte_eth_rx_burst` (or `mlx5_rx_burst_stripped` that is the equivalent direct call using mlx5 we provided for a point-to-point comparison). If built with `-lrte_xchg_mbuf`, you can use `mlx5_rx_burst_xchg` as a drop-in replacement for `rte_eth_rx_burst` as it uses our default implementation of the xchg library (`lib/librte_xchg/rte_xchg_mbuf.c`) that behaves similar to the normal DPDK. While this will not bring any performance benefits, it ensures that the first step is working. The idea behind this implementation is to allow a full replacement of the normal DPDK mechanism by X-Change, with a default behavior similar to the standard one.

A simple example is proposed in `examples/l2fwd-xchg`. Instead of the traditional rte\_mbuf of the `l2fwd` app, that versions use an xchg buffer composed of only a pointer to the buffer data, and the length of the packet data, nothing else. Indeed, this application does not use vlan, timestamps, has a single pool, does not buffer packets, ... So we need only that. The `xchg.c` version is an example made to work with that new buffer. You'll probably want to copy-paste it and start from that. With a ConnectX-5 the l2fwd-xchg has the same throughput of MTU-size packets than l2fwd because l2dwd uses nearly no memory, and the NIC/PCIe is the bottleneck. However, it does so with 2.4X less impact on the L1 cache, which leaves much more space for the very precious L1 when doing real processing at 100G.

A more complete example can be found in the implemntation of [FastClick][fastclick-repo]. The re-implementation of the RX path can be found [here][fastclick-xchg].

Basically, the set of X-Change functions allow to tell the driver how to write some metadata in the user's metadata format.

```cpp
    //Set the VLAN anno
    void xchg_set_vlan(struct xchg* xchg, uint32_t vlan) {
        SET_VLAN_TCI_ANNO(get_buf(xchg),vlan);
    }
```

The `struct xchg` does not exist. It is only a wrapper to design the user metadata. In (Fast)Click it is the Packet object. The `SET_VLAN_TCI_ANNO` macro is a Click defined macro to set the VLAN TCI of a packet in the Packet metadata space.

The second roles of the xchg functions is to tell the driver how to "peek" and "advance" in the list of metadata buffers provided by the user.

```cpp
struct xchg* xchg_next(struct rte_mbuf** rep, struct xchg** xchgs, rte_mempool* mp);
void xchg_advance(struct xchg* xchg, struct xchg*** xchgs_p);
```

In Click, packets use linked list to represent batches. Therefore, `xchg_next` peeks the first element of the list while `xchg_advance` sets the new head to the next element of the list.

Finally, it is the time to write the new receive function.

```cpp
  //Allocate a batch of _burst (32 in general) packets. It's actually just verifying the pool has at least 32 packets, and returns the pointer of the first packet of the list (it's a linked list, so nothing else to do). We'll fix the pool after we know how much packets were received.
  WritablePacket* head = WritablePacket::pool_prepare_data_burst(_burst);

  //To be able to fix the pool, we want to keep the pointer to the last received packet, so we pass a pointer the head, but knowing "pointer-1" is the last packet.
  //This pointer-1 is fixed in xchg_advance().
  WritablePacket* tail[2] = {0,head};

  unsigned n = rte_mlx5_rx_burst_xchg(_dev->port_id, iqueue, (struct xchg**)&(tail[1]), _burst);

  if (n) { // If we received some packets
    WritablePacket::pool_consumed_data_burst(n,tail[1]); //Fix the pool
    add_count(n); //Just a software counter that tracks how many packets were processed here
    ret = 1; //Return value, Click-specifc
    PacketBatch* batch = PacketBatch::make_from_simple_list(head,tail[0],n); //Set a few things to the batch
    output_push_batch(0, batch); //Process the packet (call Click's next element)
  }
```

This function does not have any loop, as everything to be done "per-packet" is pushed in the driver with xchg functions. Moreover, LTO will eventually "inline" the xchg call to a very specific binary tailored for the application.

The transmit path is more or less the same, but instead of telling the driver how to *write* the metadata, it provides the way to *read* it.

## Getting Help

If you have any questions regarding our code or the paper, you can contact [Tom Barbette][tom-page] (barbette at kth.se) and/or [Alireza Farshin][alireza-page] (farshin at kth.se).


[dpdk-page]: https://www.dpdk.org/
[packetmill-paper]: https://people.kth.se/~farshin/documents/packetmill-asplos21.pdf
[packetmill-repo]: https://github.com/aliireza/packetmill 
[fastclick-repo]: https://github.com/tbarbette/fastclick
[tom-page]: https://www.kth.se/profile/barbette
[alireza-page]: https://www.kth.se/profile/farshin/ 
[fastclick-xchg]: https://github.com/tbarbette/fastclick/blob/43deb7c0984dbdf3d26684fac8f16c19957373a9/elements/userlevel/fromdpdkdevicexchg.cc#L248
[tinynf-link]: https://www.usenix.org/conference/osdi20/presentation/pirelli
[osdi-20-page]: https://www.usenix.org/conference/osdi20
