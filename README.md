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

## Advantage over other approaches

* Pirelli et al. [OSDI'20] accelerates DPDK model by removing the need for dynamic packet metadata. But that also prevents buffering of packets, such as switching packets betweeb cores, reordering packets, stream processing, even DPI would need packet copy, hence it comes with a lot of drawbacks. X-Change reduces the number of metadata buffers too, but without such restrictions. X-Change is also more generic, as it brings programmability inside the driver, one can implement the propose exchange of buffers, or the model proposed by Pirelli et al. without even re-compiling DPDK.


## Building X-Change

You can compile/build X-Change via `usertools/dpdk-setup.sh`. We have tested X-Change with both `gcc` and `clang`.

**Please make sure that `CONFIG_RTE_LIBRTE_XCHG=y` and `CONFIG_RTE_LIBRTE_XCHG_MBUF=y` are set in `config/common_base`.**

To make the most out of X-Change, it is essential to use Link-Time Optimization (LTO). Using LTO allows the compiler to perform 'whole program' optimizations during link time and inline the conversion functions introduced by X-Change, achieving zero-overhead flexibility.



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


```bash
make install T=x86_64-native-linux-clanglto
```


## Using X-Change

As X-Change is only implemented in the mlx5 driver for now, one has to call mlx5_rx_burst_xchg instead of rte_eth_rx_burst (or mlx5_rx_burst_stripped which is the equivalent direct call using mlx5 we provided for a point-to-point comparison). If built with `-lrte_xchg_mbuf`, you can use mlx5_rx_burst_xchg as a drop-in replacement for rte_eth_rx_burst as it will use our own xchg library (`lib/librte_xchg/rte_xchg_mbuf.c`) that behaves likes the normal DPDK. Of course that will not bring any performance benefit, but ensure step 1 is working. The idea is also to allow a full replacement of the normal DPDK mechanism by X-Change, with a default behavior similar to the standard one.

To take advantage of X-Change, you have to give an implementation to all functions in `lib/librte_xchf/rte_xchg.h` in your own application. One way to start is by re-implementing the functions in `lib/librte_xchg/rte_xchg_mbuf.c` which is the implementation that leads to the standard DPDK behavior as explained above. However, you must **not** pass `-lrte_xchg_mbuf` as this would provide two implementations for the xchg API.

An example can be found in the implemntation of [FastClick][fastclick-repo]. The re-implementation of the RX path can be found [here][fastclick-xchg].

Basically the set of X-Change functions allow to tell the driver how to write some metadata in the user's metadata format.
```c++
    //Set the VLAN anno
    void xchg_set_vlan(struct xchg* xchg, uint32_t vlan) {
        SET_VLAN_TCI_ANNO(get_buf(xchg),vlan);
    }
```
The `struct xchg` does not exists. It's a wrapper to design the user metadata. In (Fast)Click it's the Packet object. This SET_VLAN_TCI_ANNO macro is a Click defined macro to set the VLAN TCI of a packet in the Packet metadata space.

The second roles of the xchg functions is to tell the driver how to "peek" and "advance" in the list of metadata buffers provided by the user.
```c++
struct xchg* xchg_next(struct rte_mbuf** rep, struct xchg** xchgs, rte_mempool* mp);
void xchg_advance(struct xchg* xchg, struct xchg*** xchgs_p);
```
In Click, packets use linked list to represent batches. xchg_next will peek the first element of the list, and xchg_advance will set the new head to the next element of the list.

Finally, it's time to write the new receive function.
```c++
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
One will notice this function has no loop. Indeed everything to be done "per-packet" is pushed in the driver with xchg functions. Moreover, LTO will actually "inline" the xchg call to a very specific binary tailored to the application.

The transmit path is more or less the same, just that instead of telling the driver how to *write* metadata, one needs to tell how to *read* metadata.

## Getting Help

If you have any questions regarding our code or the paper, you can contact [Tom Barbette][tom-page] (barbette at kth.se) and/or [Alireza Farshin][alireza-page] (farshin at kth.se).


[dpdk-page]: https://www.dpdk.org/
[packetmill-paper]: https://people.kth.se/~farshin/documents/packetmill-asplos21.pdf
[packetmill-repo]: https://github.com/aliireza/packetmill 
[fastclick-repo]: https://github.com/tbarbette/fastclick
[tom-page]: https://www.kth.se/profile/barbette
[alireza-page]: https://www.kth.se/profile/farshin/ 
[fastclick-xchg]: https://github.com/tbarbette/fastclick/blob/43deb7c0984dbdf3d26684fac8f16c19957373a9/elements/userlevel/fromdpdkdevicexchg.cc#L248
