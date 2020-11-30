# X-Change

X-Change model is an optimization to Data Plane Development Kit ([DPDK][dpdk-page]) that provides custom buffers to drivers; thus, metadata can be directly written into the applications' buffers rather than using an intermediate DPDK buffer. X-Change uses conversion functions instead of direct assignment to set the metadata fields. The X-Change API (i.e., the different conversion functions) is dependent on the driver's features, as some NICs provide more metadata. For more information, please refer to PacketMill's [paper][packetmill-paper] and [main repository][packetmill-repo]. 

**Note: Currently, X-Change only supports the MLX5 driver used by Mellanox NICs. However, X-Change is applicable to other drivers, as other (e.g., Intel) drivers are implemented similarly and have the same inefficiencies.**


## Why X-Change?

X-Change provides an efficient metadata management for packet processing. More specifically, it addresses the three main problems associated with current DPDK-based metadata management models:

1. DPDK uses a distinct metadata buffer for every packet, but these extra metadata buffers reduce cache locality. In contrast, we only need a limited number of metadata buffers, as packet processing frameworks use batching.

2. DPDK uses a generic buffer for metadata management. Consequently, different applications have to copy and/or transform the metadata fields in order to process packets.

3. All applications use one standard data structure for all kinds of packet processing. However, different network functions require different fields, resulting in carrying unused information during processing; again, reducing cache locality.

X-Change results in the following improvements:

* Enables applications to use their tailored metadata and to bypass the generic `rte_mbuf`, thus avoiding unnecessary copy/transform operations and cache evictions;

* Pushes down part of the application's RX/TX loops to initialize packet annotations into the Poll Mode Driver (PMD), thereby simplifying the application's processing path;

* Limits the amount of metadata used to the application's requirement (i.e., proportional to the RX burst size + the number of packets enqueued in software), keeping metadata cache lines warmer;

* Skips buffer allocation/release operations through DPDK buffer pools, which is inefficient due to supporting/maintaining many (unnecessary) features; and

* Makes it possible for the application to easily use different packet chaining models (e.g., vector, linked list, or a combination of both) to better fit their needs.


## Building X-Change

You can compile/build X-Change via `usertools/dpdk-setup.sh`. We have tested X-Change with both `gcc` and `clang`.

**Please make sure that `CONFIG_RTE_LIBRTE_XCHG=y` and `CONFIG_RTE_LIBRTE_XCHG_MBUF=y` are set in `config/common_base`.**

To make the most out of X-Change, it is important to enable Link-Time Optimization (LTO) to make the most out of X-Change. Using LTO enables the compiler to perform 'whole program' optimizations during link time and inline the coversion functions introduced by X-Change, achieving flexibility with zero overhead.



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

To use X-Change with any DPDK-based application, you have to export `RTE_SDK` & `RTE_TARGET` and use `-lrte_xchang_mbuf` flag during compilation. We have only tested X-Change with [FastClick][fastclick-repo]. For more information, please refer to PacketMill's [repo][packetmill-repo].


## Getting Help

If you have any questions regarding our code or the paper, you can contact [Tom Barbette][tom-page] (barbette at kth.se) and/or [Alireza Farshin][alireza-page] (farshin at kth.se).


[dpdk-page]: https://www.dpdk.org/
[packetmill-paper]: https://people.kth.se/~farshin/documents/packetmill-asplos21.pdf
[packetmill-repo]: https://github.com/aliireza/packetmill 
[fastclick-repo]: https://github.com/tbarbette/fastclick
[tom-page]: https://www.kth.se/profile/barbette
[alireza-page]: https://www.kth.se/profile/farshin/ 
