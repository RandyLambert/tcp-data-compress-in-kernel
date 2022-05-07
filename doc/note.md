### (一): 一些讨论

问: 如果要对数据压缩, 那牵扯到修改套接字中的数据,由于 linux 目前对 eBPF 修改数据的限制比较多, 也并不提倡 eBPF 函数对数据进行大量修改. 我想请教一下您在实现的时候使用了那种 BPF 函数 ? 而又是通过什么方式去修改数据的? 

答: 这里面其实不是所有的东西都能用BPF表达，譬如压缩解压算法的实现，这部分用ebpf来做是不太适合的。
所以使用BPF来做事情其实是要把机制和策略分离的。机制部分（譬如说报文的压缩解压）放到内核，策略部分放到EBPF（譬如说哪些流量需要压缩解压）来做。

机制部分再openEuler内核里面有：
https://gitee.com/openeuler/kernel/blob/e39e10f0deefd9cb8a7e3259e17383ac334df784/net/ipv4/tcp_comp.c
目前你看到的策略部分使用proc接口来控制的，只有端口一个维度。

设计上最终是通过如下方式来做：

服务器端同时支持走压缩和不走压缩两种方式，只要看tcp option里面是否带相应的参数。
客户端发送syn包的时候判断使用ebpf程序来判断是否需要做压缩，需要的话，通过ebpf程序通过TCP_COMP_TX等设置socket相应的标记，内核通过这个标记来决定要不要带特定的TCPOPT_EXP option. 连接建立以后就不需要ebpf程序暂时做什么事情了。

使用ebpf的作用是：很多情况下涉及对第三方应用程序，不使用EBPF的话就需要修改第三方代码。用EBPF来做就是为了不需要改第三方程序，直接把改设置的配置都设置好。

---

问: PDF 使用 TCP_COMP_TX 和 TCP_COMP_RX sockopt 在三次握手时进行协商,是否开启压缩功能, 但是在我查询了各个资料之后, 我发现自定义 tcp option 应该是需要修改内核代码(https://inl.info.ucl.ac.be/system/files/tcp-ebpf.pdf 这是我查到的相关论文), 因为公网路由器对 IP Option的检查较为严格，一般都会直接丢弃带有 IP Option 的报文(我尝试创建自定义 ip option 也没有成功), 所以我想问一下您用的是什么方式的来实现这个能力的?

答: TCP_COMP_TX TCP_COMP_RX这个还处于实验阶段，还没有上openEuler.
判断是否使用comp这个使用的是tcp options (TCPOPT_EXP), 不是用的IP option, 参见下面的代码
https://gitee.com/openeuler/kernel/blob/e39e10f0deefd9cb8a7e3259e17383ac334df784/net/ipv4/tcp_output.c#L436
用IP option的话应该会出现你说的问题。

---

问: 因为 bpf 程序只能使用部分 linux 内核的函数, 而且不允许使用静态库, 那做压缩时使用的类似与 zstd 的压缩算法代码量比较大, 完全编译到 ebpf 程序里二进制文件会很大, 我想问一下您是怎么做 zstd 库的拆分的呢? 而又是如何可以支持多种压缩算法的呢?

答: 策略部分用EBPF, 机制上合入内核代码。这个可以参照内核已有的KTLS这个功能。

---

问: 如果要进行数据压缩, 应该也需要申请一块内存空间存储压缩的数据, 这里如果不使用内存池等一些相关算法的话, 每次进行压缩时都要进行内存申请, 这部分开销应该也会挺大的, 我想问一下您是怎么解决的?

答: 对的，所以会看应用场景。压缩是为了省带宽，以及较少网络丢包对实际传输时长的影响，是使用CPU能力来换带宽。

CPU       带宽    可用性

=============================
空闲       紧张    可以使用
紧张       空闲    不适用

紧张       紧张    具体看收益

空闲       空闲    看网络状况，以及是否关系传输时间


社区的看到的还是不带EBPF的代码，如果你感兴趣的话，可以继续在openEuler区完成EBPF支持部分, 甚至可以把你的代码合入到openEuler里面。

魏勇军
Best Regards.

---

### (二): 如何参与开发

开发可以直接基于 https://gitee.com/openeuler/kernel/commits/OLK-5.10 这个分支下代码修改。

压缩的基础框架在openEuler的5.10代码上应该是如下几笔提交：
https://gitee.com/openeuler/kernel/commit/8ba366367f7c7e4a92e833030edb4aef9e01f51c tcp_comp: add Kconfig for tcp payload compression, 将压缩选项加入内核(KCONFIG)编译

https://gitee.com/openeuler/kernel/commit/7f39947b845d87a4e56064e7e9fff6b9cb3ec12e 
tcp_comp: add tcp comp option to SYN and SYN-ACK 需要注意在 tcp_options_received 选项中添加 comp_ok 选项还需要注意 extern struct static_key_false tcp_have_comp; 在那里定义的,comp_set_option 是第二次握手的接收方设置 tcp_out_options , comp_set_option_cond 第三次握手的接收方设置 tcp_out_options , tcp_parse_comp_option 接收是 parse 压缩选项 tcp_options_received , comp_options_write 将先前计算的TCP选项写入数据包。th = (struct tcphdr *)skb->data; 写到 skb->data字段, 通过这个函数 tcp_syn_comp_enabled 来判断是否需要开启 comp, TCP_COMP_TX 暂时还没有, 在这里直接判断是否开启压缩功能, 如果开启了就直接在此 TCP 连接上打开, 注意:这个过程由tcp_options_write()完成，该函数由tcp_transmit_skb()调用。

https://gitee.com/openeuler/kernel/commit/cc36784b15f82f87559f9e43a0f7951c7b188ac9 tcp_comp: add init and cleanup hook for compression 给压缩功能增加 init 和 cleanup 回调, 不过这个 pr 没有实现此功能, 函数是空的

https://gitee.com/openeuler/kernel/commit/dae7bed961c55d9837eada7f98f34f1adb0e9d21 
Add sysctl interface for enable/disable tcp compression by ports. 添加 sysctl 接口以通过端口启用/禁用 tcp 压缩。利用 ctl_table ipv4_table 在 /proc/sys/net/ipv4/ 下面写配置, 写支持的端口号到 sysctl_tcp_compression_ports 位图里

https://gitee.com/openeuler/kernel/commit/d8a6de61e51f6433c7f0f8ab81b20dc43161a8a5 tcp_comp: only enable compression for give server ports 只对给定的服务器端口启用压缩, 这里实现了上面没有实现的 tcp_init_compression , 注意 tcp_syn_comp_enabled 的 active 参数是判断入流量还是出流量, test_bit 去判断是否在 sysctl_tcp_compression_ports 位图

https://gitee.com/openeuler/kernel/commit/f14b0352016320538674a0b7f877d5fdd02d4343 
tcp_comp: allow ignore local tcp connections TCP comp:允许忽略本地TCP连接, 通过 tcp_comp_enabled 函数, 先过滤掉本地的套接字请求

https://gitee.com/openeuler/kernel/commit/a801cd2a9d5e730b6254fe41ef6cc6eff499dcc7 
tcp_comp: add stub proto ops for tcp compression socket
 TCP comp:为TCP压缩套接字添加stub proto ops ,利用 tcp_comp_context 暴露 tcp socket 里的 struct proto *sk_proto 和 struct rcu_head rcu, 利用 proto(tcp_prot)在 tcp_init(tcp_comp_init) 在初始化的时候, hook sendmsg 和 recvmsg ,但是这个 patch 还没有实现此功能,暂时还是用的老的 sendmsg 和 recvmsg, tcp_init_compression 和 tcp_comp_context_free, 注意 rcu_assign_pointer 和 container_of 的使用

https://gitee.com/openeuler/kernel/commit/e9ce37bbceb2779c0015fcac54cc8df7a2ec8b76 
tcp_comp: implement sendmsg for tcp compression TCP_COMP：为TCP压缩实现SENDMSG, 需要 kconfig 支持, 单次最大压缩 65464 字节, tcp_comp_context 中加入了 tcp_comp_context_tx 结构体, tcp_comp_tx_context_init 的时候也需要初始化 ZSTD 库, 初始化时, 会申请 65464 字节的数据, 之后将数据在释放, 注意 comp_get_ctx(const struct sock *sk) 可以从 sock 中拿到 tcp_comp_context, 注意 inet_csk 这个函数,他把 sock 转化为 inet_connection_sock, 在这之后利用 rcu_assign_pointer(icsk->icsk_ulp_data, ctx) 将(用户) ctx 指针写入 icsk_ulp_data; 除此之外, 用 memcopy_from_iter 函数将 iov_iter copy 到 plaintext_data 缓冲区中进行压缩

https://gitee.com/openeuler/kernel/commit/fbcb4859d8808295a5174e30250cd608ed970070 
tcp_comp: implement recvmsg for tcp compression TCP_COMP：为TCP压缩实现RecVMSG , 同上, 增加 kConfig, 增加解压的 tcp_comp_context_rx 结构体 , recvmsg 的压缩时, 从 ->data 里面读字段, 循环解压数据, 解压存放数据的地方放在 plaintext_data 之后在进行 copy

https://gitee.com/openeuler/kernel/commit/cd84ca9ffd4e490a4893a4039a2173d9a7019f73
tcp_comp: Avoiding the null pointer problem of ctx in comp_stream_read  tcp comp:避免了comp流中ctx的空指针问题 这个pr和这个pr之后的pr都是一些小小补, 只看 tcp_comm 的代码就行了

https://gitee.com/openeuler/kernel/commit/ab0323bb5b0c33cf5d3a6c4fb4def99646b539bb 
tcp_comp: Fix comp_read_size return value 修复comp_read_size返回值

https://gitee.com/openeuler/kernel/commit/d876fdbb275e8fe0849b9fb4739969c8d27a2002 
tcp_comp: Fix ZSTD_decompressStream failed 修复zstd_decpressstream失败

https://gitee.com/openeuler/kernel/commit/c5f3ee6952248b9bd4aa8c1471ff6813c4836b20 
tcp_comp: Add dpkt to save decompressed skb TCP_COMP：添加DPKT以保存解压缩SKB, 为了分离压缩数据和解压缩数据，这个 patch 在tcp comp context rx中添加了dpkt, dpkt用于保存解压缩后的skb。

https://gitee.com/openeuler/kernel/commit/c31c696f93008c61463320227600dce68879f49a 
tcp_comp: Del compressed_data and remaining_data from tcp_comp_context_rx tcp comp:删除tcp comp上下文rx中的压缩数据和剩余数据, 压缩后的数据与解压缩后的数据分离。不需要将未压缩的数据保存到剩余的数据缓冲区，可以直接从未压缩的skb读取数据。


### (三):注

__read_mostly: 我们可以将经常需要被读取的数据定义为 __read_mostly类型，这样Linux内核被加载时，该数据将自动被存放到Cache中，以提高整个系统的执行效率。
linux test_bit: https://www.cnblogs.com/zxc2man/p/14653138.html, int test_bit(nr, void *addr) 原子的返回addr位所指对象nr位
一些开发的指导：
https://gitee.com/openeuler/kernel/wikis/Contributions%20to%20openEuler%20kernel%20project

tcp_out_options 核心 struct
tcp_options_write 核心设置 tcp_options 函数
const struct sock *sk 核心设置

net/socket.c#L2905 SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args) 处调用__sys_setsockopt
||
||
net/socket.c#L2180  __sys_setsockopt 函数这里面会调用 tcp_prot.setsockopt
||
||
net/ipv4/tcp_ipv4.c#L3063 struct proto tcp_prot 结构体里面的 setsockopt 函数存放 tcp_setsockopt 指针
||
||
net/ipv4/tcp.c#L3690 tcp_setsockopt()
||
||
net/ipv4/tcp.c#L3387 do_tcp_setsockopt()

想办法修改 tcp_out_options 选项, 增加 tcp_comp_tx 和 tcp_comp_rx, 和 OPTION_COMP 相辅相成, 在 tcp_established_options 中写 socket opt
tcp_parse_aligned_timestamp

在网络网络传输过程中，最关心的就是传输效率问题。而提高传输效率最有效的方法就是对传输的数据进行压缩。但压缩数据也要耗费一定的时间，是不是压缩后一定能提高效率呢？

1.数据传输时间
假设数据大小为 D (MB)
网络带宽为 N (MBps)  -------------注意这里是MBps，而不是通常说的Mbps,      1MBps = 10Mbps,       1000Mbps=100MBps.
那么数据传输时间T1 = D/N

2.压缩后的数据传输时间

假设压缩算法压缩率为 R ------------------ 即压缩后数据大小为 D*R

压缩速度为         Vc MB/S
解压缩速度为       Vd MB/S
那么压缩后的数据传输时间 T2 =  D/Vc + D*R/N + D/Vd  = D/N * ( R + N/Vc + N/Vd)

3.分析
对比：
        T1 = D/N
        T2 = D/N*(R+N/Vc+N/vd)
发现：
        如果R + N/Vc + N/Vd < 1,则压缩后传输要更快，否则压缩后传输反而更慢。
        也就是压缩后传输能否更快是和压缩算法的 “压缩率”，“压缩/解压缩速度” 以及当前“带宽”相关
        压缩率越小，压缩/解压缩越快，带宽越小，压缩后传输越能提高效率。而在带宽不变得情况下，压缩率越小，压缩/解压缩越快 越好。
       而由于压缩率和压缩/解压缩速度成指数型反比（压缩率提高一点点，压缩/解压缩速度就大幅降低），所以在选用压缩算法时：
        最好选择压缩/解压缩速度快的算法，而不必太关注压缩率（当然也不能完全不压缩）

4.常用压缩算法对比
    这是来自网上一个常用压缩算法压缩比，压缩/解压缩速度对比图：

    压缩率R为 1/Ratio。
    ZSTD v1.3.4 在压缩等级为 1 的 Ratio 为 2.877, Vc 为 470, Vd 为 1380
    那么带入到上面公式：
    ZSTD v1.3.4 ：1/2.877 + N/470 + N/1380 = 0.35 + N*0.00285   也就是说在带宽 N < 228 MBps的情况下，采用 ZSTD v1.3.4 压缩能提高传输效率。

5.总结
  一般客户端访问服务器，需进行压缩。 （目前客户端到服务器的带宽还是比较低的）
  服务器间传输，可以不压缩，或者用 ZSTD 压缩。 （服务器间的带宽一般是1000bps，即100MBps）

  大于 228 MBps     普通传输就可以，因为网络传输速度远远高于压缩及解压缩速度了


前辈您好, 感谢您一直解答我的问题, 我已经在虚拟机上安装了openeuler 的内核, 跑了一下压缩的功能, 很强大!

剩下的时间, 我用 libbpf 先简单的写了一下 eBPF 探测流量的功能, 我写了一个 tc 程序, 功能是在 ingress 和 egress 将个 socket 发送/接受 的数据大小写到一个 eBPF map 中, 然后用户态定时去读取这个 map 中的数据, 来看这段时间 发送/接受 数据的量, 以此实现 tcp 流级别的流量检查, 我这里有几个问题想请教一下您:
1. BPF 在这里检测的时候也是会有一定的性能消耗的, 这样的性能消耗是否值得?或者说我这样统计流量速率是否合理?
2. 我认为系统在高 CPU 负载和高内存负载时也不应该去打开压缩算法, 所以我还简单写了一些探测 CPU 和 内存使用的统计, 不过是从 /proc/ 目录下直接拿的. 据我了解, socket 中的内存分配会使用 socket 所在 numa node 的内存资源, 所以我想问这部分有必要去拿一些更细粒度的信息吗? 比如各个 numa node 的内存分配情况, 或者是内存碎片率之类的. (不过我认为这个问题的优先级不高, 目前不太需要考虑这些)

后面的时间, 为了让 eBPF 和内核的压缩模块进行结合, 据我目前的了解和查询了一些资料, 我发现 BPF 程序单独做不了像流量分析这种功能, 它只负责统计数据放到 map 中, 用户态拿数据进行分析, 得出结论, 因此如果需要和对端进行协商是否要打开压缩功能, 需要利用 setsockopt() 选项做, 因此我就开始写设置套接字选项的功能, 不过目前还没有测试。
我目前先写的是 comp_tx 的功能, 不过我认为现在的实现还有很多问题和缺陷
实现流程如下:
我先在 tcp_sock 结构体上新增了 comp_tx 字段 ,这个字段是通过 setsockopt() 函数进行修改的, 实现方法是在 do_tcp_setsockopt() 处增加了解析 TCP_COMP sockopt 选项的代码, 这里直接将 comp_tx 字段写为 true,下一步我修改了 tcp_options_write 函数, 新增的写 comp_tx 选项到数据包的代码.
在接收端我在 tcp_options_received 结构体中也新加了 comp_tx 选项, 同时修改了 tcp_parse_options 函数, 在此函数中解析了新增的 comp_tx 选项, 将解析写到 tcp_options_received 结构体之中.
在后续进行 tcp_comp_sendmsg 时, 首先会判断 tcp_sock 中 comp_tx 是否打开, 如果打开了则继续往下走, 如果没有打开, 则执行之前的 sendmsg 函数, 同理, 在进行 tcp_comp_recvmsg 时, 会先判断 tcp_options_received 中 comp_tx 选项是否打开, 如果打开则继续往下走, 如果没有则执行之前的 sendmsg 函数.

目前这样的实现方案有很多问题
1. tcp_parse_options 函数并不会在每次接收包的时候调用, 我这里贴一下源码注释:
     /* Look for tcp options. Normally only called on SYN and SYNACK packets.
      * But, this can also be called on packets in the established flow when
      * the fast version below fails.
      */
    因此,在走快速路径的时候不会调用 tcp_parse_options 去解析 comp_tx 选项, 然后我找了下相关论文(https://inl.info.ucl.ac.be/system/files/tcp-ebpf.pdf 这篇论文是给 bpf_setsockopt 使用的), 发现这里面也是修改的 tcp_parse_options 函数的

2. 按照目前的实现 comp_tx 选项会在每次发包的时候进行携带, 实际上只需要在我首次执行 setsockopt() 时写入此套接字选项, 和对方进行协商就可以了, 但是目前如何写成这样, 我只会在每次发数据包时从 tcp_sock 中去找 comp_tx 选项,然后写入 tcp 头发过去.
3. 因为我是每次发数据包的会在包头携带参数表明当前是否打开了压缩, 这导致了实际上两方没有进行一个协商, 如果接受端目前性能已经达到瓶颈, 不适合打开压缩功能, 那这里有可能会造成负优化, 问题2和问题3的关键都在于如何写新增的 sockopt 和如何发送新增的 sockopt.
4. 问题3里面提到了正确的做法应该是和接受端进行协商, 是否要打开压缩功能, 但是上面我提到了 eBPF 只能做到数据提取, 数据分析是在用户态做的, 因此内核态没有用户态分析出的是否需要打开压缩功能的结论, 所以如果需要实现协商功能, 还需要在新增一个 sockopt 来去做这个工作, 给内核传递当前情况下是否时候使用 压缩/解压 功能.
5. 目前只在 setsockopt() 的路径上做了修改, 还没有更改 getsockopt(), 所以用户态暂时没办法探测某个套接字是否打开了压缩功能.

这是目前我认为比较棘手的一些问题, 我想听听您的想法
