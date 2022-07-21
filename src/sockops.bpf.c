// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// * 程序版本信息
int _version SEC("version") = 1;

// reserved option number
 #define TCPOPT_TOA 77
 #define TCPOPT_EXP	254


int port;

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 port;
    __u32 addr;
} __attribute__((packed));


SEC("sockops")
int bpf_tcpoptionstoa(struct bpf_sock_ops *skops)
{

    if(port != bpf_ntohl(skops->remote_port) && port != skops->local_port) {
        return 0;
    }

    //return value for bpf program
	int rv = -1;
	int op = (int) skops->op;
    //update_event_map(op);

    // server side
	switch (op) {
        case BPF_SOCK_OPS_TCP_LISTEN_CB: {
            bpf_printk("server: tcp listen initxx\n");
            bpf_sock_ops_cb_flags_set(skops,  skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);

            break;
        }

        //* client side
        case BPF_SOCK_OPS_TCP_CONNECT_CB: {
            bpf_printk("client: tcp connect init\n");
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);

            break;
        }
        //* client side
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
            bpf_printk("client: active established\n");

            break;
        }
        // * server side
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
            bpf_printk("server: passive established\n");
            break;
        }
        case BPF_SOCK_OPS_STATE_CB: {
                bpf_printk("state: %d-->%d\n",skops->args[0], skops->args[1]);
            if(skops->args[0] == BPF_TCP_SYN_RECV && skops->args[1] == BPF_TCP_ESTABLISHED) {
                // 解析1: 直接在 BPF_SOCK_OPS_STATE_CB 回调中进行解析, 没有接收到头文件的消息
                bpf_printk("server: BPF_TCP_LISTEN-->BPF_TCP_SYN_RECV\n");
                struct tcp_option opt = {
                    .kind = TCPOPT_TOA,
                    .len  = 0,
                };
                int ret = bpf_load_hdr_opt(skops, &opt, sizeof(opt), 0);
                bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);            
                bpf_printk("BPF_SOCK_OPS_PARSE_HDR_OPT_CB bpf_load_hdr_opt opt.port=%d, skops->local_port=%d, ret=%d\n", __bpf_ntohs(opt.port), skops->local_port,  ret);
                // bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
            }
            if(skops->args[1] == BPF_TCP_SYN_SENT) {
                bpf_printk("client: BPF_TCP_CLOSE-->BPF_TCP_SYN_SENT\n");
                // bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            }
        }
        case BPF_SOCK_OPS_HDR_OPT_LEN_CB: {
            
            //reserved space
            int option_len = sizeof(struct tcp_option);
            /* args[1] is the second argument */
            if (skops->args[1] + option_len <= 40) {
                rv = option_len;
            }
            else {
                rv = 0;
            }
            /* 保留空间已经验证成功 */
            // bpf_printk("option len is %d",rv);
		    bpf_reserve_hdr_opt(skops, rv, 0);
            break;
        }

        case BPF_SOCK_OPS_WRITE_HDR_OPT_CB: {
            // 模拟 server 发包, 通过 port 判断
            struct tcp_option opt;
            if (skops->local_port == port) {
                opt.kind = TCPOPT_TOA;
                opt.len  = 8;	// of this option struct
                opt.port = __bpf_htons(1111);
                opt.addr = __bpf_htonl(0x93d4860a);
            } else { // 模拟 client 发包
                bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
                opt.kind = TCPOPT_TOA;
                opt.len  = 8;	// of this option struct
                opt.port = __bpf_htons(2222);
                opt.addr = __bpf_htonl(0x93d4860a);
            }

            /* Server sends option */
            // * write the option
            int ret = bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);
            bpf_printk("BPF_SOCK_OPS_WRITE_HDR_OPT_CB bpf_store_hdr_opt opt.port=%d, skops->local_port=%d, ret=%d\n", __bpf_ntohs(opt.port), skops->local_port, ret);

			// cancel the settings
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            break;
        }

        case BPF_SOCK_OPS_PARSE_HDR_OPT_CB: {
            // 解析点2: server 同时注册了 BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG 回调进行解析, 同样没有解析到数据
            struct tcp_option opt = {
                .kind = TCPOPT_TOA,
                .len  = 0,
            };
            int ret = bpf_load_hdr_opt(skops, &opt, sizeof(opt), 0);            
            // if(skops->local_port != __bpf_ntohs(opt.port)) {
                bpf_printk("BPF_SOCK_OPS_PARSE_HDR_OPT_CB bpf_load_hdr_opt opt.port=%d, skops->local_port=%d, ret=%d\n", __bpf_ntohs(opt.port), skops->local_port,  ret);
            // }
			
            // cancel the settings
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
            if (skops->local_port == port) {
                bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            }
            break;
        }
        default:
            rv = -1;
        }
	skops->reply = rv;
	return 1;
}
// * 必要的许可信息
char _license[] SEC("license") = "GPL";