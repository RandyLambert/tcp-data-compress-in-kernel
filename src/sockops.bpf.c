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
	switch (op) {
        //* client side
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
            break;
        //* client side
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
            bpf_printk("client: active established\n");
            /* Client will send option */
            //* BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG enables writing tcp options
            //* bpf_sock_ops_cb_flags_set用来调用修改flag的bpf程序——BPF_SOCK_OPS_HDR_OPT_LEN_CB/BPF_SOCK_OPS_WRITE_HDR_OPT_CB
            //* send new option from client side
            
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            
            break;
        }
        // * server side
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:{

            bpf_printk("server: passive established\n");
            /* Server will send option */
            //* BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG enables writing tcp options
            //* bpf_sock_ops_cb_flags_set用来调用修改flag的bpf程序——BPF_SOCK_OPS_HDR_OPT_LEN_CB/BPF_SOCK_OPS_WRITE_HDR_OPT_CB
            //* send new option from server side
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG);
            break;
            // bpf_printk("rv := %d",rv);
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
            struct tcp_option opt = {
                .kind = TCPOPT_TOA,
                .len  = 8,	// of this option struct
                .port = __bpf_htons(skops->local_port),
                .addr = __bpf_htonl(0x93d4860a),
            };
            /* Server sends option */
            // * write the option
            int ret = bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);
            bpf_printk("BPF_SOCK_OPS_WRITE_HDR_OPT_CB bpf_store_hdr_opt ret: %d\n",ret);

			// cancel the settings
            // bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            break;
        }

        case BPF_SOCK_OPS_PARSE_HDR_OPT_CB: {
            struct tcp_option opt = {
                .kind = TCPOPT_TOA,
                .len  = 0,
            };
            int ret = bpf_load_hdr_opt(skops, &opt, sizeof(opt), 0);
            // bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags & ~BPF_SOCK_OPS_PARSE_HDR_OPT_CB);
            
            bpf_printk("BPF_SOCK_OPS_PARSE_HDR_OPT_CB: opt.port=%d, ret=%d\n", __bpf_ntohs(opt.port), ret);

        }
         
        default:
            rv = -1;
        }
	skops->reply = rv;
	return 1;
}
// * 必要的许可信息
char _license[] SEC("license") = "GPL";