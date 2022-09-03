// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#define BPF_PROG_TEST_TCP_HDR_OPTIONS
#include "test_tcp_hdr_options.h"

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif

__u8 test_kind = TCPOPT_EXP;
__u16 test_magic = 0xeB9F;
__u32 inherit_cb_flags = 0;
int port;

// * 程序版本信息
int _version SEC("version") = 1;

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct hdr_stg);
} hdr_stg_map SEC(".maps");

// reserved option number
#define TCPOPT_TOA 77
#define TCPOPT_EXP	254
#define TEST_OPTION_FLAGS(flags, option) (1 & ((flags) >> (option)))
#define SET_OPTION_FLAGS(flags, option)	((flags) |= (1 << (option)))

// ---------------------------------------------------------------- parser
static int parse_test_option(struct bpf_test_option *opt, const __u8 *start)
{
	opt->flags = *start++;

	if (TEST_OPTION_FLAGS(opt->flags, OPTION_MAX_DELACK_MS))
		opt->max_delack_ms = *start++;

	if (TEST_OPTION_FLAGS(opt->flags, OPTION_RAND))
		opt->rand = *start++;

	return 0;
}

static int load_option(struct bpf_sock_ops *skops,
		       struct bpf_test_option *test_opt, bool from_syn)
{
	union {
		struct tcp_exprm_opt exprm;
		struct tcp_opt regular;
	} search_opt;
	int ret, load_flags = from_syn ? BPF_LOAD_HDR_OPT_TCP_SYN : 0;

	if (test_kind == TCPOPT_EXP) {
		search_opt.exprm.kind = TCPOPT_EXP;
		search_opt.exprm.len = 4;
		search_opt.exprm.magic = __bpf_htons(test_magic);
		search_opt.exprm.data32 = 0;
		ret = bpf_load_hdr_opt(skops, &search_opt.exprm,
				       sizeof(search_opt.exprm), load_flags);
		if (ret < 0)
			return ret;
		return parse_test_option(test_opt, search_opt.exprm.data);
	} else {
		search_opt.regular.kind = test_kind;
		search_opt.regular.len = 0;
		search_opt.regular.data32 = 0;
		ret = bpf_load_hdr_opt(skops, &search_opt.regular,
				       sizeof(search_opt.regular), load_flags);
		if (ret < 0)
			return ret;
		return parse_test_option(test_opt, search_opt.regular.data);
	}
}

static int handle_parse_hdr(struct bpf_sock_ops *skops)
{
	struct hdr_stg *hdr_stg;
	struct tcphdr *th;

	if (!skops->sk)
		RET_CG_ERR(0);

	th = skops->skb_data;
	if (th + 1 > skops->skb_data_end)
		RET_CG_ERR(0);

	hdr_stg = bpf_sk_storage_get(&hdr_stg_map, skops->sk, NULL, 0);
	if (!hdr_stg)
		RET_CG_ERR(0);

	if (hdr_stg->resend_syn || hdr_stg->fastopen)
		/* The PARSE_ALL_HDR cb flag was turned on
		 * to ensure that the previously written
		 * options have reached the peer.
		 * Those previously written option includes:
		 *     - Active side: resend_syn in ACK during syncookie
		 *      or
		 *     - Passive side: SYNACK during fastopen
		 *
		 * A valid packet has been received here after
		 * the 3WHS, so the PARSE_ALL_HDR cb flag
		 * can be cleared now.
		 */
		clear_parse_all_hdr_cb_flags(skops);

	if (hdr_stg->resend_syn)
		/* Active side resent the syn option in ACK
		 * because the server was in syncookie mode.
		 * A valid packet has been received, so
		 * clear header cb flags if there is no
		 * more option to send.
		 */
		clear_hdr_cb_flags(skops);

	if (hdr_stg->fastopen)
		/* Passive side was in fastopen.
		 * A valid packet has been received, so
		 * the SYNACK has reached the peer.
		 * Clear header cb flags if there is no more
		 * option to send.
		 */
		clear_hdr_cb_flags(skops);

	if (th->fin) {
		struct bpf_test_option *fin_opt;
		int err;
        struct bpf_test_option active_fin_in	= {};
        struct bpf_test_option passive_fin_in	= {};

		if (hdr_stg->active)
			fin_opt = &active_fin_in;
		else
			fin_opt = &passive_fin_in;

		err = load_option(skops, fin_opt, false);
		if (err && err != -ENOMSG)
			RET_CG_ERR(err);
	}

	return CG_OK;
}
// ---------------------------------------------------------------- parser

static int handle_hdr_opt_len(struct bpf_sock_ops *skops)
{
	__u8 tcp_flags = skops_tcp_flags(skops);

	if ((tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK)
		return synack_opt_len(skops);

	if (tcp_flags & TCPHDR_SYN)
		return syn_opt_len(skops);

	if (tcp_flags & TCPHDR_FIN)
		return fin_opt_len(skops);

	if (skops_current_mss(skops))
		/* The kernel is calculating the MSS */
		return current_mss_opt_len(skops);

	if (skops->skb_len)
		return data_opt_len(skops);

	return nodata_opt_len(skops);
}

static int synack_opt_len(struct bpf_sock_ops *skops)
{
	struct bpf_test_option test_opt = {};
	__u8 optlen;
	int err;

	if (!passive_synack_out.flags)
		return CG_OK;

	err = load_option(skops, &test_opt, true);

	/* bpf_test_option is not found */
	if (err == -ENOMSG)
		return CG_OK;

	if (err)
		RET_CG_ERR(err);

	optlen = option_total_len(passive_synack_out.flags);
	if (optlen) {
		err = bpf_reserve_hdr_opt(skops, optlen, 0);
		if (err)
			RET_CG_ERR(err);
	}

	return CG_OK;
}


static int synack_opt_len(struct bpf_sock_ops *skops)
{
	struct bpf_test_option test_opt = {};
	__u8 optlen;
	int err;

	if (!passive_synack_out.flags)
		return CG_OK;

	err = load_option(skops, &test_opt, true);

	/* bpf_test_option is not found */
	if (err == -ENOMSG)
		return CG_OK;

	if (err)
		RET_CG_ERR(err);

	optlen = option_total_len(passive_synack_out.flags);
	if (optlen) {
		err = bpf_reserve_hdr_opt(skops, optlen, 0);
		if (err)
			RET_CG_ERR(err);
	}

	return CG_OK;
}

static int write_synack_opt(struct bpf_sock_ops *skops)
{
	struct bpf_test_option opt;

	if (!passive_synack_out.flags)
		/* We should not even be called since no header
		 * space has been reserved.
		 */
		RET_CG_ERR(0);

	opt = passive_synack_out;
	if (skops_want_cookie(skops))
		SET_OPTION_FLAGS(opt.flags, OPTION_RESEND);

	return store_option(skops, &opt);
}

static int syn_opt_len(struct bpf_sock_ops *skops)
{
	__u8 optlen;
	int err;

	if (!active_syn_out.flags)
		return CG_OK;

	optlen = option_total_len(active_syn_out.flags);
	if (optlen) {
		err = bpf_reserve_hdr_opt(skops, optlen, 0);
		if (err)
			RET_CG_ERR(err);
	}

	return CG_OK;
}

static int write_syn_opt(struct bpf_sock_ops *skops)
{
	if (!active_syn_out.flags)
		RET_CG_ERR(0);

	return store_option(skops, &active_syn_out);
}

static int fin_opt_len(struct bpf_sock_ops *skops)
{
	struct bpf_test_option *opt;
	struct hdr_stg *hdr_stg;
	__u8 optlen;
	int err;

	if (!skops->sk)
		RET_CG_ERR(0);

	hdr_stg = bpf_sk_storage_get(&hdr_stg_map, skops->sk, NULL, 0);
	if (!hdr_stg)
		RET_CG_ERR(0);

	if (hdr_stg->active)
		opt = &active_fin_out;
	else
		opt = &passive_fin_out;

	optlen = option_total_len(opt->flags);
	if (optlen) {
		err = bpf_reserve_hdr_opt(skops, optlen, 0);
		if (err)
			RET_CG_ERR(err);
	}

	return CG_OK;
}

static int write_fin_opt(struct bpf_sock_ops *skops)
{
	struct bpf_test_option *opt;
	struct hdr_stg *hdr_stg;

	if (!skops->sk)
		RET_CG_ERR(0);

	hdr_stg = bpf_sk_storage_get(&hdr_stg_map, skops->sk, NULL, 0);
	if (!hdr_stg)
		RET_CG_ERR(0);

	if (hdr_stg->active)
		opt = &active_fin_out;
	else
		opt = &passive_fin_out;

	if (!opt->flags)
		RET_CG_ERR(0);

	return store_option(skops, opt);
}

static int resend_in_ack(struct bpf_sock_ops *skops)
{
	struct hdr_stg *hdr_stg;

	if (!skops->sk)
		return -1;

	hdr_stg = bpf_sk_storage_get(&hdr_stg_map, skops->sk, NULL, 0);
	if (!hdr_stg)
		return -1;

	return !!hdr_stg->resend_syn;
}

static int nodata_opt_len(struct bpf_sock_ops *skops)
{
	int resend;

	resend = resend_in_ack(skops);
	if (resend < 0)
		RET_CG_ERR(0);

	if (resend)
		return syn_opt_len(skops);

	return CG_OK;
}

static int write_nodata_opt(struct bpf_sock_ops *skops)
{
	int resend;

	resend = resend_in_ack(skops);
	if (resend < 0)
		RET_CG_ERR(0);

	if (resend)
		return write_syn_opt(skops);

	return CG_OK;
}

static int data_opt_len(struct bpf_sock_ops *skops)
{
	/* Same as the nodata version.  Mostly to show
	 * an example usage on skops->skb_len.
	 */
	return nodata_opt_len(skops);
}

static int write_data_opt(struct bpf_sock_ops *skops)
{
	return write_nodata_opt(skops);
}

static int current_mss_opt_len(struct bpf_sock_ops *skops)
{
	/* Reserve maximum that may be needed */
	int err;

	err = bpf_reserve_hdr_opt(skops, option_total_len(OPTION_MASK), 0);
	if (err)
		RET_CG_ERR(err);

	return CG_OK;
}

static int handle_hdr_opt_len(struct bpf_sock_ops *skops)
{
	__u8 tcp_flags = skops_tcp_flags(skops);

	if ((tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK)
		return synack_opt_len(skops);

	if (tcp_flags & TCPHDR_SYN)
		return syn_opt_len(skops);

	if (tcp_flags & TCPHDR_FIN)
		return fin_opt_len(skops);

	if (skops_current_mss(skops))
		/* The kernel is calculating the MSS */
		return current_mss_opt_len(skops);

	if (skops->skb_len)
		return data_opt_len(skops);

	return nodata_opt_len(skops);
}

static int handle_write_hdr_opt(struct bpf_sock_ops *skops)
{
	__u8 tcp_flags = skops_tcp_flags(skops);
	struct tcphdr *th;

	if ((tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK)
		return write_synack_opt(skops);

	if (tcp_flags & TCPHDR_SYN)
		return write_syn_opt(skops);

	if (tcp_flags & TCPHDR_FIN)
		return write_fin_opt(skops);

	th = skops->skb_data;
	if (th + 1 > skops->skb_data_end)
		RET_CG_ERR(0);

	if (skops->skb_len > tcp_hdrlen(th))
		return write_data_opt(skops);

	return write_nodata_opt(skops);
}

SEC("sockops")
int bpf_tcpoptionstoa(struct bpf_sock_ops *skops)
{
	int true_val = 1;

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
            bpf_setsockopt(skops, SOL_TCP, TCP_SAVE_SYN,
                    &true_val, sizeof(true_val));
            set_hdr_cb_flags(skops, BPF_SOCK_OPS_STATE_CB_FLAG);

            break;
        }

        //* client side
        case BPF_SOCK_OPS_TCP_CONNECT_CB: {
            bpf_printk("client: tcp connect init\n");
    		set_hdr_cb_flags(skops, 0);

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
	case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
		return handle_parse_hdr(skops);
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		return handle_hdr_opt_len(skops);
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		// return handle_write_hdr_opt(skops);
        default:
            rv = -1;
    }
	skops->reply = rv;
	return 1;
}
// * 必要的许可信息
char _license[] SEC("license") = "GPL";