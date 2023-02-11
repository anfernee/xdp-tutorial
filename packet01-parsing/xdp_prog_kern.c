/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define VLAN_MAX_DEPTH 10

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto; /* NOTICE: unsigned type */
};

static __always_inline int proto_is_vlan(__u16 h_proto) {
	return !!(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD));
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	struct vlan_hdr *vlh;
	int hdrsize = sizeof(*eth);
	int i;
	__be16 h_proto;
	int inc = sizeof(*vlh);
	inc = 1;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	h_proto = eth->h_proto;
	vlh = nh->pos;


	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++)
	{
		bpf_printk("h_proto: %x", h_proto);
		if (!(proto_is_vlan(h_proto)))
			break;
		if (vlh + inc > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		vlh += inc;
	}

	nh->pos = vlh;
	return h_proto;
}

static __always_inline __u8 parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;
	int hdrsize = sizeof(*ip6h);

	bpf_printk("parse ipv6");

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}


static __always_inline __u8 parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = nh->pos;
	int hdrsize = sizeof(struct icmp6hdr);

	bpf_printk("parse icmpv6");

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6h;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

  /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	__u8 ip_proto;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	bpf_printk("h_proto: %x", nh_type);

	if (nh_type != bpf_htons(ETH_P_IPV6))
		goto out;

	/* Assignment additions go below here */
	ip_proto = parse_ip6hdr(&nh, data_end, &ip6h);
	bpf_printk("ip_proto: %d", ip_proto);

	if (ip_proto != IPPROTO_ICMPV6)
		goto out;

	ip_proto = parse_icmp6hdr(&nh, data_end, &icmp6h);

	if (ip_proto != ICMPV6_ECHO_REQUEST && ip_proto != ICMPV6_ECHO_REPLY)
		goto out;

	bpf_printk("icmp6 seq: %d", bpf_ntohs(icmp6h->icmp6_sequence));
	if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
		action = XDP_DROP;
	else
		action = XDP_PASS;

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
