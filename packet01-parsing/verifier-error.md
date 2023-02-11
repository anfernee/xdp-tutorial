

```
libbpf: load bpf program failed: Permission denied
libbpf: -- BEGIN DUMP LOG ---
libbpf: 
; int  xdp_parser_func(struct xdp_md *ctx)
0: (bf) r6 = r1
1: (b7) r1 = 2
; void *data_end = (void *)(long)ctx->data_end;
2: (61) r3 = *(u32 *)(r6 +4)
; void *data = (void *)(long)ctx->data;
3: (61) r2 = *(u32 *)(r6 +0)
; if (nh->pos + 1 > data_end)
4: (bf) r4 = r2
5: (07) r4 += 1
; if (nh->pos + 1 > data_end)
6: (2d) if r4 > r3 goto pc+6
 R1_w=inv2 R2_w=pkt(id=0,off=0,r=1,imm=0) R3_w=pkt_end(id=0,off=0,imm=0) R4_w=pkt(id=0,off=1,r=1,imm=0) R6_w=ctx(id=0,off=0,imm=0) R10=fp0
; return eth->h_proto; /* network-byte-order */
7: (71) r3 = *(u8 *)(r2 +12)
invalid access to packet, off=12 size=1, R2(id=0,off=12,r=1)
R2 offset is outside of the packet
processed 8 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0

libbpf: -- END LOG --
libbpf: failed to load program 'xdp_packet_parser'
libbpf: failed to load object 'xdp_prog_kern.o'
ERR: loading BPF-OBJ file(xdp_prog_kern.o) (-22): Invalid argument
ERR: loading file: xdp_prog_kern.o

```

With the following check, we change it from 1 to 9:
```c
	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + 9 > data_end)
		return -1;
```

The error message changed as well: `R2(id=0,off=12,r=9)`.

```
invalid access to packet, off=12 size=1, R2(id=0,off=12,r=9)
```

The kernel code is here: https://elixir.bootlin.com/linux/v6.1.9/source/kernel/bpf/verifier.c#L3595
