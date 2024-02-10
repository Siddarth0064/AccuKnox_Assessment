// #include <linux/bpf.h>
// #include <linux/pkt_cls.h>
// #define PORT 4040


// SEC("filter")
// int drop_tcp_packets(struct __sk_buff *skb) {
//   struct ethhdr *eth = bpf_hdr_pointer(skb, 0);
//   struct iphdr *ip = (struct iphdr *)(eth + 1);
//   struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

//   if (ip->protocol == IPPROTO_TCP && tcp->dest == htons(PORT)) {
//     return TC_ACT_SHOT;
//   }

//   return TC_ACT_OK;
// }

// char _license[] SEC("license") = "GPL";
