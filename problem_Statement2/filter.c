#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("filter")
int filter_prog(struct __sk_buff *skb) {
    // Get the pointer to the start of the packet data
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return 0;

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return 0;

    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return 0;

    // Check if the packet is TCP
    if (eth->h_proto != htons(ETH_P_IP) || ip->protocol != IPPROTO_TCP)
        return 0;

    // Check if the packet is destined to the specified port (4040)
    if (htons(tcp->dest) != 4040)
        return 0;

    // Retrieve the process name associated with the packet
    bpf_get_current_comm(skb, sizeof(skb->pkt_type));

    // Check if the process name matches "myprocess"
    if (strncmp(skb->pkt_type, "myprocess", sizeof(skb->pkt_type)) != 0)
        return 0;

    // Allow the packet to pass through
    return 1;
}

char _license[] SEC("license") = "GPL";
