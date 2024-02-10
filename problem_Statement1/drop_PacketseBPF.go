package main

import (
	"flag"
	"fmt"
	//"github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	//"github.com/golang/groupcache/xmc"
	"math"
	"os"
	"strings"
	"syscall"
)

const (
	filterSource = `
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define ETH_HLEN 14

int drop_packet(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, 0);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((__u32 *)ip + ip->ihl);
        if (tcp->dest == %d) {
            return -1; // Drop packet
        }
    }
    return 0; // Accept packet
}
`
)

var (
	port = flag.Int("port", 4040, "TCP port number to drop packets")
)

func main() {
	flag.Parse()

	// Load the eBPF object file
	obj, err := ebpf.LoadObjectFile("drop_packet.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load eBPF object: %v\n", err)
		os.Exit(1)
	}

	// Find the program by name in the object
	prog := obj.GetProgramByName("drop_packet")
	if prog == nil {
		fmt.Fprintf(os.Stderr, "Function 'drop_packet' not found in the object\n")
		os.Exit(1)
	}

	// Attach the eBPF program to the ingress hook of the network device
	err = syscall.SetsockoptString(sock, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, prog.FD())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach eBPF program to socket filter: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Dropping TCP packets on port %d...\n", *port)

	// Infinite loop to continuously filter packets
	for {
		buf := make([]byte, 65535)
		n, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error receiving packet: %v\n", err)
			continue
		}
		// Execute the eBPF filter on the received packet
		action, _, err := prog.Test(buf[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error executing eBPF filter: %v\n", err)
			continue
		}
		// Drop the packet if the eBPF program returned -1
		if action == math.MaxUint32 {
			fmt.Println("Packet dropped")
			continue
		}
		// Otherwise, accept the packet
		fmt.Println("Packet accepted")
	}
}
