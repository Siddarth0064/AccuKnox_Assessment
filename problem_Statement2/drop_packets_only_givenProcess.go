package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
)

func main() {
	// Load the eBPF object file
	objSpec, err := ebpf.LoadCollectionSpec("filter.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load eBPF object: %v\n", err)
		os.Exit(1)
	}

	// Retrieve the eBPF program from the loaded object file
	prog, ok := objSpec.Programs["filter_prog"]
	if !ok {
		fmt.Fprintln(os.Stderr, "filter_prog not found")
		os.Exit(1)
	}

	// Create a new socket filter with the loaded program
	filter := &ebpf.SocketFilter{
		Filter: prog,
	}

	// Attach the eBPF program to a network interface
	if err := filter.Attach("eth0"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to attach eBPF program to socket filter: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("eBPF program successfully loaded and attached")

	// Wait for termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	// Detach the eBPF program before exiting
	if err := filter.Detach(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to detach eBPF program from socket filter: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("eBPF program detached")
}
