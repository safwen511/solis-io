package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "doctor":
		fmt.Println("solis doctor: compatibility checks will be implemented here")
	case "inventory":
		fmt.Println("solis inventory: VM/QEMU inventory will be implemented here")
	case "top":
		fmt.Println("solis top: live VM I/O view will be implemented here")
	case "inspect":
		if len(os.Args) < 3 {
			fmt.Println("usage: solis inspect <vm>")
			os.Exit(1)
		}
		fmt.Printf("solis inspect: VM %s inspection will be implemented here\n", os.Args[2])
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`Solis I/O

Usage:
  solis doctor
  solis inventory
  solis top
  solis inspect <vm>

Solis I/O is a Linux-only provider-side KVM storage latency attribution tool.`)
}
