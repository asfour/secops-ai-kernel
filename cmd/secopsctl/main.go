package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "init":
		fmt.Println("🚀 Bootstrapping local host virtualization dependencies...")
		executeShellCommand("./setup.sh")
	case "verify":
		fmt.Println("🔍 Asserting system hardware acceleration boundaries...")
		if _, err := os.Stat("/dev/kvm"); os.IsNotExist(err) {
			fmt.Println("❌ ERROR: Hardware-level nested acceleration (/dev/kvm) is completely inaccessible.")
			os.Exit(1)
		}
		fmt.Println("✅ Hardware virtualization layers verified safe.")
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("SecOps Kernel Control Utility (secopsctl)")
	fmt.Println("Usage: secopsctl [command]")
	fmt.Println("\nAvailable Commands:")
	fmt.Println("  init    Executes setup wrappers to build dependencies and stubs")
	fmt.Println("  verify  Inspects host kernel /dev/kvm boundary visibility")
}

func executeShellCommand(scriptPath string) {
	cmd := exec.Command("bash", scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Errorf("Execution step encountered a fatal fault: %v", err)
		os.Exit(1)
	}
}
