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
		ok, message := verifyKVMAccess("/dev/kvm")
		fmt.Println(message)
		if !ok {
			os.Exit(1)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}

// verifyKVMAccess reports whether kvmPath exists, and the message to print
// either way. Pulled out of main's "verify" case so it's testable against
// an arbitrary path instead of being hardcoded to the real /dev/kvm.
func verifyKVMAccess(kvmPath string) (ok bool, message string) {
	if _, err := os.Stat(kvmPath); os.IsNotExist(err) {
		return false, "❌ ERROR: Hardware-level nested acceleration (/dev/kvm) is completely inaccessible."
	}
	return true, "✅ Hardware virtualization layers verified safe."
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
		fmt.Printf("Execution step encountered a fatal fault: %v\n", err)
		os.Exit(1)
	}
}
