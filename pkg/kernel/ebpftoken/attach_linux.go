//go:build linux

package ebpftoken

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func attachTracepoint(prog *ebpf.Program) (link.Link, error) {
	return link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
}
