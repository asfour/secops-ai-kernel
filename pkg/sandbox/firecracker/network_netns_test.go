package firecracker

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These tests exercise SetupNetworkFence/CountDropped/Teardown against
// real tap devices and real nftables rules — not mocks. Creating a tap
// device and nftables tables normally requires CAP_NET_ADMIN, which this
// test obtains by re-executing itself inside an unprivileged user+network
// namespace (`unshare --net --user --map-root-user`), which grants real
// CAP_NET_ADMIN scoped entirely to that throwaway namespace. This is the
// same technique runc/CNI test suites use to test network namespace
// behavior without requiring the test runner itself to be root.
//
// Guest-sent packets are simulated by opening the tap device's character
// device (exactly how Firecracker itself attaches to a tap) and writing
// raw Ethernet+IPv4 frames into it — this is a real packet arriving on
// the interface from the kernel's point of view, not a mock.

const netnsEnvVar = "SECOPS_INSIDE_TEST_NETNS"

var netnsSupportOnce struct {
	sync.Once
	supported bool
}

func requireNetworkNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv(netnsEnvVar) == "1" {
		return // already inside the unshared namespace; run normally
	}

	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not found on PATH, skipping")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not found on PATH, skipping")
	}

	netnsSupportOnce.Do(func() {
		probe := exec.Command("unshare", "--net", "--user", "--map-root-user", "true")
		netnsSupportOnce.supported = probe.Run() == nil
	})
	if !netnsSupportOnce.supported {
		t.Skip("unprivileged user+network namespaces are not supported in this environment, skipping")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command("unshare", "--net", "--user", "--map-root-user", "--",
		exe, "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), netnsEnvVar+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("unshare re-exec output:\n%s", out)
	if err != nil {
		t.Fatalf("test failed inside network namespace: %v", err)
	}
	t.SkipNow() // the real assertions already ran and passed in the child process
}

func TestNetworkFence_CountsOnlyDisallowedPackets(t *testing.T) {
	requireNetworkNamespace(t)

	fence, err := SetupNetworkFence("test-vm-netdrop", 4521) // -> 10.45.21.0/24
	if err != nil {
		t.Fatalf("SetupNetworkFence: %v", err)
	}
	defer fence.Teardown()

	before, err := fence.CountDropped()
	if err != nil {
		t.Fatalf("CountDropped (before): %v", err)
	}
	if before != 0 {
		t.Fatalf("expected 0 drops on a fresh fence, got %d", before)
	}

	injectPacket(t, fence.TapName, net.ParseIP("10.45.21.50")) // allowed
	injectPacket(t, fence.TapName, net.ParseIP("8.8.8.8"))     // disallowed
	injectPacket(t, fence.TapName, net.ParseIP("1.1.1.1"))     // disallowed

	after, err := fence.CountDropped()
	if err != nil {
		t.Fatalf("CountDropped (after): %v", err)
	}
	if after != 2 {
		t.Fatalf("expected 2 dropped packets (one allowed, two disallowed sent), got %d", after)
	}
}

func TestNetworkFence_TeardownRemovesTapAndTable(t *testing.T) {
	requireNetworkNamespace(t)

	fence, err := SetupNetworkFence("test-vm-teardown", 1234)
	if err != nil {
		t.Fatalf("SetupNetworkFence: %v", err)
	}
	if err := fence.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	if err := exec.Command("ip", "link", "show", fence.TapName).Run(); err == nil {
		t.Fatalf("expected tap device %q to be removed after Teardown", fence.TapName)
	}
	if _, err := fence.CountDropped(); err == nil {
		t.Fatal("expected CountDropped to fail after Teardown (table no longer exists)")
	}
}

// --- raw packet injection, mirroring how Firecracker itself writes to a tap fd ---

type ifReq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

func openTap(name string) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var req ifReq
	copy(req.name[:], name)
	req.flags = unix.IFF_TAP | unix.IFF_NO_PI
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, errno
	}
	return f, nil
}

func injectPacket(t *testing.T, tapName string, dstIP net.IP) {
	t.Helper()
	f, err := openTap(tapName)
	if err != nil {
		t.Fatalf("openTap(%q): %v", tapName, err)
	}
	defer f.Close()

	if _, err := f.Write(buildIPv4Frame(dstIP)); err != nil {
		t.Fatalf("writing frame to %q: %v", tapName, err)
	}
}

// buildIPv4Frame builds a minimal Ethernet+IPv4+UDP frame addressed to dstIP.
func buildIPv4Frame(dstIP net.IP) []byte {
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(eth[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800) // IPv4

	payload := []byte("probe")
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 9999)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(udp)))
	binary.BigEndian.PutUint16(ip[4:6], 1)
	ip[8] = 64 // ttl
	ip[9] = 17 // UDP
	copy(ip[12:16], net.ParseIP("10.200.0.50").To4())
	copy(ip[16:20], dstIP.To4())

	var sum uint32
	for i := 0; i < len(ip); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))

	frame := append(eth, ip...)
	return append(frame, udp...)
}
