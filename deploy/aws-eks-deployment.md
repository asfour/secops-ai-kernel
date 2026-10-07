# Enterprise Production Architecture: Distributed Multi-Region Deployment

To guarantee sub-millisecond hypervisor sandboxing latency and Ring-0 system call tracking, SecOps Kernel must be run on compute clusters that support nested hardware virtualization acceleration.

## 1. Multi-Region Cloud Footprint Selection
Standard cloud instances (e.g., AWS `t3.medium`) strip away `/dev/kvm` visibility. Production infrastructure must utilize either **Bare Metal instances** or instances featuring **hardware-assisted nested virtualization**:
* **AWS EC2 (US-East-1 & EU-West-1)**: `m6i.metal`, `c6i.metal`, or `i3en.metal` instance profiles.
* **GCP Compute Engine**: N2 or C2 machine types with the `nestedVirtualization: true` flag enabled via your IaC templates.

## 2. Multi-Cluster Kubernetes DaemonSet Specification
Deploy the core engine container as a privileged DaemonSet across your distributed agent node pools to map system interfaces out-of-band:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: secops-kernel-core
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: secops-kernel
  template:
    metadata:
      labels:
        app: secops-kernel
    spec:
      hostPID: true # Essential for out-of-band eBPF boundary tracking
      hostNetwork: true
      containers:
        - name: core-engine
          image: ghcr.io/asfour/secops-ai-kernel:v2.0.0
          securityContext:
            privileged: true # Grants permissions required to load BPF maps at Ring 0
          volumeMounts:
            - name: kvm-device
              mountPath: /dev/kvm
            - name: sys-kernel-debug
              mountPath: /sys/kernel/debug
            - name: usr-src-headers
              mountPath: /usr/src
              readOnly: true
      volumes:
        - name: kvm-device
          hostPath:
            path: /dev/kvm
        - name: sys-kernel-debug
          hostPath:
            path: /sys/kernel/debug
        - name: usr-src-headers
          hostPath:
            path: /usr/src
```
