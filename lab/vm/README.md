# Victim VM

Ubuntu 24.04 cloud image, QEMU/KVM, user-mode networking. No bridge, no tap, no
sudo required to run the VM.

## Why a VM and not a container

`auditd` is a kernel subsystem. A container shares the host kernel and cannot
produce per-container `execve` telemetry, which removes the process tree — the
richest part of an endpoint alert. A 1.5 GB VM keeps that evidence.

## Provisioning outline

```bash
# 1. Base image (~600 MB, not committed)
mkdir -p images
curl -L -o images/noble-server-cloudimg-amd64.img \
  https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img

# 2. Writable overlay
qemu-img create -f qcow2 -F qcow2 \
  -b images/noble-server-cloudimg-amd64.img disk.qcow2 20G

# 3. Seed data served to the guest over HTTP (QEMU user-net reaches the host at 10.0.2.2)
python3 -m http.server 8000 --bind 127.0.0.1 --directory seed &

# 4. Boot
qemu-system-x86_64 \
  -enable-kvm -m 1536 -smp 2 \
  -drive file=disk.qcow2,if=virtio \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8080-:80 \
  -device virtio-net-pci,netdev=net0 \
  -smbios type=1,serial=ds=nocloud-net;s=http://10.0.2.2:8000/ \
  -display none -serial file:console.log
```

Cloud-init `user-data` creates the `analyst` user, injects the lab SSH key, and
installs `openssh-server`, `nginx`, `auditd`, `suricata`, `jq`.

## Access

```bash
ssh -i keys/id_ed25519 -p 2222 analyst@127.0.0.1
```

## Snapshots

```bash
qemu-img snapshot -c clean-baseline disk.qcow2   # before a scenario
qemu-img snapshot -a clean-baseline disk.qcow2   # revert after evidence is captured
```

Take the baseline *after* the agent is enrolled and before the first attack.

## Resource budget

1.5 GB RAM, 2 vCPU, 20 GB thin disk. Host has 12 cores and 7.5 GB total; the VM
must not be started while the host is swapping.
