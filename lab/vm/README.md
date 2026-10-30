# Victim VM

Debian 12 genericcloud image, QEMU/KVM, user-mode networking. No bridge, no tap, no
sudo required to run the VM.

## Why a VM and not a container

`auditd` is a kernel subsystem. A container shares the host kernel and cannot
produce per-container `execve` telemetry, which removes the process tree — the
richest part of an endpoint alert. A 1.5 GB VM keeps that evidence.

## Provisioning outline

```bash
# 1. Base image (~600 MB, not committed)
mkdir -p images
curl -L -o images/debian-12-genericcloud-amd64.qcow2 \
  https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2

# 2. Writable overlay
qemu-img create -f qcow2 -F qcow2 \
  -b images/debian-12-genericcloud-amd64.qcow2 disk.qcow2 20G

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

## Optional: routable bridge (scenario 5 upgrade)

QEMU user networking forwards individual ports only, so nothing outside QEMU can
reach the guest's full port range. To let an attacker container scan the VM, put
the VM on a real segment:

```bash
sudo ip link add br-soc type bridge
sudo ip link set br-soc up
sudo ip addr add 192.168.122.1/24 dev br-soc
sudo ip tuntap add dev tap-soc mode tap user "$USER"
sudo ip link set tap-soc master br-soc up
```

Then change the QEMU network device to:

```
-netdev tap,id=net0,ifname=tap-soc,script=no,downscript=no
```

and give the guest a static `192.168.122.50` on `eth0`. Add a second user-mode
NIC (`-netdev user`) for internet access, because the tap has no NAT.

Attacker container options:

```bash
# simplest: shares the host network namespace
docker run --rm -it --network host kalilinux/kali-rolling

# distinct source IP: macvlan on the bridge
docker network create -d macvlan \
  --subnet=192.168.122.0/24 --gateway=192.168.122.1 \
  -o parent=br-soc soc-attack
```

Caveats:

- `--network host` makes the source address the host (`192.168.122.1`), which looks
  odd in a ticket.
- macvlan on a bridge parent is supported but has quirks; verify the container can
  reach `192.168.122.50` before building a scenario around it.
- The interfaces disappear on reboot. Wrap the block above in a script if this
  becomes the permanent setup.
- Change Suricata's `HOME_NET` to `192.168.122.0/24` afterwards.

Do this only after the core build is finished. It re-shoots scenario 5; keep the
outbound and inbound versions in separate tickets.

