# Hetzner demo runbook

Move / host the public bpfcompat demo (`bpfcompat.kernelguard.net`) on a Hetzner
bare-metal server. This replaces the Azure VM after the Azure credit expired.

## Why bare metal (not Hetzner Cloud)

The demo boots real x86 QEMU/KVM guests on each validation. **Hetzner Cloud
(shared vCPU, dedicated vCPU, and ARM/CAX alike) does not expose nested
virtualization**, so there is no `/dev/kvm` and QEMU silently falls back to TCG
software emulation (~10x slower). Only a Hetzner **dedicated / Server Auction**
host gives native KVM. The bootstrap script hard-fails if `/dev/kvm` is missing.

## 0) Order the server (manual, your Hetzner account)

1. Open the [Server Auction](https://www.hetzner.com/sb/) (no setup fee, prices
   unaffected by the June 2026 adjustment). Use
   [Server Radar](https://radar.iodev.org/) to filter.
2. Pick any modern x86-64 box (e.g. Ryzen/EPYC, 32GB+ RAM, NVMe). All current
   CPUs support VT-x/AMD-V; KVM works out of the box on bare metal.
3. Install **Ubuntu 22.04 / 24.04 LTS** (via the install image or rescue
   system). Add your SSH public key during install so `root` login works.
4. Note the server's public IP -> `HETZNER_HOST`.

## 1) Bootstrap toolchain + build + demo unit

Installs the build toolchain and `qemu-kvm`, verifies `/dev/kvm`, builds
`bpfcompat` + the static validator + examples, creates the `bpfcompat-demo`
service user (in the `kvm` group), and installs the `bpfcompat-serve` systemd
unit and `/etc/bpfcompat/serve.env` stub.

```bash
export HETZNER_HOST=<server-ip>
# optional: export HETZNER_USER=root HETZNER_SSH_KEY=~/.ssh/id_ed25519
make hetzner-bootstrap-vm
```

## 2) Set the write key and start the demo server

The server binds `127.0.0.1:8080` only. Anonymous visitors may validate and read
history; writes require the private key.

```bash
ssh root@$HETZNER_HOST \
  "sudo sed -i \"s|^BPFCOMPAT_API_WRITE_KEY=.*|BPFCOMPAT_API_WRITE_KEY=$(openssl rand -hex 32)|\" /etc/bpfcompat/serve.env"
ssh root@$HETZNER_HOST "sudo systemctl enable --now bpfcompat-serve.service"
ssh root@$HETZNER_HOST "systemctl --no-pager status bpfcompat-serve.service"
```

## 3) Repoint DNS (Cloudflare)

Update the `bpfcompat.kernelguard.net` `A` record from the old Azure IP
(`20.91.218.19`) to `$HETZNER_HOST`. Keep it **DNS only (grey cloud)** so Caddy
can complete the Let's Encrypt HTTP-01 challenge.

## 4) Configure HTTPS + host firewall (Caddy + ufw)

`ufw` opens only 22/80/443; the backend stays on `127.0.0.1:8080`.

```bash
export HETZNER_HOST=<server-ip>
export BPFCOMPAT_DOMAIN=bpfcompat.kernelguard.net
make hetzner-configure-tls
```

After completion:

- UI:     `https://bpfcompat.kernelguard.net/`
- Health: `https://bpfcompat.kernelguard.net/api/health`

## 5) Verify, then decommission Azure

```bash
curl -fsS https://bpfcompat.kernelguard.net/api/health
```

Once green, tear down the Azure VM/resource group to stop any residual billing.

## Security notes

- Backend never listens publicly: `--addr 127.0.0.1:8080` behind Caddy + `ufw`.
- `BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE=false` -- no host eBPF loading on the demo.
- Public reports are sanitized server-side (`internal/api/sanitize.go`); host
  paths, `vm_run_dir`, `qemu_command`, and `serial_log` never reach the browser.
- `.bpfcompat/runs/**` (per-run SSH keys) lives only under `/var/lib/bpfcompat-demo`.
