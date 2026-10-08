# CentOS Stream 9 kernel 725 archive repair

The three original `mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/Packages/`
URLs returned HTTP 404 on 2026-10-08. The rolling repository lists kernels
745, 749, 753, 754 and 756, not 725. This is retirement from the rolling
mirror, not an incorrect architecture/path or total loss of the build.

The authoritative [CentOS Koji build 119089](https://kojihub.stream.centos.org/koji/buildinfo?buildID=119089)
is complete, built 2026-07-15 and promoted 2026-07-16. Its
[signed archive](https://kojihub.stream.centos.org/kojifiles/packages/kernel/5.14.0/725.el9/data/signed/8483c65d/x86_64/)
serves all three exact packages (HTTP 200): kernel-core, kernel-modules-core,
and kernel-modules, each version-release `5.14.0-725.el9`, architecture
`x86_64`. Unsigned build-output URLs also exist but are deliberately not used.
`vault.centos.org/9-stream/` is not the replacement (HTTP 404).

The official signing key from
[centos.org](https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official) has full
fingerprint `99DB70FAE1D7CE227FB6488205B555B38483C65D` (short ID `8483c65d`).
Local verification uses an isolated RPM key database and `rpm -Kv`, and
records independently calculated SHA-256 values outside the source tree.
For this exact three-package signed archive set only, the guest imports the
[official SHA256-self-signed encoding](https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official-SHA256),
with the same full fingerprint independently checked against the
[authoritative key list](https://www.centos.org/keys/). Its byte SHA256 is
`5af55449d6c9bc594e2e2fb7222374cb25a8ad2d8ea6ce3de894a3201944daa2`;
the guest checks this digest before importing. The old encoding has a SHA1
self-signature; unrelated image keys include unsupported SHA1 and V6 keys.
No wildcard import or ignored import failure is used in this narrow path.
The installer requires `rpm --checksig`, enables `localpkg_gpgcheck=1`, and selects
`/boot/vmlinuz-5.14.0-725.el9.x86_64`. No `--nogpgcheck` is permitted.

725 downloads use HTTP/1.1 with explicit connection/transfer deadlines and
bounded retries; final failures remain infrastructure errors. Other vendors
and package sets retain their original installer. The requested
kernel, image, required matrix coverage and validator behavior do not change.
Offline tests assert exact signed URLs/version and verification-before-install.

Acceptance requires installed/rebooted `uname -r` exactly
`5.14.0-725.el9.x86_64`, positive required load/attach, expected invalid-object
failure, non-empty reports and exact local candidate identities. URL or RPM
availability alone is not compatibility evidence. Test outcomes and hashes
are retained in the isolated Phase 4 evidence directory; any installation,
boot or download failure remains INFRA_ERROR, not an incompatibility verdict.
