# CIFSwitch-Go

Go port of the CIFSwitch local privilege escalation (embargo lifted 2026-05-27).

> **For authorized security testing, patch validation, and research only.**
> Run exclusively on systems you own or have explicit written permission to test.

## Vulnerability

The Linux kernel's CIFS implementation does not validate that `cifs.spnego` key
descriptions originate from kernel code. An unprivileged user can call
`request_key("cifs.spnego", forged_description, ...)` directly, causing the
`cifs.upcall` helper — launched as root by `request-key` — to switch into the
attacker's mount namespace before it calls `getpwuid()` and before `setuid()`.

A fake NSS library placed in the attacker's namespace runs its constructor with
root privileges and writes a passwordless sudoers entry.

**Patch:** kernel commit introducing `cifs_spnego_key_vet_description()` which
validates that descriptions only come from kernel CIFS credential context.

## Affected

| Distribution | Status |
|---|---|
| Linux Mint 21.3 / 22.3 | Exploitable (stock) |
| CentOS Stream 9, Rocky 9, AlmaLinux 9.7 | Exploitable (stock) |
| Kali Linux | Exploitable (stock) |
| Ubuntu 18.04 – 24.04, Debian 11 – 13 | Exploitable if `cifs-utils` installed |
| Ubuntu 26.04, Fedora 40+, CentOS Stream 10 | Blocked by default LSM policy |

Requires: unprivileged user namespace creation + `cifs.upcall` reachable via
`request-key.conf`.

## Chain

```
unshare(CLONE_NEWUSER | CLONE_NEWNS)
  └─ bind-mount fake nsswitch.conf + libnss_pwn.so.2
       └─ request_key("cifs.spnego", forged_desc)
            └─ cifs.upcall (root) switches into attacker mount namespace
                 └─ getpwuid() → dlopen(libnss_pwn.so.2)
                      └─ __attribute__((constructor)) writes /etc/sudoers.d/...
                           └─ sudo -n /bin/bash -p
```

## Prerequisites

```bash
sudo apt install cifs-utils gcc          # Ubuntu/Debian
sudo yum install cifs-utils gcc          # RHEL/Rocky/AlmaLinux
sudo modprobe cifs                       # ensure kernel module is loaded
```

Verify:
```bash
grep cifs /etc/request-key.conf          # must show cifs.upcall rule
grep -w cifs /proc/filesystems           # must show "nodev cifs"
```

## Build

```bash
go build -o cifswitch-go .
```

Requires Go 1.18+ and `gcc` (for the NSS shared library compiled at runtime).

## Usage

```
./cifswitch-go
```

If successful, a root shell is spawned via `sudo -n /bin/bash -p`.

**Cleanup after testing:**
```bash
sudo rm -f /etc/sudoers.d/cifswitch-go-*
rm -rf /tmp/cifswitch-go-* /tmp/cifswitch-evidence-* /var/tmp/cifswitch-rootsh-*
```

## Structure

| File | Purpose |
|---|---|
| `main.go` | Entry point, preflight checks, LPE orchestration |
| `trigger.go` | Namespace setup, `spawnTrigger`, `runTrigger`, `request_key` / `keyctl` wrappers |
| `nss.go` | Fake NSS library C source, `compileFakeNSS`, `writeNSSwitchConf` |

## Mitigations

- Remove or replace the `cifs.spnego` rule in `/etc/request-key.conf`
- Disable unprivileged user namespaces: `sysctl -w kernel.unprivileged_userns_clone=0`
- Remove `cifs-utils` if CIFS mounts are not needed
- Apply the kernel patch that adds `cifs_spnego_key_vet_description()`

## References

- Writeup: https://heyitsas.im/posts/cifswitch/
- Original PoC: https://github.com/manizada/CIFSwitch
