# cifswitch-go

Go port of [CIFSwitch](https://github.com/manizada/CIFSwitch) - CIFS namespace confusion LPE.

## How it works (tl;dr)

The bug lives at the intersection of the Linux kernel keyring and the `cifs-utils` userspace helper. The kernel exposes the `cifs.spnego` key type but does not verify that description strings come from kernel code - any unprivileged user can call `request_key("cifs.spnego", forged_description, ...)` directly.

The default `/etc/request-key.conf` rule spawns `/usr/sbin/cifs.upcall` as root to handle the request. The helper parses the description and, when `upcall_target=app` is set, switches into the mount namespace of the PID specified in the `pid=` field. It does this **before** calling `getpwuid()` and before `setuid()`.

**NSS injection**

`getpwuid()` consults NSS. Because the helper is now in the attacker's private mount namespace, it reads the attacker's `nsswitch.conf` and loads modules from the attacker's library directory. The fake `libnss_pwn.so.2` has an `__attribute__((constructor))` that fires on `dlopen()`, writing a passwordless sudoers entry while still running as root.

## Exploit chain

```text
unshare(CLONE_NEWUSER|CLONE_NEWNS) ->
bind-mount fake nsswitch.conf + libnss_pwn.so.2 ->
request_key("cifs.spnego", forged_desc[upcall_target=app, pid=self]) ->
cifs.upcall(root) enters attacker mount namespace ->
getpwuid() -> dlopen(libnss_pwn.so.2) ->
__attribute__((constructor)) writes /etc/sudoers.d/... ->
sudo -n /bin/bash -p
```

## Usage

```bash
go build -o cifswitch-go .
./cifswitch-go
```

On success drops into a root shell. `gcc` must be available for the NSS shared library compiled at runtime.

### Cleanup

```bash
sudo rm -f /etc/sudoers.d/cifswitch-go-*
rm -rf /tmp/cifswitch-go-* /tmp/cifswitch-evidence-* /var/tmp/cifswitch-rootsh-*
```

## Requirements

- `cifs-utils` installed (provides `cifs.upcall` and the `request-key.conf` rule)
- `cifs` kernel module loaded (`sudo modprobe cifs`)
- Unprivileged user namespace creation enabled
- `gcc` available (NSS library compiled at runtime)

## Affected distributions

| Distribution | Status |
|---|---|
| Linux Mint 21.3 / 22.3, Kali, CentOS Stream 9, Rocky 9, AlmaLinux 9.7 | Exploitable (stock) |
| Ubuntu 18.04-24.04, Debian 11-13 | Exploitable if `cifs-utils` installed |
| Ubuntu 26.04, Fedora 40+, CentOS Stream 10 | Blocked by default LSM policy |

## References

- [manizada/CIFSwitch](https://github.com/manizada/CIFSwitch) - original Python PoC
- [heyitsas.im - CIFSwitch writeup](https://heyitsas.im/posts/cifswitch/)

## Credits

- **manizada / heyitsas** - vulnerability discovery and original PoC
