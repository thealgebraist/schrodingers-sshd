I can't get into our air-gapped turbine controller (`plc-scada-unit04`) in the Hammerfest OT enclave anymore after the weekend maintenance window and cert rotation. 

Normally I just run `ssh scada-unit04` from my macOS laptop (`~/.ssh/config` below) and it tunnels through our corporate VPN gateway, regional AWS transit bastions, the Stavanger partner interconnect, and the Purdue-model OT jump hosts all the way down to the field unit. Right now when I run `ssh scada-unit04` from a background deployment script (or even in my terminal), it either just hangs forever until `Operation timed out` or spits out `Permission denied (publickey).` depending on what flags I pass.

I already wasted two hours checking the `authorized_keys` and `/etc/ssh/sshd_config` on `scada-unit04` via our out-of-band IPMI serial console—I fixed a group-writable permission issue on `~/.ssh/authorized_keys` (`0664` -> `0600`) that Ansible broke on `scada-unit04`, but `ssh scada-unit04` from my laptop STILL hangs / fails with the exact same error!

Here is my current `~/.ssh/config` and what I know about the environment after the weekend change freeze:

```sshconfig
Host *
    ServerAliveInterval 15
    ServerAliveCountMax 2
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_ed25519_nordic_ot

# 1. Corp VPN Entry -> Frankfurt Core Bastion
Host gw-corp-vpn
    HostName 10.240.0.10
    User a.lindqvist
    ForwardAgent yes

# 2. Frankfurt Core -> AWS eu-central-1 Transit
Host bst-fra-core01
    HostName 10.240.12.4
    User a.lindqvist
    ProxyJump gw-corp-vpn
    ForwardAgent yes

# 3. AWS eu-central-1 -> AWS eu-north-1 (Stockholm) Peering Jump
Host bst-arn-peering02
    HostName 10.248.4.19
    User a.lindqvist
    ProxyJump bst-fra-core01
    ForwardAgent yes

# 4. Stockholm Peering -> Oslo Dedicated MPLS Edge
Host mpls-osl-edge01
    HostName 172.18.30.5
    User netops
    ProxyJump bst-arn-peering02
    ForwardAgent yes

# 5. Oslo MPLS Edge -> Equinor Stavanger Partner DMZ
Host dmz-svg-partner01
    HostName 172.18.94.12
    User ext_lindqvist
    ProxyJump mpls-osl-edge01
    ForwardAgent yes

# 6. Stavanger Partner DMZ -> Tromsø Regional Aggregator
Host reg-tos-agg01
    HostName 172.22.10.8
    User netops
    ProxyJump dmz-svg-partner01
    ForwardAgent yes

# 7. Tromsø Aggregator -> Hammerfest Site Firewall Jump
Host fw-hft-perimeter01
    HostName 172.22.88.2
    User secops
    ProxyJump reg-tos-agg01
    ForwardAgent yes

# 8. Hammerfest Perimeter -> IT/OT Demilitarized Zone (Purdue L3.5)
Host ot-hft-dmz-l35
    HostName 192.168.200.10
    User otadmin
    ProxyJump fw-hft-perimeter01
    ForwardAgent yes

# 9. Purdue L3.5 -> Operations Site Historian Jump (Purdue L3)
Host ot-hft-hist-l3
    HostName 192.168.180.15
    User otadmin
    ProxyJump ot-hft-dmz-l35
    ForwardAgent yes

# 10. Purdue L3 -> Supervisory Control Bastion (Purdue L2.5)
Host ot-hft-sup-l25
    HostName 192.168.150.22
    User scada_maint
    ProxyJump ot-hft-hist-l3
    ForwardAgent yes

# 11. Purdue L2.5 -> Subsea Wellhead Control Gateway (Purdue L2)
Host ot-hft-well-l2
    HostName 192.168.120.9
    User scada_maint
    ProxyJump ot-hft-sup-l25
    ForwardAgent yes

# 12. Purdue L2 -> Compression Train B Cell Jump
Host cell-trainb-jmp01
    HostName 192.168.90.40
    User maint
    ProxyJump ot-hft-well-l2
    ForwardAgent yes

# 13. Compression Train B -> Safety Instrumented System (SIS) Ring Gateway
Host sis-ring-gw02
    HostName 10.99.14.2
    User maint
    ProxyJump cell-trainb-jmp01
    ForwardAgent yes

# 14. SIS Ring Gateway -> Local Cabinet Concentrator 07
Host cab-conc-07
    HostName 10.99.14.107
    User root
    ProxyJump sis-ring-gw02
    ForwardAgent yes

# 15. Cabinet Concentrator 07 -> Embedded UART-to-Ethernet Bridge
Host uart-bridge-b04
    HostName 169.254.40.2
    User root
    ProxyJump cab-conc-07
    ForwardAgent yes

# 16. Target Field Unit: Turbine Controller PLC
Host scada-unit04
    HostName 169.254.40.104
    User root
    ProxyJump uart-bridge-b04
```

### Recent changes / environment notes from the weekend maintenance:
1. I rebooted my MacBook this morning after a macOS point update. My key `~/.ssh/id_ed25519_nordic_ot` has a passphrase on it, and I use Homebrew's OpenSSH (`/opt/homebrew/bin/ssh`) because we need FIDO2/sk-ed25519 support on some hosts, though my shell also has `/usr/bin/ssh-add` and Apple's launchd `SSH_AUTH_SOCK` floating around in `.zshrc`.
2. The Stockholm/Oslo team upgraded `bst-arn-peering02` to Debian 12 and hardened `/etc/ssh/sshd_config` with CIS benchmark defaults (`AllowAgentForwarding`, `AllowTcpForwarding`, etc. were touched on a few boxes, not sure which ones got reverted).
3. Network security migrated the Hammerfest perimeter (`fw-hft-perimeter01` -> `ot-hft-dmz-l35`) onto a new VLAN trunk with strict stateful inspection and a 1420-byte IPsec tunnel overhead.
4. In the lower Purdue levels (`ot-hft-well-l2` / `cell-trainb-jmp01`), the local internal DNS resolvers (`192.168.100.53` on UDP/53) were decommissioned to prevent DNS tunneling, and those jump boxes run an older stock `sshd` build.
5. On `scada-unit04` itself, the `/home/root` filesystem was remounted read-write during firmware flashing, which left `/root` and `/root/.ssh/authorized_keys` as `0664` (`root:wheel`).

Why is `ssh scada-unit04` still failing/hanging even after I fixed the permissions on `scada-unit04`, and what exact sequence of commands should I run to figure out what's actually broken without locking out our maintenance window or breaking the intermediate bastions?
