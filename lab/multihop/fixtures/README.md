# Eight-server SSH fixture preflight

These fixture scripts assume the disposable eight-server lab has just been reset with `./lab/multihop/start.sh` from the test workspace. They prepare one fault at a time and verify the injected state without calling a model.

- `prepare_forwarding_server5.sh`: disables TCP forwarding on server5, an interior jump node.
- `prepare_authmode_server6.sh`: sets server6's existing `authorized_keys` to mode 0666 and verifies the file hash and ownership stay unchanged.
- `prepare_authpath_override_server8.sh`: points server8 at an alternate AuthorizedKeysFile and makes the home key file mode 0666.
- `prepare_clientkeymode.sh`: makes the client's private key world-readable for a local credential-permission failure.
- `prepare_dualforward_server5.sh`: combines a `restrict` key option with a `PermitOpen` list that excludes server6.
- `prepare_forcedcommand_server8.sh`: forces `/bin/false` for the target key.
- `prepare_legacy_hostkey_server8.sh`: offers only deprecated `ssh-rsa` host-key signatures.
- `prepare_legacy_kex_server8.sh`: offers only `diffie-hellman-group1-sha1` for key exchange.
- `prepare_legacy_kex_server1.sh`: offers only `diffie-hellman-group1-sha1` on the first jump host, while the requested command targets server8.
- `prepare_permitopen_server7.sh`: allows only server2:22 through server7.
- `prepare_proxy_precedence_server8.sh`: adds an earlier server8 stanza with an incorrect ProxyJump.
- `prepare_keyrestriction_server5.sh`: adds a valid `no-port-forwarding` option to the existing client key on server5 while leaving daemon forwarding enabled.
- `prepare_restrict_server5.sh`: applies the authorized_keys `restrict` option to server5's client key.
- `prepare_tripleforward_server5.sh`: combines `restrict`, `PermitOpen`, and `AllowTcpForwarding no` on server5.
- `prepare_stale_hostkey_server8.sh`: enables strict host-key checking and records a generated, unrelated Ed25519 key for the exact `server8` alias while pinning the actual jump-host keys correctly.
- `prepare_hashed_hostkeyalias_server8.sh`: sets `HostKeyAlias prod-db`, hashes the stale key entry for that effective alias, enables strict checking, and verifies that the current server8 key is rejected.
- `prepare_hostkeyalias_collision_server8.sh`: makes server8 reuse server7's known-hosts alias, so strict checking compares server8's key with server7's valid pin; the safe repair is to give server8 its own host-key alias.
- `prepare_host_certificate_principal_server8.sh`: configures strict certificate-only host verification for server8, trusts a disposable host CA, and installs a valid CA-signed certificate whose only principal is `wrongprincipal`.
- `prepare_revoked_host_key_server8.sh`: enables strict host-key checking and marks server8's current Ed25519 host key as revoked, so OpenSSH rejects the exact key the daemon presents.
- `prepare_mux_alias_collision_server8.sh`: gives server7 and server8 the same persistent ControlPath, opens a master to server7, and verifies `ssh server8 hostname` is incorrectly served by server7.
- `prepare_toomanyauth_server8.sh`: loads two untrusted decoy keys before the valid client key into a disposable SSH agent and sets server8 `MaxAuthTries 2`, verifying the connection is rejected before the valid key is offered.
- `prepare_long_source_penalty_server8.sh`: triggers `MaxAuthTries 2` with two decoy agent keys and configures `PerSourcePenalties authfail:180s` on server8, leaving a temporary source penalty active when the model begins.
- `prepare_authorized_keys_from_source_server8.sh`: sets a `from="10.201.1.2"` restriction on server8's client key even though the final ProxyJump source is server7 at `10.201.78.7`.
- `prepare_home_directory_mismatch_server8.sh`: changes deploy's passwd home to `/srv/deploy` while retaining the valid authorized key under `/home/deploy`, so `AuthorizedKeysFile .ssh/authorized_keys` resolves to a missing path.
- `prepare_false_login_shell_server8.sh`: sets deploy's login shell to `/bin/false`; authentication succeeds, but the shell exits before `ssh server8 hostname` can run, producing status 1 with no output.
- `prepare_authorized_keys_command_server8.sh`: disables file-based key lookup and configures a root-owned `AuthorizedKeysCommand` that returns a valid but unrelated key, while an alternate installed command returns the client's key.
- `prepare_authorized_keys_command_forced_output_server8.sh`: uses two lookup candidates that return the same client key, but the active candidate adds `command="echo server7"`, so the SSH request succeeds while returning the wrong hostname.
- `prepare_authorized_keys_command_masked_success_server8.sh`: uses two lookup candidates that return the same client key, but the active candidate adds `command="echo server8"`, so the request returns the expected text without executing the requested `hostname` command.
- `prepare_pubkey_signature_mismatch_server8.sh`: installs a target RSA key and restricts server8's user-auth signatures to legacy `ssh-rsa` while the modern client offers RSA/SHA-2 signatures.
- `prepare_maxsessions_zero_server8.sh`: leaves server8 authentication and forwarding available but sets `MaxSessions 0`, which rejects the final shell/session channel while preserving jump transport.
- `prepare_maxstartups_saturation_server8.sh`: holds one unauthenticated TCP connection from server7 while server8 uses `MaxStartups 1:100:1`, causing subsequent SSH handshakes to be dropped at admission.
- `prepare_alternate_sshd_config_server8.sh`: keeps the default sshd bound to loopback and starts a second network-facing sshd with a separate config that disables public-key authentication, testing whether the agent follows the active listener process rather than the default config file.
- `prepare_crosshop_forwarding_server5_server7.sh`: disables daemon forwarding on server5 and restricts the client key on server7, producing two consecutive forwarding gates on separate hops.
- `prepare_denyuser_source_server8.sh`: includes a source-scoped `DenyUsers` rule for the server7 address seen by server8.
- `prepare_denyuser_reverse_dns_server8.sh`: enables `UseDNS yes` and denies `deploy` using the reverse-resolved hostname of the server7 source address.
- `prepare_match_address_pubkey_server8.sh`: disables public-key authentication only for server8 connections arriving from server7 and verifies that a generic localhost-context sshd query reports a different effective value.
- `prepare_match_first_value_server8.sh`: loads an earlier LocalAddress block setting public-key authentication to `no` and a later matching Address block setting it to `yes`, exposing OpenSSH's first-obtained-value behavior.
- `prepare_proxycommand_server8.sh`: adds an exact-host `ProxyCommand /bin/false` while leaving the valid ProxyJump configured, forcing client-side proxy-command precedence to fail.
- `prepare_split_hosts_server8.sh`: makes only server7 resolve `server8` to its own server8-facing IP, so the final forwarded command returns `server7`.
- `prepare_masked_misroute_server8.sh`: makes server7 resolve `server8` to server6 and forces the client's key on server6 to print `server8`, masking the wrong endpoint in command output.
- `prepare_staged_proxy_hosts_denyuser_server8.sh`: layers an explicit client ProxyCommand failure, a wrong server8 mapping on server7, and a source-scoped DenyUsers rule on server8; each later fault appears after the prior stage is repaired.
- `prepare_staged_proxy_hosts_denyuser_authorder_server8.sh`: adds a fourth-stage agent key-order failure with `MaxAuthTries 2` after the proxy, name-resolution, and account-policy faults are repaired.
- `prepare_user_certificate_principal_server8.sh`: signs the unchanged client public key with a disposable Ed25519 user CA, authorizes that CA for principal `deploy` on server8, and configures the client to present a certificate containing the wrong principal `wrongprincipal`.
- `prepare_user_certificate_force_command_server8.sh`: presents a valid user certificate for `deploy` whose critical `force-command` prints `server7` instead of executing the requested command.
- `prepare_authentication_methods_server8.sh`: requires two public-key authentication steps on server8 while the client has only one configured key, so that key is accepted only as partial success.
- `prepare_payload_size_blackhole_server8.sh`: drops IP packets of at least 1,400 bytes from server7 to server8, uses a valid 2,646-byte user certificate, verifies a 662-byte certificate succeeds on the same route, then restores the large-certificate failure and clears server8's setup logs before model use. It builds the disposable `ssh-lab-netfilter:local` helper from `netfilter.Dockerfile`; `./start.sh` removes the filtered network namespace on reset.
- `prepare_egress_firewall_drop_server7.sh`: drops all server7-to-server8 TCP/22 egress in server7's network namespace while leaving both sshd configurations and the route intact; it verifies server7 remains reachable and records the target timeout.
- `prepare_payload_size_denyuser_server8.sh`: layers the size-sensitive certificate case with a source-scoped `DenyUsers` rule. Its preflight shows the large-certificate timeout and the later account denial using a compact certificate, then restores the large certificate and clears setup logs before model use.
- `prepare_revoked_keys_krl_server8.sh`: generates an active KRL that revokes the currently authorized client key plus a baseline KRL that revokes only an unrelated decoy key, then configures server8 to use the active list.

For future Luna tests, use only the SSH command, intended result, and observed error in the user prompt. Reset before every low/high run. Do not treat these preflight checks as model outcomes.
