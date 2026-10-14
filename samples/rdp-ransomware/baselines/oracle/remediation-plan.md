# Remediation Plan

## P0 — Contain
1. isolate the host from the network and block the attacker IP.
   - Verify: `host shows no inbound RDP from <ip>`
   - Risk: network

## P1 — Eradicate
2. quarantine svc.exe and terminate the ransomware process — target: `/Users/Public/svc.exe`.
   - Verify: `no running process references svc.exe`
   - Risk: runtime
3. delete the UpdateHelper scheduled task — target: `/Windows/System32/Tasks/UpdateHelper`.
   - Verify: `schtasks /query has no UpdateHelper`
   - Risk: runtime
4. remove the malicious Run-key value — target: `/Windows/System32/config/SOFTWARE`.
   - Verify: `reg query ...\Run has no svc value`
   - Risk: runtime
5. stop and remove the svc-helper service — target: `/Windows/System32/svc-helper.sys`.
   - Verify: `sc query svc-helper returns not found`
   - Risk: service

## P2 — Harden
6. enable NLA and restrict RDP to VPN/allowlisted sources — target: `/Windows/System32/config/RDP-Tcp.reg`.
   - Verify: `UserAuthentication == 1 and RDP is firewalled`
   - Risk: auth

## P3 — Rotate
7. reset all local and domain credentials used on this host.
   - Verify: `credential reset timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm RDP no longer accepts unauthenticated sessions.
   - Verify: `RDP probe is refused without NLA`
   - Risk: auth
9. restore encrypted data from backup and confirm services healthy.
   - Verify: `critical services running and files restored`
   - Risk: service
