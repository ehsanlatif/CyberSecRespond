# Remediation Plan

## P1 — Eradicate
1. quarantine svc.exe and terminate the ransomware process — target: `/Users/Public/svc.exe`.
   - Verify: `no running process references svc.exe`
   - Risk: runtime
2. delete the UpdateHelper scheduled task — target: `/Windows/System32/Tasks/UpdateHelper`.
   - Verify: `schtasks /query has no UpdateHelper`
   - Risk: runtime
3. stop and remove the svc-helper service — target: `/Windows/System32/svc-helper.sys`.
   - Verify: `sc query svc-helper returns not found`
   - Risk: service

## P2 — Harden
4. enable NLA and restrict RDP to VPN/allowlisted sources — target: `/Windows/System32/config/RDP-Tcp.reg`.
   - Verify: `UserAuthentication == 1 and RDP is firewalled`
   - Risk: auth
