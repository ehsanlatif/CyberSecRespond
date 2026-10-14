# Remediation Plan

## P0 — Contain
1. isolate the host and block SMB from untrusted networks.
   - Verify: `port 445 is not reachable from outside the segment`
   - Risk: network

## P1 — Eradicate
2. quarantine the EternalBlue implant — target: `/Windows/Temp/mssecsvc.exe`.
   - Verify: `! test -f /Windows/Temp/mssecsvc.exe`
   - Risk: runtime
3. quarantine the ransomware binary and terminate the process — target: `/Users/Public/enc.exe`.
   - Verify: `no process references enc.exe`
   - Risk: runtime
4. remove the malicious WMI __EventFilter/consumer binding — target: `/Windows/System32/wbem/Repository/OBJECTS.DATA`.
   - Verify: `Get-WmiObject __EventConsumer shows no attacker consumer`
   - Risk: service
5. restore the legitimate wbemcomn.dll and remove the hijack — target: `/Windows/System32/wbem/wbemcomn.dll`.
   - Verify: `signed wbemcomn.dll is in place`
   - Risk: service

## P2 — Harden
6. apply MS17-010 and disable SMBv1 — target: `/Windows/System32/drivers/srv.sys`.
   - Verify: `SMBv1 disabled and patch present`
   - Risk: service

## P3 — Rotate
7. reset all credentials exposed in the LSASS dump (assume domain-wide).
   - Verify: `credential reset timestamps are recent`
   - Risk: auth

## P4 — Verify
8. confirm the SMBv1 exploit path is closed.
   - Verify: `MS17-010 scanner reports not vulnerable`
   - Risk: service
9. restore encrypted data from backup and confirm host health.
   - Verify: `files restored and services running`
   - Risk: service
