# Remediation Plan

## P1 — Eradicate
1. quarantine the EternalBlue implant — target: `/Windows/Temp/mssecsvc.exe`.
   - Verify: `! test -f /Windows/Temp/mssecsvc.exe`
   - Risk: runtime
2. quarantine the ransomware binary and terminate the process — target: `/Users/Public/enc.exe`.
   - Verify: `no process references enc.exe`
   - Risk: runtime

## P2 — Harden
3. apply MS17-010 and disable SMBv1 — target: `/Windows/System32/drivers/srv.sys`.
   - Verify: `SMBv1 disabled and patch present`
   - Risk: service
