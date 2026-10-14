# Intrusion Report

## Executive Summary
The host shows indicators consistent with a compromise involving unauthorized access and
subsequent malicious activity. The attacker appears to have gained entry, established
persistence, and deployed a payload.

## Attack Chain
1. Initial access via an exposed remote-access service.
2. Privilege escalation to administrative context.
3. Deployment of a malicious payload.
4. Installation of persistence mechanisms.
5. Anti-forensic activity to hinder investigation.

## Entities
Several suspicious files, processes, and network endpoints were identified during the
investigation.

## Impact
Confidentiality, integrity, and availability of the host should be considered compromised.
A full rebuild is recommended.
