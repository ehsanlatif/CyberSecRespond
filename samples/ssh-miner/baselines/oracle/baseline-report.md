# Baseline Report

Configuration and baseline weaknesses observed on the host:

| Weakness | Evidence | Capability |
|---|---|---|
| ssh-baseline (PermitRootLogin) | `/etc/ssh/sshd_config` | BAS-01 |
| mysql-remote-root (bind-address, 0.0.0.0) | `/etc/my.cnf` | BAS-02 |
