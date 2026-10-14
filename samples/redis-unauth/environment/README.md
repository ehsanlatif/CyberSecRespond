# environment/disk.tar.gz is produced by build_disk.py

Run `python3 build_disk.py tasks/<range>` after generation to synthesise the forensic image here (+ sha256) and augment `sas-mock/` with the CTI/handoff materials. The Docker build (context = this directory) bakes it read-only at `/disk`; `sas-mock/` is baked at `/sas`.

Every path cited in `tests/manifest.json` must exist inside the image (QA gate: manifest ↔ disk 100%).
