#!/usr/bin/env python3
"""Validate unit syntax using project-local copies; never start system services."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
(root / ".tmp").mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix="unit-check-", dir=root / ".tmp") as temp:
    target = Path(temp)
    units = ["anbridge-api.service", "anbridge-deploy.service"]
    for name in units:
        text = (root / "deploy/systemd" / name).read_text()
        text = text.replace("/usr/local/bin/anbridge", str(root / "bin/anbridge"))
        (target / name).write_text(text)
    (target / "nginx.service").write_text(
        "[Unit]\nDescription=Syntax-check dependency placeholder\n"
        "[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n"
    )
    environment = os.environ.copy()
    environment["SYSTEMD_UNIT_PATH"] = str(target) + ":/usr/lib/systemd/system:/lib/systemd/system"
    environment["TMPDIR"] = str(root / ".tmp")
    subprocess.run(
        ["systemd-analyze", "verify", "--man=no"] + [str(target / name) for name in units],
        env=environment, check=True,
    )
print("systemd unit syntax verified; services were not installed or started")
