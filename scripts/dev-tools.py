#!/usr/bin/env python3
"""Download/extract Debian development tools locally; never install packages.

Uses signed Debian backports metadata for Go 1.27 and local APT metadata for Nginx.
Requires Debian 13's sqv and archive keyring. Does not add APT sources or install
packages. This helper is for development, not production updates.
"""
import concurrent.futures
import hashlib
import json
import lzma
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".tools"
DOWNLOADS = TOOLS / "downloads"


def apt_record(name):
    raw = subprocess.check_output(["apt-cache", "show", name], text=True).split("\n\n")[0]
    return dict(
        line.split(": ", 1)
        for line in raw.splitlines()
        if ": " in line and not line.startswith(" ")
    )
def download(metadata):
    name = metadata["Package"]
    filename = metadata["Filename"]
    archive = "debian-security" if filename.startswith("pool/updates/") else "debian"
    source = f"https://deb.debian.org/{archive}/{filename}"
    destination = DOWNLOADS / Path(filename).name
    if not destination.exists() or hashlib.sha256(destination.read_bytes()).hexdigest() != metadata["SHA256"]:
        temporary = destination.with_suffix(destination.suffix + ".partial")
        with urllib.request.urlopen(source, timeout=60) as response, temporary.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        if hashlib.sha256(temporary.read_bytes()).hexdigest() != metadata["SHA256"]:
            temporary.unlink()
            raise RuntimeError(f"SHA256 verification failed for {name}")
        temporary.replace(destination)
    subprocess.run(["dpkg-deb", "-x", str(destination), str(TOOLS / "sysroot")], check=True)
    return {"package": name, "version": metadata["Version"], "sha256": metadata["SHA256"], "source": source}


def backports_records():
    directory = TOOLS / "apt-backports"
    directory.mkdir(exist_ok=True)
    base = "https://deb.debian.org/debian/dists/trixie-backports/"
    with urllib.request.urlopen(base + "InRelease", timeout=30) as response:
        (directory / "InRelease").write_bytes(response.read())
    authenticated = directory / "Release.verified.new"
    authenticated.unlink(missing_ok=True)
    subprocess.run([
        "sqv", "--keyring", "/usr/share/keyrings/debian-archive-keyring.pgp",
        "--cleartext", "--output", str(authenticated), str(directory / "InRelease")
    ], check=True)
    text = authenticated.read_text()
    authenticated.replace(directory / "Release.verified")
    from datetime import datetime, timezone
    from email.utils import parsedate_to_datetime
    for line in text.splitlines():
        if line.startswith("Valid-Until: ") and parsedate_to_datetime(line[13:]) < datetime.now(timezone.utc):
            raise RuntimeError("Debian Release metadata expired")
    index = "main/binary-amd64/Packages.xz"
    hashes = text.split("SHA256:\n", 1)[1]
    expected = next(
        line.split()[0] for line in hashes.splitlines()
        if len(line.split()) == 3 and line.split()[2] == index
    )
    with urllib.request.urlopen(base + index, timeout=30) as response:
        compressed = response.read()
    if hashlib.sha256(compressed).hexdigest() != expected:
        raise RuntimeError("Debian package index checksum mismatch")
    (directory / "Packages.xz").write_bytes(compressed)
    records = []
    for block in lzma.decompress(compressed).decode().split("\n\n"):
        record = dict(
            line.split(": ", 1) for line in block.splitlines()
            if ": " in line and not line.startswith(" ")
        )
        if record.get("Package") in ["golang-1.27-go", "golang-1.27-src"]:
            records.append(record)
    if len(records) != 2:
        raise RuntimeError("Go 1.27 package pair unavailable in signed metadata")
    return records


def main():
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    packages = backports_records() + [apt_record("nginx")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        records = list(executor.map(download, packages))
    (TOOLS / "manifest.json").write_text(json.dumps(records, indent=2) + "\n")
    for record in records:
        print(f'{record["package"]} {record["version"]}: verified and extracted')


if __name__ == "__main__":
    main()
