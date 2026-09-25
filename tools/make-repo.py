#!/usr/bin/env python3
"""Turn a directory of .deb files into a minimal apt/Debian repository.

Sileo, Zebra and APT expect a directory containing Packages, Packages.gz and
Release, with the actual packages reachable relative to that directory via the
Filename field. This script lays that out under <out>/pool/main/w/wipecode/.
"""

import argparse
import email.utils
import gzip
import hashlib
import io
import lzma
import os
import shutil
import sys
import tarfile

ARCH = "iphoneos-arm64"
COMPONENT = "main"
SUITE = "stable"
ORIGIN = "WipeCode"
POOL = f"pool/{COMPONENT}/w/wipecode"

# Fields we regenerate ourselves; whatever the .deb control says is dropped.
GENERATED = {"filename", "size", "md5sum", "sha1", "sha256"}

# Field order apt clients expect to see first.
FIELD_ORDER = [
    "Package",
    "Name",
    "Version",
    "Architecture",
    "Essential",
    "Section",
    "Priority",
    "Installed-Size",
    "Maintainer",
    "Depends",
    "Recommends",
    "Conflicts",
    "Breaks",
    "Replaces",
    "Provides",
    "Description",
]


def ar_members(raw):
    if raw[:8] != b"!<arch>\n":
        raise ValueError("not a deb (ar) archive")
    pos, out = 8, []
    while pos + 60 <= len(raw):
        name = raw[pos : pos + 16].decode().strip().rstrip("/")
        size = int(raw[pos + 48 : pos + 58].decode().strip())
        out.append((name, raw[pos + 60 : pos + 60 + size]))
        pos += 60 + size + (size % 2)
    return out


def maybe_decompress(name, body):
    if name.endswith(".xz"):
        return lzma.decompress(body)
    if name.endswith(".gz"):
        return gzip.decompress(body)
    return body


def read_control(deb_path):
    with open(deb_path, "rb") as fh:
        members = ar_members(fh.read())
    for name, body in members:
        if not name.startswith("control.tar"):
            continue
        with tarfile.open(fileobj=io.BytesIO(maybe_decompress(name, body))) as tar:
            for member in tar.getmembers():
                if member.name.lstrip("./") == "control":
                    text = tar.extractfile(member).read().decode("utf-8")
                    return parse_control(text)
    raise ValueError(f"{deb_path}: no DEBIAN/control found")


def parse_control(text):
    fields, key = {}, None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t" and key:
            fields[key] += "\n" + line
        else:
            key, _, value = line.partition(":")
            key = key.strip()
            fields[key] = value.strip()
    return fields


def digests(path):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def stanza(control, filename, size, sums):
    md5, sha1, sha256 = sums
    merged = dict(control)
    merged["Filename"] = filename
    merged["Size"] = str(size)
    merged["MD5sum"] = md5
    merged["SHA1"] = sha1
    merged["SHA256"] = sha256

    lines, seen = [], set()
    for field in FIELD_ORDER:
        if field in merged and field not in GENERATED:
            lines.append(f"{field}: {merged[field]}")
            seen.add(field)
    for field in sorted(merged):
        if field in seen or field in GENERATED:
            continue
        lines.append(f"{field}: {merged[field]}")
    return "\n".join(lines)


def build(out_dir, debs):
    pool_dir = os.path.join(out_dir, *POOL.split("/"))
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(pool_dir)

    stanzas = []
    versions = []
    for deb in sorted(debs):
        base = os.path.basename(deb)
        target = os.path.join(pool_dir, base)
        shutil.copy2(deb, target)
        control = read_control(deb)
        versions.append(control.get("Version", "0"))
        stanzas.append(
            stanza(control, f"{POOL}/{base}", os.path.getsize(target), digests(target))
        )

    packages = "\n\n".join(stanzas) + "\n"
    # newline="\n" keeps the working copy LF on Windows; .gitattributes stores LF.
    with open(os.path.join(out_dir, "Packages"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(packages)
    # mtime=0 keeps the output byte-identical across runs so CI only commits
    # when the contents actually change.
    gz_path = os.path.join(out_dir, "Packages.gz")
    with open(gz_path, "wb") as raw, gzip.GzipFile(
        filename="", mode="wb", fileobj=raw, mtime=0
    ) as fh:
        fh.write(packages.encode("utf-8"))

    index = ["Packages", "Packages.gz"]
    sections = {"MD5Sum": [], "SHA256": []}
    for name in index:
        full = os.path.join(out_dir, name)
        size = os.path.getsize(full)
        sections["MD5Sum"].append(f" {digests(full)[0]} {size} {name}")
        sections["SHA256"].append(f" {digests(full)[2]} {size} {name}")

    # Date is derived from the newest input .deb rather than "now", so re-running
    # with the same inputs produces a byte-identical Release and CI stays a no-op.
    newest = max(os.path.getmtime(d) for d in debs)
    release = [
        f"Origin: {ORIGIN}",
        f"Label: {ORIGIN}",
        f"Suite: {SUITE}",
        f"Codename: {SUITE}",
        # Tracked from the packages themselves so the suite version cannot drift
        # away from what is actually being offered.
        f"Version: {max(versions)}",
        f"Architectures: {ARCH}",
        f"Components: {COMPONENT}",
        f"Date: {email.utils.formatdate(newest, usegmt=True)}",
        "MD5Sum:",
        *sections["MD5Sum"],
        "SHA256:",
        *sections["SHA256"],
        "",
    ]
    with open(os.path.join(out_dir, "Release"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(release))

    return len(debs)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out", help="output directory (the apt repo root)")
    ap.add_argument("debs", nargs="+", help="input .deb files")
    args = ap.parse_args()

    missing = [d for d in args.debs if not os.path.isfile(d)]
    if missing:
        sys.exit("missing: " + ", ".join(missing))

    count = build(args.out, args.debs)
    print(f"wrote apt repo with {count} package(s) to {args.out}")


if __name__ == "__main__":
    main()
