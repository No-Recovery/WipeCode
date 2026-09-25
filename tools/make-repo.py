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
import subprocess
import sys
import tarfile

ARCH = "iphoneos-arm64"
COMPONENT = "main"
SUITE = "stable"
ORIGIN = "WipeCode"
POOL = f"pool/{COMPONENT}/w/wipecode"

# Clients disagree about which binary-<arch> they fetch. The packages really are
# arm64 only, but an arm64 package list is also a valid answer for the generic
# spellings, so mirroring the index across them costs nothing and removes a whole
# class of "Packages returned status 404" that only shows up on a device.
ARCH_DIRS = ["iphoneos-arm64", "iphoneos-arm", "all"]

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


def write_text(path, text):
    # newline="\n" keeps the working copy LF on Windows; .gitattributes stores LF.
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def write_gz(path, text):
    # mtime=0 keeps the output byte-identical across runs so CI only commits
    # when the contents actually change.
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as raw, gzip.GzipFile(
        filename="", mode="wb", fileobj=raw, mtime=0
    ) as fh:
        fh.write(text.encode("utf-8"))


def checksum_lines(root, names):
    md5, sha256 = [], []
    for name in names:
        full = os.path.join(root, *name.split("/"))
        size = os.path.getsize(full)
        md5.append(f" {digests(full)[0]} {size} {name}")
        sha256.append(f" {digests(full)[2]} {size} {name}")
    return md5, sha256


# Sileo rejects a source whose bare URL 404s, and it may also look for the
# conventional dists/ tree. Serving both layouts means neither client has a
# reason to fail.
INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WipeCode package source</title>
<style>
body {{ font: 15px/1.6 -apple-system, system-ui, sans-serif; margin: 2rem auto; max-width: 40rem; padding: 0 1rem; }}
code {{ background: #f2f2f7; padding: .1rem .3rem; border-radius: .25rem; }}
</style>
</head>
<body>
<h1>WipeCode</h1>
<p>Add this URL as a package source in Sileo or Zebra:</p>
<p><code>{base}</code></p>
<p>Install <code>com.vo1dek.wipecode-sb</code> first, then
<code>com.vo1dek.wipecode-pref</code>.</p>
<p>Warning: this tweak performs Erase All Content and Settings. It is
irreversible. Test on a device with nothing on it.</p>
</body>
</html>
"""


def export_public_key(out_dir, fingerprint, gpg_home):
    """Publish the armored public key next to the index.

    Sileo can only trust the source once it holds this key, and the only way for
    the user to get it is over HTTP from the source itself.
    """
    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg not found; cannot export the public key")
    armored = subprocess.run(
        [gpg, "--homedir", gpg_home, "--batch", "--armor", "--export", fingerprint],
        check=True, capture_output=True,
    ).stdout
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in armored:
        raise SystemExit("exported key is not a public key block")
    path = os.path.join(out_dir, "WipeCode-index-signing-key.asc")
    with open(path, "wb") as fh:
        fh.write(armored)
    return path


def sign_release(release_path, fingerprint, gpg_home, passphrase):
    """Write the clearsigned InRelease and the detached Release.gpg beside it.

    Sileo validates the signature on a source and rejects an unsigned one with a
    misleading "Packages returned status 404", so these are not optional.
    """
    # dists/<suite>/Release has no extension to split on, so build the sibling
    # names from the directory instead of from splitext().
    here = os.path.dirname(release_path)
    inrelease = os.path.join(here, "InRelease")
    detached = os.path.join(here, "Release.gpg")

    # which() rather than a bare "gpg": CreateProcess does not apply PATHEXT, so
    # on Windows the extensionless name is not found.
    gpg = shutil.which("gpg")
    if gpg is None:
        raise SystemExit("gpg not found; cannot sign the index")

    common = [gpg, "--homedir", gpg_home, "--batch", "--yes", "--pinentry-mode", "loopback"]
    if passphrase:
        common += ["--passphrase", passphrase]

    subprocess.run(
        common + ["--armor", "--detach-sign", "--local-user", fingerprint,
                  "--output", detached, release_path],
        check=True,
    )
    subprocess.run(
        common + ["--clearsign", "--local-user", fingerprint,
                  "--output", inrelease, release_path],
        check=True,
    )
    return inrelease, detached


def build(out_dir, debs, fingerprint=None, gpg_home=None, passphrase=None):
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
    # Date is derived from the newest input .deb rather than "now", so re-running
    # with the same inputs produces byte-identical output and CI stays a no-op.
    date = email.utils.formatdate(max(os.path.getmtime(d) for d in debs), usegmt=True)
    suite_version = max(versions)

    # Flat layout, at the source root.
    write_text(os.path.join(out_dir, "Packages"), packages)
    write_gz(os.path.join(out_dir, "Packages.gz"), packages)
    md5, sha256 = checksum_lines(out_dir, ["Packages", "Packages.gz"])
    write_text(
        os.path.join(out_dir, "Release"),
        "\n".join(
            [
                f"Origin: {ORIGIN}",
                f"Label: {ORIGIN}",
                f"Suite: {SUITE}",
                f"Codename: {SUITE}",
                # Tracked from the packages themselves so the suite version cannot
                # drift away from what is actually being offered.
                f"Version: {suite_version}",
                f"Architectures: {ARCH}",
                f"Components: {COMPONENT}",
                f"Date: {date}",
                "MD5Sum:",
                *md5,
                "SHA256:",
                *sha256,
                "",
            ]
        ),
    )

    # Conventional dists/ layout, which is what APT proper looks for. The index is
    # mirrored across every binary-<arch> spelling a client might ask for.
    for arch_dir in ARCH_DIRS:
        binary = f"dists/{SUITE}/{COMPONENT}/binary-{arch_dir}"
        write_text(os.path.join(out_dir, binary, "Packages"), packages)
        write_gz(os.path.join(out_dir, binary, "Packages.gz"), packages)
        md5, sha256 = checksum_lines(
            out_dir, [f"{binary}/Packages", f"{binary}/Packages.gz"]
        )
        write_text(
            os.path.join(out_dir, binary, "Release"),
            "\n".join(
                [
                    f"Origin: {ORIGIN}",
                    f"Label: {ORIGIN}",
                    f"Suite: {SUITE}",
                    f"Codename: {SUITE}",
                    f"Version: {suite_version}",
                    f"Architectures: {arch_dir}",
                    f"Components: {COMPONENT}",
                    f"Date: {date}",
                    "MD5Sum:",
                    *md5,
                    "SHA256:",
                    *sha256,
                    "",
                ]
            ),
        )

    # The suite Release must account for the per-component files, named relative
    # to dists/<suite>/. All three are listed: apt looks for Release plus both
    # Packages variants, and a missing entry makes it fall back badly.
    comp_files = []
    for arch_dir in ARCH_DIRS:
        binary = f"{COMPONENT}/binary-{arch_dir}"
        comp_files += [f"{binary}/Release", f"{binary}/Packages", f"{binary}/Packages.gz"]
    md5, sha256 = checksum_lines(os.path.join(out_dir, "dists", SUITE), comp_files)
    write_text(
        os.path.join(out_dir, "dists", SUITE, "Release"),
        "\n".join(
            [
                f"Origin: {ORIGIN}",
                f"Label: {ORIGIN}",
                f"Suite: {SUITE}",
                f"Codename: {SUITE}",
                f"Version: {suite_version}",
                f"Architectures: {ARCH}",
                f"Components: {COMPONENT}",
                f"Date: {date}",
                "MD5Sum:",
                *md5,
                "SHA256:",
                *sha256,
                "",
            ]
        ),
    )

    # A bare index.html so the source root answers 200 instead of 404; Sileo
    # validates the base URL before it will accept a source.
    write_text(
        os.path.join(out_dir, "index.html"),
        INDEX_HTML.format(base="https://no-recovery.github.io/WipeCode"),
    )

    if fingerprint:
        export_public_key(out_dir, fingerprint, gpg_home)
        # The suite Release is what apt verifies, so that is the one signed.
        sign_release(
            os.path.join(out_dir, "dists", SUITE, "Release"),
            fingerprint,
            gpg_home,
            passphrase,
        )

    return len(debs)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out", help="output directory (the apt repo root)")
    ap.add_argument("debs", nargs="+", help="input .deb files")
    ap.add_argument("--sign-key", help="fingerprint of the index signing key")
    ap.add_argument("--gpg-home", help="GnuPG home holding the signing key")
    ap.add_argument("--gpg-passphrase", default="", help="passphrase for that key")
    args = ap.parse_args()

    missing = [d for d in args.debs if not os.path.isfile(d)]
    if missing:
        sys.exit("missing: " + ", ".join(missing))

    if args.sign_key and not args.gpg_home:
        sys.exit("--sign-key also needs --gpg-home")

    count = build(
        args.out,
        args.debs,
        fingerprint=args.sign_key,
        gpg_home=args.gpg_home,
        passphrase=args.gpg_passphrase,
    )
    print(f"wrote apt repo with {count} package(s) to {args.out}")


if __name__ == "__main__":
    main()
