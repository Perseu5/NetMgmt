#!/usr/bin/env python3
"""
Build PAN-OS custom App-ID pattern values from a folder of CA certificates.

Reads every .cer / .crt / .pem / .der file in the folder (PEM or DER; several
certs in one PEM file are fine) and writes a copy/paste sheet with, per cert:
  - Verification values: SPKI SHA-256 (base64 + hex), thumbprint SHA-256
  - Or Condition values to paste into the GUI:
      SKI pattern  \\x8014<ski>\\x        -> blocks every cert this CA signed
      CN pattern   \\x550403<t><l>\\x<CN>  -> backup match on the CA name

Optional: --known hashes.txt  (one SPKI or thumbprint SHA-256 per line,
base64 or hex, colons/spaces OK) to confirm each cert is one you meant.

Usage:
  pip install cryptography
  python3 panos_cert_patterns.py <folder> [--known hashes.txt]

Output: <folder>/panos_patterns.txt
"""
import argparse, base64, binascii, hashlib, re, sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
except ImportError:
    sys.exit("Missing package. Run:  pip install cryptography")

EXTS = {".cer", ".crt", ".pem", ".der"}
REGEX_SPECIAL = set(".*+?()[]{}|^$\\")


def load_certs(path):
    data = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificates(data)
    return [x509.load_der_x509_certificate(data)]


def norm_hash(text):
    """Return lowercase hex for a base64 or hex SHA-256 hash, or None."""
    t = re.sub(r"[\s:]", "", text.strip())
    if not t or t.startswith("#"):
        return None
    if re.fullmatch(r"[0-9a-fA-F]{64}", t):
        return t.lower()
    try:
        raw = base64.b64decode(t, validate=True)
        if len(raw) == 32:
            return raw.hex()
    except (binascii.Error, ValueError):
        pass
    return None


def esc(text):
    return "".join("\\" + c if c in REGEX_SPECIAL else c for c in text)


def cn_pattern(cert):
    der = cert.subject.public_bytes()
    i = der.find(b"\x06\x03\x55\x04\x03")  # OID 2.5.4.3 commonName
    if i < 0:
        return "", ""
    tag, ln = der[i + 5], der[i + 6]
    if ln & 0x80:  # CN longer than 127 bytes: skip
        return "", ""
    raw = der[i + 7:i + 7 + ln]
    cn = raw.decode("utf-8", "replace")
    if any(b > 0x7E or b < 0x20 for b in raw):
        # Non-ASCII CN: emit as pure hex so the bytes match exactly
        return cn, f"\\x550403{tag:02x}{ln:02x}{raw.hex()}\\x"
    return cn, f"\\x550403{tag:02x}{ln:02x}\\x{esc(cn)}"


def analyze(cert):
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    h = hashlib.sha256(spki).digest()
    try:
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        note = ""
    except x509.ExtensionNotFound:
        ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
        note = "No SKI extension in this cert; value was computed. Confirm it matches a leaf's AKI."
    cn, cnp = cn_pattern(cert)
    exp = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "expires": exp.date().isoformat(),
        "spki_b64": base64.b64encode(h).decode(),
        "spki_hex": h.hex(),
        "thumb": cert.fingerprint(hashes.SHA256()).hex(),
        "ski": ski.hex(),
        "ski_pattern": f"\\x80{len(ski):02x}{ski.hex()}\\x",
        "ski_note": note,
        "cn": cn,
        "cn_pattern": cnp,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--known", help="file of known SPKI/thumbprint SHA-256 hashes")
    a = ap.parse_args()

    folder = Path(a.folder)
    files = sorted(p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in EXTS)
    if not files:
        sys.exit(f"No .cer/.crt/.pem/.der files in {folder}")

    known = {}
    if a.known:
        for line in Path(a.known).read_text().splitlines():
            hx = norm_hash(line)
            if hx:
                known[hx] = False
            elif line.strip() and not line.strip().startswith("#"):
                print(f"WARNING: could not read hash line: {line.strip()}")

    rows, seen = [], set()
    for f in files:
        try:
            certs = load_certs(f)
        except Exception as e:
            print(f"SKIP {f.name}: not a readable certificate ({e})")
            continue
        for i, c in enumerate(certs):
            r = analyze(c)
            r["file"] = f.name if len(certs) == 1 else f"{f.name} (cert {i + 1})"
            r["dup"] = r["ski"] in seen
            seen.add(r["ski"])
            if known:
                hits = []
                if r["spki_hex"] in known:
                    known[r["spki_hex"]] = True; hits.append("SPKI hash")
                if r["thumb"] in known:
                    known[r["thumb"]] = True; hits.append("thumbprint")
                r["verified"] = "YES - matched " + " and ".join(hits) if hits else "NO - not in your hash list"
            else:
                r["verified"] = "not checked (no --known file given)"
            rows.append(r)

    L = []
    L.append("PAN-OS custom application: Or Condition values")
    L.append("=" * 72)
    L.append("Every Or Condition goes under the SAME And Condition.")
    L.append("For each one:  Operator = Pattern Match   Context = ssl-rsp-certificate")
    L.append("               Qualifier = (leave empty)")
    L.append("Copy only the text after 'Pattern:'.")
    L.append("")

    n = 0
    for r in rows:
        n += 1
        L.append("-" * 72)
        L.append(f"[{n}] {r['file']}")
        L.append("-" * 72)
        L.append(f"Subject:     {r['subject']}")
        L.append(f"Issuer:      {r['issuer']}")
        L.append(f"Expires:     {r['expires']}")
        L.append("")
        L.append("Verify before using:")
        L.append(f"  Verified:            {r['verified']}")
        L.append(f"  SPKI SHA-256 b64:    {r['spki_b64']}")
        L.append(f"  SPKI SHA-256 hex:    {r['spki_hex']}")
        L.append(f"  Thumbprint SHA-256:  {r['thumb']}")
        L.append(f"  SKI:                 {r['ski']}")
        if r["ski_note"]:
            L.append(f"  NOTE: {r['ski_note']}")
        if r["dup"]:
            L.append("  NOTE: same SKI as an earlier cert. You do not need to add it again.")
        if r["verified"].startswith("NO"):
            L.append("  WARNING: this cert is not in your hash list. Do not add it unless you are sure.")
        L.append("")
        L.append("Or Condition 1 (main block)")
        L.append(f"  Name:     int{n:02d}-ski")
        L.append(f"  Pattern:  {r['ski_pattern']}")
        L.append("")
        if r["cn_pattern"]:
            L.append("Or Condition 2 (backup, matches CA name)")
            L.append(f"  Name:     int{n:02d}-cn")
            L.append(f"  Pattern:  {r['cn_pattern']}")
            L.append(f"  (CN text: {r['cn']})")
        else:
            L.append("Or Condition 2: no usable CN in this cert, skip.")
        L.append("")

    L.append("=" * 72)
    L.append(f"Certificates processed: {len(rows)}")
    if known:
        missing = [h for h, hit in known.items() if not hit]
        bad = [r["file"] for r in rows if r["verified"].startswith("NO")]
        if bad:
            L.append("Certs NOT in your hash list: " + ", ".join(bad))
        if missing:
            L.append(f"Hashes from your list with no matching cert ({len(missing)}):")
            L.extend(f"  {h}" for h in missing)
        if not bad and not missing:
            L.append("All certs verified, and every hash in your list was matched.")

    out = folder / "panos_patterns.txt"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
