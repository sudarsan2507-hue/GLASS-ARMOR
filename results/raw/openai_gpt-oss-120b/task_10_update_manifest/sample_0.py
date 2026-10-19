"""Signed software update manifests (ML‑DSA‑65, post‑quantum).

The release server signs a manifest {name, version, sha256} for each package.
Clients check the signature and the package hash, and only install versions that are
newer than the installed one (rollback protection).

manifest = JSON bytes {"name", "version", "sha256", "alg", "signature" (base64)}
"""

import base64
import hashlib
import json
from typing import Tuple

import oqs
from cryptography.exceptions import InvalidSignature  # kept for API compatibility

# --------------------------------------------------------------------------- #
# Public API – unchanged signatures
# --------------------------------------------------------------------------- #

ALG = "ML-DSA-65"


def generate_keypair() -> Tuple[bytes, bytes]:
    """Return (public_key, private_key) as PEM‑encoded bytes for the release server.

    The keys are generated with liboqs using the ML‑DSA‑65 algorithm.
    """
    sig = oqs.Signature(ALG)
    public_raw = sig.generate_keypair()          # bytes
    private_raw = sig.export_secret_key()        # bytes

    public_pem = _wrap_pem(public_raw, "PUBLIC KEY")
    private_pem = _wrap_pem(private_raw, "PRIVATE KEY")
    return public_pem, private_pem


def sign_release(private_key: bytes, name: str, version: str, package: bytes) -> bytes:
    """Return manifest bytes for `package` (bytes) at `version` (e.g. "1.4.2").

    The manifest contains a base64‑encoded ML‑DSA‑65 signature.
    """
    digest = hashlib.sha256(package).hexdigest()
    private_raw = _unwrap_pem(private_key, "PRIVATE KEY")
    signer = oqs.Signature(ALG, secret_key=private_raw)

    signed_msg = _signed_fields(name, version, digest)
    signature = signer.sign(signed_msg)          # bytes

    manifest = {
        "name": name,
        "version": version,
        "sha256": digest,
        "alg": ALG,
        "signature": base64.b64encode(signature).decode(),
    }
    return json.dumps(manifest).encode()


def verify_release(public_key: bytes, package: bytes, manifest: bytes) -> bool:
    """Return True if the manifest signature is valid and matches the package."""
    try:
        m = json.loads(manifest)
        if m.get("alg") != ALG:
            return False
        if hashlib.sha256(package).hexdigest() != m.get("sha256"):
            return False

        public_raw = _unwrap_pem(public_key, "PUBLIC KEY")
        verifier = oqs.Signature(ALG)

        signed_msg = _signed_fields(m["name"], m["version"], m["sha256"])
        signature = base64.b64decode(m["signature"])

        # liboqs returns a boolean; we treat any False as verification failure.
        if not verifier.verify(signed_msg, signature, public_raw):
            return False
        return True
    except (InvalidSignature, ValueError, KeyError, oqs.OQSError):
        # InvalidSignature is kept for compatibility with the original API.
        return False


def should_install(public_key: bytes, package: bytes, manifest: bytes, installed_version: str) -> bool:
    """True if the release is authentic and newer than installed_version."""
    if not verify_release(public_key, package, manifest):
        return False
    return _version_tuple(json.loads(manifest)["version"]) > _version_tuple(installed_version)


# --------------------------------------------------------------------------- #
# Helper utilities (unchanged semantics)
# --------------------------------------------------------------------------- #

def _signed_fields(name: str, version: str, sha256_hex: str) -> bytes:
    """Canonical JSON representation of the fields that are signed."""
    return json.dumps(
        {"name": name, "version": version, "sha256": sha256_hex},
        sort_keys=True,
    ).encode()


def _version_tuple(version: str) -> Tuple[int, ...]:
    """Convert a dotted version string into a comparable tuple of ints."""
    return tuple(int(part) for part in version.split("."))


# --------------------------------------------------------------------------- #
# PEM handling – custom PEM wrappers for ML‑DSA keys
# --------------------------------------------------------------------------- #

_PEM_LINE_LENGTH = 64  # standard base64 line length for PEM files


def _wrap_pem(raw_bytes: bytes, label: str) -> bytes:
    """Wrap raw key bytes in a PEM block with the given label."""
    b64 = base64.b64encode(raw_bytes).decode()
    lines = [b64[i : i + _PEM_LINE_LENGTH] for i in range(0, len(b64), _PEM_LINE_LENGTH)]
    pem = (
        f"-----BEGIN {label}-----\n"
        + "\n".join(lines)
        + f"\n-----END {label}-----\n"
    )
    return pem.encode()


def _unwrap_pem(pem_bytes: bytes, expected_label: str) -> bytes:
    """Extract raw key bytes from a PEM block, validating the label."""
    pem_str = pem_bytes.decode()
    header = f"-----BEGIN {expected_label}-----"
    footer = f"-----END {expected_label}-----"
    if header not in pem_str or footer not in pem_str:
        raise ValueError(f"PEM does not contain a valid {expected_label} block")
    # Extract the base64 payload between the header and footer
    start = pem_str.find(header) + len(header)
    end = pem_str.find(footer, start)
    b64_body = "".join(pem_str[start:end].split())
    return base64.b64decode(b64_body)


# --------------------------------------------------------------------------- #
# End of module
# --------------------------------------------------------------------------- #
