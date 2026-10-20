"""Signed software update manifests (ML‑DSA‑65, post‑quantum).

The release server signs a manifest {name, version, sha256} for each package.
Clients check the signature and the package hash, and only install versions that are
newer than the installed one (rollback protection).

manifest = JSON bytes {"name", "version", "sha256", "alg", "signature" (base64)}
"""

import base64
import hashlib
import json

import oqs

# Algorithm identifier used in the manifest
ALG = "ML-DSA-65"


def generate_keypair():
    """Return (public_key, private_key) as raw bytes for the release server.

    The keys are generated with liboqs using the ML‑DSA‑65 signature scheme.
    """
    signer = oqs.Signature(ALG)
    public_key = signer.generate_keypair()          # bytes
    private_key = signer.export_secret_key()        # bytes
    return public_key, private_key


def _signed_fields(name, version, sha256_hex):
    """Canonical byte representation of the fields that are signed."""
    return json.dumps(
        {"name": name, "version": version, "sha256": sha256_hex},
        sort_keys=True,
    ).encode()


def sign_release(private_key, name, version, package):
    """Return manifest bytes for `package` (bytes) at `version` (e.g. "1.4.2").

    The manifest contains the package hash, the algorithm identifier and a
    base‑64 encoded ML‑DSA‑65 signature.
    """
    digest = hashlib.sha256(package).hexdigest()
    signer = oqs.Signature(ALG, secret_key=private_key)
    signature = signer.sign(_signed_fields(name, version, digest))
    manifest = {
        "name": name,
        "version": version,
        "sha256": digest,
        "alg": ALG,
        "signature": base64.b64encode(signature).decode(),
    }
    return json.dumps(manifest).encode()


def verify_release(public_key, package, manifest):
    """Return True if the manifest signature is valid and matches the package."""
    try:
        m = json.loads(manifest)
        if m["alg"] != ALG or hashlib.sha256(package).hexdigest() != m["sha256"]:
            return False

        signature = base64.b64decode(m["signature"])
        verifier = oqs.Signature(ALG)
        ok = verifier.verify(
            _signed_fields(m["name"], m["version"], m["sha256"]),
            signature,
            public_key,
        )
        return ok
    except (ValueError, KeyError, Exception):
        return False


def _version_tuple(version):
    """Convert a dotted version string into a comparable tuple of ints."""
    return tuple(int(part) for part in version.split("."))


def should_install(public_key, package, manifest, installed_version):
    """True if the release is authentic and newer than installed_version."""
    if not verify_release(public_key, package, manifest):
        return False
    return _version_tuple(json.loads(manifest)["version"]) > _version_tuple(
        installed_version
    )
