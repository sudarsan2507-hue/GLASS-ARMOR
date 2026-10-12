"""Signed software update manifests. Post-quantum version (ML-DSA-65).

The release server signs a manifest {name, version, sha256} for each package with
ML-DSA-65 (with a fixed context string). Clients check the signature and the package
hash, and only install versions that are newer than the installed one (rollback protection).

manifest = JSON bytes {"name", "version", "sha256", "alg", "signature" (base64)}
"""
import base64
import hashlib
import json

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ALG = "ML-DSA-65"
CONTEXT = b"pq-gate update manifest v1"


def generate_keypair():
    """Return (public_key, private_key) as bytes for the release server."""
    with oqs.Signature(ALG) as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key


def _signed_fields(name, version, sha256_hex):
    return json.dumps({"name": name, "version": version, "sha256": sha256_hex},
                      sort_keys=True).encode()


def sign_release(private_key, name, version, package):
    """Return manifest bytes for `package` (bytes) at `version` (e.g. "1.4.2")."""
    digest = hashlib.sha256(package).hexdigest()
    with oqs.Signature(ALG, secret_key=private_key) as sig:
        signature = sig.sign_with_ctx_str(_signed_fields(name, version, digest), CONTEXT)
    return json.dumps({"name": name, "version": version, "sha256": digest, "alg": ALG,
                       "signature": base64.b64encode(signature).decode()}).encode()


def verify_release(public_key, package, manifest):
    """Return True if the manifest signature is valid and matches the package."""
    try:
        m = json.loads(manifest)
        if hashlib.sha256(package).hexdigest() != m["sha256"]:
            return False
        if m["alg"] == "ES256":  # releases signed before the migration
            key = serialization.load_pem_public_key(public_key)
            key.verify(base64.b64decode(m["signature"]),
                       _signed_fields(m["name"], m["version"], m["sha256"]),
                       ec.ECDSA(hashes.SHA256()))
            return True
        if m["alg"] != ALG:
            return False
        with oqs.Signature(ALG) as sig:
            return sig.verify_with_ctx_str(_signed_fields(m["name"], m["version"], m["sha256"]),
                                           base64.b64decode(m["signature"]), CONTEXT, public_key)
    except Exception:
        return False


def _version_tuple(version):
    return tuple(int(part) for part in version.split("."))


def should_install(public_key, package, manifest, installed_version):
    """True if the release is authentic and newer than installed_version."""
    if not verify_release(public_key, package, manifest):
        return False
    return _version_tuple(json.loads(manifest)["version"]) > _version_tuple(installed_version)
