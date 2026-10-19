"""Signed software update manifests (ML-KEM / ML-DSA).

The release server signs a manifest {name, version, sha256} for each package.
Clients check the signature and the package hash, and only install versions that are
newer than the installed one (rollback protection).

manifest = JSON bytes {"name", "version", "sha256", "alg", "signature" (base64)}
"""
import base64
import hashlib
import json

from oqs import Signature
from cryptography.hazmat.primitives import hashes

ALG = "ML-DSA-65"


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the release server."""
    sig = Signature("ML-DSA-65")
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    return public_key, secret_key


def _signed_fields(name, version, sha256_hex):
    return json.dumps({"name": name, "version": version, "sha256": sha256_hex},
                      sort_keys=True).encode()


def sign_release(private_key, name, version, package):
    """Return manifest bytes for `package` (bytes) at `version` (e.g. "1.4.2")."""
    digest = hashlib.sha256(package).hexdigest()
    sig = Signature("ML-DSA-65", secret_key=private_key)
    signature = sig.sign(_signed_fields(name, version, digest))
    return json.dumps({"name": name, "version": version, "sha256": digest, "alg": ALG,
                       "signature": base64.b64encode(signature).decode()}).encode()


def verify_release(public_key, package, manifest):
    """Return True if the manifest signature is valid and matches the package."""
    try:
        m = json.loads(manifest)
        if m["alg"] != ALG or hashlib.sha256(package).hexdigest() != m["sha256"]:
            return False
        sig = Signature("ML-DSA-65")
        sig.import_public_key(public_key)
        sig.verify(base64.b64decode(m["signature"]),
                   _signed_fields(m["name"], m["version"], m["sha256"]))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def _version_tuple(version):
    return tuple(int(part) for part in version.split("."))


def should_install(public_key, package, manifest, installed_version):
    """True if the release is authentic and newer than installed_version."""
    if not verify_release(public_key, package, manifest):
        return False
    return _version_tuple(json.loads(manifest)["version"]) > _version_tuple(installed_version)
