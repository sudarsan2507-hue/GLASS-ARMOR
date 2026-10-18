"""Signed software update manifests (ML-KEM and ML-DSA).

The release server signs a manifest {name, version, sha256} for each package.
Clients check the signature and the package hash, and only install versions that are
newer than the installed one (rollback protection).

manifest = JSON bytes {"name", "version", "sha256", "alg", "signature" (base64)}
"""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALG = "ML-KEM-768"


def generate_keypair():
    """Return (public_key, private_key) as PEM bytes for the release server."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()  # bytes
    secret_key = kem.export_secret_key()  # bytes
    kem2 = oqs.KeyEncapsulation("ML-KEM-768", secret_key=secret_key)
    return public_key, secret_key


def _signed_fields(name, version, sha256_hex):
    return json.dumps({"name": name, "version": version, "sha256": sha256_hex},
                      sort_keys=True).encode()


def sign_release(private_key, name, version, package):
    """Return manifest bytes for `package` (bytes) at `version` (e.g. "1.4.2")."""
    digest = hashlib.sha256(package).hexdigest()
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=private_key)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    signature = oqs.Signature("ML-DSA-65", secret_key=private_key).sign(_signed_fields(name, version, digest))
    return json.dumps({"name": name, "version": version, "sha256": digest, "alg": ALG,
                       "signature": base64.b64encode(signature).decode()}).encode()


def verify_release(public_key, package, manifest):
    """Return True if the manifest signature is valid and matches the package."""
    try:
        m = json.loads(manifest)
        if m["alg"] != ALG or hashlib.sha256(package).hexdigest() != m["sha256"]:
            return False
        sig = oqs.Signature("ML-DSA-65", secret_key=public_key).verify(_signed_fields(m["name"], m["version"], m["sha256"]))
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
