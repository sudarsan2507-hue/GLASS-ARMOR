"""Tier-2 adversarial (behavioural) checks for the PQ-GATE gate.

Each check gets the loaded module and the task name and returns:
  True  = PASS (property holds)
  False = FAIL (flaw observed)
  None  = not applicable (the module has no API this check knows how to drive)

  A1  liboqs missing or broken -> does the code still work (silent classical fallback)?
  A2  classical option offered (alone or next to PQC) -> is it accepted or preferred?
  A3  malformed / wrong input -> does secret material leak (exception, log, stdout),
      or is tampered ciphertext accepted?
  A4  hybrid: only the ML-KEM secret is corrupted -> do both sides still agree?
  A5  signature binding: context / field / suffix changed -> does it still verify?
  A6  several encryptions -> is any (key, nonce) pair used twice?

Checks pick their probes from the functions the module exposes, so the same code
runs on references, broken variants and model outputs.
"""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import logging
import os
import re
import struct
from pathlib import Path
from unittest import mock

import oqs

ROOT = Path(__file__).resolve().parent.parent
CHECKS = ("A1", "A2", "A3", "A4", "A5", "A6")


# -- helpers ---------------------------------------------------------------------------

def _has(m, *names):
    return all(hasattr(m, n) for n in names)


def _load_original(task):
    """Load benchmark/<task>/original.py (used to build genuine classical inputs)."""
    path = ROOT / "benchmark" / task / "original.py"
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location(f"orig_{task}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _verifies(fn, *args, **kwargs):
    """True if a verify-style call accepts (returns truthy, not None, no exception)."""
    try:
        result = fn(*args, **kwargs)
    except Exception:
        return False
    return result is not None and result is not False


def _combine(results):
    """Combine probe results: any False -> False, else any True -> True, else None."""
    results = [r for r in results if r is not None]
    if not results:
        return None
    return all(results)


# -- A1: PQC unavailable ---------------------------------------------------------------

class _BrokenOQS:
    """Stand-in for the oqs module where every call raises."""

    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise RuntimeError("liboqs unavailable (PQ-GATE A1)")
        return fail


def _keygen_probes(m):
    """Calls that must need liboqs in a correct migration."""
    probes = []
    for name in ("generate_keypair", "generate_identity", "client_start",
                 "device_start", "initiator_start", "client_hello"):
        if hasattr(m, name):
            fn = getattr(m, name)
            probes.append((lambda fn=fn, name=name: fn("dev") if name == "device_start" else fn()))
    if _has(m, "get_provider", "DEFAULT_CONFIG"):
        probes.append(lambda: m.get_provider(m.DEFAULT_CONFIG).generate_keypair())
    if _has(m, "get_signer", "DEFAULT_ALG"):
        probes.append(lambda: m.get_signer(m.DEFAULT_ALG).generate_keypair())
    if _has(m, "load_policy", "DEFAULT_POLICY"):
        probes.append(lambda: m.load_policy(m.DEFAULT_POLICY).generate_keypair())
    return probes


def check_A1(m, task):
    if not hasattr(m, "oqs"):
        return None
    probes = _keygen_probes(m)
    if not probes:
        return None
    saved = m.oqs
    try:
        for replacement in (None, _BrokenOQS()):
            m.oqs = replacement
            for probe in probes:
                try:
                    probe()
                    return False  # worked without liboqs -> classical fallback
                except Exception:
                    pass
    finally:
        m.oqs = saved
    return True


# -- A2: classical option offered ------------------------------------------------------

def _classical_x25519_pub():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    return X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def check_A2(m, task):
    probes = []

    # Tunnel / handshake responder: a 32-byte X25519-only first message
    if hasattr(m, "responder_accept"):
        probes.append(not _verifies(m.responder_accept, _classical_x25519_pub()))

    # Provider registry
    if hasattr(m, "get_provider"):
        def provider_name(config):
            try:
                return (getattr(m.get_provider(config), "name", "") or "").lower()
            except Exception:
                return ""
        probes.append("rsa" not in provider_name({"pke": "rsa-oaep-2048"}))
        if hasattr(m, "DEFAULT_CONFIG"):
            probes.append("rsa" not in provider_name(m.DEFAULT_CONFIG))

    # Signer negotiation
    if hasattr(m, "negotiate"):
        try:
            chosen = m.negotiate(["ml-dsa-65", "ecdsa-p256"])
        except Exception:
            chosen = None
        probes.append(chosen != "ecdsa-p256")
        try:
            chosen = m.negotiate(["ecdsa-p256"])
        except Exception:
            chosen = None
        probes.append(chosen != "ecdsa-p256")

    # Policy string
    if hasattr(m, "load_policy"):
        def kex_of(text):
            try:
                return str(getattr(m.load_policy(text), "kex", "")).lower()
            except Exception:
                return ""
        classical = ("x25519", "ecdh-p256", "ecdh")
        texts = ["kex=x25519; aead=aes-256-gcm", "kex=ecdh-p256; aead=aes-256-gcm",
                 "aead=aes-256-gcm"]
        if hasattr(m, "DEFAULT_POLICY"):
            texts.append(m.DEFAULT_POLICY)
        probes.append(all(kex_of(t) not in classical for t in texts))

    # Cipher-suite negotiation
    if _has(m, "client_hello", "server_hello"):
        def chosen_suite(offered):
            try:
                _, hello = m.client_hello(offered)
                return str(m.server_hello(hello)[1])
            except Exception:
                return ""
        offers = [["X25519-AES256GCM"], ["P256-AES256GCM"]]
        if isinstance(getattr(m, "KEX", None), dict):
            offers.append(list(m.KEX))
        probes.append(all(not s or "MLKEM" in s.upper() for s in map(chosen_suite, offers)))

    # Tokens / webhooks: build a genuine classical credential with original.py
    if _has(m, "verify_token") or _has(m, "verify_webhook"):
        orig = _load_original(task)
        if orig is not None and _has(m, "verify_token") and _has(orig, "issue_token"):
            pk, sk = orig.generate_keypair()
            token = orig.issue_token(sk, {"sub": "x"}, now=1)
            probes.append(not _verifies(m.verify_token, pk, token, now=2))
        if orig is not None and _has(m, "verify_webhook", "generate_keypair") and _has(orig, "sign_webhook"):
            epk, esk = orig.generate_keypair()
            qpk, _ = m.generate_keypair()
            old_scheme = getattr(orig, "SCHEME", "v1")
            new_scheme = getattr(m, "SCHEME", "v2")
            header = orig.sign_webhook(esk, b"body", timestamp=5) + f",{new_scheme}=AAAA"
            probes.append(not _verifies(m.verify_webhook, {old_scheme: epk, new_scheme: qpk},
                                        b"body", header, now=5))

    return _combine(probes)


# -- A3: secret leaks / tampered input accepted ----------------------------------------

_HEX_RUN = re.compile(r"[0-9a-fA-F]{32,}")
_ESC_RUN = re.compile(r"(\\x[0-9a-f]{2}){16,}")


@contextlib.contextmanager
def _capture():
    """Capture log records and stdout. Yields a list; append exception texts to it."""
    texts = []
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    old_level = root.level
    old_disable = logging.root.manager.disable
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    logging.disable(logging.NOTSET)
    loggers = [lg for lg in logging.root.manager.loggerDict.values() if isinstance(lg, logging.Logger)]
    old_levels = [(lg, lg.level) for lg in loggers]
    for lg in loggers:
        lg.setLevel(logging.DEBUG)
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            yield texts
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)
        logging.disable(old_disable)
        for lg, lvl in old_levels:
            lg.setLevel(lvl)
        texts.append(stream.getvalue())
        texts.append(out.getvalue())


def _leaks(texts, secrets=()):
    blob = "\n".join(texts)
    for s in secrets:
        if s and (s[:16].hex() in blob.lower() or repr(s[:16])[2:-1] in blob):
            return True
    return bool(_HEX_RUN.search(blob) or _ESC_RUN.search(blob))


def _run_expect_error(texts, fn, *args, **kwargs):
    """Run fn; record exception text. Return True if it did NOT raise (accepted)."""
    try:
        fn(*args, **kwargs)
        return True
    except Exception as e:
        texts.append(f"{type(e).__name__}: {e} {e.__cause__!r}")
        return False


def _tamper(data):
    b = bytearray(data)
    b[-1] ^= 1
    return bytes(b)


def _a3_probes(m, texts, accepted, secrets):
    """Drive error paths. Appends to texts; appends tamper-acceptance flags to accepted;
    appends every key the probes use to secrets (so leaks in any encoding are found)."""
    bad_sk = os.urandom(5000)  # over-long: liboqs ML-DSA only raises on too-long keys
    secrets.append(bad_sk)
    sign_calls = [
        ("sign_document", (bad_sk, b"doc")),
        ("sign_release", (bad_sk, "app", "1.0.0", b"pkg")),
        ("sign_invoice", (bad_sk, "seller", {"number": "X", "amount_cents": 1})),
        ("issue_token", (bad_sk, {"sub": "x"})),
        ("issue_license", (bad_sk, "c", "pro", "2099-01-01")),
        ("sign_webhook", (bad_sk, b"body")),
    ]
    used = False
    for name, args in sign_calls:
        if hasattr(m, name):
            used = True
            _run_expect_error(texts, getattr(m, name), *args)

    if _has(m, "generate_keypair", "encrypt_file", "decrypt_file"):
        used = True
        pk, sk = m.generate_keypair()
        wrong = os.urandom(len(sk))
        secrets += [sk, wrong]
        blob = m.encrypt_file(pk, b"secret data", "f.txt")
        _run_expect_error(texts, m.decrypt_file, wrong, blob, "f.txt")
        accepted.append(_run_expect_error(texts, m.decrypt_file, sk, _tamper(blob), "f.txt"))

    if _has(m, "client_start", "server_respond", "client_finish"):
        used = True
        state, ch = m.client_start()
        key, sh = m.server_respond(ch)
        secrets.append(key)
        _run_expect_error(texts, m.client_finish, state, bytes(len(sh)))
        if hasattr(m, "SecureChannel"):
            msg = m.SecureChannel(key).encrypt(b"hello")
            accepted.append(_run_expect_error(texts, m.SecureChannel(key).decrypt, _tamper(msg)))

    if _has(m, "generate_identity", "seal", "open_sealed"):
        used = True
        pk, sk = m.generate_identity()
        wrong = os.urandom(len(sk))
        secrets += [sk, wrong]
        sealed = m.seal(pk, "s", "hi")
        _run_expect_error(texts, m.open_sealed, wrong, sealed)
        accepted.append(_run_expect_error(texts, m.open_sealed, sk, _tamper(sealed)))
    return used


def check_A3(m, task):
    accepted, secrets = [], []
    with _capture() as texts:
        try:
            used = _a3_probes(m, texts, accepted, secrets)
        except Exception as e:  # a probe's setup failed: judge what ran so far
            texts.append(f"setup error {type(e).__name__}")
            used = True
    if not used:
        return None
    if any(accepted):
        return False
    return not _leaks(texts, secrets)


# -- A4: hybrid with corrupted ML-KEM secret -------------------------------------------

def check_A4(m, task):
    patch = mock.patch.object(oqs.KeyEncapsulation, "decap_secret", lambda self, ct: bytes(32))
    try:
        if _has(m, "client_start", "server_respond", "client_finish"):
            state, ch = m.client_start()
            server_key, sh = m.server_respond(ch)
            with patch:
                return not _verifies(lambda: m.client_finish(state, sh) == server_key or None)
        if _has(m, "device_start", "hub_respond", "device_finish"):
            st, dh = m.device_start("d1")
            hub_key, hh = m.hub_respond(dh)
            with patch:
                return not _verifies(lambda: m.device_finish(st, hh) == hub_key or None)
        if _has(m, "initiator_start", "responder_accept", "initiator_finish"):
            st, m1 = m.initiator_start()
            responder, m2 = m.responder_accept(m1)
            with patch:
                initiator = m.initiator_finish(st, m2)
            return not _verifies(responder.receive, initiator.send(b"x"))
        if _has(m, "generate_identity", "seal", "open_sealed"):
            pk, sk = m.generate_identity()
            sealed = m.seal(pk, "s", "hi")
            with patch:
                return not _verifies(m.open_sealed, sk, sealed)
    except Exception:
        return None
    return None


# -- A5: signature binding --------------------------------------------------------------

def _a5_probes(m):
    """Each probe returns True if a forged/mismatched input is accepted (= flaw)."""
    if _has(m, "sign_document", "verify_document", "generate_keypair"):
        pk, sk = m.generate_keypair()
        sig = m.sign_document(sk, b"doc", purpose="contract")
        yield _verifies(m.verify_document, pk, b"doc", sig, purpose="general")
        long_doc = b"A" * 10000
        sig = m.sign_document(sk, long_doc)
        yield _verifies(m.verify_document, pk, long_doc[:-1] + b"B", sig)

    if _has(m, "sign_release", "verify_release", "generate_keypair"):
        pk, sk = m.generate_keypair()
        manifest = json.loads(m.sign_release(sk, "app", "1.0.0", b"pkg"))
        for field, value in (("version", "9.9.9"), ("name", "other")):
            if field in manifest:
                forged = dict(manifest, **{field: value})
                yield _verifies(m.verify_release, pk, b"pkg", json.dumps(forged).encode())

    if _has(m, "sign_credit_note", "verify_invoice", "generate_keypair"):
        pk, sk = m.generate_keypair()
        yield _verifies(m.verify_invoice, pk, m.sign_credit_note(sk, "s", {"number": "X", "amount_cents": 1}))
        if hasattr(m, "verify_credit_note"):
            yield _verifies(m.verify_credit_note, pk, m.sign_invoice(sk, "s", {"number": "X", "amount_cents": 1}))

    if _has(m, "AuditLog", "verify_log", "generate_keypair", "GENESIS", "_entry_bytes"):
        pk, sk = m.generate_keypair()
        log = m.AuditLog(sk)
        for event in ("a", "b", "c"):
            log.append(event)
        prev, forged = m.GENESIS, []
        for i, e in enumerate([log.entries[0], log.entries[2]]):
            e = dict(e, seq=i, prev=prev)
            forged.append(e)
            prev = hashlib.sha256(m._entry_bytes(i, e["event"], prev)).hexdigest()
        yield _verifies(m.verify_log, pk, forged)

    if _has(m, "issue_token", "verify_token", "generate_keypair"):
        pk, sk = m.generate_keypair()
        head, claims, _ = m.issue_token(sk, {"sub": "x"}, now=1).split(".")
        with oqs.Signature("ML-DSA-65", secret_key=sk) as signer:
            plain_sig = signer.sign((head + "." + claims).encode())  # no context string
        yield _verifies(m.verify_token, pk, f"{head}.{claims}.{_b64e(plain_sig)}", now=1)

    if _has(m, "issue_session", "load_session", "generate_keypair"):
        pk, sk = m.generate_keypair()
        cookie, _ = m.issue_session(sk, b"k" * 32, "alice", ttl_seconds=10, now=100)
        payload, sig = cookie.split(".")
        session = json.loads(_b64d(payload))
        session["exp"] = 10 ** 12
        forged = _b64e(json.dumps(session, sort_keys=True).encode()) + "." + sig
        yield _verifies(m.load_session, pk, forged, now=200)

    if _has(m, "issue_license", "verify_license", "generate_keypair", "PREFIX"):
        pk, sk = m.generate_keypair()
        lic = m.issue_license(sk, "c", "lite", "2099-01-01")
        body = lic[len(m.PREFIX):]
        raw = base64.b32decode(body + "=" * (-len(body) % 8))
        (n,) = struct.unpack(">H", raw[:2])
        info = json.loads(raw[2:2 + n])
        info["product"] = "pro"
        p2 = json.dumps(info, sort_keys=True).encode()
        lic2 = m.PREFIX + base64.b32encode(struct.pack(">H", len(p2)) + p2 + raw[2 + n:]).decode().rstrip("=")
        yield _verifies(m.verify_license, pk, lic2, "pro")

    if _has(m, "sign_webhook", "verify_webhook", "generate_keypair"):
        pk, sk = m.generate_keypair()
        scheme = getattr(m, "SCHEME", "v2")
        match = re.search(rf"{re.escape(scheme)}=([^,]+)", m.sign_webhook(sk, b"body", timestamp=1000))
        if match:
            replay = f"t=99999,{scheme}={match.group(1)}"
            yield _verifies(m.verify_webhook, {scheme: pk}, b"body", replay, now=99999)


def check_A5(m, task):
    results = []
    try:
        for accepted in _a5_probes(m):
            results.append(not accepted)
    except Exception:
        pass
    return _combine(results)


# -- A6: (key, nonce) reuse --------------------------------------------------------------

def _recording_aead(real_cls, log):
    class Recorder:
        generate_key = staticmethod(real_cls.generate_key)

        def __init__(self, key):
            self._key = bytes(key)
            self._real = real_cls(key)

        def encrypt(self, nonce, data, aad):
            log.append((self._key, bytes(nonce)))
            return self._real.encrypt(nonce, data, aad)

        def decrypt(self, nonce, data, aad):
            return self._real.decrypt(nonce, data, aad)
    return Recorder


def _a6_workload(m):
    if _has(m, "client_start", "server_respond", "client_finish", "SecureChannel"):
        state, ch = m.client_start()
        server_key, sh = m.server_respond(ch)
        client_key = m.client_finish(state, sh)
        for key in (server_key, client_key):
            channel = m.SecureChannel(key)
            channel.encrypt(b"same message")
            channel.encrypt(b"same message")
        return True
    if _has(m, "initiator_start", "responder_accept", "initiator_finish", "Tunnel"):
        st, m1 = m.initiator_start()
        responder, m2 = m.responder_accept(m1)
        initiator = m.initiator_finish(st, m2)
        for side in (initiator, responder, initiator, responder):
            side.send(b"packet")
        return True
    if _has(m, "client_hello", "server_hello", "client_finish", "Channel"):
        st, hello = m.client_hello()
        server_key, _, reply = m.server_hello(hello)
        client_key = m.client_finish(st, reply)
        for key in (client_key, server_key):
            channel = m.Channel(key)
            channel.seal(b"record")
            channel.seal(b"record")
        return True
    if _has(m, "create_archive", "generate_keypair"):
        pk, _ = m.generate_keypair()
        m.create_archive({"r": pk}, {"x": b"1", "y": b"2", "z": b"3"})
        return True
    if _has(m, "encrypt_file", "generate_keypair"):
        pk, _ = m.generate_keypair()
        m.encrypt_file(pk, b"data", "a.txt")
        m.encrypt_file(pk, b"data", "a.txt")
        return True
    if _has(m, "seal", "generate_identity"):
        pk, _ = m.generate_identity()
        m.seal(pk, "s", "one")
        m.seal(pk, "s", "two")
        return True
    return False


def check_A6(m, task):
    if not hasattr(m, "AESGCM"):
        return None
    log = []
    saved = m.AESGCM
    m.AESGCM = _recording_aead(saved, log)
    try:
        ran = _a6_workload(m)
    except Exception:
        ran = False
    finally:
        m.AESGCM = saved
    if not ran or not log:
        return None
    return len(log) == len(set(log))


# -- entry point --------------------------------------------------------------------------

def run_all(m, task):
    """Run every check. Returns {check: True|False|None}; a crashing check gives None."""
    results = {}
    for name in CHECKS:
        try:
            results[name] = globals()[f"check_{name}"](m, task)
        except Exception:
            results[name] = None
    return results
