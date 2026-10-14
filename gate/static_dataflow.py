"""Small AST dataflow ("taint") checks for properties Semgrep cannot express.

Tags that flow through assignments, expressions, function arguments and return values:
  CL   classical shared secret   (result of `<key>.exchange(...)`)
  PQ   ML-KEM shared secret       (result of `decap_secret`, 2nd value of `encap_secret`)
  CT   contains the KEM ciphertext (1st value of `encap_secret`; anything the
       `decap_secret` argument was cut from, followed back through callers)
`<kdf>.derive(...)` returns a derived key: CL/PQ tags stop there.

  P1  a raw CL/PQ secret is used directly as an AEAD key (no KDF in between)
  P6  hybrid modules only (both CL and PQ appear): every KDF that takes a raw
      secret must take BOTH secrets, and its info/salt must contain CT

The analysis is deliberately simple: flow-insensitive, context-insensitive (all calls
to one function share its parameter tags), methods resolved by name. It can miss
flaws or wrongly pass; it is a heuristic, like every static rule here.
"""
import ast
from collections import defaultdict

AEADS = {"AESGCM", "ChaCha20Poly1305", "AESCCM", "AESGCMSIV", "AESOCB3"}
MODULE = "<module>"


def _call_name(call):
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


class _Analysis:
    def __init__(self, tree):
        self.tree = tree
        self.imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.imports.update((a.asname or a.name).split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.imports.update(a.asname or a.name for a in node.names)
        # module-level dicts that map names to AEAD classes, e.g. AEADS = {"aes": AESGCM}
        self.aead_maps = set()
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
                if any(isinstance(v, ast.Name) and v.id in AEADS for v in node.value.values):
                    self.aead_maps.update(t.id for t in node.targets if isinstance(t, ast.Name))
        self.funcs = defaultdict(list)       # name -> [FunctionDef]
        self.scope_of = {}                   # FunctionDef -> scope id
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs[node.name].append(node)
                self.scope_of[node] = f"{node.name}@{node.lineno}"
        self.tags = defaultdict(lambda: defaultdict(set))   # scope -> name -> tags
        self.deps = defaultdict(lambda: defaultdict(set))   # scope -> name -> names it came from
        self.ct_marked = defaultdict(set)                   # scope -> names containing CT
        self.returns = {}                                   # scope -> list of tag sets (tuple) or [set]
        self.call_sites = defaultdict(list)                 # func scope -> [(caller scope, call, offset)]
        self.kdf_vars = defaultdict(dict)                   # scope -> name -> HKDF call
        self.kdf_sites = []                                 # (scope, kdf call, ikm expr, line)
        self.aead_sites = []                                # (scope, key expr, line)
        self.changed = False

    # -- helpers --
    def _params(self, fn):
        names = [a.arg for a in fn.args.posonlyargs + fn.args.args]
        offset = 1 if names and names[0] in ("self", "cls") else 0
        return names, offset

    def _key(self, scope, node):
        """Variable key for a target / name expression, or None."""
        if isinstance(node, ast.Name):
            return scope, node.id
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
            return MODULE, "self." + node.attr        # instance attributes shared module-wide
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            return self._key(scope, node.value)
        if isinstance(node, ast.Starred):
            return self._key(scope, node.value)
        return None

    def _add(self, scope, name, tags):
        cur = self.tags[scope][name]
        if not tags <= cur:
            cur |= tags
            self.changed = True

    def _names(self, scope, expr):
        """Data variable keys read by expr (skips module names and called functions)."""
        out = set()
        for node in ast.walk(expr):
            if isinstance(node, ast.Call):
                continue
            if isinstance(node, ast.Name) and node.id not in self.imports and node.id not in self.funcs:
                out.add((scope, node.id))
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
                out.add((MODULE, "self." + node.attr))
        return out

    def _mark_ct(self, keys):
        todo = list(keys)
        while todo:
            scope, name = todo.pop()
            if name in self.ct_marked[scope]:
                continue
            self.ct_marked[scope].add(name)
            self.changed = True
            todo.extend((scope, d) for d in self.deps[scope][name])
            # a parameter that contains CT: so do the matching arguments in every caller
            for fn_list in self.funcs.values():
                for fn in fn_list:
                    if self.scope_of[fn] != scope:
                        continue
                    params, offset = self._params(fn)
                    if name in params:
                        idx = params.index(name) - offset
                        for caller, call, _ in self.call_sites[scope]:
                            if 0 <= idx < len(call.args):
                                todo.extend(self._names(caller, call.args[idx]))
                            for kw in call.keywords:
                                if kw.arg == name:
                                    todo.extend(self._names(caller, kw.value))

    # -- expressions --
    def expr(self, scope, e):
        if e is None:
            return set()
        if isinstance(e, ast.Name):
            t = set(self.tags[scope].get(e.id, set())) | set(self.tags[MODULE].get(e.id, set()))
            if e.id in self.ct_marked[scope] or e.id in self.ct_marked[MODULE]:
                t.add("CT")
            return t
        if isinstance(e, ast.Attribute):
            if isinstance(e.value, ast.Name) and e.value.id == "self":
                k = "self." + e.attr
                t = set(self.tags[MODULE].get(k, set()))
                if k in self.ct_marked[MODULE]:
                    t.add("CT")
                return t
            if isinstance(e.value, ast.Name) and e.value.id in self.imports:
                return set()
            return self.expr(scope, e.value)
        if isinstance(e, ast.Call):
            return self.call(scope, e)
        if isinstance(e, ast.Lambda):
            return set()
        out = set()
        for child in ast.iter_child_nodes(e):
            if isinstance(child, ast.expr):
                out |= self.expr(scope, child)
            elif isinstance(child, ast.comprehension):
                out |= self.expr(scope, child.iter)
        return out

    def call(self, scope, c):
        name = _call_name(c)
        arg_tags = set()
        for a in c.args:
            arg_tags |= self.expr(scope, a)
        for kw in c.keywords:
            arg_tags |= self.expr(scope, kw.value)

        if name == "exchange":
            return {"CL"}
        if name == "decap_secret":
            for a in c.args:
                self._mark_ct(self._names(scope, a))
            return {"PQ"}
        if name == "encap_secret":
            return {"PQ", "CT"}
        is_aead_map = (isinstance(c.func, ast.Subscript) and isinstance(c.func.value, ast.Name)
                       and c.func.value.id in self.aead_maps)
        if (name in AEADS or is_aead_map) and c.args:
            self.aead_sites.append((scope, c.args[0], c.lineno))
        if name == "derive" and isinstance(c.func, ast.Attribute) and c.args:
            kdf = c.func.value
            if isinstance(kdf, ast.Name):
                kdf = self.kdf_vars[scope].get(kdf.id, kdf)
            if isinstance(kdf, ast.Call) and _call_name(kdf) in ("HKDF", "HKDFExpand", "ConcatKDFHash"):
                self.kdf_sites.append((scope, kdf, c.args[0], c.lineno))
            return {"KEY"}
        base = set()
        external = False
        if isinstance(c.func, ast.Attribute):
            receiver = c.func.value
            base = self.expr(scope, receiver)  # e.g. secret.hex(); also visits AESGCM(key) in AESGCM(key).encrypt
            external = (isinstance(receiver, ast.Name) and receiver.id in self.imports) or \
                       (isinstance(receiver, ast.Call) and _call_name(receiver) in self.imports)
        if name in self.funcs and not external:
            out = set()
            for fn in self.funcs[name]:
                fscope = self.scope_of[fn]
                params, offset = self._params(fn)
                site = (scope, c, offset)
                if site not in self.call_sites[fscope]:
                    self.call_sites[fscope].append(site)
                for i, a in enumerate(c.args):
                    if i + offset < len(params):
                        self._add(fscope, params[i + offset], self.expr(scope, a))
                for kw in c.keywords:
                    if kw.arg in params:
                        self._add(fscope, kw.arg, self.expr(scope, kw.value))
                for t in self.returns.get(fscope, []):
                    out |= t
            return out
        return arg_tags | base

    # -- statements --
    def assign(self, scope, targets, value):
        name = _call_name(value) if isinstance(value, ast.Call) else None
        for target in targets:
            if isinstance(target, (ast.Tuple, ast.List)):
                elems = target.elts
                parts = None
                if name == "encap_secret" and len(elems) == 2:
                    self.call(scope, value)
                    parts = [{"CT"}, {"PQ"}]
                elif isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(elems):
                    parts = [self.expr(scope, v) for v in value.elts]
                    for el, v in zip(elems, value.elts):
                        k = self._key(scope, el)
                        if k:
                            self.deps[k[0]][k[1]] |= {n for s, n in self._names(scope, v) if s == k[0]}
                elif name in self.funcs:
                    self.call(scope, value)
                    rets = [self.returns.get(self.scope_of[fn], []) for fn in self.funcs[name]]
                    if all(len(r) == len(elems) for r in rets) and rets:
                        parts = [set().union(*(r[i] for r in rets)) for i in range(len(elems))]
                if parts is None:
                    t = self.expr(scope, value)
                    parts = [t] * len(elems)
                for el, t in zip(elems, parts):
                    k = self._key(scope, el)
                    if k:
                        self._add(k[0], k[1], t)
                        if not isinstance(value, (ast.Tuple, ast.List)):
                            self.deps[k[0]][k[1]] |= {n for s, n in self._names(scope, value) if s == k[0]}
            else:
                k = self._key(scope, target)
                if k:
                    if isinstance(value, ast.Call) and name in ("HKDF", "HKDFExpand", "ConcatKDFHash") \
                            and isinstance(target, ast.Name):
                        self.kdf_vars[scope][target.id] = value
                    self._add(k[0], k[1], self.expr(scope, value))
                    self.deps[k[0]][k[1]] |= {n for s, n in self._names(scope, value) if s == k[0]}

    def block(self, scope, body):
        for st in body:
            self.stmt(scope, st)

    def stmt(self, scope, st):
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.block(self.scope_of[st], st.body)
        elif isinstance(st, ast.ClassDef):
            self.block(MODULE, st.body)
        elif isinstance(st, ast.Assign):
            self.assign(scope, st.targets, st.value)
        elif isinstance(st, (ast.AnnAssign, ast.AugAssign)) and st.value is not None:
            self.assign(scope, [st.target], st.value)
        elif isinstance(st, ast.Return) and st.value is not None:
            if isinstance(st.value, ast.Tuple):
                new = [self.expr(scope, v) for v in st.value.elts]
            else:
                new = [self.expr(scope, st.value)]
            old = self.returns.get(scope)
            if old is None or len(old) != len(new):
                merged = new if old is None else [set().union(*old, *new)]
            else:
                merged = [a | b for a, b in zip(old, new)]
            if merged != old:
                self.returns[scope] = merged
                self.changed = True
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            self.assign(scope, [st.target], st.iter)
            self.block(scope, st.body + st.orelse)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                self.expr(scope, item.context_expr)
            self.block(scope, st.body)
        elif isinstance(st, ast.If):
            self.expr(scope, st.test)
            self.block(scope, st.body + st.orelse)
        elif isinstance(st, ast.While):
            self.block(scope, st.body + st.orelse)
        elif isinstance(st, ast.Try):
            self.block(scope, st.body + st.orelse + st.finalbody)
            for h in st.handlers:
                self.block(scope, h.body)
        elif isinstance(st, ast.Expr):
            self.expr(scope, st.value)
        elif isinstance(st, ast.Raise) and st.exc is not None:
            self.expr(scope, st.exc)

    def run(self):
        for _ in range(30):
            self.changed = False
            self.kdf_sites, self.aead_sites = [], []
            self.block(MODULE, self.tree.body)
            if not self.changed:
                break


def check(source):
    """Return {check: [findings]} for P1 and P6."""
    tree = ast.parse(source)
    a = _Analysis(tree)
    a.run()
    findings = defaultdict(list)

    def add(check_id, rule, line, msg):
        item = {"rule": rule, "line": line, "message": msg}
        if item not in findings[check_id]:
            findings[check_id].append(item)

    for scope, key_expr, line in a.aead_sites:
        tags = a.expr(scope, key_expr)
        if tags & {"CL", "PQ"}:
            add("P1", "pqgate-P1-dataflow-raw-secret-key", line,
                "Raw KEM/DH shared secret used directly as an AEAD key (no KDF).")

    calls = {_call_name(n) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    hybrid = "exchange" in calls and bool(calls & {"encap_secret", "decap_secret"})
    if hybrid:
        combiner_sites = 0
        for scope, kdf, ikm, line in a.kdf_sites:
            ikm_tags = a.expr(scope, ikm)
            if not ikm_tags & {"CL", "PQ"}:
                continue  # KDF of an already-derived key (e.g. rekeying)
            combiner_sites += 1
            if "CL" not in ikm_tags or "PQ" not in ikm_tags:
                missing = "ML-KEM" if "PQ" not in ikm_tags else "classical"
                add("P6", "pqgate-P6-dataflow-secret-missing", line,
                    f"Hybrid KDF input does not include the {missing} shared secret.")
            bound = set()
            for kw in kdf.keywords:
                if kw.arg in ("info", "salt", "otherinfo"):
                    bound |= a.expr(scope, kw.value)
            if "CT" not in bound:
                add("P6", "pqgate-P6-dataflow-no-transcript", line,
                    "Hybrid KDF info/salt does not include the KEM ciphertext (no transcript binding).")
        if combiner_sites == 0:
            add("P6", "pqgate-P6-dataflow-no-kdf", 1,
                "Hybrid module: shared secrets never reach a KDF.")
    return dict(findings)


if __name__ == "__main__":
    import json
    import sys
    print(json.dumps(check(open(sys.argv[1], encoding="utf-8").read()), indent=2))
