#!/usr/bin/env python3
# GÉNÉRÉ depuis legion-core/core/legion_verify.py par build_verifier.py — ne pas éditer à la main.
"""Vérifieur HORS LIGNE des reçus legion-core (SEAL et produits enfants). Un seul fichier, aucun code LEGION, aucun réseau.
Dépendance : cryptography (Ed25519). Modèle : verify_tlog.py.

  python3 legion_verify.py RECU.json [--log-vkey VKEY]
      [--file F | --sha256 HEX]                      SEAL (legion-seal/v0)
      [--artifact F] [--commit HEX]                  reçu de build (legion-build/v0)
      [--dataset-dir D | --manifest F]               snapshot de dataset (legion-dataset/v0)
      [--input F] [--output F]                       exécution d'agent (legion-agentrun/v0)
      [--expect CHAMP=VALEUR ...]                    attente générique sur un champ de l'entrée signée
      [--newer-head NOTE --consistency HEX,HEX,...]  tête plus récente : le journal n'a pas réécrit l'historique

La clé du journal est ÉPINGLÉE (PINNED_VKEY ou --log-vkey) ; celle du reçu n'est jamais crue ; origine = nom de la clé.
Étapes : (1) entrée = octets JCS RFC 8785 exacts, schéma du profil ; (2) attentes (hash du fichier, commit…) = entrée signée ;
(3) annexes (label) = leur engagement SHA-256 ; (4) note C2SP : origine, taille, signature Ed25519 ; (5) inclusion RFC 9162 ;
(6) optionnel : cohérence RFC 9162 vers une tête plus récente. Sortie : « RESULTAT: VALIDE » (0) ou « RESULTAT: INVALID — … » (1)."""
import argparse, base64, hashlib, json, os, re, sys, unicodedata

PINNED_VKEY = "seal.legion-api.com/v0+00ec1419+AXnDNIhBBOIB5xL1K9dhevS53LniduuMCiEogoSLyYoL"
HEX64, HEX40 = re.compile(r"^[0-9a-f]{64}$"), re.compile(r"^[0-9a-f]{40}$")
TS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class Invalid(Exception):
    pass


# ---------------------------------------------------------------- primitives
def jcs(v):
    """RFC 8785 pour le sous-ensemble des schémas (objets, chaînes, entiers, booléens, null)."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        if abs(v) > 2 ** 53:
            raise Invalid("entier hors plage JCS")
        return str(v)
    if isinstance(v, str):
        out = []
        for c in v:
            o = ord(c)
            if 0xD800 <= o <= 0xDFFF:
                raise Invalid("demi-paire de substitution")
            out.append({'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(c)
                       or ("\\u%04x" % o if o < 0x20 else c))
        return '"' + "".join(out) + '"'
    if isinstance(v, dict):
        ks = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(jcs(k) + ":" + jcs(v[k]) for k in ks) + "}"
    raise Invalid("type non autorisé dans l'entrée : %s" % type(v).__name__)


def parse_vkey(v):
    name, kid, b64 = v.split("+", 2)              # le base64 de la clé peut contenir « + »
    raw = base64.b64decode(b64, validate=True)
    if raw[0] != 1 or len(raw) != 33 or hashlib.sha256(name.encode() + b"\n" + raw).digest()[:4] != bytes.fromhex(kid):
        raise Invalid("clé du registre incohérente (vkey)")
    return name, bytes.fromhex(kid), raw[1:]


def node(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def verify_inclusion(leaf, index, size, path, root):          # RFC 9162 §2.1.3.2
    if not 0 <= index < size or any(len(p) != 32 for p in path):
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1; sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root


def verify_consistency(m, n, old, new, proof):                 # RFC 9162 §2.1.4.2
    if m == n:
        return old == new and not proof
    if not 0 < m < n or not proof or any(len(p) != 32 for p in proof):
        return False
    if m & (m - 1) == 0:
        proof = [old] + proof
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1; sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node(c, fr), node(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1; sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1; sn >>= 1
    return sn == 0 and fr == old and sr == new


def open_note(note, vk):
    """Note C2SP signée -> (origine, taille, racine). Lève Invalid si la signature épinglée manque ou est fausse."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(note, str) or not note.endswith("\n") or "\r" in note or "\n\n" not in note:
        raise Invalid("note signée malformée (c2sp.org/signed-note)")
    body, sigs = note.split("\n\n", 1); body += "\n"
    lines = body.split("\n")
    if len(lines) != 4 or lines[3] != "" or not lines[1].isdigit() or (lines[1] != "0" and lines[1][0] == "0"):
        raise Invalid("checkpoint malformé (c2sp.org/tlog-checkpoint)")
    root = base64.b64decode(lines[2], validate=True)
    if len(root) != 32:
        raise Invalid("racine de taille incorrecte")
    name, kid, pub = vk
    for l in sigs.split("\n")[:-1]:
        if not l.startswith("— "):
            raise Invalid("ligne de signature malformée")
        n, s64 = l[2:].rsplit(" ", 1); s = base64.b64decode(s64, validate=True)
        if n == name and len(s) == 68 and s[:4] == kid:
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(s[4:], body.encode())
            except Exception:
                raise Invalid("signature Ed25519 du registre invalide")
            return lines[0], int(lines[1]), root
    raise Invalid("aucune signature de la clé épinglée sur la tête")


def dataset_manifest(root):
    """Manifeste canonique d'un dossier : lignes « <sha256> <taille> <chemin relatif NFC> », triées par octets UTF-8 du chemin.
    Fichiers réguliers seulement ; .git ignoré ; lien symbolique ou chemin non NFC = refus (ambiguïté)."""
    rows = []
    for d, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(x for x in dirs if x != ".git")
        for x in dirs:
            if os.path.islink(os.path.join(d, x)):
                raise Invalid("lien symbolique refusé : %s" % os.path.join(d, x))
        for f in files:
            p = os.path.join(d, f); rel = os.path.relpath(p, root).replace(os.sep, "/")
            if os.path.islink(p) or not os.path.isfile(p):
                raise Invalid("fichier non régulier refusé : %s" % rel)
            if unicodedata.normalize("NFC", rel) != rel or "\n" in rel:
                raise Invalid("chemin non NFC ou avec saut de ligne : %r" % rel)
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                for blk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(blk)
            rows.append((rel.encode("utf-8"), "%s %d %s\n" % (h.hexdigest(), os.path.getsize(p), rel)))
    return "".join(r for _, r in sorted(rows)).encode("utf-8")


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


# ---------------------------------------------------------------- profils (schémas des produits)
BASE = {"v", "kind", "observed_at", "submitter"}


def _hex64(e, *ks):
    for k in ks:
        if not isinstance(e.get(k), str) or not HEX64.match(e[k]):
            raise Invalid("champ %s : 64 hex minuscules attendus" % k)


def _text(e, k, mx, opt=False):
    v = e.get(k)
    if v is None and opt:
        return
    if not isinstance(v, str) or not 0 < len(v) <= mx or any(unicodedata.category(c) in ("Cc", "Cf") for c in v):
        raise Invalid("champ %s : texte 1..%d sans caractère de contrôle attendu" % (k, mx))


def p_seal(e, r):
    if set(e) != BASE | {"sha256", "label_sha256"}:
        raise Invalid("champs d'entrée inattendus")
    _hex64(e, "sha256")
    if e["label_sha256"] is not None:
        _hex64(e, "label_sha256")
    lab = r.get("label")
    if lab is not None and hashlib.sha256(lab.encode("utf-8")).hexdigest() != e["label_sha256"]:
        raise Invalid("le label ne correspond pas à label_sha256")
    return {"sha256": e["sha256"], "genesis_number": r["leaf_index"] if r["leaf_index"] < 1000 else None,
            "label_verified": lab, "label_committed_but_not_provided": e["label_sha256"] is not None and lab is None}


def p_build(e, r):
    if set(e) != BASE | {"repo", "commit", "ref", "artifact_name", "artifact_sha256", "artifact_size", "tree_clean"}:
        raise Invalid("champs d'entrée inattendus")
    _hex64(e, "artifact_sha256"); _text(e, "repo", 200); _text(e, "artifact_name", 200); _text(e, "ref", 200, opt=True)
    if not isinstance(e["commit"], str) or not (HEX40.match(e["commit"]) or HEX64.match(e["commit"])):
        raise Invalid("commit : 40 ou 64 hex attendus")
    if not isinstance(e["artifact_size"], int) or isinstance(e["artifact_size"], bool) or e["artifact_size"] < 0 or not isinstance(e["tree_clean"], bool):
        raise Invalid("artifact_size / tree_clean invalides")
    return {"repo": e["repo"], "commit": e["commit"], "artifact_name": e["artifact_name"], "artifact_sha256": e["artifact_sha256"],
            "tree_clean_declared": e["tree_clean"]}


def p_dataset(e, r):
    if set(e) != BASE | {"dataset", "revision", "manifest_sha256", "file_count", "total_bytes"}:
        raise Invalid("champs d'entrée inattendus")
    _hex64(e, "manifest_sha256"); _text(e, "dataset", 200); _text(e, "revision", 100)
    for k in ("file_count", "total_bytes"):
        if not isinstance(e[k], int) or isinstance(e[k], bool) or e[k] < 0:
            raise Invalid("%s invalide" % k)
    return {"dataset": e["dataset"], "revision": e["revision"], "manifest_sha256": e["manifest_sha256"], "file_count": e["file_count"]}


def p_agentrun(e, r):
    if set(e) != BASE | {"agent", "run_id", "input_sha256", "output_sha256", "started_at", "ended_at"}:
        raise Invalid("champs d'entrée inattendus")
    _hex64(e, "input_sha256", "output_sha256"); _text(e, "agent", 100); _text(e, "run_id", 100)
    if not (isinstance(e["started_at"], str) and TS.match(e["started_at"]) and isinstance(e["ended_at"], str) and TS.match(e["ended_at"])) \
            or e["started_at"] > e["ended_at"]:
        raise Invalid("started_at/ended_at : horodatages UTC ordonnés attendus")
    return {"agent": e["agent"], "run_id": e["run_id"], "input_sha256": e["input_sha256"], "output_sha256": e["output_sha256"],
            "started_at_declared": e["started_at"], "ended_at_declared": e["ended_at"]}


def p_rules(e, r):
    if set(e) != BASE | {"rules_version", "rules_sha256"}:
        raise Invalid("champs d'entrée inattendus")
    _hex64(e, "rules_sha256")
    return {"rules_version": e["rules_version"], "rules_sha256": e["rules_sha256"]}


def p_tombstone(e, r):
    if not {"target_leaf", "reason"} <= set(e) or not isinstance(e["target_leaf"], int) or e["target_leaf"] >= r["leaf_index"]:
        raise Invalid("tombstone invalide (cible absente ou postérieure)")
    return {"target_leaf": e["target_leaf"], "reason": e["reason"], "sha256": e.get("target_sha256")}


PROFILES = {("legion-seal/v0", "seal"): p_seal, ("legion-build/v0", "build"): p_build,
            ("legion-dataset/v0", "dataset_snapshot"): p_dataset, ("legion-agentrun/v0", "agent_run"): p_agentrun}
SCHEMAS = {s for s, _ in PROFILES}


def verify_receipt(r, vkey=None, expect=None, newer=None, cons=None):
    vk = parse_vkey(vkey or PINNED_VKEY)
    b = base64.b64decode(r["entry_jcs_b64"], validate=True)
    e = json.loads(b)
    if not isinstance(e, dict) or jcs(e).encode("utf-8") != b:
        raise Invalid("entrée non canonique (JCS RFC 8785)")
    if "entry" in r and r["entry"] != e:
        raise Invalid("le champ entry ne correspond pas aux octets signés")
    if e.get("v") not in SCHEMAS:
        raise Invalid("schéma d'entrée inconnu")
    if not isinstance(e.get("observed_at"), str) or not TS.match(e["observed_at"]) or e.get("submitter") not in ("public", "operator"):
        raise Invalid("observed_at / submitter invalides")
    kind = e.get("kind")
    prof = PROFILES.get((e["v"], kind)) or {"tombstone": p_tombstone, "rules": p_rules}.get(kind)
    if prof is None:
        raise Invalid("type d'entrée inconnu pour ce schéma")
    extra = prof(e, r)
    for k, want in (expect or {}).items():           # attentes : comparées aux OCTETS SIGNÉS uniquement
        if want is None:
            continue
        if k not in e:
            raise Invalid("attente %s : ce champ n'existe pas dans une entrée %s" % (k, kind))
        if e[k] != want:
            raise Invalid("%s du reçu (%s) ≠ attendu (%s)" % (k, e[k], want))
    if r.get("observed_at") not in (None, e["observed_at"]):
        raise Invalid("observed_at du reçu ≠ celui de l'entrée signée")
    origin, size, root = open_note(r["signed_head"], vk)
    if origin != vk[0]:
        raise Invalid("origine %r ≠ nom de la clé épinglée %r" % (origin, vk[0]))
    if size != r["tree_size"]:
        raise Invalid("taille de la tête ≠ tree_size du reçu")
    path = [bytes.fromhex(h) for h in r["inclusion_proof"]]
    if not verify_inclusion(hashlib.sha256(b"\x00" + b).digest(), r["leaf_index"], size, path, root):
        raise Invalid("preuve d'inclusion RFC 9162 invalide")
    out = {"leaf_index": r["leaf_index"], "tree_size": size, "kind": kind, "schema": e["v"], "origin": origin,
           "observed_at_declared": e["observed_at"], "submitter": e["submitter"]}
    out.update(extra)
    if newer:
        o2, n2, root2 = open_note(newer, vk)
        if o2 != origin or not verify_consistency(size, n2, root, root2, [bytes.fromhex(h) for h in cons or []]):
            raise Invalid("tête plus récente NON cohérente avec celle du reçu (historique réécrit ?)")
        out["consistent_with_tree_size"] = n2
    return out


def verify(r, want_sha=None, vkey=None, newer=None, cons=None):
    """Compatibilité SEAL : verify(reçu, sha256 attendu, vkey, tête récente, preuve de cohérence)."""
    e = json.loads(base64.b64decode(r["entry_jcs_b64"], validate=True))
    exp = {} if want_sha is None else ({"sha256": want_sha} if e.get("kind") == "seal" else {"_seal_hash": want_sha})
    if "_seal_hash" in exp:
        raise Invalid("hash attendu fourni pour une entrée %s" % e.get("kind"))
    return verify_receipt(r, vkey, exp, newer, cons)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("receipt"); ap.add_argument("--log-vkey")
    g = ap.add_mutually_exclusive_group(); g.add_argument("--file"); g.add_argument("--sha256")
    ap.add_argument("--artifact"); ap.add_argument("--commit")
    g2 = ap.add_mutually_exclusive_group(); g2.add_argument("--dataset-dir"); g2.add_argument("--manifest")
    ap.add_argument("--input"); ap.add_argument("--output"); ap.add_argument("--expect", action="append", default=[])
    ap.add_argument("--newer-head"); ap.add_argument("--consistency", default="")
    a = ap.parse_args()
    try:
        r = json.load(open(a.receipt, encoding="utf-8"))
        exp = {}
        if a.file: exp["sha256"] = file_sha(a.file)
        if a.sha256: exp["sha256"] = a.sha256.lower()
        if a.artifact: exp["artifact_sha256"] = file_sha(a.artifact); exp["artifact_size"] = os.path.getsize(a.artifact)
        if a.commit: exp["commit"] = a.commit.lower()
        if a.dataset_dir: m = dataset_manifest(a.dataset_dir); exp["manifest_sha256"] = hashlib.sha256(m).hexdigest(); exp["file_count"] = m.count(b"\n")
        if a.manifest: exp["manifest_sha256"] = file_sha(a.manifest)
        if a.input: exp["input_sha256"] = file_sha(a.input)
        if a.output: exp["output_sha256"] = file_sha(a.output)
        for x in a.expect:
            k, v = x.split("=", 1); exp[k] = v
        newer = open(a.newer_head, encoding="utf-8").read() if a.newer_head else None
        res = verify_receipt(r, a.log_vkey, exp, newer, [x for x in a.consistency.split(",") if x])
    except (Invalid, KeyError, ValueError, TypeError, IndexError, UnicodeDecodeError, OSError) as ex:
        print("RESULTAT: INVALID — %s%s" % (type(ex).__name__ + ": " if not isinstance(ex, Invalid) else "", ex)); return 1
    print(json.dumps(res, ensure_ascii=False))
    print("RESULTAT: VALIDE" + ("" if exp else " (structure et preuve ; aucun contenu fourni pour comparer)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
