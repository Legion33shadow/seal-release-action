#!/usr/bin/env python3
"""seal-release: seal the SHA-256 of release artifacts in LEGION SEAL, write receipts, badges and a job summary.
Standard library only. Sends ONLY {"sha256": ..., "label": "build <repo>@<commit7>"} per file: never the file, never a
token (this action reads no secret). Inputs come from the composite action as INPUT_* environment variables."""
import glob, hashlib, json, os, subprocess, sys, time, unicodedata, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PINNED_VKEY = "seal.legion-api.com/v0+00ec1419+AXnDNIhBBOIB5xL1K9dhevS53LniduuMCiEogoSLyYoL"
CLAIM = ("A receipt proves that this artifact's SHA-256 was recorded in the LEGION SEAL log at this date (registry clock). "
         "It does NOT prove that the artifact is free of defects or malware, who built it, or where it came from. "
         "Single operator, no independent witness yet.")


def inp(name, default=""):
    return os.environ.get("INPUT_" + name.upper().replace("-", "_"), default).strip()


def files_from(patterns):
    out = []
    for p in patterns.replace(",", "\n").split():
        hits = sorted(f for f in glob.glob(p, recursive=True) if os.path.isfile(f))
        out += [f for f in hits if f not in out]
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def label_for(repo, commit, prefix):
    """Registry rules: ≤64 chars, NFC, no URL, no control characters. The repo name is cut, never the commit."""
    tail = "@" + commit[:7]
    head = (prefix + " ").lstrip() if prefix else ""
    room = 64 - len(head) - len(tail)
    lab = head + repo[:max(room, 0)] + tail
    lab = unicodedata.normalize("NFC", lab).strip()
    if "://" in lab.lower() or "www." in lab.lower():
        lab = head.strip() + tail
    return lab


def submit(base, body, test, tries=3):
    hdr = {"Content-Type": "application/json", "User-Agent": "seal-release-action/1"}
    if test:
        hdr["X-Legion-Test"] = "seal-release-action"
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    for k in range(tries):
        q = urllib.request.Request(base + "/seal/v1/submit", data=data, headers=hdr, method="POST")
        try:
            with urllib.request.urlopen(q, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8", "replace")[:300]
            if e.code == 429 and k + 1 < tries:
                time.sleep(min(int(e.headers.get("Retry-After") or 60), 60)); continue
            raise RuntimeError("HTTP %d: %s" % (e.code, msg))


def verify(receipt_path, file_path):
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return None, "skipped: python3 'cryptography' not installed on this runner (pip install cryptography)"
    p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "verify_seal.py"), receipt_path, "--file", file_path, "--log-vkey", PINNED_VKEY],
                       capture_output=True, text=True)
    last = (p.stdout.strip().splitlines() or [""])[-1]
    return p.returncode == 0 and last.startswith("RESULTAT: VALIDE"), last


def main():
    base = (inp("base-url") or "https://seal.legion-api.com").rstrip("/")
    test = inp("test", "false").lower() == "true"
    fail = inp("fail-on-error", "false").lower() == "true"
    rdir = inp("receipts-dir") or "seal-receipts"
    repo = os.environ.get("GITHUB_REPOSITORY", "local/repo"); commit = os.environ.get("GITHUB_SHA", "0" * 40)
    label = label_for(repo, commit, inp("label-prefix", "build"))
    files = files_from(inp("files"))
    if not files:
        print("::error::seal-release: no file matches 'files'"); return 1
    os.makedirs(rdir, exist_ok=True)
    rows, errors = [], []
    for f in files:
        h = sha256(f); body = {"sha256": h, "label": label}
        print("seal-release: %s sha256=%s" % (f, h))
        print("seal-release: POST %s/seal/v1/submit %s%s" % (base, json.dumps(body, ensure_ascii=False), " (X-Legion-Test)" if test else ""))
        try:
            r = submit(base, body, test)
            if r.get("entry", {}).get("sha256") != h:
                raise RuntimeError("receipt hash does not match the local hash")
        except Exception as ex:  # noqa: BLE001
            errors.append((f, str(ex))); print("::%s::seal-release: %s: %s" % ("error" if fail else "warning", f, ex)); continue
        i = r["leaf_index"]; rp = os.path.join(rdir, "%s.seal-%d.json" % (os.path.basename(f), i))
        with open(rp, "w") as o:
            json.dump(r, o, ensure_ascii=False, indent=1)
        ok, vmsg = verify(rp, f)
        pub = r["proof_url"].split("/seal/v1/")[0]          # origine publique annoncée par le reçu signé
        badge = "[![sealed](%s/seal/v1/badge/%d.svg)](%s/seal/v1/proof/%d)" % (pub, i, pub, i)
        print("seal-release: leaf %d%s proof %s receipt %s verify: %s" % (i, " (already sealed: first entry)" if r.get("duplicate_of_first_submission") else "",
                                                                           r["proof_url"], rp, vmsg))
        if ok is False:
            errors.append((f, "offline verification failed: " + vmsg))
        rows.append({"file": f, "sha256": h, "leaf_index": i, "proof_url": r["proof_url"], "receipt": rp, "badge": badge,
                     "duplicate": bool(r.get("duplicate_of_first_submission")), "verified": ok, "observed_at": r["observed_at"]})
    md = ["## LEGION SEAL — release artifacts", "", "| file | sha256 | leaf | observed_at (registry clock) | offline check |", "|---|---|---|---|---|"]
    for x in rows:
        md.append("| `%s` | `%s` | [%d](%s)%s | %s | %s |" % (x["file"], x["sha256"], x["leaf_index"], x["proof_url"], " (first entry)" if x["duplicate"] else "",
                                                         x["observed_at"], {True: "VALIDE", False: "INVALID", None: "skipped"}[x["verified"]]))
    if rows:
        md += ["", "Badge for your README:", "", "```", rows[0]["badge"], "```", "", rows[0]["badge"], "",
               "Verify offline (no network, Python 3 + cryptography): download the receipt from this job's artifacts, then", "",
               "```", "curl -sO https://raw.githubusercontent.com/Legion33shadow/legion-seal/main/verify_seal.py",
               "python3 verify_seal.py %s --file %s" % (os.path.basename(rows[0]["receipt"]), os.path.basename(rows[0]["file"])), "```"]
    for f, e in errors:
        md.append("- not sealed or not verified: `%s` (%s)" % (f, e))
    md += ["", "> " + CLAIM]
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as o:
            o.write("\n".join(md) + "\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as o:
            o.write("receipts=%s\n" % json.dumps(rows, separators=(",", ":")))
            o.write("badge=%s\n" % (rows[0]["badge"] if rows else ""))
    return 1 if (errors and fail) else 0


if __name__ == "__main__":
    sys.exit(main())
