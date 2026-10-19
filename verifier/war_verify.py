"""Work-acceptance record verifier, profile 1.3 (schema trilatic.acceptance-receipt/1.2).

Reference verifier using only the Python standard library. It implements Ed25519 (with the profile 1.3 key rule),
JCS (RFC 8785), and an RFC 3161 imprint, time and accuracy scan. No network, no dependencies.
Usage:  python war_verify.py VECTOR.json [VECTOR.json ...]   -> prints AGREE/DIFF per vector, exit 1 on any DIFF
        python war_verify.py --outcome VECTOR.json           -> prints the computed outcome as JSON
"""

import base64
import datetime
import hashlib
import json
import sys

SCHEMA_V1 = "trilatic.acceptance-receipt/1"
SCHEMA_V11 = "trilatic.acceptance-receipt/1.1"
SCHEMA_V12 = "trilatic.acceptance-receipt/1.2"
RESULT_VOCAB = ["pass", "fail", "not-evaluated", "error"]

# ---------------------------------------------------------------- Ed25519 (RFC 8032, verify only)
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
O = (0, 1, 1, 0)


def _decode_point(b):
    b = bytearray(b)
    x_sign = b[31] >> 7
    b[31] &= 0x7F
    y = int.from_bytes(b, "little")
    if y >= P:
        return None
    y2 = y * y % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    vx2 = v * x * x % P
    if vx2 != u:
        if vx2 == (-u) % P:
            x = x * SQRT_M1 % P
        else:
            return None
    if x == 0 and x_sign == 1:
        return None
    if (x & 1) != x_sign:
        x = (-x) % P
    return (x, y, 1, x * y % P)


def _add(p1, p2):
    X1, Y1, Z1, T1 = p1
    X2, Y2, Z2, T2 = p2
    A = (Y1 - X1) * (Y2 - X2) % P
    B = (Y1 + X1) * (Y2 + X2) % P
    C = T1 * 2 * D * T2 % P
    Dd = Z1 * 2 * Z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(pt, k):
    r, q = O, pt
    while k > 0:
        if k & 1:
            r = _add(r, q)
        q = _add(q, q)
        k >>= 1
    return r


def _eq(p1, p2):
    return (p1[0] * p2[2] - p2[0] * p1[2]) % P == 0 and (
        p1[1] * p2[2] - p2[1] * p1[2]
    ) % P == 0


_BY = 4 * pow(5, P - 2, P) % P
_B = _decode_point(_BY.to_bytes(32, "little"))


def verify_ed25519(sig, msg, pub):
    if len(sig) != 64 or len(pub) != 32:
        return False
    A, R = _decode_point(pub), _decode_point(sig[:32])
    if not A or not R:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
    return _eq(_mul(_B, S), _add(R, _mul(A, h)))


def key_is_canonical_prime_order(pub):
    """Key rule (profile 1.3): canonical encoding of a point of prime order L."""
    if not pub or len(pub) != 32:
        return False
    A = _decode_point(pub)
    if not A or _eq(A, O):
        return False
    return _eq(_mul(A, L), O)


# ---------------------------------------------------------------- canonical JSON
def _num(v):
    if isinstance(v, bool):
        raise ValueError("bool")
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError("NaN and Infinity are not valid JSON numbers")
        if v.is_integer() and abs(v) < 1e21:
            return str(int(v))
        return repr(
            v
        )  # ES6 and repr agree for the shortest round-trip form in the common range
    return str(v)


def jcs(v):
    """RFC 8785: keys sorted by UTF-16 code units, strings escape only quote, backslash and controls."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in keys
            )
            + "}"
        )
    raise ValueError("unsupported value in receipt")


def canonical_v1(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float):
        if not v.is_integer():
            raise ValueError("non-integer number in receipt")
        return str(int(v))
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=True)
    if isinstance(v, list):
        return "[" + ",".join(canonical_v1(x) for x in v) + "]"
    if isinstance(v, dict):
        return (
            "{"
            + ",".join(canonical_v1(k) + ":" + canonical_v1(v[k]) for k in sorted(v))
            + "}"
        )
    raise ValueError("unsupported value in receipt")


def canonical_for(body):
    schema = body.get("schema")
    if schema == SCHEMA_V1:
        return canonical_v1(body)
    if schema in (SCHEMA_V11, SCHEMA_V12):
        s = body.get("suite")
        if (
            body.get("canonicalization") != "JCS-RFC8785"
            or not isinstance(s, dict)
            or s.get("digest") != "sha-256"
            or s.get("signature") != "Ed25519"
            or len(s) != 2
        ):
            raise ValueError(
                "This receipt declares a canonicalization or suite this verifier does not support."
            )
        return jcs(body)
    raise ValueError("Unsupported receipt version: " + str(schema)[:60])


# ---------------------------------------------------------------- RFC 3161 imprint scan
SHA256_OID = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])


def _imprint_is_sha256(tsr, at):
    if at < 2 or tsr[at - 2] != 0x04 or tsr[at - 1] != 0x20:
        return False
    end = at - 2
    if end >= 2 and tsr[end - 2] == 0x05 and tsr[end - 1] == 0x00:
        end -= 2
    return end >= len(SHA256_OID) and tsr[end - len(SHA256_OID) : end] == SHA256_OID


def _accuracy_at(tsr, i):
    if i + 1 >= len(tsr) or tsr[i] != 0x30:
        return None
    end = i + 2 + tsr[i + 1]
    ms, j, any_ = 0.0, i + 2, False
    while j < end and j + 1 < len(tsr):
        tag, ln = tsr[j], tsr[j + 1]
        n = int.from_bytes(tsr[j + 2 : j + 2 + ln], "big")
        if tag == 0x02:
            ms += n * 1000
        elif tag == 0x80:
            ms += n
        elif tag == 0x81:
            ms += n / 1000
        else:
            return None
        any_ = True
        j += 2 + ln
    return ms if any_ else None


def _iso_from_gen(g):
    if len(g) < 14 or not g[:14].isdigit():
        return None
    return f"{g[0:4]}-{g[4:6]}-{g[6:8]}T{g[8:10]}:{g[10:12]}:{g[12:14]}Z"


def tsr_time_for(tsr, digest):
    at = tsr.find(digest)
    if at < 0 or not _imprint_is_sha256(tsr, at):
        return {"imprint": False, "time": None, "accuracy_ms": None}
    for i in range(at + len(digest), len(tsr) - 16):
        if tsr[i] == 0x18 and tsr[i + 1] == 0x0F:
            return {
                "imprint": True,
                "time": _iso_from_gen(tsr[i + 2 : i + 17].decode("ascii", "replace")),
                "accuracy_ms": _accuracy_at(tsr, i + 17),
            }
    return {"imprint": True, "time": None, "accuracy_ms": None}


def _ms(iso):
    return (
        datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=datetime.timezone.utc)
        .timestamp()
        * 1000
    )


# ---------------------------------------------------------------- record checks
def overall_verdict(results, human):
    if human and human.get("status") == "complete" and human.get("outcome") == "fail":
        return "fail"
    req = [r.get("result") for r in results if r.get("required") is not False]
    if "fail" in req:
        return "fail"
    if not req or any(x != "pass" for x in req):
        return "incomplete"
    return "pass"


def independence_of(parties):
    chk = (parties or {}).get("checker") or {}
    prod = (parties or {}).get("producer") or {}
    name = str(prod.get("name") or "").strip().lower()
    if not name or name in ("unspecified", "unknown"):
        return "undeclared"
    if name == str(chk.get("name") or "").strip().lower() or (
        prod.get("key_id") and prod.get("key_id") == chk.get("key_id")
    ):
        return "self-checked"
    return "independent"


def _check_v12(doc, out, criteria_bytes, criteria_tsr):
    b = doc["receipt"]
    problems, warnings = set(), set()
    if out.get("key_rejected"):
        problems.add("KEY_REJECTED")
    elif not out["signature"]:
        problems.add("SIGNATURE_INVALID")
    parties = b.get("parties") or {}
    chk, prod = parties.get("checker") or {}, parties.get("producer") or {}
    if chk.get("key_id") != doc["signature"].get("key_id"):
        problems.add("CHECKER_NOT_SIGNER")
    if chk.get("key_id") and chk.get("key_id") == prod.get("key_id"):
        problems.add("KEY_COLLISION")
    derived = independence_of(parties)
    out["independence"] = b.get("independence")
    if derived != b.get("independence"):
        problems.add("INDEPENDENCE_INCONSISTENT")
    if b.get("independence") == "self-checked":
        warnings.add("SELF_CHECKED")
    if derived == "undeclared":
        warnings.add("PRODUCER_UNDECLARED")
    results = b.get("results") if isinstance(b.get("results"), list) else []
    if any(r.get("result") not in RESULT_VOCAB for r in results):
        problems.add("RESULT_VOCABULARY")
    out["verdict_recomputed"] = overall_verdict(results, b.get("human_review"))
    if out["verdict_recomputed"] != b.get("verdict"):
        problems.add("VERDICT_MISMATCH")

    c = b.get("criteria") or {}
    claimed = str(c.get("sha256") or "").lower()
    out["criteria_hash"] = "unavailable"
    out["criteria_committed_before_check"] = "unknown"
    if criteria_bytes is not None:
        h = hashlib.sha256(criteria_bytes).hexdigest()
        out["criteria_hash"] = "match" if h == claimed else "mismatch"
        if h != claimed:
            problems.add("CRITERIA_HASH_MISMATCH")
        else:
            try:
                cd = json.loads(criteria_bytes.decode("utf-8"))
                want = sorted(
                    (x.get("id"), bool(x.get("required")))
                    for x in cd.get("criteria") or []
                )
                got = sorted((r.get("id"), bool(r.get("required"))) for r in results)
                if (
                    want != got
                    or cd.get("criteria_set") != c.get("id")
                    or cd.get("version") != c.get("version")
                ):
                    problems.add("CRITERIA_RESULTS_MISMATCH")
            except Exception:
                problems.add("CRITERIA_UNREADABLE")

    committed, commit_acc, token_timed = c.get("committed_at"), 0, False
    if criteria_tsr is not None:
        try:
            digest = bytes.fromhex(claimed)
        except ValueError:
            digest = b"\x00" * 33  # cannot occur in a token
        t = tsr_time_for(criteria_tsr, digest)
        if not t["imprint"]:
            problems.add("CRITERIA_TIMESTAMP_MISMATCH")
        elif t["time"]:
            if c.get("committed_at") != t["time"]:
                problems.add("CRITERIA_TIME_MISMATCH")
            committed, commit_acc, token_timed = t["time"], t["accuracy_ms"] or 0, True
    if not token_timed:
        warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")

    ts = out["timestamp"]
    cover = ts.get("token_time") if ts.get("tsr") == "match" else None
    issued = b.get("issued_utc")
    ref = cover if cover and (not issued or _ms(cover) < _ms(issued)) else issued
    ref_acc = (ts.get("token_accuracy_ms") or 0) if cover and ref == cover else 0
    if committed and ref:
        before = _ms(committed) + commit_acc < _ms(ref) - ref_acc
        out["criteria_committed_before_check"] = "yes" if before else "no"
        if not before:
            problems.add("CRITERIA_COMMITTED_AFTER_CHECK")
    out["problem_codes"] = sorted(problems)
    out["warning_codes"] = sorted(warnings)


def verify_receipt(
    doc, keyset, criteria_bytes=None, criteria_tsr=None, receipt_tsr=None
):
    out = {
        "signature": None,
        "timestamp": {"status": "none"},
        "problem_codes": [],
        "warning_codes": [],
    }
    if (
        not isinstance(doc, dict)
        or not doc.get("receipt")
        or not doc.get("signature")
        or doc["signature"].get("alg") != "Ed25519"
    ):
        out["reason"] = "not an acceptance receipt"
        return out
    body = canonical_for(doc["receipt"]).encode("utf-8")
    signed_key_id = (
        doc["receipt"]["key_id"]
        if "key_id" in doc["receipt"]
        else doc["signature"].get("key_id")
    )
    entry = next(
        (
            k
            for k in (keyset or {}).get("keys") or []
            if k.get("key_id") == signed_key_id
        ),
        None,
    )
    if signed_key_id != doc["signature"].get("key_id"):
        out["signature"] = False
    elif entry and not key_is_canonical_prime_order(
        base64.b64decode(entry["public_key_base64"])
    ):
        out["signature"], out["key_rejected"] = False, True
    elif not entry:
        out["signature"] = False
    else:
        try:
            out["signature"] = verify_ed25519(
                base64.b64decode(doc["signature"]["value"]),
                body,
                base64.b64decode(entry["public_key_base64"]),
            )
        except Exception:
            out["signature"] = False
    body_hash = hashlib.sha256(body).digest()
    t = doc.get("timestamp") or {"status": "none"}
    if t.get("status") == "granted":
        out["timestamp"] = {
            "status": "granted",
            "tsr": "not_provided",
            "token_time": None,
        }
        if receipt_tsr is not None:
            r = tsr_time_for(receipt_tsr, body_hash)
            out["timestamp"].update(
                tsr="match" if r["imprint"] else "mismatch",
                token_time=r["time"] if r["imprint"] else None,
                token_accuracy_ms=r["accuracy_ms"] if r["imprint"] else None,
            )
    if doc["receipt"].get("schema") == SCHEMA_V12:
        _check_v12(doc, out, criteria_bytes, criteria_tsr)
    elif out.get("key_rejected"):
        out["problem_codes"] = ["KEY_REJECTED"]
    elif not out["signature"]:
        out["problem_codes"] = ["SIGNATURE_INVALID"]
    return out


def vector_outcome(vec):
    i = vec["inputs"]
    try:
        canonical_for(i["receipt"]["receipt"])
    except ValueError:
        return {"refused": True, "reason": "unknown schema, canonicalization or suite"}
    b64 = lambda k: base64.b64decode(i[k]) if i.get(k) else None
    v = verify_receipt(
        i["receipt"],
        i["keys"],
        b64("criteria_file_base64"),
        b64("criteria_tsr_base64"),
        b64("receipt_tsr_base64"),
    )
    ts = v["timestamp"]
    return {
        "signature_valid": v["signature"] is True,
        "problem_codes": v["problem_codes"],
        "warning_codes": v["warning_codes"],
        "independence": v.get("independence"),
        "criteria_hash": v.get("criteria_hash"),
        "criteria_committed_before_check": v.get("criteria_committed_before_check"),
        "verdict_stated": i["receipt"]["receipt"].get("verdict"),
        "verdict_recomputed": v.get("verdict_recomputed"),
        "receipt_timestamp": "none"
        if ts["status"] != "granted" or ts["tsr"] == "not_provided"
        else ("imprint_match" if ts["tsr"] == "match" else "imprint_mismatch"),
    }


def _norm(o):
    return {k: sorted(x) if k.endswith("_codes") else x for k, x in o.items()}


def main(argv):
    if argv[:1] == ["--outcome"]:
        for f in argv[1:]:
            print(
                json.dumps(
                    vector_outcome(json.load(open(f, encoding="utf-8"))),
                    indent=1,
                    sort_keys=True,
                )
            )
        return 0
    bad = 0
    for f in argv:
        vec = json.load(open(f, encoding="utf-8"))
        got, exp = vector_outcome(vec), vec["expected"]
        g = _norm({k: got.get(k) for k in exp})
        ok = g == _norm(exp)
        print(("AGREE " if ok else "DIFF  ") + f.replace("\\", "/").split("/")[-1])
        if not ok:
            bad += 1
            for k in exp:
                if g.get(k) != _norm(exp).get(k):
                    print(f"    {k}: expected {exp[k]!r} got {got.get(k)!r}")
    print(f"{len(argv) - bad}/{len(argv)} agree")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
