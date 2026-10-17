# Work-acceptance record (draft profile, schema 1.2)

A work-acceptance record is a checking party's signed findings about a delivered file, against criteria that were fixed before the check.
It is distinct from a counterparty's acceptance decision (accepted / rejected / disputed). A counterparty acceptance can reference a
work-acceptance record by digest, so "the checker found X" and "the counterparty accepted it" remain two signatures from two parties.

## Properties
1. **Bound to the exact file**: SHA-256 of the delivered file (and of the original, when there is one).
2. **Criteria committed first**: the criteria document has its own SHA-256 and an RFC 3161 timestamp (or a binding to terms the counterparty signed). A verifier
   reports whether the commitment predates the record's issue time.
3. **Checker independence is checkable**: `parties.checker` and `parties.producer` are named separately. The checker key must not equal the producer key; a self-check is
   labelled `independence: "self-checked"` and verifiers warn on it.
4. **Verdict vocabulary**: each criterion result is `pass | fail | not-evaluated | error`. The overall verdict is `pass` only if every required criterion is `pass`;
   any required `not-evaluated` or `error` makes it `incomplete`, never `pass`. Verifiers recompute the verdict from the results.
5. **Verifiable from bytes**: canonical form JCS (RFC 8785). Ed25519 signature over the canonical `receipt` object. An RFC 3161 token over the SHA-256 of the canonical
   receipt. Suites are declared in the record (`canonicalization`, `suite`). No hosted service or account is needed.

## Verification procedure (summary)
1. Parse; refuse an unknown schema, canonicalization or suite.
2. JCS-canonicalize `receipt`; verify the Ed25519 signature with the key identified by `key_id`.
3. If the delivered file is supplied, compare its SHA-256 with `files.remediated.sha256`.
4. If the criteria document is supplied, compare its SHA-256 with `criteria.sha256`; compare `criteria.committed_at` with `issued_utc` → `criteria_committed_before_check`.
5. Check the timestamp token's message imprint against SHA-256 of the canonical receipt.
6. Recompute the verdict from per-criterion results and compare it with the stated verdict.
7. Emit problem codes (e.g. `KEY_COLLISION`, `CRITERIA_HASH_MISMATCH`, `VERDICT_MISMATCH`) and warning codes (e.g. `SELF_CHECKED`, `CRITERIA_COMMITTED_AFTER_CHECK`).

## Vectors (`vectors/`, CC0)
| file | case |
|---|---|
| 01-valid.json | valid, independent, criteria committed first |
| 02-criteria-committed-after-issue.json | criteria commitment later than the issue time |
| 03-self-checked.json | checker == producer organisation |
| 04-required-not-evaluated.json | a required criterion `not-evaluated` → `incomplete` |
| 05-checker-key-equals-producer-key.json | key collision |

Each file contains its inputs and an `expected` object with the outcome an independent verifier should reproduce. The keys in the vectors are test keys:
never trust them. The timestamp tokens in the vectors are structurally valid but not signed by a real time-stamp authority, so they test imprint and time handling only.

## Status
Draft, offered for the evidence-record discussion in x402-foundation/tsc#4 and referenced by ACP SEP #303 (Section 7.4a). Independent clean-room
implementations are welcome; please report any disagreement with a vector's `expected` outcome as an issue.

Licence: text CC BY 4.0; vectors CC0 1.0.
