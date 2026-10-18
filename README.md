# Work-acceptance record (draft profile 1.2.1, schema 1.2)

A work-acceptance record is a checking party's signed findings about a delivered file, against criteria that were fixed before the check.
It is distinct from a counterparty's acceptance decision (accepted / rejected / disputed). A counterparty acceptance can reference a
work-acceptance record by digest, so "the checker found X" and "the counterparty accepted it" remain two signatures from two parties.

## Properties
1. **Bound to the exact file**: SHA-256 of the delivered file (and of the original, when there is one).
2. **Criteria committed first**: the criteria document has its own SHA-256 and an RFC 3161 timestamp (or a binding to terms the counterparty signed). A verifier
   reports whether the commitment predates the check. The token over `criteria.sha256` is authoritative for when; `criteria.committed_at` is the checker's own claim.
3. **Checker independence is checkable**: `parties.checker` and `parties.producer` are named separately. The checker key must not equal the producer key; a self-check is
   labelled `independence: "self-checked"` and verifiers warn on it.
4. **Verdict vocabulary**: each criterion result is `pass | fail | not-evaluated | error`. The overall verdict is `pass` only if every required criterion is `pass`.
   Any required `fail` makes it `fail`, and `fail` takes precedence over `incomplete`; otherwise any required `not-evaluated` or `error` makes it `incomplete`, never `pass`.
   Verifiers recompute the verdict from the results; a stated verdict that differs is `VERDICT_MISMATCH`.
5. **Verifiable from bytes**: canonical form JCS (RFC 8785). Ed25519 signature over the canonical `receipt` object. An RFC 3161 token over the SHA-256 of the canonical
   receipt. Suites are declared in the record (`canonicalization`, `suite`). No hosted service or account is needed.

## Verification procedure (summary)
1. Parse; refuse an unknown schema, canonicalization or suite.
2. JCS-canonicalize `receipt`; verify the Ed25519 signature with the key identified by `key_id`. On failure report `SIGNATURE_INVALID`; the remaining checks may still be reported as diagnostics, but the contents are not presented as results.
3. If the delivered file is supplied, compare its SHA-256 with `files.remediated.sha256`.
4. If the criteria document is supplied, compare its SHA-256 with `criteria.sha256` (`CRITERIA_HASH_MISMATCH`); when it matches, check the results correspond to the criteria (`CRITERIA_RESULTS_MISMATCH`).
5. Criteria commitment. If a timestamp token is supplied, its imprint must equal `criteria.sha256` (`CRITERIA_TIMESTAMP_MISMATCH` for a token over other bytes) and its `genTime` is authoritative; a `criteria.committed_at` that disagrees is `CRITERIA_TIME_MISMATCH`. Without a token, fall back to `committed_at` and warn `CRITERIA_COMMITMENT_UNVERIFIED`. The criteria were committed before the check iff the commitment time is strictly earlier than the reference time: the genTime of the record's own token when a token covering the record is supplied, else `issued_utc`. If not, `criteria_committed_before_check` is `no` and `CRITERIA_COMMITTED_AFTER_CHECK` is raised. **That is a problem, not a warning.**
6. Check the record's timestamp token imprint against SHA-256 of the canonical receipt; report `receipt_timestamp` as `none` (no timestamp or no token supplied), `imprint_match` or `imprint_mismatch`. A mismatching token is never used as evidence of time.
7. Recompute the verdict from the per-criterion results (property 4) and compare it with the stated verdict (`VERDICT_MISMATCH`).
8. Emit problem codes (`SIGNATURE_INVALID`, `CHECKER_NOT_SIGNER`, `KEY_COLLISION`, `INDEPENDENCE_INCONSISTENT`, `RESULT_VOCABULARY`, `VERDICT_MISMATCH`, `CRITERIA_HASH_MISMATCH`, `CRITERIA_RESULTS_MISMATCH`, `CRITERIA_TIMESTAMP_MISMATCH`, `CRITERIA_TIME_MISMATCH`, `CRITERIA_COMMITTED_AFTER_CHECK`) and warning codes (`SELF_CHECKED`, `PRODUCER_UNDECLARED`, `CRITERIA_COMMITMENT_UNVERIFIED`). The record is accepted as stated when the signature is valid and there are no problem codes. Code lists are sets: compare without regard to order.

## Vectors (`vectors/`, CC0)
| file | case |
|---|---|
| 01-valid.json | valid, independent, criteria committed first |
| 02-criteria-committed-after-issue.json | criteria commitment later than the check |
| 03-self-checked.json | checker == producer organisation |
| 04-required-not-evaluated.json | a required criterion `not-evaluated` → `incomplete` |
| 05-checker-key-equals-producer-key.json | key collision |
| 06-receipt-edited-after-signing.json | a finding edited after signing (contributed by babyblueviper1, CC0) |
| 07-criteria-file-swapped.json | another criteria document supplied (contributed by babyblueviper1, CC0) |
| 08-receipt-token-over-another-receipt.json | the record's token covers another record (contributed by babyblueviper1, CC0) |
| 09-stated-pass-recomputes-incomplete.json | signed `pass` with a required criterion `not-evaluated` (contributed by babyblueviper1, CC0) |
| 10-committed-at-contradicts-token.json | `committed_at` before the check, token genTime after it (contributed by babyblueviper1, CC0) |
| 11-required-criterion-fails.json | a required `fail` (contributed by babyblueviper1, CC0) |

Each file contains its inputs and an `expected` object with the outcome an independent verifier should reproduce. The keys in the vectors are test keys:
never trust them. The timestamp tokens in the vectors are structurally valid but not signed by a real time-stamp authority, so they test imprint and time handling only.

## Changelog
**Profile 1.2.1 (2026-10-17; schema identifier unchanged).** Resolves ambiguities found by an independent clean-room review (babyblueviper1): `CRITERIA_COMMITTED_AFTER_CHECK` is a problem; the token over `criteria.sha256` is authoritative for commitment time (`CRITERIA_TIME_MISMATCH`, fallback with `CRITERIA_COMMITMENT_UNVERIFIED`); verdict rule completed (required `fail` wins, `VERDICT_MISMATCH`); reference time uses the record's token only when it covers the record; vectors 06-11 added.
**Profile 1.2.** First draft, vectors 01-05.

## Status
Draft, offered for the evidence-record discussion in x402-foundation/tsc#4 and referenced by ACP SEP #303 (Section 7.4a). Independent clean-room
implementations are welcome; please report any disagreement with a vector's `expected` outcome as an issue.

Licence: text CC BY 4.0; vectors CC0 1.0.
