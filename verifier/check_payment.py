"""Check a receipt's optional `payment` member (x402 exact, EVM) against the chain. Profile 1.4.1; outcome-neutral.

Standard library only. Reads a receipt envelope (receipt.json) or a test vector, and asks a JSON-RPC endpoint:
  1. USDC-style EIP-3009 `authorizationState(payer, nonce)` on `asset`: the authorization was used.
  2. When `settlement_tx` is given: the transaction succeeded, `asset` emitted `AuthorizationUsed(payer, nonce)` and
     `Transfer(payer -> pay_to, amount)`, and its block is no later than `issued_utc`.
Status: verified (1 and 2), authorization_used (1 only; no settlement_tx, so terms are unchecked), not_found,
mismatch, unsupported. Nothing here changes the record's outcome.

Usage: python check_payment.py RECEIPT_OR_VECTOR.json [--rpc URL]
"""

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

RPC = {
    "eip155:8453": "https://mainnet.base.org",
    "eip155:84532": "https://sepolia.base.org",
}
SEL_AUTHORIZATION_STATE = "0xe94a0102"  # authorizationState(address,bytes32)
TOPIC_AUTHORIZATION_USED = (
    "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"
)
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def http_rpc(url):
    def call(method, params):
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode()
        for attempt in range(5):
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "war-check-payment/1",
                },
            )
            try:
                r = json.load(urllib.request.urlopen(req, timeout=30))
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 4:
                    time.sleep(2**attempt)
                    continue
                raise
            if "error" in r:
                raise RuntimeError("%s: %s" % (method, r["error"]))
            return r["result"]

    return call


def _word(hex_str):
    return hex_str.lower().removeprefix("0x").rjust(64, "0")


def _addr(topic):
    return "0x" + topic[-40:].lower()


def body_of(doc):
    if "inputs" in doc:
        doc = doc["inputs"]["receipt"]
    return doc["receipt"] if "receipt" in doc else doc


_REQUIRED = (
    "protocol",
    "scheme",
    "network",
    "asset",
    "payer",
    "pay_to",
    "amount",
    "nonce",
)


def _in_form(p):
    """The x402 exact form: exactly the required members plus optional settlement_tx, all strings; network is eip155:
    and a decimal chain id without leading zeros (CAIP-2); amount a decimal string of atomic units; addresses 20 bytes,
    nonce 32 bytes, settlement_tx 32 bytes, each 0x-prefixed hex."""
    import re

    if set(p) - {"settlement_tx"} != set(_REQUIRED) or not all(
        isinstance(v, str) for v in p.values()
    ):
        return False
    hexn = lambda v, n: re.fullmatch(r"0x[0-9a-fA-F]{%d}" % (2 * n), v) is not None
    return (
        re.fullmatch(r"eip155:[1-9][0-9]{0,31}", p["network"]) is not None
        and re.fullmatch(r"0|[1-9][0-9]*", p["amount"]) is not None
        and all(hexn(p[k], 20) for k in ("asset", "payer", "pay_to"))
        and hexn(p["nonce"], 32)
        and ("settlement_tx" not in p or hexn(p["settlement_tx"], 32))
    )


def check_payment(body, rpc):
    p = body.get("payment")
    if not isinstance(p, dict):
        return {"status": "unsupported", "reason": "no payment member"}
    if (
        p.get("protocol") != "x402"
        or p.get("scheme") != "exact"
        or not str(p.get("network", "")).startswith("eip155:")
    ):
        return {"status": "unsupported", "reason": "only x402 exact on eip155 networks"}
    if not _in_form(p):
        return {
            "status": "unsupported",
            "reason": "payment member outside the x402 exact form",
        }
    asset, payer, pay_to = p["asset"].lower(), p["payer"].lower(), p["pay_to"].lower()
    nonce = "0x" + _word(p["nonce"])
    used = rpc(
        "eth_call",
        [
            {
                "to": asset,
                "data": SEL_AUTHORIZATION_STATE + _word(payer) + _word(nonce),
            },
            "latest",
        ],
    )
    if int(used, 16) != 1:
        return {
            "status": "not_found",
            "reason": "authorization (payer, nonce) not used on %s" % asset,
        }
    tx = p.get("settlement_tx")
    if not tx:
        return {
            "status": "authorization_used",
            "reason": "nonce used; no settlement_tx, so amount and pay_to are unchecked",
        }
    rcpt = rpc("eth_getTransactionReceipt", [tx])
    if rcpt is None:
        return {"status": "not_found", "reason": "settlement_tx not found"}
    if int(rcpt["status"], 16) != 1:
        return {"status": "mismatch", "reason": "settlement_tx reverted"}
    logs = [l for l in rcpt["logs"] if l["address"].lower() == asset]
    if not any(
        l["topics"][0] == TOPIC_AUTHORIZATION_USED
        and _addr(l["topics"][1]) == payer
        and l["topics"][2].lower() == nonce
        for l in logs
    ):
        return {
            "status": "mismatch",
            "reason": "settlement_tx does not use this (payer, nonce)",
        }
    if not any(
        l["topics"][0] == TOPIC_TRANSFER
        and _addr(l["topics"][1]) == payer
        and _addr(l["topics"][2]) == pay_to
        and int(l["data"], 16) == int(p["amount"])
        for l in logs
    ):
        return {
            "status": "mismatch",
            "reason": "no Transfer of amount from payer to pay_to in settlement_tx",
        }
    block = rpc("eth_getBlockByNumber", [rcpt["blockNumber"], False])
    settled = datetime.fromtimestamp(int(block["timestamp"], 16), timezone.utc)
    issued = datetime.strptime(body["issued_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    if settled > issued:
        return {
            "status": "mismatch",
            "reason": "settled %s, after issued_utc" % settled.isoformat(),
        }
    return {
        "status": "verified",
        "reason": "settled %s in block %d"
        % (settled.strftime("%Y-%m-%dT%H:%M:%SZ"), int(rcpt["blockNumber"], 16)),
    }


def main(argv):
    rpc_url = None
    if "--rpc" in argv:
        i = argv.index("--rpc")
        rpc_url = argv[i + 1]
        argv = argv[:i] + argv[i + 2 :]
    with open(argv[0], encoding="utf-8") as f:
        body = body_of(json.load(f))
    net = (body.get("payment") or {}).get("network")
    url = rpc_url or RPC.get(net)
    if not url:
        print(
            json.dumps(
                {
                    "status": "unsupported",
                    "reason": "no RPC known for %s; pass --rpc" % net,
                }
            )
        )
        return 2
    r = check_payment(body, http_rpc(url))
    print(json.dumps(r))
    return 0 if r["status"] in ("verified", "authorization_used") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
