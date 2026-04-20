#!/usr/bin/env python3
"""
Multi-chain minimal batch shadow-signer speed scan for Morpho multisigs.
"""
import json
import sys
import os
import time
from web3 import Web3

RPC_MAP = {
    1: os.environ.get("ETH_RPC_URL", "https://eth.drpc.org"),
    10: "https://optimism.drpc.org",
    137: "https://polygon.drpc.org",
    8453: os.environ.get("BASE_RPC_URL", "https://base.drpc.org"),
    42161: os.environ.get("ARB_RPC_URL", "https://arbitrum.drpc.org"),
}

MORPHO_JSON = "morpho_msig_results_v1_and_v2.json"

GET_OWNERS_SEL = "0xa0e67e2b"
GET_THRESHOLD_SEL = "0xe75235b8"
IS_OWNER_SEL = "0x2f54bf6e"

SENTINEL = "0x0000000000000000000000000000000000000001"
SLOT_OWNERS = 2
SLOT_OWNER_COUNT = 3

KNOWN_SINGLETONS = {
    '0xd9db270c1b5e3bd161e8c8503c55ceabee709552',
    '0x41675c099f32341bf84bfc5382af534df5c7461a',
    '0x29fcb43b465fB62e509067F2d4F625121A7D24c3',
    '0xfb1bffc9d739b8d520daf37df666da4c687191ea',
    '0x34cfac646f301356faa8b21e94227e3583fe3f5f',
}


def call_view(w3, addr, selector, params=""):
    return w3.eth.call({"to": addr, "data": selector + params})


def decode_address_array(data):
    if len(data) < 64:
        return []
    offset = int(data[:32].hex(), 16)
    length = int(data[offset:offset + 32].hex(), 16)
    addrs = []
    for i in range(length):
        start = offset + 32 + i * 32
        addrs.append(Web3.to_checksum_address(data[start + 12:start + 32].hex()))
    return addrs


def compute_owner_slot(address):
    addr_padded = address.lower()[2:].zfill(64)
    slot_padded = format(SLOT_OWNERS, "064x")
    return Web3.keccak(hexstr=addr_padded + slot_padded).hex()


def scan_safe(w3, addr):
    findings = []
    try:
        owners = decode_address_array(call_view(w3, addr, GET_OWNERS_SEL))
    except Exception:
        return None  # not a Safe

    try:
        threshold = int(call_view(w3, addr, GET_THRESHOLD_SEL).hex(), 16)
    except Exception:
        threshold = 0

    try:
        owner_count_storage = int(w3.eth.get_storage_at(addr, SLOT_OWNER_COUNT).hex(), 16)
    except Exception:
        owner_count_storage = None

    if owner_count_storage is not None and owner_count_storage != len(owners):
        findings.append({"type": "owner_count_mismatch", "severity": "high",
                         "details": f"ownerCount storage={owner_count_storage} but getOwners() returns {len(owners)}"})

    for o in owners:
        try:
            p = o[2:].lower().zfill(64)
            result = call_view(w3, addr, IS_OWNER_SEL, p)
            if not bool(int(result.hex(), 16)):
                findings.append({"type": "isowner_false_for_listed", "severity": "critical",
                                 "details": f"Address {o} in getOwners() but isOwner() returns false"})
        except Exception:
            pass

    if threshold > len(owners):
        findings.append({"type": "threshold_exceeds_owners", "severity": "high",
                         "details": f"Threshold ({threshold}) > listed owner count ({len(owners)})"})

    # Linked list walk
    linked = []
    current = SENTINEL
    visited = set()
    for _ in range(100):
        slot = compute_owner_slot(current)
        try:
            raw = w3.eth.get_storage_at(addr, slot)
        except Exception:
            break
        next_addr = Web3.to_checksum_address(raw[12:].hex())
        if next_addr == SENTINEL:
            break
        if next_addr in visited:
            findings.append({"type": "linked_list_anomaly", "severity": "high",
                             "details": f"Linked list anomaly: CYCLE at {next_addr}"})
            break
        visited.add(next_addr)
        linked.append(next_addr)
        current = next_addr
    else:
        findings.append({"type": "linked_list_anomaly", "severity": "high",
                         "details": "Linked list max depth exceeded"})

    owners_set = {o.lower() for o in owners}
    linked_set = {o.lower() for o in linked}
    for o in linked:
        if o.lower() not in owners_set:
            findings.append({"type": "linked_list_orphan", "severity": "critical",
                             "details": f"Linked list contains {o} not returned by getOwners()"})
    for o in owners:
        if o.lower() not in linked_set:
            findings.append({"type": "missing_from_linked_list", "severity": "high",
                             "details": f"Owner {o} in getOwners() but not found in linked list traversal"})

    return findings


def main():
    with open(MORPHO_JSON) as f:
        data = json.load(f)

    # Group by chain
    by_chain = {}
    for m in data["multisigs"]:
        cid = m["chain_id"]
        addr = Web3.to_checksum_address(m["address"])
        by_chain.setdefault(cid, set()).add(addr)

    print("Addresses per chain:")
    for cid in sorted(by_chain):
        print(f"  Chain {cid}: {len(by_chain[cid])}")

    results = []
    total_findings = 0
    scanned = 0
    skipped_no_rpc = 0

    for cid, addresses in sorted(by_chain.items()):
        if cid not in RPC_MAP:
            print(f"\nSkipping chain {cid}: no RPC configured")
            for addr in addresses:
                results.append({"address": addr, "chain_id": cid, "skipped": True, "reason": "no_rpc"})
                skipped_no_rpc += 1
            continue

        rpc_url = RPC_MAP[cid]
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not w3.is_connected():
            print(f"\nSkipping chain {cid}: RPC connection failed ({rpc_url})")
            for addr in addresses:
                results.append({"address": addr, "chain_id": cid, "skipped": True, "reason": "rpc_failed"})
                skipped_no_rpc += 1
            continue

        print(f"\nScanning chain {cid} via {rpc_url} ({len(addresses)} addresses)")
        for i, addr in enumerate(sorted(addresses), 1):
            try:
                code = w3.eth.get_code(addr)
                if len(code) <= 2:
                    results.append({"address": addr, "chain_id": cid, "skipped": True, "reason": "no_code"})
                    continue
            except Exception as e:
                results.append({"address": addr, "chain_id": cid, "skipped": True, "reason": str(e)})
                continue

            findings = scan_safe(w3, addr)
            if findings is None:
                results.append({"address": addr, "chain_id": cid, "skipped": True, "reason": "not_a_safe"})
                continue

            scanned += 1
            total_findings += len(findings)
            if findings:
                print(f"  [{i}/{len(addresses)}] {addr}: {len(findings)} finding(s)")
                for f in findings:
                    print(f"      [{f['type']}] {f['severity']}: {f['details']}")
            elif i % 20 == 0 or i == len(addresses):
                print(f"  [{i}/{len(addresses)}] scanned...")

            results.append({"address": addr, "chain_id": cid, "skipped": False, "findings": findings})

    with_findings = [r for r in results if not r.get("skipped") and r.get("findings")]

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Scanned valid Safes: {scanned}")
    print(f"Skipped: {len(results) - scanned}")
    print(f"Total findings: {total_findings}")
    print(f"Multisigs with findings: {len(with_findings)}")

    if with_findings:
        print("\nMultisigs with potential shadow signers:")
        for r in with_findings:
            print(f"  {r['address']} (chain {r['chain_id']}):")
            for f in r["findings"]:
                print(f"    - [{f['type']}] {f['severity']}: {f['details']}")
    else:
        print("\nNo shadow signer findings detected in any scanned multisig.")

    with open("morpho_speed_scan_all_chains_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to morpho_speed_scan_all_chains_results.json")


if __name__ == "__main__":
    main()
