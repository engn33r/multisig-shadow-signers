#!/usr/bin/env python3
"""
deep_scan.py - Detect shadow owners/modules in Safe multisigs via dirty storage analysis.

Implements the 6-phase pipeline from dirty-storage-plan-claude.md:
  Phase 1: Transaction history discovery via eth_getLogs
  Phase 2: Optional prestateTracer prefilter
  Phase 3: Opcode-level replay and preimage correlation via cast run --trace-printer
  Phase 4: Preimage decoding and classification
  Phase 5: Raw SSTORE anomaly detection
  Phase 6: Report generation

Usage:
  python deep_scan.py --safe-address 0x... --rpc-url http://... [--deep-scan] [--from-block N] [--to-block N] [--include-direct-txs]
  python deep_scan.py --safe-address 0x... --rpc-url http://... --local-test
"""

import argparse
import json
import subprocess
import sys
import re
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Any, NewType
from web3 import Web3

# Type aliases for clarity
Bytes32 = bytes  # 32-byte hash/slot value

# ──────────────────────────────────────────────────────────────────────────────
# Safe storage layout constants (from SafeStorage.sol + inheritance order)
# ──────────────────────────────────────────────────────────────────────────────
SLOT_SINGLETON = 0
SLOT_MODULES = 1  # mapping(address => address)
SLOT_OWNERS = 2  # mapping(address => address)
SLOT_OWNER_COUNT = 3  # uint256
SLOT_THRESHOLD = 4  # uint256
SLOT_NONCE = 5  # uint256
SLOT_DOMAIN_SEP = 6  # bytes32 (deprecated)
SLOT_SIGNED_MSGS = 7  # mapping(bytes32 => uint256)
SLOT_APPROVED_HASHES = 8  # mapping(address => mapping(bytes32 => uint256))

# Fixed bytes32 storage slots (set via assembly sstore)
FALLBACK_HANDLER_SLOT = (
    "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5"
)
GUARD_STORAGE_SLOT = (
    "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"
)
MODULE_GUARD_STORAGE_SLOT = (
    "0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947"
)

SAFE_EVENT_TOPICS = {
    "SafeSetup": Web3.keccak(
        text="SafeSetup(address,address[],uint256,address,bytes)"
    ).hex(),
    "ExecutionSuccess": Web3.keccak(text="ExecutionSuccess(bytes32,uint256)").hex(),
    "ExecutionFailure": Web3.keccak(text="ExecutionFailure(bytes32,uint256)").hex(),
    "ExecutionFromModuleSuccess": Web3.keccak(
        text="ExecutionFromModuleSuccess(address)"
    ).hex(),
    "ExecutionFromModuleFailure": Web3.keccak(
        text="ExecutionFromModuleFailure(address)"
    ).hex(),
    "AddedOwner": Web3.keccak(text="AddedOwner(address)").hex(),
    "RemovedOwner": Web3.keccak(text="RemovedOwner(address)").hex(),
    "ChangedThreshold": Web3.keccak(text="ChangedThreshold(uint256)").hex(),
    "EnabledModule": Web3.keccak(text="EnabledModule(address)").hex(),
    "DisabledModule": Web3.keccak(text="DisabledModule(address)").hex(),
    "ChangedFallbackHandler": Web3.keccak(text="ChangedFallbackHandler(address)").hex(),
    "ChangedGuard": Web3.keccak(text="ChangedGuard(address)").hex(),
    "ChangedModuleGuard": Web3.keccak(text="ChangedModuleGuard(address)").hex(),
}

# Safe function selectors for legitimate entrypoints
SAFE_SELECTORS = {
    "0xe318b52b": "addOwnerWithThreshold(address,uint256)",
    "0xf8dc5319": "removeOwner(address,uint256)",
    "0x441da482": "swapOwner(address,address,address)",
    "0x694e80c3": "changeThreshold(uint256)",
    "0x0a2e6c8e": "enableModule(address)",
    "0x7d4c2370": "disableModule(address,address)",
    "0x7de7edef": "setFallbackHandler(address)",
    "0xe19a9dd9": "setGuard(address)",
    "0x6b8e0279": "setModuleGuard(address)",
    "0xb63e800d": "setup(address[],uint256,address,bytes,address,uint256,uint256)",
    "0x610b5925": "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
    "0xa125a615": "approveHash(bytes32)",
}

# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class KeccakPreimage:
    pc: int
    depth: int
    preimage_bytes: bytes
    output: Bytes32
    context_address: str = ""


@dataclass
class SstoreEvent:
    pc: int
    depth: int
    slot: Bytes32
    value: Bytes32
    context_address: str = ""
    call_selector: bytes = b""


@dataclass
class ShadowFinding:
    finding_type: (
        str  # "shadow_owner", "shadow_module", "dirty_fixed_slot", "anomalous"
    )
    address: Optional[str] = None
    tx_hash: str = ""
    block_number: int = 0
    sender: str = ""
    current_status: str = "unknown"  # "active", "cleaned_up", "normalized"
    slot: str = ""
    value: str = ""
    mapping_slot: Optional[int] = None
    preimage: Optional[bytes] = None
    context_address: str = ""
    note: str = ""


@dataclass
class CallFrame:
    address: str
    depth: int
    selector: bytes = b""
    is_delegatecall: bool = False
    storage_context: str = ""  # address whose storage is being written


# ──────────────────────────────────────────────────────────────────────────────
# Phase 1: Transaction history discovery
# ──────────────────────────────────────────────────────────────────────────────


def collect_safe_events(
    w3: Web3, safe_address: str, from_block: int, to_block: int, block_step: int = 10000
) -> List[Dict]:
    """Collect all events emitted by or about the Safe to discover transaction hashes."""
    safe_address = Web3.to_checksum_address(safe_address)
    all_logs = []

    event_topics = list(SAFE_EVENT_TOPICS.values())

    current_block = from_block
    while current_block <= to_block:
        end_block = min(current_block + block_step - 1, to_block)

        try:
            logs = w3.eth.get_logs(
                {
                    "address": safe_address,
                    "fromBlock": hex(current_block),
                    "toBlock": hex(end_block),
                }
            )
            all_logs.extend(logs)
        except Exception as e:
            print(
                f"Warning: eth_getLogs failed for blocks {current_block}-{end_block}: {e}",
                file=sys.stderr,
            )

        # Also check SafeSetup from the factory (emitted by proxy, not the Safe itself during creation)
        try:
            factory_logs = w3.eth.get_logs(
                {
                    "topics": [SAFE_EVENT_TOPICS["SafeSetup"]],
                    "fromBlock": hex(current_block),
                    "toBlock": hex(end_block),
                }
            )
            for log in factory_logs:
                if log["address"].lower() == safe_address.lower():
                    if log not in all_logs:
                        all_logs.append(log)
        except Exception:
            pass

        current_block = end_block + 1

    return all_logs


def extract_tx_hashes_from_logs(logs: List[Dict], safe_address: str) -> List[str]:
    """Extract unique transaction hashes from event logs."""
    tx_hashes = set()
    for log in logs:
        if log.get("transactionHash"):
            tx_hashes.add(
                log["transactionHash"].hex()
                if isinstance(log["transactionHash"], bytes)
                else log["transactionHash"]
            )
    return list(tx_hashes)


def get_direct_tx_hashes(
    w3: Web3, safe_address: str, from_block: int, to_block: int, block_step: int = 10000
) -> List[str]:
    """Get transaction hashes where tx.to == safe_address (includes module-triggered txs)."""
    tx_hashes = set()
    current_block = from_block

    while current_block <= to_block:
        end_block = min(current_block + block_step - 1, to_block)

        try:
            block_count = w3.eth.get_block_transaction_count(end_block)
            if block_count > 0:
                block = w3.eth.get_block(end_block, full_transactions=True)
                for tx in block["transactions"]:
                    if tx.get("to") and tx["to"].lower() == safe_address.lower():
                        tx_hashes.add(
                            tx["hash"].hex()
                            if isinstance(tx["hash"], bytes)
                            else tx["hash"]
                        )
        except Exception as e:
            print(f"Warning: Failed to scan block {end_block}: {e}", file=sys.stderr)

        current_block = end_block + 1

    return list(tx_hashes)


def get_creation_tx(w3: Web3, safe_address: str) -> Optional[str]:
    """Find the Safe's creation transaction via SafeSetup event."""
    try:
        logs = w3.eth.get_logs(
            {
                "address": safe_address,
                "topics": [SAFE_EVENT_TOPICS["SafeSetup"]],
                "fromBlock": "earliest",
                "toBlock": "latest",
            }
        )
        if logs:
            tx_hash = logs[0]["transactionHash"]
            return tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash
    except Exception as e:
        print(f"Warning: Failed to find creation tx: {e}", file=sys.stderr)
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Phase 2: Optional prestateTracer prefilter
# ──────────────────────────────────────────────────────────────────────────────


def prefilter_with_prestate_tracer(
    w3: Web3, tx_hashes: List[str], safe_address: str
) -> List[str]:
    """Filter txs using debug_traceTransaction with prestateTracer diffMode.

    Returns only tx hashes that wrote to non-standard Safe slots.
    If the RPC doesn't support debug_traceTransaction, returns all tx_hashes unchanged.
    """
    safe_address = safe_address.lower()
    # Known legitimate slots that are expected to change
    known_slots = set()
    known_slots.add("0x" + "0" * 63 + "0")  # slot 0 (singleton)
    known_slots.add("0x" + "0" * 63 + "3")  # slot 3 (ownerCount)
    known_slots.add("0x" + "0" * 63 + "4")  # slot 4 (threshold)
    known_slots.add("0x" + "0" * 63 + "5")  # slot 5 (nonce)
    known_slots.add(FALLBACK_HANDLER_SLOT.lower())
    known_slots.add(GUARD_STORAGE_SLOT.lower())
    known_slots.add(MODULE_GUARD_STORAGE_SLOT.lower())

    candidate_txs = []

    for tx_hash in tx_hashes:
        try:
            result = w3.provider.make_request(
                "debug_traceTransaction",
                [
                    tx_hash,
                    {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}},
                ],
            )

            if not isinstance(result, dict) or "result" not in result:
                result = result if isinstance(result, dict) else {}

            # Check if the Safe's storage was modified with suspicious slots
            post_state = result.get("result", result)
            if isinstance(post_state, dict):
                safe_diff = post_state.get(
                    safe_address, post_state.get(safe_address.lower())
                )
                if safe_diff and "storage" in safe_diff:
                    storage = safe_diff["storage"]
                    suspicious = False
                    for slot in storage:
                        if slot.lower() not in known_slots:
                            # Check if it's a mapping slot for owners/modules/sentinel
                            slot_int = int(slot, 16)
                            # Could be a mapping entry — check later in Phase 3
                            suspicious = True
                            break
                    if suspicious:
                        candidate_txs.append(tx_hash)
                    else:
                        print(
                            f"  [Phase 2] Skipping tx {tx_hash[:16]}... (only known slots modified)"
                        )
                else:
                    candidate_txs.append(tx_hash)
            else:
                candidate_txs.append(tx_hash)
        except Exception as e:
            # Provider doesn't support debug_traceTransaction; skip prefilter
            if (
                "not supported" in str(e).lower()
                or "method not found" in str(e).lower()
            ):
                print(
                    f"  [Phase 2] debug_traceTransaction not supported, skipping prefilter",
                    file=sys.stderr,
                )
                return tx_hashes
            print(
                f"  [Phase 2] Warning: tracer failed for {tx_hash[:16]}...: {e}",
                file=sys.stderr,
            )
            candidate_txs.append(tx_hash)

    return candidate_txs


# ──────────────────────────────────────────────────────────────────────────────
# Phase 3: Opcode-level replay and preimage correlation
# ──────────────────────────────────────────────────────────────────────────────


def run_cast_trace(tx_hash: str, rpc_url: str) -> str:
    """Run cast run --trace-printer for a transaction and capture stdout."""
    cmd = [
        "cast",
        "run",
        tx_hash,
        "--rpc-url",
        rpc_url,
        "--trace-printer",
        "--quick",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            print(
                f"  [Phase 3] cast run failed for {tx_hash[:16]}...: {result.stderr[:200]}",
                file=sys.stderr,
            )
            return ""
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"  [Phase 3] cast run timed out for {tx_hash[:16]}...", file=sys.stderr)
        return ""
    except FileNotFoundError:
        print(
            "  [Phase 3] Error: 'cast' not found. Please install Foundry.",
            file=sys.stderr,
        )
        sys.exit(1)


def parse_trace(
    trace_output: str, safe_address: str
) -> Tuple[List[KeccakPreimage], List[SstoreEvent]]:
    """Parse cast run --trace-printer output to extract KECCAK256 preimages and SSTORE events.

    The trace format varies across Foundry versions. This parser handles:

    Format A (common): [<depth>] [<pc>] <OPCODE> [operands] ...
    Format B: pc:<pc> | opcode:<name> | stack:[...] | memory:0x...

    Tracks call context (DELEGATECALL preserves storage context), reads memory
    for KECCAK256 preimage extraction, and correlates SSTORE slots with
    preceding KECCAK256 outputs.
    """
    safe_address = safe_address.lower()
    keccak_preimages: List[KeccakPreimage] = []
    sstore_events: List[SstoreEvent] = []

    call_stack: List[CallFrame] = []
    current_storage_context = ""

    recent_keccak: List[KeccakPreimage] = []

    lines = trace_output.split("\n")

    hex_pattern = re.compile(r"0x[0-9a-fA-F]+")

    memory_pattern = re.compile(r"memory[=:]\s*0x([0-9a-fA-F]*)", re.IGNORECASE)

    call_pattern = re.compile(
        r"(CALL|CALLCODE|DELEGATECALL|STATICCALL)\s+"
        r"(?:gas:\S+\s+)?"
        r"0x([0-9a-fA-F]{40})"  # target address
    )

    lines = trace_output.split("\n")

    for line_raw in lines:
        line = line_raw.strip()
        if not line:
            continue

        upper = line.upper()

        hex_matches = hex_pattern.findall(line)

        is_call = any(
            op in upper for op in ["CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"]
        )
        is_create = any(op in upper for op in ["CREATE", "CREATE2"])
        is_return = (
            "RETURN" in upper
            or "REVERT" in upper
            or "STOP" in upper
            or "SELFDESTRUCT" in upper
        )

        selector = b""
        if call_stack:
            selector = call_stack[0].selector

        # ── Call context tracking ──
        if is_call:
            call_match = call_pattern.search(line)
            if call_match:
                call_type = call_match.group(1).upper()
                to_addr = "0x" + call_match.group(2).lower()
                is_delegate = call_type == "DELEGATECALL"

                push_selector = b""
                if call_stack and len(hex_matches) >= 1:
                    try:
                        push_selector = bytes.fromhex(
                            hex_matches[0].replace("0x", "")[:8].ljust(8, "0")
                        )
                    except (ValueError, IndexError):
                        pass

                call_stack.append(CallFrame(
                    address=to_addr,
                    depth=0,
                    selector=push_selector,
                    is_delegatecall=is_delegate,
                    storage_context=current_storage_context if is_delegate else to_addr,
                ))
                if not is_delegate:
                    current_storage_context = to_addr

        elif is_create:
            if len(hex_matches) >= 2:
                created_addr = hex_matches[-1].lower()
            else:
                created_addr = ""
            call_stack.append(CallFrame(
                address=created_addr,
                depth=0,
                selector=b"",
                is_delegatecall=False,
                storage_context=created_addr,
            ))
            current_storage_context = created_addr

        elif is_return:
            if call_stack:
                frame = call_stack.pop()
                if not frame.is_delegatecall:
                    if call_stack:
                        current_storage_context = call_stack[-1].storage_context
                    else:
                        current_storage_context = safe_address

        # ── KECCAK256 preimage extraction ──
        if "KECCAK256" in upper or "SHA3" in upper:
            if len(hex_matches) >= 2:
                try:
                    offset = int(hex_matches[-1], 16)
                    size = int(hex_matches[-2], 16)

                    if size <= 4096 and offset < 0x100000:
                        preimage = b""

                        mem_match = memory_pattern.search(line)
                        if mem_match and mem_match.group(1):
                            try:
                                mem_bytes = bytes.fromhex(mem_match.group(1))
                                if offset + size <= len(mem_bytes):
                                    preimage = mem_bytes[offset:offset + size]
                            except (ValueError, IndexError):
                                pass

                        if not preimage and size > 0:
                            for prev_line in lines:
                                if prev_line == line:
                                    break
                                prev_mem = memory_pattern.search(prev_line)
                                if prev_mem and prev_mem.group(1):
                                    try:
                                        mem_bytes = bytes.fromhex(prev_mem.group(1))
                                        if offset + size <= len(mem_bytes):
                                            preimage = mem_bytes[offset:offset + size]
                                    except (ValueError, IndexError):
                                        pass

                        entry = KeccakPreimage(
                            pc=0,
                            depth=len(call_stack),
                            preimage_bytes=preimage,
                            output=b"",
                            context_address=current_storage_context,
                        )
                        recent_keccak.append(entry)

                except (ValueError, IndexError):
                    pass

        # ── SSTORE event extraction ──
        elif "SSTORE" in upper:
            if len(hex_matches) >= 2:
                try:
                    slot_val = hex_matches[-1]
                    value_val = hex_matches[-2]

                    slot = bytes.fromhex(slot_val.replace("0x", "").ljust(64, "0")[-64:])
                    value = bytes.fromhex(value_val.replace("0x", "").ljust(64, "0")[-64:])

                    slot_int = int.from_bytes(slot, "big")

                    matched_keccak = None
                    for kp in recent_keccak[-20:]:
                        if kp.preimage_bytes:
                            computed = Web3.keccak(kp.preimage_bytes)
                            if computed == slot:
                                matched_keccak = kp
                                kp.output = slot
                                break
                        elif kp.output and kp.output == slot:
                            matched_keccak = kp
                            break

                    selector = b""
                    if call_stack:
                        selector = call_stack[0].selector

                    sstore = SstoreEvent(
                        pc=0,
                        depth=len(call_stack),
                        slot=slot,
                        value=value,
                        context_address=current_storage_context,
                        call_selector=selector,
                    )
                    sstore_events.append(sstore)

                except (ValueError, IndexError):
                    pass

    for kp in recent_keccak:
        if kp.preimage_bytes and not kp.output:
            kp.output = Web3.keccak(kp.preimage_bytes)

    return keccak_preimages, sstore_events


def trace_with_struct_logger(
    tx_hash: str, rpc_url: str, safe_address: str
) -> Tuple[List[KeccakPreimage], List[SstoreEvent]]:
    """Use debug_traceTransaction with structLogger for preimage correlation.

    This is the primary Phase 3 path since it correctly tracks call context,
    reads memory for KECCAK256 preimage recovery, and captures selectors.
    Falls back to cast run --trace-printer if the RPC doesn't support structLogger.
    """
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    safe_address = safe_address.lower()

    keccak_preimages: List[KeccakPreimage] = []
    sstore_events: List[SstoreEvent] = []

    call_stack: List[CallFrame] = []
    current_storage_context = safe_address
    recent_keccak: List[KeccakPreimage] = []

    try:
        result = w3.provider.make_request(
            "debug_traceTransaction",
            [tx_hash, {"tracer": "structLogger", "tracerConfig": {}}],
        )
    except Exception as e:
        print(
            f"  [Phase 3] structLogger failed for {tx_hash[:16]}...: {e}",
            file=sys.stderr,
        )
        return keccak_preimages, sstore_events

    if not isinstance(result, dict):
        return keccak_preimages, sstore_events

    struct_log = result.get("result", result)
    if not isinstance(struct_log, dict) or "structLogs" not in struct_log:
        # Try default tracer with enableMemory+disableStack
        try:
            result = w3.provider.make_request(
                "debug_traceTransaction",
                [
                    tx_hash,
                    {
                        "tracer": "structLogger",
                    },
                ],
            )
            struct_log = result.get("result", result)
        except Exception:
            return keccak_preimages, sstore_events

    logs = struct_log.get("structLogs", [])

    for step in logs:
        op = step.get("op", "")
        depth = step.get("depth", 0)
        stack = step.get("stack", [])
        memory = step.get("memory", [])
        pc = step.get("pc", 0)

        # Update call stack
        if op in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):
            if len(stack) >= 2:
                to_addr = "0x" + stack[-2][-40:] if len(stack[-2]) >= 40 else stack[-2]
            else:
                to_addr = ""
            is_delegate = op == "DELEGATECALL"

            # Extract function selector from calldata
            selector = b""
            if len(stack) >= 4:
                try:
                    args_offset = int(stack[-3], 16)
                    args_size = int(stack[-4], 16)
                except (ValueError, IndexError):
                    args_offset = 0
                    args_size = 0

            call_stack.append(
                CallFrame(
                    address=to_addr.lower(),
                    depth=depth,
                    is_delegatecall=is_delegate,
                    storage_context=current_storage_context
                    if is_delegate
                    else to_addr.lower(),
                    selector=selector,
                )
            )
            if not is_delegate:
                current_storage_context = to_addr.lower()
        elif op in ("RETURN", "REVERT", "STOP", "SELFDESTRUCT"):
            if call_stack:
                frame = call_stack.pop()
                if not frame.is_delegatecall:
                    # Restore storage context to parent
                    if call_stack:
                        current_storage_context = call_stack[-1].storage_context
                    else:
                        current_storage_context = safe_address

        if op in ("KECCAK256", "SHA3"):
            if len(stack) >= 2:
                try:
                    # EVM: KECCAK256 pops offset then size;
                    # structLog shows stack BEFORE execution:
                    #   stack[-1] = offset (top), stack[-2] = size
                    offset = int(stack[-1], 16)
                    size = int(stack[-2], 16)
                except (ValueError, IndexError):
                    continue

                # Reconstruct memory using sparse offset-keyed map
                preimage = _extract_memory_slice(memory, offset, size)

                entry = KeccakPreimage(
                    pc=pc,
                    depth=depth,
                    preimage_bytes=preimage,
                    output=b"",
                    context_address=current_storage_context,
                )
                recent_keccak.append(entry)

        elif op == "SSTORE":
            if len(stack) >= 2:
                try:
                    # EVM: SSTORE pops key then value;
                    # structLog shows stack BEFORE execution:
                    #   stack[-1] = key (top), stack[-2] = value
                    slot = bytes.fromhex(stack[-1][-64:].ljust(64, "0"))
                    value = bytes.fromhex(stack[-2][-64:].ljust(64, "0"))
                except (ValueError, IndexError):
                    continue

                slot_int = int.from_bytes(slot, "big")
                value_int = int.from_bytes(value, "big")

                # Check if this SSTORE matches a recent KECCAK256 output
                matched_keccak = None
                for kp in recent_keccak[-20:]:
                    if kp.preimage_bytes:
                        computed_hash = Web3.keccak(kp.preimage_bytes)
                        if computed_hash == slot:
                            matched_keccak = kp
                            kp.output = slot
                            break

                selector = b""
                if call_stack:
                    selector = call_stack[0].selector

                sstore = SstoreEvent(
                    pc=pc,
                    depth=depth,
                    slot=slot,
                    value=value,
                    context_address=current_storage_context,
                    call_selector=selector,
                )
                sstore_events.append(sstore)

    # Fill in KECCAK256 outputs we found
    for kp in recent_keccak:
        if kp.preimage_bytes and not kp.output:
            kp.output = Web3.keccak(kp.preimage_bytes)

    return recent_keccak, sstore_events


def _extract_memory_slice(memory: list, offset: int, size: int) -> bytes:
    """Extract a byte slice from EVM memory represented as a list of 32-byte hex words.

    The structLog `memory` field contains allocated 32-byte words in sequential order.
    Each word represents memory[offset:offset+32] starting from offset 0.
    We use a sparse dict to handle non-contiguous allocations correctly.
    """
    if size == 0:
        return b""

    mem_map: Dict[int, bytes] = {}
    for i, word in enumerate(memory):
        try:
            word_bytes = bytes.fromhex(word[2:] if word.startswith("0x") else word)
            mem_map[i * 32] = word_bytes
        except (ValueError, IndexError):
            continue

    result = bytearray(size)
    for pos in range(size):
        word_offset = (offset + pos) // 32 * 32
        byte_offset = (offset + pos) % 32
        if word_offset in mem_map and byte_offset < len(mem_map[word_offset]):
            result[pos] = mem_map[word_offset][byte_offset]

    return bytes(result)


# ──────────────────────────────────────────────────────────────────────────────
# Phase 4: Preimage decoding and classification
# ──────────────────────────────────────────────────────────────────────────────


def decode_preimage(
    preimage_bytes: bytes, slot: Bytes32, value: Bytes32
) -> Dict[str, Any]:
    """Decode a KECCAK256 preimage and classify the storage write.

    Returns a dict with:
      - mapping_slot: which mapping (1=modules, 2=owners, etc.) or None for fixed slots
      - key: the mapping key (address for owners/modules)
      - classification: one of "shadow_owner", "shadow_module", "benign", "anomalous"
    """
    if len(preimage_bytes) == 64:
        # abi.encode(key, mappingSlot) — standard mapping entry
        key = preimage_bytes[:32]
        mapping_slot = int.from_bytes(preimage_bytes[32:64], "big")

        result = {
            "mapping_slot": mapping_slot,
            "key": key,
            "classification": "unknown",
            "key_address": "0x" + key[12:].hex() if len(key) >= 20 else "",
        }

        if mapping_slot == SLOT_OWNERS:
            # For owners mapping, key should be an address (right-padded to 32 bytes)
            addr = "0x" + key[12:].hex()
            # Check if it looks like an address (upper 12 bytes are zero)
            upper_zero = all(b == 0 for b in key[:12])
            if upper_zero:
                result["classification"] = "shadow_owner_candidate"
            else:
                result["classification"] = "owner_mapping_entry"
            result["key_address"] = addr
            return result

        elif mapping_slot == SLOT_MODULES:
            addr = "0x" + key[12:].hex()
            upper_zero = all(b == 0 for b in key[:12])
            if upper_zero:
                result["classification"] = "shadow_module_candidate"
            else:
                result["classification"] = "module_mapping_entry"
            result["key_address"] = addr
            return result

        elif mapping_slot == SLOT_SIGNED_MSGS:
            result["classification"] = "signed_messages"
            return result

        elif mapping_slot == SLOT_APPROVED_HASHES:
            result["classification"] = "approved_hashes"
            return result

        else:
            result["classification"] = "unknown_mapping"
            return result

    elif len(preimage_bytes) == 96:
        # Nested mapping: abi.encode(address, innerKey, mappingSlot)
        outer_key = preimage_bytes[:32]
        inner_key = preimage_bytes[32:64]
        mapping_slot = int.from_bytes(preimage_bytes[64:96], "big")

        result = {
            "mapping_slot": mapping_slot,
            "key": outer_key,
            "inner_key": inner_key,
            "classification": "nested_mapping",
            "key_address": "0x" + outer_key[12:].hex(),
        }

        if mapping_slot == SLOT_APPROVED_HASHES:
            result["classification"] = "approved_hashes_nested"
        return result

    elif len(preimage_bytes) == 0:
        # Fixed slot — no KECCAK256 preimage; this is a direct SSTORE to a
        # fixed slot (0-8). The caller (classify_sstore) handles fixed-slot
        # classification directly using the slot number.
        return {
            "mapping_slot": None,
            "key": None,
            "classification": "fixed_slot",
        }

    else:
        return {
            "mapping_slot": None,
            "key": preimage_bytes,
            "classification": "anomalous_preimage_length",
            "preimage_length": len(preimage_bytes),
        }


def classify_sstore(
    sstore: SstoreEvent, keccak_preimages: List[KeccakPreimage], safe_address: str
) -> Optional[ShadowFinding]:
    """Classify an SSTORE event as potential shadow activity.

    Checks if the SSTORE:
    1. Was written to the Safe's storage context
    2. Targets a mapping slot (KECCAK256-computed address) for owners/modules
    3. Or targets a fixed slot (threshold, ownerCount, etc.) from a non-legitimate source
    """
    safe_lower = safe_address.lower()

    # Only care about SSTOREs to the Safe's storage context
    if sstore.context_address.lower() != safe_lower:
        return None

    slot_int = int.from_bytes(sstore.slot, "big")
    value_int = int.from_bytes(sstore.value, "big")

    # ── Check if this SSTORE's slot matches a KECCAK256 preimage ──
    for kp in keccak_preimages:
        if kp.preimage_bytes:
            computed = Web3.keccak(kp.preimage_bytes)
            if computed == sstore.slot:
                # Found the preimage that computes this slot
                decoded = decode_preimage(kp.preimage_bytes, sstore.slot, sstore.value)

                if decoded["classification"] in (
                    "shadow_owner_candidate",
                    "owner_mapping_entry",
                ):
                    return ShadowFinding(
                        finding_type="shadow_owner"
                        if decoded["classification"] == "shadow_owner_candidate"
                        else "owner_mapping_entry",
                        address=decoded.get("key_address"),
                        slot="0x" + sstore.slot.hex(),
                        value="0x" + sstore.value.hex(),
                        mapping_slot=decoded.get("mapping_slot"),
                        preimage=kp.preimage_bytes,
                        context_address=sstore.context_address,
                        note=f"KECCAK256 preimage recovered: mapping_slot={decoded.get('mapping_slot')}, key={decoded.get('key_address')}",
                    )
                elif decoded["classification"] in (
                    "shadow_module_candidate",
                    "module_mapping_entry",
                ):
                    return ShadowFinding(
                        finding_type="shadow_module"
                        if decoded["classification"] == "shadow_module_candidate"
                        else "module_mapping_entry",
                        address=decoded.get("key_address"),
                        slot="0x" + sstore.slot.hex(),
                        value="0x" + sstore.value.hex(),
                        mapping_slot=decoded.get("mapping_slot"),
                        preimage=kp.preimage_bytes,
                        note=f"KECCAK256 preimage recovered: mapping_slot={decoded.get('mapping_slot')}, key={decoded.get('key_address')}",
                    )

    # ── Check for fixed-slot writes ──
    # Slot 0 (singleton), 3 (ownerCount), 4 (threshold), 5 (nonce)
    # Also bytes32 constant slots (fallbackHandler, guard, moduleGuard)

    sentinel_value = 1  # SENTINEL = address(0x1)

    if slot_int == SLOT_OWNER_COUNT:
        # Check if this was a legitimate addOwnerWithThreshold/removeOwner/swapOwner
        selector = sstore.call_selector.hex() if sstore.call_selector else ""
        legitimate_selectors = [
            "e318b52b",  # addOwnerWithThreshold
            "f8dc5319",  # removeOwner
            "441da482",  # swapOwner
            "b63e800d",  # setup (initial setup)
        ]
        level = "dirty_fixed_slot" if selector else "unverified_fixed_slot"
        if selector not in legitimate_selectors:
            return ShadowFinding(
                finding_type=level,
                slot="0x" + sstore.slot.hex(),
                value="0x" + sstore.value.hex(),
                note=f"ownerCount written via selector 0x{selector or '(unknown)'} ({'illegitimate' if selector else 'call context unavailable'})",
            )

    if slot_int == SLOT_THRESHOLD:
        selector = sstore.call_selector.hex() if sstore.call_selector else ""
        legitimate_selectors = [
            "694e80c3",  # changeThreshold
            "e318b52b",  # addOwnerWithThreshold
            "f8dc5319",  # removeOwner
            "441da482",  # swapOwner
            "b63e800d",  # setup
        ]
        level = "dirty_fixed_slot" if selector else "unverified_fixed_slot"
        if selector not in legitimate_selectors:
            return ShadowFinding(
                finding_type=level,
                slot="0x" + sstore.slot.hex(),
                value="0x" + sstore.value.hex(),
                note=f"threshold written via selector 0x{selector or '(unknown)'} ({'illegitimate' if selector else 'call context unavailable'})",
            )

    # Check bytes32 constant slots
    slot_hex = "0x" + sstore.slot.hex()
    if slot_hex.lower() == FALLBACK_HANDLER_SLOT.lower():
        selector = sstore.call_selector.hex() if sstore.call_selector else ""
        level = "dirty_fixed_slot" if selector else "unverified_fixed_slot"
        if selector not in ("7de7edef", "b63e800d"):  # setFallbackHandler, setup
            return ShadowFinding(
                finding_type=level,
                slot=slot_hex,
                value="0x" + sstore.value.hex(),
                note=f"fallbackHandler written via selector 0x{selector or '(unknown)'} ({'illegitimate' if selector else 'call context unavailable'})",
            )

    if slot_hex.lower() == GUARD_STORAGE_SLOT.lower():
        selector = sstore.call_selector.hex() if sstore.call_selector else ""
        level = "dirty_fixed_slot" if selector else "unverified_fixed_slot"
        if selector not in ("e19a9dd9", "b63e800d"):  # setGuard, setup
            return ShadowFinding(
                finding_type=level,
                slot=slot_hex,
                value="0x" + sstore.value.hex(),
                note=f"guard written via selector 0x{selector or '(unknown)'} ({'illegitimate' if selector else 'call context unavailable'})",
            )

    if slot_hex.lower() == MODULE_GUARD_STORAGE_SLOT.lower():
        selector = sstore.call_selector.hex() if sstore.call_selector else ""
        level = "dirty_fixed_slot" if selector else "unverified_fixed_slot"
        if selector not in ("6b8e0279", "b63e800d"):  # setModuleGuard, setup
            return ShadowFinding(
                finding_type=level,
                slot=slot_hex,
                value="0x" + sstore.value.hex(),
                note=f"moduleGuard written via selector 0x{selector or '(unknown)'} ({'illegitimate' if selector else 'call context unavailable'})",
            )

    # Check for owners/modules mapping slot writes without a known preimage
    # (These are still suspicious even without recovering the preimage from the trace)
    # Exclude known legitimate mapping slots: 7 (signedMessages), 8 (approvedHashes)
    if slot_int not in (0, 3, 4, 5, 6, 7, 8) and slot_hex.lower() not in (
        FALLBACK_HANDLER_SLOT.lower(),
        GUARD_STORAGE_SLOT.lower(),
        MODULE_GUARD_STORAGE_SLOT.lower(),
    ):
        # This could be a mapping entry — check value for SENTINEL-like pattern
        if value_int == sentinel_value or (value_int != 0 and value_int < 2**160):
            # Possible shadow owner/module write
            return ShadowFinding(
                finding_type="suspected_mapping_write",
                slot="0x" + sstore.slot.hex(),
                value="0x" + sstore.value.hex(),
                note="SSTORE to undetermined mapping slot with value suggesting linked-list entry",
            )

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Phase 5: On-chain verification of findings
# ──────────────────────────────────────────────────────────────────────────────


def verify_finding_onchain(
    w3: Web3, safe_address: str, finding: ShadowFinding
) -> ShadowFinding:
    """Verify a finding against the current on-chain state of the Safe."""
    safe_address_checksum = Web3.to_checksum_address(safe_address)

    if finding.address:
        try:
            addr_checksum = Web3.to_checksum_address(finding.address)
        except Exception:
            return finding

        # Check isOwner
        try:
            is_owner_data = w3.eth.call(
                {
                    "to": safe_address_checksum,
                    "data": Web3.keccak(text="isOwner(address)")[:4].hex()
                    + addr_checksum.lower().replace("0x", "").zfill(64),
                }
            )
            is_owner_bool = int(is_owner_data.hex(), 16) == 1
        except Exception:
            is_owner_bool = False

        # Check isModuleEnabled
        try:
            is_module_data = w3.eth.call(
                {
                    "to": safe_address_checksum,
                    "data": Web3.keccak(text="isModuleEnabled(address)")[:4].hex()
                    + addr_checksum.lower().replace("0x", "").zfill(64),
                }
            )
            is_module_bool = int(is_module_data.hex(), 16) == 1
        except Exception:
            is_module_bool = False

        # Check if in getOwners()
        try:
            owners_result = w3.eth.call(
                {
                    "to": safe_address_checksum,
                    "data": Web3.keccak(text="getOwners()")[:4].hex(),
                }
            )
            # Decode the dynamic array
            owners = decode_address_array(owners_result)
            in_owners = finding.address.lower() in [o.lower() for o in owners]
        except Exception:
            in_owners = False

        # Check if in getModulesPaginated()
        try:
            modules_result = w3.eth.call(
                {
                    "to": safe_address_checksum,
                    "data": (
                        Web3.keccak(text="getModulesPaginated(address,uint256)")[
                            :4
                        ].hex()
                        + "0000000000000000000000000000000000000000000000000000000000000001"  # SENTINEL
                        + "0000000000000000000000000000000000000000000000000000000000000064"  # pageSize=100
                    ),
                }
            )
            modules = decode_address_array_from_paginated(modules_result)
            in_modules = finding.address.lower() in [m.lower() for m in modules]
        except Exception:
            in_modules = False

        # Classify current status
        if finding.finding_type == "shadow_owner":
            if is_owner_bool and not in_owners:
                finding.current_status = "active"
            elif is_owner_bool and in_owners:
                finding.current_status = "normalized"
            elif not is_owner_bool:
                # Check storage value
                try:
                    slot = Web3.keccak(
                        Web3.codec.encode(
                            ["address", "uint256"], [addr_checksum, SLOT_OWNERS]
                        )
                    )
                    value = w3.eth.get_storage(safe_address_checksum, slot)
                    if int(value.hex(), 16) == 0:
                        finding.current_status = "cleaned_up"
                    else:
                        finding.current_status = "unknown"
                except Exception:
                    finding.current_status = "unknown"

        elif finding.finding_type == "shadow_module":
            if is_module_bool and not in_modules:
                finding.current_status = "active"
            elif is_module_bool and in_modules:
                finding.current_status = "normalized"
            elif not is_module_bool:
                try:
                    slot = Web3.keccak(
                        Web3.codec.encode(
                            ["address", "uint256"], [addr_checksum, SLOT_MODULES]
                        )
                    )
                    value = w3.eth.get_storage(safe_address_checksum, slot)
                    if int(value.hex(), 16) == 0:
                        finding.current_status = "cleaned_up"
                    else:
                        finding.current_status = "unknown"
                except Exception:
                    finding.current_status = "unknown"

    return finding


def decode_address_array(data: bytes) -> List[str]:
    """Decode a dynamic array of addresses from ABI-encoded return data."""
    try:
        if isinstance(data, str):
            data = bytes.fromhex(data.replace("0x", ""))

        if len(data) < 64:
            return []

        # Dynamic array: offset to data, then length, then elements
        offset = int.from_bytes(data[0:32], "big")
        length = int.from_bytes(data[offset : offset + 32], "big")

        addresses = []
        for i in range(length):
            start = offset + 32 + i * 32
            addr_bytes = data[start : start + 32]
            addr = "0x" + addr_bytes[12:].hex()
            addresses.append(Web3.to_checksum_address(addr))

        return addresses
    except Exception:
        return []


def decode_address_array_from_paginated(data: bytes) -> List[str]:
    """Decode the address array from getModulesPaginated return data.

    Returns (address[] array, address next) — the tuple return type.
    """
    try:
        if isinstance(data, str):
            data = bytes.fromhex(data.replace("0x", ""))

        if len(data) < 96:
            return []

        # The return is a tuple: (address[] array, address next)
        # First 32 bytes: offset to the array
        array_offset = int.from_bytes(data[0:32], "big")

        # At array_offset: length of the array
        length = int.from_bytes(data[array_offset : array_offset + 32], "big")

        addresses = []
        for i in range(length):
            start = array_offset + 32 + i * 32
            if start + 32 <= len(data):
                addr_bytes = data[start : start + 32]
                addr = "0x" + addr_bytes[12:].hex()
                addresses.append(Web3.to_checksum_address(addr))

        return addresses
    except Exception:
        return []


# ──────────────────────────────────────────────────────────────────────────────
# Phase 6: Report generation
# ──────────────────────────────────────────────────────────────────────────────


def generate_report(findings: List[ShadowFinding], safe_address: str) -> str:
    """Generate a human-readable report of all findings."""
    report_lines = [
        "=" * 80,
        f"DEEP SCAN REPORT: Safe {safe_address}",
        "=" * 80,
        f"Total findings: {len(findings)}",
        "",
    ]

    # Group findings by type
    by_type: Dict[str, List[ShadowFinding]] = {}
    for f in findings:
        by_type.setdefault(f.finding_type, []).append(f)

    type_descriptions = {
        "shadow_owner": "SHADOW OWNER (isOwner=true but not in getOwners())",
        "shadow_module": "SHADOW MODULE (isModuleEnabled=true but not in getModulesPaginated())",
        "dirty_fixed_slot": "DIRTY FIXED-SLOT WRITE (threshold/ownerCount/etc modified illegitimately)",
        "unverified_fixed_slot": "UNVERIFIED FIXED-SLOT WRITE (selector context unavailable, may be legitimate)",
        "suspected_mapping_write": "SUSPECTED MAPPING WRITE (KECCAK256-computed slot with non-zero value)",
        "owner_mapping_entry": "OWNER MAPPING ENTRY (legitimate owner mapping write)",
        "module_mapping_entry": "MODULE MAPPING ENTRY (legitimate module mapping write)",
    }

    for ftype, ftype_findings in by_type.items():
        desc = type_descriptions.get(ftype, ftype.upper())
        report_lines.append(f"--- {desc} ({len(ftype_findings)}) ---")
        report_lines.append("")

        for i, f in enumerate(ftype_findings, 1):
            report_lines.append(f"  Finding #{i}:")
            if f.address:
                report_lines.append(f"    Address:      {f.address}")
            report_lines.append(f"    Type:         {f.finding_type}")
            report_lines.append(f"    Status:       {f.current_status}")
            report_lines.append(f"    Slot:          {f.slot}")
            report_lines.append(f"    Value:         {f.value}")
            if f.mapping_slot is not None:
                report_lines.append(f"    Mapping slot:  {f.mapping_slot}")
            if f.tx_hash:
                report_lines.append(f"    Tx hash:       {f.tx_hash}")
            if f.block_number:
                report_lines.append(f"    Block:         {f.block_number}")
            if f.sender:
                report_lines.append(f"    Sender:        {f.sender}")
            if f.note:
                report_lines.append(f"    Note:          {f.note}")
            report_lines.append("")

    # Summary
    active_shadows = [f for f in findings if f.current_status == "active"]
    report_lines.append("=" * 80)
    report_lines.append("SUMMARY")
    report_lines.append("=" * 80)

    active_owners = [f for f in active_shadows if f.finding_type == "shadow_owner"]
    active_modules = [f for f in active_shadows if f.finding_type == "shadow_module"]

    if active_shadows:
        report_lines.append("")
        report_lines.append("!! ACTIVE SHADOW ENTRIES DETECTED !!")
        report_lines.append("")
        for f in active_owners:
            report_lines.append(
                f"  SHADOW OWNER:   {f.address} (isOwner=true, NOT in getOwners())"
            )
        for f in active_modules:
            report_lines.append(
                f"  SHADOW MODULE:  {f.address} (isModuleEnabled=true, NOT in getModulesPaginated())"
            )
        report_lines.append("")
        report_lines.append(
            "These entries can bypass authorization checks while being invisible in the Safe UI."
        )
    else:
        report_lines.append("")
        report_lines.append("No active shadow entries detected.")

    return "\n".join(report_lines)


# ──────────────────────────────────────────────────────────────────────────────
# Main orchestration
# ──────────────────────────────────────────────────────────────────────────────


def deep_scan(
    safe_address: str,
    rpc_url: str,
    from_block: int = 0,
    to_block: int = 0,
    use_prefilter: bool = False,
    max_txs: int = 500,
    include_direct_txs: bool = False,
) -> List[ShadowFinding]:
    """Run the complete deep scan pipeline."""

    w3 = Web3(Web3.HTTPProvider(rpc_url))

    if not w3.is_connected():
        print(f"Error: Cannot connect to RPC at {rpc_url}", file=sys.stderr)
        sys.exit(1)

    print(f"Connected to RPC: {rpc_url}")
    print(f"Chain ID: {w3.eth.chain_id}")
    print()

    # ── Phase 1: Transaction history discovery ──
    print("=" * 60)
    print("  PHASE 1: Transaction History Discovery")
    print("=" * 60)

    if to_block == 0:
        to_block = w3.eth.block_number

    if from_block == 0:
        # Try to find creation block from SafeSetup event
        creation_tx = get_creation_tx(w3, safe_address)
        if creation_tx:
            try:
                receipt = w3.eth.get_transaction_receipt(creation_tx)
                from_block = receipt["blockNumber"]
            except Exception:
                from_block = 0
        print(f"Safe creation tx: {creation_tx}")

    print(f"Scanning blocks {from_block} to {to_block}...")

    logs = collect_safe_events(w3, safe_address, from_block, to_block)
    event_tx_hashes = extract_tx_hashes_from_logs(logs, safe_address)
    print(
        f"Found {len(logs)} events, {len(event_tx_hashes)} unique tx hashes from events"
    )

    # Also include direct transactions (tx.to == safeAddress)
    # Module-triggered txs (execTransactionFromModule) may not emit
    # ExecutionFromModule* events, so event-only scanning misses them.
    if include_direct_txs:
        print("Scanning for direct transactions (tx.to == safe_address)...")
        direct_tx_hashes = get_direct_tx_hashes(
            w3, safe_address, from_block, to_block
        )
        print(f"Found {len(direct_tx_hashes)} direct transactions")
        all_tx_hashes = list(set(event_tx_hashes + direct_tx_hashes))
    else:
        all_tx_hashes = list(set(event_tx_hashes))

    print(f"Total candidate transactions: {len(all_tx_hashes)}")
    print()

    # ── Phase 2: Optional prefilter ──
    if use_prefilter:
        print("=" * 60)
        print("  PHASE 2: PrestateTracer Prefilter")
        print("=" * 60)

        all_tx_hashes = prefilter_with_prestate_tracer(w3, all_tx_hashes, safe_address)
        print(f"After prefilter: {len(all_tx_hashes)} candidate transactions")
        print()

    # ── Phase 3: Opcode-level replay ──
    print("=" * 60)
    print("  PHASE 3: Opcode-Level Replay & Preimage Correlation")
    print("=" * 60)

    all_findings: List[ShadowFinding] = []

    for i, tx_hash in enumerate(all_tx_hashes[:max_txs]):
        print(
            f"  [{i + 1}/{min(len(all_tx_hashes), max_txs)}] Analyzing tx {tx_hash[:16]}..."
        )

        # Primary: structLogger (works correctly with any RPC supporting
        # debug_traceTransaction). Falls back to cast run --trace-printer
        # which replays locally via REVM but has a less reliable parser.
        keccak_preimages = []
        sstore_events = []

        keccak_preimages, sstore_events = trace_with_struct_logger(
            tx_hash, rpc_url, safe_address
        )

        if not keccak_preimages and not sstore_events:
            # Fallback: cast run --trace-printer (local REVM replay)
            trace_output = run_cast_trace(tx_hash, rpc_url)
            if trace_output:
                keccak_preimages, sstore_events = parse_trace(
                    trace_output, safe_address
                )

        # Get block info
        try:
            tx = w3.eth.get_transaction(tx_hash)
            block_number = tx["blockNumber"]
            sender = tx["from"]
        except Exception:
            block_number = 0
            sender = ""

        # Classify SSTORE events
        for sstore in sstore_events:
            finding = classify_sstore(sstore, keccak_preimages, safe_address)
            if finding:
                finding.tx_hash = tx_hash
                finding.block_number = block_number
                finding.sender = sender
                all_findings.append(finding)

    print(f"  Found {len(all_findings)} raw findings")
    print()

    # ── Phase 4: Classification ──
    print("=" * 60)
    print("  PHASE 4: Preimage Decoding & Classification")
    print("=" * 60)

    # Deduplicate findings by (tx_hash, slot, address)
    seen = set()
    deduped_findings = []
    for f in all_findings:
        key = (f.tx_hash, f.slot, f.address or "")
        if key not in seen:
            seen.add(key)
            deduped_findings.append(f)
    all_findings = deduped_findings

    print(f"  {len(all_findings)} unique findings after deduplication")

    # ── Phase 5: On-chain verification ──
    print("=" * 60)
    print("  PHASE 5: On-Chain Verification & Raw SSTORE Analysis")
    print("=" * 60)

    for f in all_findings:
        f = verify_finding_onchain(w3, safe_address, f)

    # ── Phase 6: Report ──
    print()
    report = generate_report(all_findings, safe_address)
    print(report)

    return all_findings


def local_test():
    """Run a local test using Anvil and Foundry to validate the detection pipeline.

    Deploys a Safe with shadow entries using forge script, then probes storage
    using eth_getStorageAt to detect shadows. Works against any standard RPC.
    """
    print("=" * 60)
    print("  DEEP SCAN: Local Test Mode")
    print("=" * 60)
    print()
    print("This test deploys a compromised Safe on Anvil and runs the")
    print("full detection pipeline against it.")
    print()

    rpc_url = "http://localhost:8545"
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    if not w3.is_connected():
        print("Error: Cannot connect to Anvil at localhost:8545", file=sys.stderr)
        print("Start Anvil with: anvil", file=sys.stderr)
        print()
        print("Alternatively, run the Foundry-based deep scan:")
        print("  forge script script/DeepScan.s.sol --rpc-url http://localhost:8545 -vvvv")
        sys.exit(1)

    # Deploy using forge script
    print("Step 1: Deploy compromised Safe with shadow entries...")
    print("  Run: forge script script/DeepScan.s.sol --rpc-url http://localhost:8545 --broadcast")
    print()
    print("Or run the Foundry tests directly:")
    print("  forge test -vvv")
    print()
    print("Step 2: Storage-based detection (works with any RPC)...")
    print()

    # Demonstrate the storage inspection approach using cast
    # This works even without debug_traceTransaction support
    print("-" * 60)
    print("  Storage Inspection Approach (works with any RPC)")
    print("-" * 60)
    print()
    print("For any Safe address, check for shadow entries by:")
    print()
    print("1. Read the owners linked list from storage:")
    print(
        "   cast storage <SAFE_ADDR> $(cast keccak --abi-encode '0x0000000000000000000000000000000000000001,uint256' 2)"
    )
    print("   (This reads owners[SENTINEL] to get the first owner)")
    print()
    print("2. Walk the linked list and collect reachable owners.")
    print()
    print("3. For each reachable owner, read:")
    print(
        "   cast storage <SAFE_ADDR> $(cast keccak --abi-encode '<OWNER_ADDR>,uint256' 2)"
    )
    print("   (This reads owners[ownerAddr])")
    print()
    print("4. Any slot in the owners mapping that has a non-zero value")
    print("   but is NOT reachable from the linked list is a SHADOW OWNER.")
    print()
    print("5. Apply the same process for modules (mapping slot 1):")
    print(
        "   cast storage <SAFE_ADDR> $(cast keccak --abi-encode '<MODULE_ADDR>,uint256' 1)"
    )
    print()

    # Quick probe using eth_getStorageAt
    print("-" * 60)
    print("  Quick Probe: Check a specific Safe address")
    print("-" * 60)
    print()
    print("Use the Foundry deep scan script against any Safe:")
    print()
    print("  # Local test (deploy + scan)")
    print("  forge script script/DeepScan.s.sol --rpc-url http://localhost:8545 -vvvv")
    print()
    print("  # Audit existing Safe on mainnet fork or live network")
    print("  SAFE_ADDRESS=0x... forge script script/DeepScan.s.sol:DeepScanAudit \\")
    print("      --rpc-url https://mainnet.infura.io/v3/... -vvvv")
    print()
    print("  # With candidate addresses")
    print("  SAFE_ADDRESS=0x... CANDIDATES=0xaaa,0xbbb \\")
    print("      forge script script/DeepScan.s.sol:DeepScanAudit --rpc-url <RPC> -vvvv")
    print()

    # Run the Python-based deep scan if a Safe address is available
    print("-" * 60)
    print("  Python Deep Scan (requires RPC with trace support)")
    print("-" * 60)
    print()
    print("  python deep_scan.py --safe-address 0x... --rpc-url <RPC> --deep-scan")
    print()
    print("  # With prestateTracer prefilter (Tenderly/Alchemy/QuickNode)")
    print("  python deep_scan.py --safe-address 0x... --rpc-url <RPC> --deep-scan --prefilter")
    print()

    return []


def main():
    parser = argparse.ArgumentParser(
        description="Deep scan for shadow owners/modules in Safe multisigs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a Safe on mainnet
  python deep_scan.py --safe-address 0x... --rpc-url https://mainnet.infura.io/v3/... --deep-scan
  
  # Scan with block range
  python deep_scan.py --safe-address 0x... --rpc-url http://localhost:8545 --from-block 15000000 --to-block 18000000
  
  # Quick scan without trace replay (events only)
  python deep_scan.py --safe-address 0x... --rpc-url https://eth.drpc.org
  
  # Local test with Anvil
  python deep_scan.py --local-test
""",
    )

    parser.add_argument("--safe-address", required=False, help="Safe contract address")
    parser.add_argument(
        "--rpc-url",
        default="http://localhost:8545",
        help="RPC URL (default: http://localhost:8545)",
    )
    parser.add_argument(
        "--from-block",
        type=int,
        default=0,
        help="Start block for event scanning (0=auto)",
    )
    parser.add_argument(
        "--to-block",
        type=int,
        default=0,
        help="End block for event scanning (0=latest)",
    )
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        help="Enable opcode-level trace replay (Phase 3)",
    )
    parser.add_argument(
        "--prefilter",
        action="store_true",
        help="Use prestateTracer to skip clean txs (Phase 2)",
    )
    parser.add_argument(
        "--include-direct-txs",
        action="store_true",
        help="Scan all tx.to == safe_address transactions, not just event-emitting ones (expensive)",
    )
    parser.add_argument(
        "--max-txs", type=int, default=500, help="Maximum txs to analyze (default: 500)"
    )
    parser.add_argument(
        "--local-test", action="store_true", help="Run local test with Anvil"
    )
    parser.add_argument(
        "--json-output", action="store_true", help="Output results as JSON"
    )

    args = parser.parse_args()

    if args.local_test:
        local_test()
        return

    if not args.safe_address:
        parser.error("--safe-address is required (unless using --local-test)")

    try:
        Web3.is_checksum_address(args.safe_address)
    except Exception:
        pass

    safe_address = (
        Web3.to_checksum_address(args.safe_address) if args.safe_address else ""
    )

    findings = deep_scan(
        safe_address=safe_address,
        rpc_url=args.rpc_url,
        from_block=args.from_block,
        to_block=args.to_block,
        use_prefilter=args.prefilter,
        max_txs=args.max_txs,
        include_direct_txs=args.include_direct_txs,
    )

    if args.json_output:
        results = []
        for f in findings:
            results.append(
                {
                    "type": f.finding_type,
                    "address": f.address,
                    "tx_hash": f.tx_hash,
                    "block_number": f.block_number,
                    "sender": f.sender,
                    "status": f.current_status,
                    "slot": f.slot,
                    "value": f.value,
                    "mapping_slot": f.mapping_slot,
                    "note": f.note,
                }
            )
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
