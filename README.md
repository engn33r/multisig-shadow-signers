# Shadow Owners & Modules PoC

A Foundry-based proof of concept demonstrating how "shadow" owners and modules can be hidden inside a Safe multisig. Shadow entries are authorized to act (sign transactions or execute via module) but are **invisible** in the standard Safe UI and getter functions (`getOwners()`, `getModulesPaginated()`).

This is an educational security PoC — not a production tool.

## Background

Safe multisigs store owners and modules in linked-list mappings (`mapping(address => address)`) with a sentinel address (`0x1`) marking the list boundaries:

```
owners[SENTINEL] -> owner1 -> owner2 -> owner3 -> SENTINEL
```

`getOwners()` traverses this linked list, while `isOwner(addr)` simply checks `owners[addr] != address(0)`. An entry can exist in the mapping without being reachable from the sentinel — making it pass `isOwner()` while being absent from `getOwners()`.

Shadow entries are injected by executing a `DELEGATECALL` to a contract that writes directly to the mapping's storage slot via `sstore`.

## Injection Methods

There are **two ways** to inject a shadow signer:

### Method 1: During `setup()` (At Creation)
When creating a Safe, the `setup()` function accepts `to` and `data` parameters. If `to` is non-zero, `setupModules()` executes a `DELEGATECALL` to that address with the provided data. This runs in the Safe's storage context, allowing direct writes to the `owners` mapping.

```solidity
bytes memory initializer = abi.encodeWithSelector(
    Safe.setup.selector,
    owners,              // legitimate owners
    threshold,
    address(injector),   // to: delegatecall target
    abi.encodeWithSelector(
        ShadowOwnerInjector.injectShadowOwner.selector, 
        shadowOwner      // the hidden owner address
    ),
    address(0), address(0), 0, payable(address(0))
);
```

**Characteristics:**
- No signatures required (setup is atomic with proxy creation)
- Shadow exists from day one
- Requires the attacker to control the Safe creation process

### Method 2: Via `execTransaction()` with `DelegateCall` (Post-Creation)
An existing Safe can inject a shadow through a regular multisig transaction that uses `Enum.Operation.DelegateCall`:

```solidity
safe.execTransaction(
    address(injector),           // to: injector contract
    0,                           // value
    injectCalldata,              // call data
    Enum.Operation.DelegateCall, // <-- critical: runs in Safe's context
    0, 0, 0, address(0), payable(address(0)),
    signatures                   // signed by legitimate owners
);
```

**Characteristics:**
- Requires threshold signatures from legitimate owners
- Owners may not realize the delegatecall is malicious
- Can be injected long after Safe creation
- More stealthy (appears as a "normal" transaction to reviewers)

Both methods use the same underlying mechanism: the `ShadowOwnerInjector` contract writes directly to storage slot 2 (the `owners` mapping), setting `owners[shadow] = SENTINEL` without inserting the shadow into the linked list.

The same technique applies to the `modules` mapping (slot 1) as to the `owners` mapping (slot 2).

### Optional Cleanup: Self-Destruct

After injection, the attacker can call `injector.destroy()` to self-destruct the injector contract. This removes the on-chain bytecode (pre-Cancun) or marks it for deletion, making forensic analysis harder. The shadow remains in the Safe's storage regardless.

See `ShadowOwnerSelfDestructTest` for a demonstration.

Reference: [Lido — Multisig Shadow Owners Guide](https://docs.lido.fi/guides/multisig-shadow-owners/)

## Repo Structure

| Path | Description |
|------|-------------|
| `src/ShadowOwnerInjector.sol` | Contract that injects shadow owners via `DELEGATECALL`. Writes directly to storage slot 2 without updating the linked list. |
| `src/ShadowModuleInjector.sol` | Contract that injects shadow modules via `DELEGATECALL`. Writes directly to storage slot 1. |
| `src/SafeDetector.sol` | Reusable library with detection primitives: signature recovery, calldata extraction, candidate probing, and dormant shadow detection. |
| `script/DetectShadows.s.sol` | Foundry scripts for auditing existing Safes using candidate probing (Plans 1–4). |
| `script/DeepScan.s.sol` | Foundry scripts for the 6-phase dirty storage pipeline: `DeepScanScript` (local PoC) and `DeepScanAudit` (on-chain audit). |
| `test/ShadowOwner.t.sol` | Tests demonstrating shadow owner attacks and injection methods. |
| `test/ShadowModule.t.sol` | Tests demonstrating shadow module attacks (more dangerous than shadow owners). |
| `test/Detection.t.sol` | Tests for Plans 1–4 (signature recovery, event analysis, candidate probing, dormant detection). |
| `test/DeepScan.t.sol` | Tests for Phase 3–5 of the dirty storage pipeline: storage write detection, KECCAK256 preimage decoding, classification, fixed-slot anomaly detection, and full pipeline simulation. |
| `test/DeepScanIntegration.t.sol` | End-to-end integration tests: compound attacks (module injects owner), cross-phase interactions, and SafeDetector integration. |
| `test/utils/ShadowTestBase.sol` | Shared test base contract with common constants, setup logic, and helper functions. |
| `detect_shadows.py` | Python script for candidate-based detection on live Safes via RPC. |
| `deep_scan.py` | Python script implementing the 6-phase dirty storage pipeline (event collection, prestateTracer prefilter, opcode replay, preimage decoding, on-chain verification, report generation). |
| `requirements.txt` | Python dependencies (`web3`, `eth-abi`, `requests`). |
| `needed-fixes.md` | Implementation status tracker for the deep scan pipeline. |

## Python Detection Scripts

### detect_shadows.py — Candidate-Based Detection

The `detect_shadows.py` script provides a standalone Python tool for checking live Safe contracts for shadow owners and shadow modules without needing Foundry.

### Installation

```bash
pip install -r requirements.txt
```

### Usage

Basic check (verifies current owners are properly listed):

```bash
python detect_shadows.py 0xYourSafeAddress 1
```

Check specific candidate addresses (for suspected shadows):

```bash
python detect_shadows.py 0xYourSafeAddress 1 --candidates 0xSuspect1,0xSuspect2,0xSuspect3
```

Use a custom RPC:

```bash
python detect_shadows.py 0xYourSafeAddress 8453 --rpc-url https://base.llamarpc.com
```

Enable storage slot analysis:

```bash
python detect_shadows.py 0xYourSafeAddress 1 --candidates 0xSuspect1 --check-storage
```

### deep_scan.py — Dirty Storage Pipeline

The `deep_scan.py` script implements the full 6-phase pipeline that discovers shadow addresses **without prior candidate knowledge** by recovering KECCAK256 preimages from opcode-level traces.

```bash
# Full deep scan on mainnet
python deep_scan.py --safe-address 0x... --rpc-url https://mainnet.infura.io/v3/... --deep-scan

# With prestateTracer prefilter (reduces Phase 3 workload)
python deep_scan.py --safe-address 0x... --rpc-url <RPC> --deep-scan --prefilter

# Specify block range
python deep_scan.py --safe-address 0x... --rpc-url <RPC> --from-block 15000000 --to-block 18000000

# JSON output for programmatic use
python deep_scan.py --safe-address 0x... --rpc-url <RPC> --deep-scan --json-output

# Local test mode (requires Anvil)
python deep_scan.py --local-test
```

### Finding Types

| Type | Meaning |
|------|---------|
| `shadow_owner` | `isOwner() == true` but address not in `getOwners()` |
| `shadow_module` | `isModuleEnabled() == true` but address not in `getModulesPaginated()` |
| `dirty_fixed_slot` | Threshold, ownerCount, fallbackHandler, guard, or moduleGuard written by an illegitimate selector |
| `unverified_fixed_slot` | Same slots written but call context unavailable (could be legitimate) |
| `suspected_mapping_write` | SSTORE to an undetermined mapping slot with a value suggesting a linked-list entry |

### Exit Codes (detect_shadows.py)

| Code | Meaning |
|------|---------|
| 0 | No shadows detected |
| 1 | Shadows detected |
| 2 | Error occurred |

### Supported Chains

Default RPCs are provided for:
- Ethereum (1)
- Base (8453)
- Arbitrum (42161)
- Optimism (10)
- Polygon (137)
- BSC (56)
- Sonic (146)
- Katana (747474)

Use `--rpc-url` for other chains or custom endpoints.

### How `deep_scan.py` Works

1. **Phase 1**: Collect all transactions involving the Safe via `eth_getLogs`.
2. **Phase 2** (optional): Use `debug_traceTransaction` with `prestateTracer` to skip transactions that only modified known-legitimate slots.
3. **Phase 3**: Replay each candidate transaction using `debug_traceTransaction` with structLogger (primary) or `cast run --trace-printer` (fallback). Track KECCAK256 preimages and SSTORE events, correlating slots with their preimages.
4. **Phase 4**: Decode 64-byte preimages as `abi.encode(key, mappingSlot)`. Classify as shadow owner (slot 2), shadow module (slot 1), signed messages (slot 7), approved hashes (slot 8), or anomalous.
5. **Phase 5**: Probe recovered addresses on-chain via `isOwner()` / `isModuleEnabled()`. Flag fixed-slot writes (threshold, ownerCount, fallbackHandler, guard, moduleGuard) from illegitimate selectors.
6. **Phase 6**: Generate a report with finding type, address, tx hash, block, sender, status, and notes.

## What This Repo Demonstrates

### Shadow Owners (test/ShadowOwner.t.sol)

| Test | What it proves |
|------|---------------|
| `test_shadowOwnerIsHiddenButAuthorized` | `isOwner(shadow)` returns true, but `getOwners()` does not include the shadow address. Threshold is based only on visible owners. |
| `test_shadowOwnerCanSignTransaction` | A real `execTransaction` sending ETH succeeds using signatures from 1 legitimate owner + the shadow owner. |
| `test_storageInspection` | Raw storage reads via `vm.load()` show the orphaned mapping entry and confirm the shadow is unreachable in the linked list. |
| `test_injectShadowViaExecTransaction` | Shadow owner is injected post-setup via a DELEGATECALL `execTransaction`, then used to co-sign a transfer. |

#### More Subtle Attack: Self-Destruct Pattern (test/ShadowOwner.t.sol::ShadowOwnerSelfDestructTest)

An attacker can make the injection even harder to detect by **self-destructing the injector contract** after the shadow is added:

```solidity
// 1. Inject shadow via DELEGATECALL
safe.execTransaction(
    address(injector), 
    0, 
    injectCalldata, 
    Enum.Operation.DelegateCall,
    ...
);

// 2. Self-destruct the injector (separate transaction)
injector.destroy();
```

**Effect:** The injector bytecode is removed from chain (pre-Cancun) or marked for deletion, while the **shadow remains in the Safe's storage** and can still sign transactions.

⚠️ **EIP-6780 Note:** Since the Cancun hard fork (2024), `SELFDESTRUCT` only deletes code if called in the same transaction the contract was created. In separate transactions, code remains but ETH is transferred. For older chains or pre-Cancun forks, this pattern fully removes the bytecode.

| Test | What it proves |
|------|---------------|
| `test_selfDestructAttackPattern` | Injector can self-destruct after injection. Shadow remains functional even if injector code is gone. |

### Shadow Modules (test/ShadowModule.t.sol)

Shadow modules are **more dangerous** than shadow owners:

| Capability | Shadow Owner | Shadow Module |
|------------|--------------|---------------|
| Can execute transactions | ✅ Yes | ✅ Yes |
| Requires owner signatures | ✅ Yes (threshold) | ❌ **No signatures needed** |
| Visible in UI | ❌ No | ❌ No |

A shadow module can call `execTransactionFromModule()` to execute arbitrary transactions **without any owner approval**. This is a single-step compromise vs. multi-sig for shadow owners.

| Test | What it proves |
|------|----------------|
| `test_shadowModuleIsHiddenButEnabled` | `isModuleEnabled(shadow)` returns true, but `getModulesPaginated()` does not list it. |
| `test_shadowModuleCanExecuteWithoutSignatures` | The shadow module calls `execTransactionFromModule()` to drain ETH — **no owner signatures needed**. |
| `test_moduleStorageInspection` | Raw storage reads show the orphaned modules mapping entry. |
| `test_injectShadowModuleViaExecTransaction` | Shadow module is injected post-setup via DELEGATECALL, then used to drain funds. |

## SafeDetector Library (src/SafeDetector.sol)

A reusable Solidity library providing pure/view functions for shadow detection. Can be used in:
- **Foundry tests** (validating detection against PoCs)
- **Foundry scripts** (auditing Safes on a fork or live network)
- **On-chain contracts** (e.g., a Guard that checks for shadows before execution)

### Core Functions

| Function | Purpose |
|----------|---------|
| `recoverSigners()` | Recovers signer addresses from packed Safe signatures (handles ECDSA, eth_sign, contract signatures, approved hashes). |
| `findUnlistedSigners()` | Identifies signers that are not in `getOwners()` — detects active shadows. |
| `findShadowOwners()` | Probes a list of candidate addresses to find shadow owners (`isOwner() == true` but not in `getOwners()`). |
| `findShadowModules()` | Probes candidates to find shadow modules (`isModuleEnabled() == true` but not in `getModulesPaginated()`). |
| `extractAddressesFromCalldata()` | Extracts address-sized values from arbitrary calldata (heuristic for finding shadow addresses). |
| `detectDormantShadowsFromHistory()` | Scans historical calldata to find candidate addresses, then probes for shadows. |
| `analyzeSetupDelegatecall()` | Flags suspicious setup delegatecall targets that are neither owners nor modules. |

## Detection (test/Detection.t.sol)

The repo implements **4 detection plans** for finding shadows:

| Plan | Name | Detects | Key Function |
|------|------|---------|--------------|
| 1 | **Signature Recovery** | Active shadows (have signed) | `findUnlistedSigners()` |
| 2 | **Event/Delegatecall Analysis** | Suspicious setup patterns | `analyzeSetupDelegatecall()` |
| 3 | **Candidate Probing** | Known candidate addresses | `findShadowOwners()`, `findShadowModules()` |
| 4 | **Dormant Shadow Detection** | Shadows never signed | `detectDormantShadowsFromHistory()` |

### Plan 1: Signature Recovery (Active Shadows)
Shadows that have signed at least one transaction.

| Test | What it proves |
|------|----------------|
| `test_detectShadowViaSignatureRecovery` | Recovers signer addresses from transaction signatures and checks if any are unlisted in `getOwners()`. |
| `test_noFalsePositivesWithLegitSigners` | Verifies no false positives when all signers are legitimate. |

**How it works:** When a shadow co-signes a transaction, its address appears in the signature data. `SafeDetector.recoverSigners()` extracts these addresses, and `findUnlistedSigners()` identifies any that don't appear in `getOwners()`.

### Plan 2: Event-Based / Delegatecall Analysis
Analyzes Safe setup and event history for suspicious patterns.

| Test | What it proves |
|------|----------------|
| `test_flagSuspiciousSetupDelegatecall` | Flags setup delegatecall targets that are neither owners nor modules. |
| `test_cleanSetupNotFlagged` | Verifies clean setups (no delegatecall) are not flagged. |
| `test_findOwnersWithoutEvents` | Event-based audit can identify owners without corresponding `AddedOwner` events. |

### Plan 3: Candidate Probing
Probes specific addresses to check if they're shadows.

| Test | What it proves |
|------|----------------|
| `test_findShadowOwners` | Detects shadow owners by probing candidate addresses. |
| `test_findShadowModules` | Detects shadow modules by probing candidate addresses. |
| `test_fullScan` | Combined scan for both shadow owners and modules. |
| `test_extractCandidatesFromCalldata` | Extracts addresses from calldata automatically. |
| `test_noFalsePositives` | Verifies legitimate addresses don't trigger false positives. |

### Plan 4: Dormant Shadow Detection
Shadows that were injected but have **never signed** a transaction.

| Test | Detection Method | What it proves |
|------|------------------|----------------|
| `test_detectDormantShadowFromInjectorCalldata` | **Calldata Extraction** | Extracts addresses from historical transaction calldata (e.g., the delegatecall that injected the shadow) and probes them. |
| `test_detectDormantShadowWithoutSignatures` | **Historical Scanning** | Full flow: scan all historical calldata for candidate addresses, then check if any are shadow owners. |

**How it works:** Since shadows must be injected via `DELEGATECALL`, their addresses appear in the calldata of:
- The `setup()` initializer (if injected at creation)
- Any `execTransaction` with `Operation.DelegateCall` (if injected post-creation)

`SafeDetector.extractAddressesFromCalldata()` extracts candidate addresses, and `detectDormantShadowsFromHistory()` probes them against the Safe.

### Detection Limitations (Plans 1–4)

| Shadow Type | Detectable? | Method |
|-------------|-------------|--------|
| Active (has signed) | ✅ Yes | Signature recovery from transactions |
| Dormant (never signed) | ✅ Yes | Calldata extraction from historical delegatecalls |
| Unknown address | ❌ No | Must know candidate addresses to probe |

**Key insight:** Plans 1–4 require either prior knowledge of candidate addresses or that the shadow has signed a transaction. The deep scan pipeline (below) addresses this limitation by recovering shadow addresses directly from opcode-level traces — no candidate knowledge needed.

## Deep Scan: Dirty Storage Detection (Phase 1–6)

The deep scan pipeline discovers shadow addresses **without any prior candidate knowledge** by analyzing raw storage writes and KECCAK256 preimages in opcode-level traces. When a shadow is injected via `DELEGATECALL`, the injector computes `keccak256(abi.encode(shadowAddress, mappingSlot))` before writing to that slot. With memory-enabled traces, the full 64-byte preimage is visible — revealing the shadow address directly.

### Pipeline Overview

| Phase | Name | What it does |
|-------|------|-------------|
| 1 | Transaction History Discovery | Collects all tx hashes from Safe events (`SafeSetup`, `ExecutionSuccess`, etc.). |
| 2 | PrestateTracer Prefilter (optional) | Skips txs that only modify known-legitimate storage slots, reducing Phase 3 workload by 10–100×. |
| 3 | Opcode-Level Replay & Preimage Correlation | Replays each tx via `debug_traceTransaction` (structLogger) or `cast run --trace-printer`, tracking KECCAK256 preimages and SSTORE events to recover shadow addresses. |
| 4 | Preimage Decoding & Classification | Decodes 64-byte preimages as `abi.encode(key, mappingSlot)`, classifies as shadow owner (slot 2), shadow module (slot 1), signed messages (slot 7), approved hashes (slot 8), or anomalous. |
| 5 | On-Chain Verification & Raw SSTORE Analysis | Probes recovered addresses against `isOwner()` / `isModuleEnabled()` / `getOwners()` / `getModulesPaginated()` to classify as active, cleaned-up, or normalized. Also flags dirty fixed-slot writes (threshold, ownerCount, fallbackHandler, guard, moduleGuard) from non-legitimate selectors. |
| 6 | Report Generation | Emits per-finding records with type, address, tx hash, block, sender, current status, slot, and value. |

### Additional Detection Strategies (Not Yet Implemented)

| Plan | Method | Finds unknowns | Implementation status |
|------|--------|---------------|---------------------|
| C | Merkle Patricia Trie traversal via `eth_getProof` | Yes | Not started |
| D | `debug_storageRangeAt` direct enumeration | Yes | Not started |
| E | Enhanced calldata extraction + slot verification | No | Not started |

See `dirty-storage-plan-glm.md` for the full specification of Plans A–E.

## Deep Scan Tests (test/DeepScan.t.sol)

Solidity tests validating the dirty storage detection pipeline using Foundry's `vm.record()` / `vm.accesses()` and `vm.load()`:

### Phase 3: Storage Write Detection

| Test | What it proves |
|------|---------------|
| `test_detectShadowOwnerViaStorageWrites` | Records storage writes during shadow injection and identifies the KECCAK256-computed slot for the shadow owner. Confirms the slot value is `SENTINEL` (linked-list entry) while the shadow is absent from `getOwners()`. |
| `test_detectShadowModuleViaStorageWrites` | Same as above for shadow modules (mapping slot 1). |

### Phase 4: Preimage Decoding & Classification

| Test | What it proves |
|------|---------------|
| `test_decodeOwnerMappingPreimage` | Recovers the shadow owner address from a 64-byte KECCAK256 preimage (`abi.encode(shadowOwner, 2)`) and confirms it maps to the correct storage slot. |
| `test_decodeModuleMappingPreimage` | Same as above for shadow modules (`abi.encode(shadowModule, 1)`). |
| `test_legitimateOwnerNotClassifiedAsShadow` | A legitimate owner's mapping slot is non-zero but the owner IS in `getOwners()` — not classified as a shadow. |
| `test_shadowOwnerClassification` | Shadow passes `isOwner()` but is absent from `getOwners()`. Legitimate owner passes both. |
| `test_shadowModuleClassification` | Shadow passes `isModuleEnabled()` but is absent from `getModulesPaginated()`. |
| `test_approvedHashesNotClassifiedAsShadow` | 96-byte preimages for `approvedHashes` (slot 8) are classified as legitimate, not shadow. |
| `test_signedMessagesNotClassifiedAsShadow` | 64-byte preimages for `signedMessages` (slot 7) are classified as legitimate, not shadow. |

### Phase 5: Fixed-Slot Anomaly Detection

| Test | What it proves |
|------|---------------|
| `test_detectThresholdOverwrite` | Direct `SSTORE` to slot 4 (threshold) changes the value, detectable as a dirty fixed-slot write. |
| `test_detectOwnerCountOverwrite` | Direct `SSTORE` to slot 3 (ownerCount) changes the value, detectable as a dirty fixed-slot write. |
| `test_detectInjectionViaExecTransaction` | Shadow injection via `execTransaction` with `DelegateCall` is detectable through storage write recording. |

### Full Pipeline & Slot Enumeration

| Test | What it proves |
|------|---------------|
| `test_fullPipelineAgainstShadowOwner` | Complete pipeline: enumerate slots, walk linked list, confirm shadow is unreachable but `isOwner()` passes. |
| `test_fullPipelineAgainstShadowModule` | Same for shadow modules. |
| `test_cleanSafeNoShadows` | Clean Safe produces zero shadow findings. |
| `test_slotEnumerationDetectsShadows` | Linked-list walk confirms the shadow address is unreachable from `SENTINEL`. |

## Deep Scan Integration Tests (test/DeepScanIntegration.t.sol)

Integration tests covering cross-phase scenarios not duplicated in DeepScan.t.sol:

| Test | What it proves |
|------|---------------|
| `test_detectShadowViaStorageWrites` | Storage write detection via `vm.record()` catches shadow owner injection. |
| `test_detectInjectionViaExecTransaction` | Post-creation injection via `execTransaction(DelegateCall)` is detected. |
| `test_phase5_moduleInjectsOwner` | Compound attack: shadow module injects a secondary shadow owner via `execTransactionFromModule` (0 owner signatures needed). Both injections detected. |
| `test_thresholdOverwrite` | Threshold reduction from 2→1 detected via `vm.load`. |
| `test_ownerCountOverwrite` | OwnerCount inflation to 100 detected via `vm.load`. |
| `test_cleanSafeNoAnomalies` | Clean Safe's `ownerCount` matches `getOwners().length`. |
| `test_fullPipelineShadowOwner` | E2E: KECCAK256 preimage recovered, shadow classified correctly. |
| `test_fullPipelineShadowModule` | E2E: shadow module detected via preimage + classification. |
| `test_fullPipelineBothShadows` | E2E: both shadow owner and module detected in one Safe. |
| `test_linkedListReachability` | Linked-list walk confirms shadow owner is unreachable from `SENTINEL`. |
| `test_safeDetectorFullScan` | `SafeDetector.fullScan()` correctly identifies exactly 1 shadow from candidate list. |
| `test_candidateExtractionFromCalldata` | `SafeDetector.extractAddressesFromCalldata()` extracts shadow address from injector calldata, which is then detected as shadow. |

## Scripts

### DetectShadows (script/DetectShadows.s.sol)

Candidate-probing scripts using Plans 1–4:

| Script | Purpose | Usage |
|--------|---------|-------|
| `DetectShadowsPoC` | Demonstrates detection against a fresh PoC Safe with injected shadows. | `forge script script/DetectShadows.s.sol:DetectShadowsPoC` |
| `AuditExistingSafe` | Audits an existing Safe on-chain (requires `SAFE_ADDRESS` env var). | `forge script script/DetectShadows.s.sol:AuditExistingSafe --rpc-url <RPC>` |

### DeepScan (script/DeepScan.s.sol)

Dirty storage pipeline scripts using Phases 1–6:

| Script | Purpose | Usage |
|--------|---------|-------|
| `DeepScanScript` | Deploys PoC Safes with shadows, records storage writes, classifies findings, and checks fixed slots. | `forge script script/DeepScan.s.sol:DeepScanScript` |
| `DeepScanAudit` | Audits an existing Safe on-chain: probes candidates, walks linked lists, checks `ownerCount` vs listed owners. Requires `SAFE_ADDRESS` env var. | `SAFE_ADDRESS=0x... forge script script/DeepScan.s.sol:DeepScanAudit --rpc-url <RPC>` |

The DeepScan scripts demonstrate the full dirty storage pipeline: storage write recording, KECCAK256 preimage recovery, classification, and fixed-slot anomaly detection.

### DeployShadowSafe (script/DeployShadowSafe.s.sol)

Deploy-only script that stands up a Safe multisig with a shadow owner and/or shadow module injected during `setup()`. Works against a local Anvil fork and against real chains (Base, mainnet, etc.).

**Environment variables** (all optional unless noted):

| Var | Default | Purpose |
|-----|---------|---------|
| `PRIVATE_KEY` | Anvil key 0 | Deployer key. **Required on real chains.** |
| `SHADOW_MODE` | `both` | `owner` \| `module` \| `both` \| `none` |
| `SHADOW_OWNER` | `vm.addr(0xBEEF)` | Address to inject as a hidden owner |
| `SHADOW_MODULE` | `vm.addr(0xBAAD)` | Address to inject as a hidden module |
| `THRESHOLD` | `2` | Signature threshold |
| `OWNER_1` … `OWNER_N` | 3 deterministic test owners | Explicit owner addresses (1-indexed, up to 32) |
| `SAFE_SINGLETON` | deploy new | Reuse an existing Safe singleton |
| `SAFE_FACTORY` | deploy new | Reuse an existing `SafeProxyFactory` |
| `OWNER_INJECTOR` | deploy new | Reuse an existing `ShadowOwnerInjector` |
| `MODULE_INJECTOR` | deploy new | Reuse an existing `ShadowModuleInjector` |
| `BOTH_INJECTOR` | deploy new | Reuse an existing `ShadowBothInjector` |
| `SALT_NONCE` | `block.timestamp` | Proxy deployment salt nonce |

#### Deploy on a local Anvil fork of mainnet

```bash
# Terminal 1: start a mainnet fork
anvil --fork-url $MAINNET_RPC

# Terminal 2: deploy a Safe with hidden owner + module (defaults)
forge script script/DeployShadowSafe.s.sol \
    --rpc-url http://localhost:8545 \
    --broadcast -vvvv

# Or inject a hidden module instead:
SHADOW_MODE=module \
    forge script script/DeployShadowSafe.s.sol \
    --rpc-url http://localhost:8545 \
    --broadcast -vvvv

# Custom owners + threshold + explicit shadow address:
OWNER_1=0xAAA... OWNER_2=0xBBB... OWNER_3=0xCCC... \
SHADOW_OWNER=0xDEAD... THRESHOLD=2 \
    forge script script/DeployShadowSafe.s.sol \
    --rpc-url http://localhost:8545 \
    --broadcast -vvvv
```

#### Deploy to Base (or any real chain)

Fund the deployer address first. The script deploys its own Safe singleton, `SafeProxyFactory`, and injector on the target chain so no canonical addresses are required.

```bash
export PRIVATE_KEY=0x...                # funded deployer
export BASE_RPC=https://mainnet.base.org

forge script script/DeployShadowSafe.s.sol \
    --rpc-url $BASE_RPC \
    --broadcast -vvvv

# To reuse infrastructure across multiple Safes, grab the singleton/factory/
# injector addresses printed on the first run and pass them back:
SAFE_SINGLETON=0x... SAFE_FACTORY=0x... OWNER_INJECTOR=0x... \
    forge script script/DeployShadowSafe.s.sol \
    --rpc-url $BASE_RPC \
    --broadcast -vvvv
```

The script logs the deployed `Safe`, `Singleton`, `ProxyFactory`, and injector addresses, then verifies `isOwner(shadowOwner)` / `isModuleEnabled(shadowModule)` returns `true` while `getOwners()` / `getModulesPaginated()` hides the entry.

> **`SHADOW_MODE=both`** (the default) uses a combined injector (`src/ShadowBothInjector.sol`) that writes both `owners[shadowOwner]` and `modules[shadowModule]` in a single `setup()` delegatecall, so one script run plants both hidden entries at creation time.

### End-to-End: Deploy and Detect on Anvil

This walkthrough deploys a Safe with both a shadow owner and shadow module (the default), then runs the detector script against the deployed Safe to confirm both hidden entries are found.

#### 1. Start Anvil

```bash
anvil --fork-url $MAINNET_RPC
```

You can also run Anvil without forking (`anvil`), but forking provides the real Safe singleton and factory bytecode.

#### 2. Deploy the Shadow Safe

```bash
forge script script/DeployShadowSafe.s.sol \
    --rpc-url http://localhost:8545 \
    --broadcast -vvvv
```

This deploys with `SHADOW_MODE=both` by default, injecting both a shadow owner (`vm.addr(0xBEEF)`) and a shadow module (`vm.addr(0xBAAD)`) during `setup()`.

Look for these lines in the output and note the addresses:

```
Safe:            0x...   # <-- SAFE_ADDRESS
Shadow owner:    0x...   # <-- candidate owner address
Shadow module:   0x...   # <-- candidate module address
```

The post-deploy verification will confirm:

```
isOwner(shadowOwner):       true (HIDDEN)
isModuleEnabled(shadowMod): true (HIDDEN)
```

`getOwners()` will **not** include the shadow owner, and `getModulesPaginated()` will **not** include the shadow module.

#### 3. Run the Detector Script

Use `AuditExistingSafe` to probe the deployed Safe for shadow entries. Pass the shadow addresses as candidates via the `CANDIDATES` env var:

```bash
SAFE_ADDRESS=<SAFE_ADDRESS> \
CANDIDATES=<SHADOW_OWNER_ADDR>,<SHADOW_MODULE_ADDR> \
    forge script script/DetectShadows.s.sol:AuditExistingSafe \
    --rpc-url http://localhost:8545 -vvvv
```

Replace `<SAFE_ADDRESS>`, `<SHADOW_OWNER_ADDR>`, and `<SHADOW_MODULE_ADDR>` with the addresses from step 2.

> **Note:** The `AuditExistingSafe` script currently accepts a single address via `CANDIDATES`. To probe both the shadow owner and shadow module, run the script twice — once with each address.

Example for probing the shadow owner:

```bash
SAFE_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3 \
CANDIDATES=0xa85315e1e4c34f56dfafb4e3b83ac3a9b0de9d6 \
    forge script script/DetectShadows.s.sol:AuditExistingSafe \
    --rpc-url http://localhost:8545 -vvvv
```

#### 4. Verify Detection Output

A successful detection produces output like:

```
DETECTED 1 shadow(s):
  [SHADOW OWNER] 0x... 
```

Or for the shadow module probe:

```
DETECTED 1 shadow(s):
  [SHADOW MODULE] 0x...
```

This confirms the detector correctly identifies entries that pass `isOwner()`/`isModuleEnabled()` but are absent from `getOwners()`/`getModulesPaginated()` — validating that the injection worked and the detection script catches it.

#### Alternative: Python Detection

You can also use the Python script for candidate-based detection:

```bash
# Against the local Anvil node (chain ID 31337)
python detect_shadows.py <SAFE_ADDRESS> 31337 \
    --rpc-url http://localhost:8545 \
    --candidates <SHADOW_OWNER_ADDR>,<SHADOW_MODULE_ADDR>
```

The Python script probes both `isOwner()` and `isModuleEnabled()` in a single run, so you can pass both candidate addresses at once.

## Storage Layout

From `SafeStorage.sol`, the relevant slots:

| Slot | Variable | Type |
|------|----------|------|
| 0 | `singleton` | `address` |
| 1 | `modules` | `mapping(address => address)` |
| 2 | `owners` | `mapping(address => address)` |
| 3 | `ownerCount` | `uint256` |
| 4 | `threshold` | `uint256` |

The storage slot for a mapping entry is `keccak256(abi.encode(key, slot))`. For example, `owners[0xABCD...]` is at `keccak256(abi.encode(0xABCD..., 2))`.

## How to Run

### Prerequisites
- [Foundry](https://book.getfoundry.sh/getting-started/installation) installed

### Build & Test

```bash
# Clone and enter the repo
git clone <repo-url> && cd shadow-owners

# Install dependencies (if not already present)
forge install

# Build
forge build

# Run all tests with verbose output
forge test -vvvv

# Run specific test suites
forge test --match-contract DeepScanTest -vvvv
forge test --match-contract DeepScanIntegrationTest -vvvv
forge test --match-contract Detection -vvvv
```

### Running Scripts

```bash
# Candidate-probing detection script
forge script script/DetectShadows.s.sol:DetectShadowsPoC -vvvv

# Audit an existing Safe (requires RPC endpoint)
export SAFE_ADDRESS=0x...
forge script script/DetectShadows.s.sol:AuditExistingSafe --rpc-url <RPC_URL> -vvvv

# Deep scan: local PoC
forge script script/DeepScan.s.sol --rpc-url http://localhost:8545 -vvvv

# Deep scan: audit existing Safe
export SAFE_ADDRESS=0x...
forge script script/DeepScan.s.sol:DeepScanAudit --rpc-url <RPC_URL> -vvvv
```

### Running Python Scripts

```bash
# Install dependencies
pip install -r requirements.txt

# Candidate-based detection
python detect_shadows.py 0xSafeAddress 1 --candidates 0xSuspect1,0xSuspect2

# Deep scan (requires RPC with trace support)
python deep_scan.py --safe-address 0x... --rpc-url https://mainnet.infura.io/v3/... --deep-scan

# Deep scan with prestateTracer prefilter
python deep_scan.py --safe-address 0x... --rpc-url <RPC> --deep-scan --prefilter
```

### Reading the Output

With `-vvvv`, each test prints:
- **Console logs** showing the before/after state (isOwner, getOwners, balances)
- **Execution traces** showing the delegatecall into the injector and the `sstore` that writes the shadow entry
- **ecrecover traces** showing which addresses signed the transaction

### Manual Storage Inspection

To inspect storage slots manually after deploying to a local Anvil node:

```bash
# Check if an address is a listed owner
cast call <SAFE_ADDR> "getOwners()(address[])"

# Check if an address passes isOwner
cast call <SAFE_ADDR> "isOwner(address)(bool)" <SHADOW_ADDR>

# Read the raw storage slot for owners[SHADOW_ADDR]
# Slot = keccak256(abi.encode(SHADOW_ADDR, 2))
cast storage <SAFE_ADDR> <COMPUTED_SLOT>
```

## Implementation Status

| Component | Status |
|-----------|--------|
| `SafeDetector.sol` (Plans 1–4) | ✅ Complete |
| `detect_shadows.py` (candidate probing) | ✅ Complete |
| `DeepScan.t.sol` (Phases 3–5) | ✅ Complete |
| `DeepScanIntegration.t.sol` | ✅ Complete |
| `deep_scan.py` (Phase 1–6) | ⚠️ Partial — Phase 1 works; Phase 3 structLogger path works; cast run parser rewritten but less reliable; Phase 2 prefilter works but `known_slots` incomplete |
| Plan C: Merkle Trie via `eth_getProof` | ❌ Not started |
| Plan D: `debug_storageRangeAt` enumeration | ❌ Not started |
| Plan E: Enhanced calldata + slot verification | ❌ Not started |

See `needed-fixes.md` for detailed implementation status and known issues.

## Non-Goals

- This is not a production-safe multisig implementation.
- The Python deep scan is not a production-hardened audit tool; it is an experimental pipeline that may produce false positives or miss shadows.
- The dirty storage pipeline does not replace on-chain guards — it is detection only.
- `debug_storageRangeAt`-based enumeration (Plan D) and Merkle trie traversal (Plan C) are not yet implemented.
