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
| `script/DetectShadows.s.sol` | Foundry scripts for auditing existing Safes on-chain. Includes both proof-of-concept and production audit modes. |
| `test/ShadowOwner.t.sol` | Tests demonstrating shadow owner attacks and injection methods. |
| `test/ShadowModule.t.sol` | Tests demonstrating shadow module attacks (more dangerous than shadow owners). |
| `test/Detection.t.sol` | Comprehensive detection tests organized into 5 plans covering different detection strategies. |

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

### Detection Limitations

| Shadow Type | Detectable? | Method |
|-------------|-------------|--------|
| Active (has signed) | ✅ Yes | Signature recovery from transactions |
| Dormant (never signed) | ✅ Yes | Calldata extraction from historical delegatecalls |
| Unknown address | ❌ No | Must know candidate addresses to probe |

**Key insight:** You cannot "discover" an arbitrary shadow address without prior knowledge. Detection requires either:
1. The shadow to have signed (address in signature data)
2. Access to historical calldata that contains the shadow address (setup or delegatecall data)

## Scripts (script/DetectShadows.s.sol)

Foundry scripts for auditing Safes:

| Script | Purpose | Usage |
|--------|---------|-------|
| `DetectShadowsPoC` | Demonstrates detection against a fresh PoC Safe with injected shadows. | `forge script script/DetectShadows.s.sol:DetectShadowsPoC` |
| `AuditExistingSafe` | Audits an existing Safe on-chain (requires `SAFE_ADDRESS` env var). | `forge script script/DetectShadows.s.sol:AuditExistingSafe --rpc-url <RPC>` |

The scripts demonstrate how to use `SafeDetector` library functions to analyze real Safes and detect potential shadow entries.

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
```

### Running Scripts

```bash
# Run the PoC detection script
forge script script/DetectShadows.s.sol:DetectShadowsPoC -vvvv

# Audit an existing Safe (requires RPC endpoint)
export SAFE_ADDRESS=0x...
forge script script/DetectShadows.s.sol:AuditExistingSafe --rpc-url <RPC_URL> -vvvv
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

## Key Takeaway

**Shadow owners** can co-sign transactions but require threshold-many signatures (including themselves). **Shadow modules** are strictly more dangerous — they can execute arbitrary transactions with zero owner signatures. Both are invisible through standard Safe interfaces.

**Detection approaches:**
- **Active shadows**: Recover signer addresses from transaction signatures and compare against `getOwners()`
- **Dormant shadows**: Extract addresses from historical calldata (setup/delegatecall transactions) and probe them
- **Both types**: Probe candidate addresses where `isOwner(candidate) == true` but candidate ∉ `getOwners()`

The fundamental challenge is **address discovery** — you must know which addresses to check, either from signatures or historical calldata.

## Non-Goals

- This is not a production-safe multisig implementation.
- This is not a detection tool for mainnet multisigs; it is a minimal PoC to explain the mechanism.
