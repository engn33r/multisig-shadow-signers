# Shadow Owners & Modules PoC

A Foundry-based proof of concept demonstrating how "shadow" owners and modules can be hidden inside a Safe multisig. Shadow entries are authorized to act (sign transactions or execute via module) but are **invisible** in the standard Safe UI and getter functions (`getOwners()`, `getModulesPaginated()`).

This is an educational security PoC — not a production tool.

## Background

Safe multisigs store owners and modules in linked-list mappings (`mapping(address => address)`) with a sentinel address (`0x1`) marking the list boundaries:

```
owners[SENTINEL] -> owner1 -> owner2 -> owner3 -> SENTINEL
```

`getOwners()` traverses this linked list, while `isOwner(addr)` simply checks `owners[addr] != address(0)`. An entry can exist in the mapping without being reachable from the sentinel — making it pass `isOwner()` while being absent from `getOwners()`.

Shadow entries are injected by executing a `DELEGATECALL` to a contract that writes directly to the mapping's storage slot via `sstore`. This can happen during:
- **`setup()`** — the `to`/`data` parameters trigger a delegatecall in `setupModules()`
- **`execTransaction()`** — using `Enum.Operation.DelegateCall` as the operation type

The same technique applies to the `modules` mapping (slot 1) as to the `owners` mapping (slot 2).

Reference: [Lido — Multisig Shadow Owners Guide](https://docs.lido.fi/guides/multisig-shadow-owners/)

## What This Repo Demonstrates

### Shadow Owners (test/ShadowOwner.t.sol)

| Test | What it proves |
|------|---------------|
| `test_shadowOwnerIsHiddenButAuthorized` | `isOwner(shadow)` returns true, but `getOwners()` does not include the shadow address. Threshold is based only on visible owners. |
| `test_shadowOwnerCanSignTransaction` | A real `execTransaction` sending ETH succeeds using signatures from 1 legitimate owner + the shadow owner. |
| `test_storageInspection` | Raw storage reads via `vm.load()` show the orphaned mapping entry and confirm the shadow is unreachable in the linked list. |
| `test_injectShadowViaExecTransaction` | Shadow owner is injected post-setup via a DELEGATECALL `execTransaction`, then used to co-sign a transfer. |

### Shadow Modules (test/ShadowModule.t.sol)

| Test | What it proves |
|------|---------------|
| `test_shadowModuleIsHiddenButEnabled` | `isModuleEnabled(shadow)` returns true, but `getModulesPaginated()` does not list it. |
| `test_shadowModuleCanExecuteWithoutSignatures` | The shadow module calls `execTransactionFromModule()` to drain ETH — no owner signatures needed. |
| `test_moduleStorageInspection` | Raw storage reads show the orphaned modules mapping entry. |
| `test_injectShadowModuleViaExecTransaction` | Shadow module is injected post-setup via DELEGATECALL, then used to drain funds. |

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

Detection requires comparing on-chain storage against the linked list, or monitoring for `DELEGATECALL` operations in transaction proposals.

## Non-Goals

- This is not a production-safe multisig implementation.
- This is not a detection tool for mainnet multisigs; it is a minimal PoC to explain the mechanism.
