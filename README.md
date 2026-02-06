# Shadow Owners PoC

One little-known attack vector for multisig is [shadow owners](https://docs.lido.fi/guides/multisig-shadow-owners/). This repository will implement a Proof of Concept (PoC) that deploys a Safe-style multisig with a hidden "shadow" owner. The goal is to demonstrate how an address can be authorized to execute transactions while remaining invisible to the standard `getOwners()` list and Safe UI, and to make that behavior observable in a controlled, testable setup. Note that shadow modules are also a risk.

**Background**
- Safe multisigs store owners in a linked-list mapping of `address -> address` with a sentinel address marking the end of the list. Entries that are not reachable from the sentinel can exist in storage but will not appear in `getOwners()`.
- A shadow owner can be added by writing to storage during `setup()`, `executeTransaction()`, or `executeTransactionFromModule()` via `DELEGATECALL`, which allows arbitrary storage mutation.

**What This Repo Will Do**
- Deploy a Safe-like multisig in a local test environment.
- Add a shadow owner by mutating the owners mapping via a delegatecall during setup or execution.
- Prove the shadow owner is authorized (e.g., `isOwner` or signature acceptance) while remaining absent from `getOwners()`.
- Show how this creates "dirty" storage that does not match the expected Safe storage layout, and how to read the affected storage slots with Foundry tooling (for example, `cast storage`).

**Non-Goals**
- This is not a production-safe multisig implementation.
- This is not a detection tool for mainnet multisigs; it is a minimal PoC to explain the mechanism.

**Tooling**
This is a Foundry project. Use standard Foundry workflows (`forge build`, `forge test`, `forge script`) as the PoC is implemented.
