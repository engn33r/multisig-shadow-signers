// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISafe} from "@safe/interfaces/ISafe.sol";
import {Enum} from "@safe/libraries/Enum.sol";

/// @title SafeDetector
/// @notice Reusable detection primitives for finding shadow owners and shadow modules
///         in Safe multisigs. Shadow entries exist in the raw storage mapping but are
///         not reachable from the linked-list traversal, making them invisible to
///         getOwners() / getModulesPaginated() while passing isOwner() / isModuleEnabled().
///
/// @dev This library provides pure/view functions that can be called from:
///      - Foundry tests (validating detection against a PoC)
///      - Foundry scripts (auditing Safes on a fork or live network)
///      - On-chain contracts (e.g. a Guard that checks for shadows before execution)
library SafeDetector {
    /// @notice Result of probing a single candidate address.
    struct ShadowResult {
        address candidate;
        bool isShadowOwner; // isOwner() == true but not in getOwners()
        bool isShadowModule; // isModuleEnabled() == true but not in getModulesPaginated()
    }

    // =========================================================================
    //  Plan 1: Signature Recovery
    // =========================================================================

    /// @notice Split a packed Safe signature at index `i` into its v, r, s components.
    /// @dev Safe packs signatures as 65-byte chunks: r (32) || s (32) || v (1).
    /// @param signatures The concatenated packed signatures.
    /// @param i The signature index (0-based).
    /// @return v The recovery byte.
    /// @return r The r component.
    /// @return s The s component.
    function splitSignature(bytes memory signatures, uint256 i) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        uint256 offset = i * 65;
        assembly {
            r := mload(add(signatures, add(32, offset)))
            s := mload(add(signatures, add(64, offset)))
            v := byte(0, mload(add(signatures, add(96, offset))))
        }
    }

    /// @notice Recover signer addresses from packed Safe ECDSA signatures.
    /// @dev Only handles standard ECDSA sigs (v >= 27). For contract signatures (v==0)
    ///      and approved hashes (v==1), the signer address is encoded in `r` directly.
    /// @param txHash The Safe transaction hash that was signed.
    /// @param signatures The packed signatures from execTransaction().
    /// @param count Number of signatures to recover (typically == threshold).
    /// @return signers Array of recovered signer addresses.
    function recoverSigners(bytes32 txHash, bytes memory signatures, uint256 count)
        internal
        pure
        returns (address[] memory signers)
    {
        signers = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = splitSignature(signatures, i);
            if (v == 0 || v == 1) {
                // Contract signature or approved hash: signer address is in `r`
                signers[i] = address(uint160(uint256(r)));
            } else if (v >= 27) {
                // Standard ECDSA or eth_sign (v > 30 means eth_sign, but ecrecover
                // handles the adjusted v values the same way Safe does)
                if (v > 30) {
                    // eth_sign: Safe adjusts v by +4 and wraps the hash
                    signers[i] =
                        ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)), v - 4, r, s);
                } else {
                    signers[i] = ecrecover(txHash, v, r, s);
                }
            }
        }
    }

    /// @notice Find signers that signed a Safe transaction but are NOT in getOwners().
    /// @param safe The Safe contract to check.
    /// @param txHash The transaction hash that was signed.
    /// @param signatures The packed signatures from the execTransaction call.
    /// @param count Number of signatures (typically == threshold).
    /// @return unlistedSigners Array of signer addresses not in getOwners() (may contain address(0) padding).
    /// @return unlistedCount Number of unlisted signers found.
    function findUnlistedSigners(ISafe safe, bytes32 txHash, bytes memory signatures, uint256 count)
        internal
        view
        returns (address[] memory unlistedSigners, uint256 unlistedCount)
    {
        address[] memory signers = recoverSigners(txHash, signatures, count);
        address[] memory listedOwners = safe.getOwners();

        unlistedSigners = new address[](count);
        unlistedCount = 0;

        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == address(0)) continue;
            if (!_isInArray(signers[i], listedOwners)) {
                unlistedSigners[unlistedCount] = signers[i];
                unlistedCount++;
            }
        }
    }

    // =========================================================================
    //  Plan 2: Event-Based Heuristics
    // =========================================================================

    /// @notice Check if a Safe's setup() included a delegatecall (non-zero `to` param).
    /// @dev In production, decode the proxy creation tx calldata to extract the setup()
    ///      parameters. This function checks a known `to` address against the Safe's
    ///      current state to see if it has any legitimate role.
    /// @param safe The Safe to check.
    /// @param setupDelegatecallTarget The `to` address from the setup() call.
    /// @return suspicious True if the target is not an owner or module (one-shot injector).
    /// @return isOwner Whether the target is currently an owner.
    /// @return isModule Whether the target is currently an enabled module.
    function analyzeSetupDelegatecall(ISafe safe, address setupDelegatecallTarget)
        internal
        view
        returns (bool suspicious, bool isOwner, bool isModule)
    {
        if (setupDelegatecallTarget == address(0)) {
            return (false, false, false); // No delegatecall in setup
        }
        isOwner = safe.isOwner(setupDelegatecallTarget);
        isModule = safe.isModuleEnabled(setupDelegatecallTarget);
        // A legitimate setup delegatecall target (like SafeToL2Setup) would typically
        // not remain as an owner or module. But a target that is neither is suspicious:
        // it did something during setup and then had no ongoing role.
        suspicious = !isOwner && !isModule;
    }

    /// @notice Given a set of addresses that had AddedOwner events, find any that are
    ///         no longer owners (removed) and any current owners missing an AddedOwner event.
    /// @dev The latter case (owner without AddedOwner) can indicate a shadow owner that was
    ///      injected via raw sstore rather than the legitimate addOwnerWithThreshold path.
    ///      NOTE: Initial owners set during setup() DO appear in the SafeSetup event but
    ///      do NOT get individual AddedOwner events. So the initial owners must be passed
    ///      separately as `setupOwners`.
    /// @param safe The Safe to check.
    /// @param addedOwnerEvents Addresses from all AddedOwner events in the Safe's history.
    /// @param removedOwnerEvents Addresses from all RemovedOwner events.
    /// @param setupOwners The initial owners from the SafeSetup event.
    /// @return ownersWithoutEvents Current owners that have no corresponding AddedOwner
    ///         event or setupOwners entry (potential shadows injected via setup delegatecall).
    /// @return count Number of owners without events.
    function findOwnersWithoutEvents(
        ISafe safe,
        address[] memory addedOwnerEvents,
        address[] memory removedOwnerEvents,
        address[] memory setupOwners
    ) internal view returns (address[] memory ownersWithoutEvents, uint256 count) {
        address[] memory currentOwners = safe.getOwners();
        ownersWithoutEvents = new address[](currentOwners.length);
        count = 0;

        for (uint256 i = 0; i < currentOwners.length; i++) {
            address owner = currentOwners[i];
            bool hasAddedEvent = _isInArray(owner, addedOwnerEvents);
            bool wasInSetup = _isInArray(owner, setupOwners);
            bool wasRemoved = _isInArray(owner, removedOwnerEvents);

            // If the owner wasn't in setup AND has no AddedOwner event, it's suspicious.
            // If it was removed and re-added, the AddedOwner event covers it.
            if (!hasAddedEvent && !wasInSetup && !wasRemoved) {
                ownersWithoutEvents[count] = owner;
                count++;
            }
        }
    }

    // =========================================================================
    //  Plan 3: Candidate Probing
    // =========================================================================

    /// @notice Probe a list of candidate addresses against a Safe to find shadow owners.
    /// @dev A shadow owner has isOwner() == true but is not in getOwners().
    /// @param safe The Safe to check.
    /// @param candidates Array of candidate addresses to probe.
    /// @return shadows Array of ShadowResult structs for candidates that ARE shadow owners.
    /// @return shadowCount Number of shadow owners found.
    function findShadowOwners(ISafe safe, address[] memory candidates)
        internal
        view
        returns (ShadowResult[] memory shadows, uint256 shadowCount)
    {
        address[] memory listedOwners = safe.getOwners();
        shadows = new ShadowResult[](candidates.length);
        shadowCount = 0;

        for (uint256 i = 0; i < candidates.length; i++) {
            address c = candidates[i];
            if (c == address(0) || c == address(0x1)) continue; // Skip zero and sentinel

            bool passesIsOwner = safe.isOwner(c);
            bool inList = _isInArray(c, listedOwners);

            if (passesIsOwner && !inList) {
                shadows[shadowCount] = ShadowResult({candidate: c, isShadowOwner: true, isShadowModule: false});
                shadowCount++;
            }
        }
    }

    /// @notice Probe a list of candidate addresses against a Safe to find shadow modules.
    /// @dev A shadow module has isModuleEnabled() == true but is not in getModulesPaginated().
    /// @param safe The Safe to check.
    /// @param candidates Array of candidate addresses to probe.
    /// @return shadows Array of ShadowResult structs for candidates that ARE shadow modules.
    /// @return shadowCount Number of shadow modules found.
    function findShadowModules(ISafe safe, address[] memory candidates)
        internal
        view
        returns (ShadowResult[] memory shadows, uint256 shadowCount)
    {
        (address[] memory listedModules,) = safe.getModulesPaginated(address(0x1), 100);
        shadows = new ShadowResult[](candidates.length);
        shadowCount = 0;

        for (uint256 i = 0; i < candidates.length; i++) {
            address c = candidates[i];
            if (c == address(0) || c == address(0x1)) continue;

            bool passesIsEnabled = safe.isModuleEnabled(c);
            bool inList = _isInArray(c, listedModules);

            if (passesIsEnabled && !inList) {
                shadows[shadowCount] = ShadowResult({candidate: c, isShadowOwner: false, isShadowModule: true});
                shadowCount++;
            }
        }
    }

    /// @notice Combined scan: probe candidates for both shadow owners AND shadow modules.
    /// @param safe The Safe to check.
    /// @param candidates Array of candidate addresses.
    /// @return shadows Array of all shadow findings.
    /// @return shadowCount Total number of shadows found.
    function fullScan(ISafe safe, address[] memory candidates)
        internal
        view
        returns (ShadowResult[] memory shadows, uint256 shadowCount)
    {
        address[] memory listedOwners = safe.getOwners();
        (address[] memory listedModules,) = safe.getModulesPaginated(address(0x1), 100);

        shadows = new ShadowResult[](candidates.length);
        shadowCount = 0;

        for (uint256 i = 0; i < candidates.length; i++) {
            address c = candidates[i];
            if (c == address(0) || c == address(0x1)) continue;

            bool isShadowOwner = safe.isOwner(c) && !_isInArray(c, listedOwners);
            bool isShadowModule = safe.isModuleEnabled(c) && !_isInArray(c, listedModules);

            if (isShadowOwner || isShadowModule) {
                shadows[shadowCount] =
                    ShadowResult({candidate: c, isShadowOwner: isShadowOwner, isShadowModule: isShadowModule});
                shadowCount++;
            }
        }
    }

    // =========================================================================
    //  Calldata Extraction Helpers
    // =========================================================================

    /// @notice Extract address-sized values from arbitrary calldata.
    /// @dev Scans every 32-byte word after the 4-byte selector and returns values
    ///      that look like addresses (upper 12 bytes are zero, lower 20 bytes non-zero,
    ///      not zero address, not sentinel). This is a heuristic - it may produce false
    ///      positives on uint256 values that happen to fit the address pattern.
    /// @param data The calldata to scan (including 4-byte selector).
    /// @return addresses Array of extracted candidate addresses.
    /// @return count Number of addresses found.
    function extractAddressesFromCalldata(bytes memory data)
        internal
        pure
        returns (address[] memory addresses, uint256 count)
    {
        // Each param is a 32-byte word; skip the 4-byte selector
        if (data.length < 36) return (new address[](0), 0);

        uint256 maxParams = (data.length - 4) / 32;
        addresses = new address[](maxParams);
        count = 0;

        for (uint256 i = 0; i < maxParams; i++) {
            uint256 offset = 4 + (i * 32);
            bytes32 word;
            assembly {
                word := mload(add(data, add(32, offset)))
            }

            uint256 val = uint256(word);
            // Check if upper 96 bits are zero (looks like an address)
            // and lower 160 bits are non-zero and not sentinel
            if (val != 0 && val == (val & type(uint160).max) && val != 1) {
                addresses[count] = address(uint160(val));
                count++;
            }
        }
    }

    // =========================================================================
    //  Plan 4: Dormant Shadow Detection
    // =========================================================================

    /// @notice Scan historical transaction calldata to extract candidate addresses
    ///         that might be dormant shadows, then probe them.
    /// @dev This is designed for use in Foundry scripts against a forked network
    ///      where you can fetch historical transactions via RPC.
    /// @param safe The Safe to check.
    /// @param historicalCalldata Array of calldata from past Safe transactions
    ///        (setup initializer, delegatecall execTransactions, etc).
    /// @return shadows Array of detected shadow owners from the candidates.
    /// @return shadowCount Number of dormant shadows found.
    function detectDormantShadowsFromHistory(ISafe safe, bytes[] memory historicalCalldata)
        internal
        view
        returns (ShadowResult[] memory shadows, uint256 shadowCount)
    {
        // Collect all unique addresses from historical calldata
        address[] memory allCandidates = new address[](historicalCalldata.length * 10); // rough estimate
        uint256 candidateCount = 0;

        for (uint256 i = 0; i < historicalCalldata.length; i++) {
            (address[] memory extracted, uint256 extractedCount) = extractAddressesFromCalldata(historicalCalldata[i]);

            for (uint256 j = 0; j < extractedCount; j++) {
                address candidate = extracted[j];
                // Skip duplicates
                bool alreadyAdded = false;
                for (uint256 k = 0; k < candidateCount; k++) {
                    if (allCandidates[k] == candidate) {
                        alreadyAdded = true;
                        break;
                    }
                }
                if (!alreadyAdded) {
                    allCandidates[candidateCount] = candidate;
                    candidateCount++;
                }
            }
        }

        // Trim array to actual size
        address[] memory candidates = new address[](candidateCount);
        for (uint256 i = 0; i < candidateCount; i++) {
            candidates[i] = allCandidates[i];
        }

        // Probe candidates for shadows
        return findShadowOwners(safe, candidates);
    }

    // =========================================================================
    //  Internal Helpers
    // =========================================================================

    function _isInArray(address target, address[] memory arr) private pure returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == target) return true;
        }
        return false;
    }
}
