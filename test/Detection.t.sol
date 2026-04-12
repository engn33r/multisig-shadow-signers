// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {Enum} from "@safe/libraries/Enum.sol";
import {ISafe} from "@safe/interfaces/ISafe.sol";
import {SafeDetector} from "../src/SafeDetector.sol";
import {ShadowOwnerInjector} from "../src/ShadowOwnerInjector.sol";
import {ShadowModuleInjector} from "../src/ShadowModuleInjector.sol";

// =========================================================================
//  Shared setup: deploys a Safe with a shadow owner injected during setup()
// =========================================================================
abstract contract ShadowOwnerFixture is Test {
    Safe public singleton;
    SafeProxyFactory public factory;
    ShadowOwnerInjector public injector;
    Safe public safe;

    uint256 constant OWNER1_KEY = 0xA001;
    uint256 constant OWNER2_KEY = 0xA002;
    uint256 constant OWNER3_KEY = 0xA003;
    uint256 constant SHADOW_KEY = 0xBEEF;

    address owner1;
    address owner2;
    address owner3;
    address shadowOwner;

    function setUp() public virtual {
        owner1 = vm.addr(OWNER1_KEY);
        owner2 = vm.addr(OWNER2_KEY);
        owner3 = vm.addr(OWNER3_KEY);
        shadowOwner = vm.addr(SHADOW_KEY);

        singleton = new Safe();
        factory = new SafeProxyFactory();
        injector = new ShadowOwnerInjector();

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners, uint256(2),
            address(injector),
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, shadowOwner),
            address(0), address(0), uint256(0), payable(address(0))
        );

        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), initializer, 0);
        safe = Safe(payable(address(proxy)));
        vm.deal(address(safe), 1 ether);
    }

    function _sortAndSign(uint256 keyA, uint256 keyB, bytes32 hash) internal pure returns (bytes memory) {
        address addrA = vm.addr(keyA);
        address addrB = vm.addr(keyB);
        if (addrA > addrB) (keyA, keyB) = (keyB, keyA);
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(keyA, hash);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(keyB, hash);
        return abi.encodePacked(rA, sA, vA, rB, sB, vB);
    }
}

// =========================================================================
//  Plan 1: Signature Recovery Detection
// =========================================================================

/// @title DetectionPlan1Test
/// @notice Uses SafeDetector.recoverSigners + findUnlistedSigners to detect a shadow
///         owner that co-signed a transaction.
contract DetectionPlan1Test is ShadowOwnerFixture {
    /// @notice Execute a tx signed by owner1 + shadow, then detect the shadow via
    ///         signature recovery.
    function test_detectShadowViaSignatureRecovery() public {
        address recipient = makeAddr("recipient");
        uint256 sendAmount = 0.1 ether;

        bytes32 txHash = safe.getTransactionHash(
            recipient, sendAmount, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), safe.nonce()
        );

        bytes memory signatures = _sortAndSign(OWNER1_KEY, SHADOW_KEY, txHash);

        safe.execTransaction(
            recipient, sendAmount, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), signatures
        );

        // DETECTION: recover signers and find unlisted ones
        uint256 threshold = safe.getThreshold();
        (address[] memory unlisted, uint256 count) =
            SafeDetector.findUnlistedSigners(ISafe(payable(address(safe))), txHash, signatures, threshold);

        assertTrue(count > 0, "should detect at least one unlisted signer");
        assertEq(unlisted[0], shadowOwner, "unlisted signer should be the shadow owner");

        // Also verify recoverSigners directly
        address[] memory signers = SafeDetector.recoverSigners(txHash, signatures, threshold);
        assertEq(signers.length, 2, "should recover 2 signers");

        console.log("=== Plan 1: Signature Recovery Detection ===");
        console.log("Recovered signers:");
        address[] memory listed = safe.getOwners();
        for (uint256 i = 0; i < signers.length; i++) {
            bool inList = _isInArray(signers[i], listed);
            console.log("  %s  listed=%s", signers[i], inList ? "YES" : "NO  <-- SHADOW");
        }
        console.log("Unlisted signers found: %d", count);
    }

    /// @notice Verify that when all signers are legitimate, no shadows are detected.
    function test_noFalsePositivesWithLegitSigners() public {
        address recipient = makeAddr("recipient2");

        bytes32 txHash = safe.getTransactionHash(
            recipient, 0.05 ether, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), safe.nonce()
        );

        // Sign with two legitimate owners only
        bytes memory signatures = _sortAndSign(OWNER1_KEY, OWNER2_KEY, txHash);

        safe.execTransaction(
            recipient, 0.05 ether, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), signatures
        );

        (, uint256 count) = SafeDetector.findUnlistedSigners(
            ISafe(payable(address(safe))), txHash, signatures, safe.getThreshold()
        );

        assertEq(count, 0, "no unlisted signers when all signers are legitimate");
        console.log("=== Plan 1: No False Positives ===");
        console.log("All signers are listed owners - no shadows detected (correct).");
    }

    function _isInArray(address target, address[] memory arr) internal pure returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == target) return true;
        }
        return false;
    }
}

// =========================================================================
//  Plan 2: Event-Based / Delegatecall Analysis
// =========================================================================

/// @title DetectionPlan2Test
/// @notice Uses SafeDetector.analyzeSetupDelegatecall and findOwnersWithoutEvents
///         to flag suspicious setup patterns.
contract DetectionPlan2Test is ShadowOwnerFixture {
    /// @notice Detect that the setup delegatecall target is suspicious (not an owner or module).
    function test_flagSuspiciousSetupDelegatecall() public view {
        (bool suspicious, bool isOwner, bool isModule) =
            SafeDetector.analyzeSetupDelegatecall(ISafe(payable(address(safe))), address(injector));

        assertTrue(suspicious, "setup delegatecall target should be flagged as suspicious");
        assertFalse(isOwner, "injector should not be an owner");
        assertFalse(isModule, "injector should not be a module");

        console.log("=== Plan 2: Setup Delegatecall Analysis ===");
        console.log("Target:     %s", address(injector));
        console.log("Is owner:   false");
        console.log("Is module:  false");
        console.log("Suspicious: YES");
    }

    /// @notice A clean setup (to=address(0)) should not be flagged.
    function test_cleanSetupNotFlagged() public {
        // Deploy a clean Safe
        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        bytes memory cleanInit = abi.encodeWithSelector(
            Safe.setup.selector,
            owners, uint256(2),
            address(0), "", address(0), address(0), uint256(0), payable(address(0))
        );
        SafeProxy cleanProxy = factory.createProxyWithNonce(address(singleton), cleanInit, 99);
        Safe cleanSafe = Safe(payable(address(cleanProxy)));

        (bool suspicious, , ) =
            SafeDetector.analyzeSetupDelegatecall(ISafe(payable(address(cleanSafe))), address(0));

        assertFalse(suspicious, "clean setup should not be flagged");
        console.log("=== Plan 2: Clean Setup ===");
        console.log("No delegatecall target - not suspicious (correct).");
    }

    /// @notice Simulate event-based detection: owners from SafeSetup event match getOwners(),
    ///         but the shadow is NOT in either (it's in storage but not in the list).
    function test_findOwnersWithoutEvents() public view {
        // Simulate: these are the owners from the SafeSetup event
        address[] memory setupOwners = new address[](3);
        setupOwners[0] = owner1;
        setupOwners[1] = owner2;
        setupOwners[2] = owner3;

        // No AddedOwner or RemovedOwner events in this scenario (only setup)
        address[] memory addedEvents = new address[](0);
        address[] memory removedEvents = new address[](0);

        (, uint256 count) =
            SafeDetector.findOwnersWithoutEvents(
                ISafe(payable(address(safe))), addedEvents, removedEvents, setupOwners
            );

        // All current owners were in the setup event, so count should be 0.
        // The shadow owner is NOT in getOwners() so it won't appear here either.
        // This highlights that Plan 2 alone can't find shadows that aren't in the list -
        // it needs to be combined with Plan 4 (probing candidates from calldata).
        assertEq(count, 0, "all listed owners have corresponding events");

        console.log("=== Plan 2: Event Audit ===");
        console.log("All listed owners match setup event - no discrepancy in the list.");
        console.log("NOTE: Shadow is in storage but NOT in getOwners(), so event audit");
        console.log("alone cannot find it. Must combine with Plan 4 (candidate probing).");
    }
}

// =========================================================================
//  Plan 4: Candidate Probing Detection
// =========================================================================

/// @title DetectionPlan4Test
/// @notice Uses SafeDetector.findShadowOwners, findShadowModules, fullScan, and
///         extractAddressesFromCalldata to detect shadows from candidate lists.
contract DetectionPlan4Test is Test {
    Safe public singleton;
    SafeProxyFactory public factory;
    ShadowOwnerInjector public ownerInjector;
    ShadowModuleInjector public moduleInjector;
    Safe public safeShadowOwner;
    Safe public safeShadowModule;

    uint256 constant OWNER1_KEY = 0xA001;
    uint256 constant OWNER2_KEY = 0xA002;
    uint256 constant OWNER3_KEY = 0xA003;

    address owner1;
    address owner2;
    address owner3;
    address shadowOwner = address(0xDEAD);
    address shadowModule = address(0xBAAD);

    function setUp() public {
        owner1 = vm.addr(OWNER1_KEY);
        owner2 = vm.addr(OWNER2_KEY);
        owner3 = vm.addr(OWNER3_KEY);

        singleton = new Safe();
        factory = new SafeProxyFactory();
        ownerInjector = new ShadowOwnerInjector();
        moduleInjector = new ShadowModuleInjector();

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        // Safe with shadow owner
        bytes memory init1 = abi.encodeWithSelector(
            Safe.setup.selector,
            owners, uint256(2),
            address(ownerInjector),
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, shadowOwner),
            address(0), address(0), uint256(0), payable(address(0))
        );
        safeShadowOwner = Safe(payable(address(
            factory.createProxyWithNonce(address(singleton), init1, 0)
        )));

        // Safe with shadow module
        bytes memory init2 = abi.encodeWithSelector(
            Safe.setup.selector,
            owners, uint256(2),
            address(moduleInjector),
            abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, shadowModule),
            address(0), address(0), uint256(0), payable(address(0))
        );
        safeShadowModule = Safe(payable(address(
            factory.createProxyWithNonce(address(singleton), init2, 1)
        )));
    }

    /// @notice Detect shadow owner by probing candidate list.
    function test_findShadowOwners() public view {
        address[] memory candidates = new address[](4);
        candidates[0] = shadowOwner;
        candidates[1] = owner1;
        candidates[2] = address(0x1234); // innocent address
        candidates[3] = address(ownerInjector);

        (SafeDetector.ShadowResult[] memory shadows, uint256 count) =
            SafeDetector.findShadowOwners(ISafe(payable(address(safeShadowOwner))), candidates);

        assertEq(count, 1, "should find exactly 1 shadow owner");
        assertEq(shadows[0].candidate, shadowOwner);
        assertTrue(shadows[0].isShadowOwner);

        console.log("=== Plan 4: Shadow Owner Probing ===");
        console.log("Probed %d candidates, found %d shadow(s)", candidates.length, count);
        console.log("Shadow owner: %s", shadows[0].candidate);
    }

    /// @notice Detect shadow module by probing candidate list.
    function test_findShadowModules() public view {
        address[] memory candidates = new address[](3);
        candidates[0] = shadowModule;
        candidates[1] = address(0x5678);
        candidates[2] = address(moduleInjector);

        (SafeDetector.ShadowResult[] memory shadows, uint256 count) =
            SafeDetector.findShadowModules(ISafe(payable(address(safeShadowModule))), candidates);

        assertEq(count, 1, "should find exactly 1 shadow module");
        assertEq(shadows[0].candidate, shadowModule);
        assertTrue(shadows[0].isShadowModule);

        console.log("=== Plan 4: Shadow Module Probing ===");
        console.log("Probed %d candidates, found %d shadow(s)", candidates.length, count);
        console.log("Shadow module: %s", shadows[0].candidate);
    }

    /// @notice fullScan detects both owner and module shadows in one pass.
    function test_fullScan() public view {
        // Probe the shadow-owner Safe with both shadow addresses
        address[] memory candidates = new address[](5);
        candidates[0] = shadowOwner;
        candidates[1] = shadowModule;
        candidates[2] = owner1;
        candidates[3] = owner2;
        candidates[4] = address(0x9999);

        (SafeDetector.ShadowResult[] memory shadows, uint256 count) =
            SafeDetector.fullScan(ISafe(payable(address(safeShadowOwner))), candidates);

        // Only shadowOwner should be found (shadowModule is not injected in this Safe)
        assertEq(count, 1, "should find 1 shadow in owner-only Safe");
        assertEq(shadows[0].candidate, shadowOwner);
        assertTrue(shadows[0].isShadowOwner);
        assertFalse(shadows[0].isShadowModule);

        console.log("=== Plan 4: Full Scan (owner Safe) ===");
        console.log("Found %d shadow(s) out of %d candidates", count, candidates.length);
    }

    /// @notice Extract candidate addresses from injector calldata automatically.
    function test_extractCandidatesFromCalldata() public view {
        bytes memory calldata1 = abi.encodeWithSelector(
            ShadowOwnerInjector.injectShadowOwner.selector,
            shadowOwner
        );

        (address[] memory extracted, uint256 extractedCount) =
            SafeDetector.extractAddressesFromCalldata(calldata1);

        assertEq(extractedCount, 1, "should extract 1 address");
        assertEq(extracted[0], shadowOwner, "extracted address should match shadow");

        // Now use extracted addresses to probe
        (, uint256 shadowCount) =
            SafeDetector.findShadowOwners(ISafe(payable(address(safeShadowOwner))), extracted);

        assertEq(shadowCount, 1, "extracted candidate should be detected as shadow");

        console.log("=== Plan 4: Calldata Extraction + Probing ===");
        console.log("Extracted %d address(es) from calldata", extractedCount);
        console.log("  candidate: %s", extracted[0]);
        console.log("Probing result: SHADOW OWNER DETECTED");
    }

    /// @notice No false positives: probing legitimate owners and random addresses.
    function test_noFalsePositives() public view {
        address[] memory candidates = new address[](5);
        candidates[0] = owner1;
        candidates[1] = owner2;
        candidates[2] = owner3;
        candidates[3] = address(0x1111);
        candidates[4] = address(0x2222);

        (, uint256 ownerCount) =
            SafeDetector.findShadowOwners(ISafe(payable(address(safeShadowOwner))), candidates);
        (, uint256 moduleCount) =
            SafeDetector.findShadowModules(ISafe(payable(address(safeShadowOwner))), candidates);

        assertEq(ownerCount, 0, "no shadow owners among legitimate addresses");
        assertEq(moduleCount, 0, "no shadow modules among legitimate addresses");

        console.log("=== Plan 4: No False Positives ===");
        console.log("Probed %d legitimate/random addresses - 0 shadows (correct).", candidates.length);
    }
}
