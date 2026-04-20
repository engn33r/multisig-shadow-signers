// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Safe} from "@safe/Safe.sol";
import {Enum} from "@safe/libraries/Enum.sol";
import {ISafe} from "@safe/interfaces/ISafe.sol";
import {SafeDetector} from "../src/SafeDetector.sol";
import {ShadowOwnerInjector} from "../src/ShadowOwnerInjector.sol";
import {ShadowModuleInjector} from "../src/ShadowModuleInjector.sol";
import {ShadowTestBase} from "./utils/ShadowTestBase.sol";

/// @title DeepScanIntegrationTest
/// @notice End-to-end integration tests for the complete 6-phase dirty storage
///         detection pipeline. These tests cover cross-phase interactions and
///         scenarios not duplicated in DeepScan.t.sol or Detection.t.sol.
contract DeepScanIntegrationTest is ShadowTestBase {
    Safe public safeWithShadowOwner;
    Safe public safeWithShadowModule;
    Safe public safeWithBothShadows;
    Safe public cleanSafe;

    function setUp() public {
        _setUpBase();

        // Safe with shadow owner injected during setup
        safeWithShadowOwner = _deploySafeWithShadowOwner(_defaultOwners(), 2, shadowOwner);
        vm.deal(address(safeWithShadowOwner), 1 ether);

        // Safe with shadow module injected during setup
        safeWithShadowModule = _deploySafeWithShadowModule(_defaultOwners(), 2, shadowModule);
        vm.deal(address(safeWithShadowModule), 1 ether);

        // Safe with both shadow owner and shadow module
        safeWithBothShadows = _deploySafeWithShadowOwner(_defaultOwners(), 2, shadowOwner);
        vm.deal(address(safeWithBothShadows), 1 ether);
        // Inject shadow module via execTransaction
        bytes memory injectData =
            abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, shadowModule);
        bytes32 txHash = safeWithBothShadows.getTransactionHash(
            address(moduleInjector), 0, injectData, Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), safeWithBothShadows.nonce()
        );
        safeWithBothShadows.execTransaction(
            address(moduleInjector), 0, injectData, Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), _sortAndSign(OWNER1_KEY, OWNER2_KEY, txHash)
        );

        // Clean Safe
        cleanSafe = _deployCleanSafe(_defaultOwners(), 2);
        vm.deal(address(cleanSafe), 1 ether);
    }

    // =========================================================================
    //  Phase 1 + 3: Storage write recording + KECCAK256 slot detection
    // =========================================================================

    /// @notice Record storage writes during injection and detect shadow slots.
    function test_detectShadowViaStorageWrites() public {
        Safe freshProxy;
        vm.record();
        freshProxy = _deploySafeWithShadowOwner(_defaultOwners(), 2, shadowOwner);

        (, bytes32[] memory writes) = vm.accesses(address(freshProxy));

        bytes32 shadowOwnerSlot = keccak256(abi.encode(shadowOwner, SLOT_OWNERS));
        bool found = false;
        for (uint256 i = 0; i < writes.length; i++) {
            if (writes[i] == shadowOwnerSlot) found = true;
        }
        assertTrue(found, "should detect write to shadow owner slot");

        bytes32 storedValue = vm.load(address(freshProxy), shadowOwnerSlot);
        assertEq(storedValue, bytes32(uint256(uint160(SENTINEL))), "shadow owner slot value should be SENTINEL");
    }

    // =========================================================================
    //  Phase 5: Detection via execTransaction (compound attack)
    // =========================================================================

    /// @notice Detect shadow injection via execTransaction with storage recording.
    function test_detectInjectionViaExecTransaction() public {
        uint256 SHADOW_OWNER_KEY = 0xDEAD;
        address execShadow = vm.addr(SHADOW_OWNER_KEY);

        bytes memory injectCalldata =
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, execShadow);

        bytes32 txHash = cleanSafe.getTransactionHash(
            address(ownerInjector), 0, injectCalldata, Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), cleanSafe.nonce()
        );
        bytes memory signatures = _sortAndSign(OWNER1_KEY, OWNER2_KEY, txHash);

        vm.record();
        bool success = cleanSafe.execTransaction(
            address(ownerInjector), 0, injectCalldata, Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), signatures
        );
        assertTrue(success, "injection tx must succeed");

        (, bytes32[] memory writes) = vm.accesses(address(cleanSafe));

        bytes32 shadowSlot = keccak256(abi.encode(execShadow, SLOT_OWNERS));
        bool foundShadowSlot = false;
        for (uint256 i = 0; i < writes.length; i++) {
            if (writes[i] == shadowSlot) foundShadowSlot = true;
        }
        assertTrue(foundShadowSlot, "should detect write to shadow owner slot");
        assertTrue(cleanSafe.isOwner(execShadow), "shadow should pass isOwner()");
        assertFalse(_isInArray(execShadow, cleanSafe.getOwners()), "shadow should NOT be in getOwners()");
    }

    /// @notice Detect compound attack: shadow module injects shadow owner via execTransactionFromModule.
    function test_phase5_moduleInjectsOwner() public {
        MaliciousModule malModule = new MaliciousModule();
        address secondaryShadow = makeAddr("secondaryShadow");

        // Inject the malicious module into safeWithShadowModule
        bytes memory injectData =
            abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, address(malModule));
        bytes32 txHash = safeWithShadowModule.getTransactionHash(
            address(moduleInjector), 0, injectData, Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), safeWithShadowModule.nonce()
        );
        safeWithShadowModule.execTransaction(
            address(moduleInjector), 0, injectData, Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), _sortAndSign(OWNER1_KEY, OWNER2_KEY, txHash)
        );

        assertTrue(safeWithShadowModule.isModuleEnabled(address(malModule)), "malModule should be enabled");
        assertFalse(_isInArray(address(malModule), _getModulesList(address(safeWithShadowModule))), "malModule hidden");

        // Use the shadow module to inject a secondary shadow owner (0 signatures needed)
        ShadowOwnerInjector secInjector = new ShadowOwnerInjector();
        vm.record();
        malModule.injectShadowOwner(address(safeWithShadowModule), address(secInjector), secondaryShadow);
        (, bytes32[] memory ownerInjectWrites) = vm.accesses(address(safeWithShadowModule));

        assertTrue(safeWithShadowModule.isOwner(secondaryShadow), "secondary shadow should pass isOwner()");
        assertFalse(_isInArray(secondaryShadow, safeWithShadowModule.getOwners()), "secondary shadow hidden");

        bytes32 secondarySlot = keccak256(abi.encode(secondaryShadow, SLOT_OWNERS));
        bool foundSecondary = false;
        for (uint256 i = 0; i < ownerInjectWrites.length; i++) {
            if (ownerInjectWrites[i] == secondarySlot) foundSecondary = true;
        }
        assertTrue(foundSecondary, "should detect write to secondary shadow slot");
    }

    // =========================================================================
    //  Phase 5: Fixed-slot anomaly detection
    // =========================================================================

    /// @notice Threshold overwrite detection via raw SSTORE.
    function test_thresholdOverwrite() public {
        assertEq(cleanSafe.getThreshold(), 2, "threshold should be 2 before");
        vm.store(address(cleanSafe), bytes32(uint256(SLOT_THRESHOLD)), bytes32(uint256(1)));
        assertEq(cleanSafe.getThreshold(), 1, "threshold should be 1 after overwrite");
    }

    /// @notice OwnerCount overwrite detection.
    function test_ownerCountOverwrite() public {
        bytes32 before = vm.load(address(cleanSafe), bytes32(uint256(SLOT_OWNER_COUNT)));
        assertEq(uint256(before), 3, "ownerCount should be 3");

        vm.store(address(cleanSafe), bytes32(uint256(SLOT_OWNER_COUNT)), bytes32(uint256(100)));
        bytes32 after_ = vm.load(address(cleanSafe), bytes32(uint256(SLOT_OWNER_COUNT)));
        assertEq(uint256(after_), 100, "ownerCount should be 100 after overwrite");
    }

    /// @notice Clean Safe has no anomalies.
    function test_cleanSafeNoAnomalies() public {
        bytes32 countVal = vm.load(address(cleanSafe), bytes32(uint256(SLOT_OWNER_COUNT)));
        assertEq(uint256(countVal), cleanSafe.getOwners().length, "ownerCount should match listed");
    }

    // =========================================================================
    //  Full pipeline: E2E detection
    // =========================================================================

    /// @notice Full E2E: detect shadow owner via storage + KECCAK256 preimage.
    function test_fullPipelineShadowOwner() public view {
        address safeAddr = address(safeWithShadowOwner);

        bytes32 slot = keccak256(abi.encode(shadowOwner, SLOT_OWNERS));
        bytes32 value = vm.load(safeAddr, slot);
        assertTrue(uint256(value) > 0, "shadow owner slot should be non-zero");

        // Decode preimage: abi.encode(shadowOwner, 2)
        bytes memory preimage = abi.encode(shadowOwner, SLOT_OWNERS);
        assertEq(keccak256(preimage), slot, "preimage hash should match");

        // Classification
        assertTrue(safeWithShadowOwner.isOwner(shadowOwner), "isOwner should be true");
        assertFalse(_isInArray(shadowOwner, safeWithShadowOwner.getOwners()), "shadow hidden from getOwners()");
    }

    /// @notice Full E2E: detect shadow module.
    function test_fullPipelineShadowModule() public view {
        address safeAddr = address(safeWithShadowModule);

        bytes32 slot = keccak256(abi.encode(shadowModule, SLOT_MODULES));
        bytes32 value = vm.load(safeAddr, slot);
        assertTrue(uint256(value) > 0, "shadow module slot should be non-zero");

        assertTrue(safeWithShadowModule.isModuleEnabled(shadowModule), "isModuleEnabled should be true");
        assertFalse(_isInArray(shadowModule, _getModulesList(safeAddr)), "shadow hidden from getModulesPaginated()");
    }

    /// @notice Full E2E: detect both shadows in one Safe.
    function test_fullPipelineBothShadows() public view {
        ISafe safe = ISafe(payable(address(safeWithBothShadows)));

        bool isO = safe.isOwner(shadowOwner);
        bool inO = _isInArray(shadowOwner, safe.getOwners());
        bool isM = safe.isModuleEnabled(shadowModule);
        bool inM = _isInArray(shadowModule, _getModulesList(address(safeWithBothShadows)));

        assertTrue(isO, "shadow owner should pass isOwner()");
        assertFalse(inO, "shadow owner hidden");
        assertTrue(isM, "shadow module should pass isModuleEnabled()");
        assertFalse(inM, "shadow module hidden");

        bytes32 ownerSlot = keccak256(abi.encode(shadowOwner, SLOT_OWNERS));
        bytes32 moduleSlot = keccak256(abi.encode(shadowModule, SLOT_MODULES));
        assertTrue(uint256(vm.load(address(safeWithBothShadows), ownerSlot)) > 0, "owner slot non-zero");
        assertTrue(uint256(vm.load(address(safeWithBothShadows), moduleSlot)) > 0, "module slot non-zero");
    }

    /// @notice Linked-list walk confirms shadow unreachable.
    function test_linkedListReachability() public view {
        address safeAddr = address(safeWithShadowOwner);
        address current = SENTINEL;
        bool shadowFound = false;
        for (uint256 i = 0; i < 20; i++) {
            bytes32 nextSlot = keccak256(abi.encode(current, SLOT_OWNERS));
            address next = address(uint160(uint256(vm.load(safeAddr, nextSlot))));
            if (next == SENTINEL || next == address(0)) break;
            if (next == shadowOwner) shadowFound = true;
            current = next;
        }
        assertFalse(shadowFound, "shadow owner should NOT be reachable via linked list");
    }

    // =========================================================================
    //  SafeDetector integration
    // =========================================================================

    /// @notice fullScan detects both shadow types.
    function test_safeDetectorFullScan() public {
        address[] memory candidates = new address[](5);
        candidates[0] = shadowOwner;
        candidates[1] = owner1;
        candidates[2] = owner2;
        candidates[3] = makeAddr("random");
        candidates[4] = address(ownerInjector);

        (SafeDetector.ShadowResult[] memory shadows, uint256 count) =
            SafeDetector.fullScan(ISafe(payable(address(safeWithShadowOwner))), candidates);

        assertEq(count, 1, "should find exactly 1 shadow");
        assertEq(shadows[0].candidate, shadowOwner);
        assertTrue(shadows[0].isShadowOwner);
        assertFalse(shadows[0].isShadowModule);
    }

    /// @notice Calldata extraction + probing detects shadow from injector data.
    function test_candidateExtractionFromCalldata() public view {
        bytes memory injectorData =
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, shadowOwner);

        (address[] memory extracted, uint256 extractedCount) = SafeDetector.extractAddressesFromCalldata(injectorData);
        assertEq(extractedCount, 1, "should extract 1 address");
        assertEq(extracted[0], shadowOwner);

        (, uint256 shadowCount) =
            SafeDetector.findShadowOwners(ISafe(payable(address(safeWithShadowOwner))), extracted);
        assertEq(shadowCount, 1, "extracted candidate should be detected as shadow");
    }
}

/// @title Minimal malicious module for compound attack testing
contract MaliciousModule {
    function injectShadowOwner(address safe, address injector, address shadowOwner) external {
        bytes memory data = abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, shadowOwner);
        Safe(payable(safe)).execTransactionFromModule(injector, 0, data, Enum.Operation.DelegateCall);
    }
}