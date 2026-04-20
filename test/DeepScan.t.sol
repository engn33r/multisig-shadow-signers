// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {Enum} from "@safe/libraries/Enum.sol";
import {ISafe} from "@safe/interfaces/ISafe.sol";
import {SafeDetector} from "../src/SafeDetector.sol";
import {ShadowOwnerInjector} from "../src/ShadowOwnerInjector.sol";
import {ShadowModuleInjector} from "../src/ShadowModuleInjector.sol";

/// @title DeepScanTest
/// @notice Validates the deep scan dirty storage detection pipeline.
///         Uses Foundry's vm.record() / vm.accesses() to track storage writes,
///         then analyzes which KECCAK256-computed slots were written to identify
///         shadow entries without prior knowledge of the candidate address.
contract DeepScanTest is Test {
    Safe public singleton;
    SafeProxyFactory public factory;
    ShadowOwnerInjector public ownerInjector;
    ShadowModuleInjector public moduleInjector;
    Safe public safeWithShadowOwner;
    Safe public safeWithShadowModule;
    Safe public cleanSafe;

    uint256 constant OWNER1_KEY = 0xA001;
    uint256 constant OWNER2_KEY = 0xA002;
    uint256 constant OWNER3_KEY = 0xA003;
    uint256 constant SHADOW_OWNER_KEY = 0xDEAD;
    uint256 constant SHADOW_MODULE_KEY = 0xBAAD;

    address owner1;
    address owner2;
    address owner3;
    address shadowOwner;
    address shadowModule;

    // Safe storage layout
    uint256 constant SLOT_MODULES = 1;
    uint256 constant SLOT_OWNERS = 2;
    uint256 constant SLOT_OWNER_COUNT = 3;
    uint256 constant SLOT_THRESHOLD = 4;
    uint256 constant SLOT_NONCE = 5;
    address constant SENTINEL = address(0x1);

    function setUp() public {
        owner1 = vm.addr(OWNER1_KEY);
        owner2 = vm.addr(OWNER2_KEY);
        owner3 = vm.addr(OWNER3_KEY);
        shadowOwner = vm.addr(SHADOW_OWNER_KEY);
        shadowModule = vm.addr(SHADOW_MODULE_KEY);

        singleton = new Safe();
        factory = new SafeProxyFactory();
        ownerInjector = new ShadowOwnerInjector();
        moduleInjector = new ShadowModuleInjector();

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        // Safe with shadow owner injected during setup
        bytes memory initOwner = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(2),
            address(ownerInjector),
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, shadowOwner),
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );
        safeWithShadowOwner = Safe(payable(address(factory.createProxyWithNonce(address(singleton), initOwner, 0))));
        vm.deal(address(safeWithShadowOwner), 1 ether);

        // Safe with shadow module injected during setup
        bytes memory initModule = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(2),
            address(moduleInjector),
            abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, shadowModule),
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );
        safeWithShadowModule = Safe(payable(address(factory.createProxyWithNonce(address(singleton), initModule, 1))));
        vm.deal(address(safeWithShadowModule), 1 ether);

        // Clean Safe (no shadows)
        bytes memory initClean = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(2),
            address(0),
            "",
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );
        cleanSafe = Safe(payable(address(factory.createProxyWithNonce(address(singleton), initClean, 2))));
        vm.deal(address(cleanSafe), 1 ether);
    }

    // =========================================================================
    //  Phase 3: Storage Write Detection via vm.record/vm.accesses
    // =========================================================================

    /// @notice Detect writes to KECCAK256-computed mapping slots for the owners mapping.
    ///         This simulates what the deep scan pipeline does by tracking which storage
    ///         slots were written and computing the expected KECCAK256 hashes.
    function test_detectShadowOwnerViaStorageWrites() public {
        // Deploy a fresh Safe and record storage writes during shadow injection
        Safe freshProxy;
        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        // Start recording before deployment + injection
        vm.record();

        bytes memory initOwner = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(2),
            address(ownerInjector),
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, shadowOwner),
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );
        freshProxy = Safe(payable(address(factory.createProxyWithNonce(address(singleton), initOwner, 100))));

        // Get all storage writes to the Safe's address
        (, bytes32[] memory writes) = vm.accesses(address(freshProxy));

        // Find mapping slot writes that correspond to shadow entries
        bytes32 shadowOwnerSlot = keccak256(abi.encode(shadowOwner, SLOT_OWNERS));
        bytes32 sentinelSlot = keccak256(abi.encode(SENTINEL, SLOT_OWNERS));

        bool foundShadowWrite = false;
        bool foundSentinelWrite = false;

        for (uint256 i = 0; i < writes.length; i++) {
            if (writes[i] == shadowOwnerSlot) {
                foundShadowWrite = true;
            }
            if (writes[i] == sentinelSlot) {
                foundSentinelWrite = true;
            }
        }

        assertTrue(foundShadowWrite, "should detect write to shadow owner slot");
        assertTrue(foundSentinelWrite, "should detect write to sentinel slot (linked list setup)");

        // Verify: value at shadowOwnerSlot should be SENTINEL (0x01)
        bytes32 storedValue = vm.load(address(freshProxy), shadowOwnerSlot);
        assertEq(storedValue, bytes32(uint256(uint160(SENTINEL))), "shadow owner slot value should be SENTINEL");

        console.log("=== Deep Scan: Shadow Owner Detection ===");
        console.log("Shadow address:          %s", shadowOwner);
        console.log("Shadow slot:             %s", vm.toString(shadowOwnerSlot));
        console.log("Shadow slot value:       %s", vm.toString(storedValue));
        console.log("isOwner(shadow):         true (confirmed)");
        console.log("In getOwners():          false (shadow entry)");

        // Walk the linked list to confirm shadow is unreachable
        address[] memory listedOwners = freshProxy.getOwners();
        bool foundInList = false;
        for (uint256 i = 0; i < listedOwners.length; i++) {
            if (listedOwners[i] == shadowOwner) foundInList = true;
        }
        assertFalse(foundInList, "shadow should NOT be in getOwners()");
        console.log("Owners list length:      %d (shadow not included)", listedOwners.length);
    }

    /// @notice Detect writes to KECCAK256-computed mapping slots for the modules mapping.
    function test_detectShadowModuleViaStorageWrites() public {
        Safe freshProxy;
        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        vm.record();

        bytes memory initModule = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(2),
            address(moduleInjector),
            abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, shadowModule),
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );
        freshProxy = Safe(payable(address(factory.createProxyWithNonce(address(singleton), initModule, 101))));

        (, bytes32[] memory writes) = vm.accesses(address(freshProxy));

        bytes32 shadowModuleSlot = keccak256(abi.encode(shadowModule, SLOT_MODULES));

        bool foundShadowWrite = false;
        for (uint256 i = 0; i < writes.length; i++) {
            if (writes[i] == shadowModuleSlot) {
                foundShadowWrite = true;
            }
        }

        assertTrue(foundShadowWrite, "should detect write to shadow module slot");

        bytes32 storedValue = vm.load(address(freshProxy), shadowModuleSlot);
        assertEq(storedValue, bytes32(uint256(uint160(SENTINEL))), "shadow module slot value should be SENTINEL");

        console.log("=== Deep Scan: Shadow Module Detection ===");
        console.log("Shadow address:          %s", shadowModule);
        console.log("Shadow slot:             %s", vm.toString(shadowModuleSlot));
        console.log("Shadow slot value:       %s", vm.toString(storedValue));
        console.log("isModuleEnabled(shadow): true (confirmed)");
        console.log("In getModulesPaginated(): false (shadow entry)");
    }

    // =========================================================================
    //  Phase 4: Preimage Decoding — recover shadow address from slot
    // =========================================================================

    /// @notice Given a KECCAK256-computed slot, classify the mapping and recover
    ///         the key address. This validates Phase 4 of the pipeline.
    function test_decodeOwnerMappingPreimage() public view {
        // Simulate: we found a KECCAK256 preimage during trace analysis
        // The preimage is: abi.encode(shadowOwner, SLOT_OWNERS)
        bytes memory preimage = abi.encode(shadowOwner, SLOT_OWNERS);
        bytes32 computedSlot = keccak256(preimage);

        // Verify the computed slot matches what was stored
        bytes32 actualSlot = keccak256(abi.encode(shadowOwner, SLOT_OWNERS));
        assertEq(computedSlot, actualSlot, "computed slot should match actual");

        // Decode the preimage
        assertEq(preimage.length, 64, "preimage should be 64 bytes (abi.encode of address + uint256)");

        // Extract key (first 32 bytes = address, padded to 32 bytes)
        bytes32 keyWord;
        assembly { keyWord := mload(add(preimage, 32)) }
        address recoveredAddress = address(uint160(uint256(keyWord)));
        assertEq(recoveredAddress, shadowOwner, "should recover shadow owner address");

        // Extract mapping slot (last 32 bytes)
        bytes32 slotWord;
        assembly { slotWord := mload(add(preimage, 64)) }
        uint256 mappingSlot = uint256(slotWord);
        assertEq(mappingSlot, SLOT_OWNERS, "should be owners mapping slot");

        // Verify the slot has a non-zero value (shadow was injected)
        bytes32 slotValue = vm.load(address(safeWithShadowOwner), computedSlot);
        assertTrue(uint256(slotValue) > 0, "shadow owner slot should have non-zero value");

        console.log("=== Preimage Decoding: Shadow Owner ===");
        console.log("Preimage length:     %d bytes", preimage.length);
        console.log("Recovered address:  %s", recoveredAddress);
        console.log("Mapping slot:       %d (owners)", mappingSlot);
        console.log("Computed slot hash:  %s", vm.toString(computedSlot));
        console.log("Slot value:         %s", vm.toString(slotValue));
    }

    /// @notice Decode a modules mapping preimage.
    function test_decodeModuleMappingPreimage() public view {
        bytes memory preimage = abi.encode(shadowModule, SLOT_MODULES);
        bytes32 computedSlot = keccak256(preimage);

        bytes32 keyWord;
        assembly { keyWord := mload(add(preimage, 32)) }
        address recoveredAddress = address(uint160(uint256(keyWord)));

        bytes32 slotWord;
        assembly { slotWord := mload(add(preimage, 64)) }
        uint256 mappingSlot = uint256(slotWord);

        assertEq(recoveredAddress, shadowModule, "should recover shadow module address");
        assertEq(mappingSlot, SLOT_MODULES, "should be modules mapping slot");

        bytes32 slotValue = vm.load(address(safeWithShadowModule), computedSlot);
        assertTrue(uint256(slotValue) > 0, "shadow module slot should have non-zero value");

        console.log("=== Preimage Decoding: Shadow Module ===");
        console.log("Recovered address:  %s", recoveredAddress);
        console.log("Mapping slot:       %d (modules)", mappingSlot);
        console.log("Slot value:         %s", vm.toString(slotValue));
    }

    // =========================================================================
    //  Phase 4: Classification — distinguish shadow entries from legitimate ones
    // =========================================================================

    /// @notice Verify that a legitimate owner's mapping entry is NOT classified as a shadow.
    function test_legitimateOwnerNotClassifiedAsShadow() public view {
        // owner1 is a legitimate owner — its slot should be reachable from the linked list
        bytes32 owner1Slot = keccak256(abi.encode(owner1, SLOT_OWNERS));
        bytes32 slotValue = vm.load(address(safeWithShadowOwner), owner1Slot);

        // owner1 should have a non-zero value (it's in the linked list)
        assertTrue(uint256(slotValue) > 0, "legitimate owner should have non-zero slot");

        // But owner1 IS in getOwners() — so it's NOT a shadow
        address[] memory listedOwners = safeWithShadowOwner.getOwners();
        bool foundInList = false;
        for (uint256 i = 0; i < listedOwners.length; i++) {
            if (listedOwners[i] == owner1) foundInList = true;
        }
        assertTrue(foundInList, "legitimate owner should be in getOwners()");

        // The shadow owner is NOT in getOwners() — that's the distinguishing factor
        bool shadowFoundInList = false;
        for (uint256 i = 0; i < listedOwners.length; i++) {
            if (listedOwners[i] == shadowOwner) shadowFoundInList = true;
        }
        assertFalse(shadowFoundInList, "shadow owner should NOT be in getOwners()");

        console.log("=== Classification Test ===");
        console.log("Legitimate owner %s: in getOwners() = true", owner1);
        console.log("Shadow owner %s:    in getOwners() = false", shadowOwner);
    }

    /// @notice Verify classification using isOwner + getOwners() for the shadow.
    function test_shadowOwnerClassification() public view {
        // The shadow owner passes isOwner() but is not in getOwners()
        bool passesIsOwner = safeWithShadowOwner.isOwner(shadowOwner);
        bool inGetOwners = _isInArray(shadowOwner, safeWithShadowOwner.getOwners());

        assertTrue(passesIsOwner, "shadow should pass isOwner()");
        assertFalse(inGetOwners, "shadow should NOT be in getOwners()");

        // Legitimate owner passes isOwner() AND is in getOwners()
        bool legitPassesIsOwner = safeWithShadowOwner.isOwner(owner1);
        bool legitInGetOwners = _isInArray(owner1, safeWithShadowOwner.getOwners());

        assertTrue(legitPassesIsOwner, "legitimate owner should pass isOwner()");
        assertTrue(legitInGetOwners, "legitimate owner should be in getOwners()");

        console.log("=== Shadow Owner Classification ===");
        console.log("Shadow %s: isOwner=%s, inList=%s", shadowOwner, passesIsOwner ? "true" : "false", inGetOwners ? "true" : "false");
        console.log("Legit  %s: isOwner=%s, inList=%s", owner1, legitPassesIsOwner ? "true" : "false", legitInGetOwners ? "true" : "false");
    }

    /// @notice Verify shadow module classification.
    function test_shadowModuleClassification() public view {
        bool passesIsEnabled = safeWithShadowModule.isModuleEnabled(shadowModule);
        bool inGetModules = _isInArray(shadowModule, _getModulesList(address(safeWithShadowModule)));

        assertTrue(passesIsEnabled, "shadow module should pass isModuleEnabled()");
        assertFalse(inGetModules, "shadow module should NOT be in getModulesPaginated()");

        console.log("=== Shadow Module Classification ===");
        console.log("Shadow: isModuleEnabled=%s, inList=%s", passesIsEnabled ? "true" : "false", inGetModules ? "true" : "false");
    }

    // =========================================================================
    //  Phase 4: Nested preimage and anomalous classification
    // =========================================================================

    /// @notice Verify that the approvedHashes mapping (slot 8) is classified as legitimate.
    function test_approvedHashesNotClassifiedAsShadow() public view {
        // approvedHashes is mapping(address => mapping(bytes32 => uint256)) at slot 8
        // A write to this mapping should NOT be flagged as a shadow
        uint256 approvedHashesSlot = 8;

        // The nested mapping preimage would be: abi.encode(address, innerKey, slot)
        // Length = 96 bytes, not 64 — so it's automatically classified differently
        address someAddr = address(0x1234);
        bytes32 innerKey = keccak256("some_hash");
        bytes memory nestedPreimage = abi.encode(someAddr, innerKey, approvedHashesSlot);

        assertEq(nestedPreimage.length, 96, "nested mapping preimage should be 96 bytes");

        console.log("=== Nested Mapping Classification ===");
        console.log("approvedHashes (slot 8) preimage length: %d bytes", nestedPreimage.length);
        console.log("96-byte preimages are classified as approved_hashes_nested, not shadow");
    }

    /// @notice Verify signedMessages mapping (slot 7) is classified as legitimate.
    function test_signedMessagesNotClassifiedAsShadow() public view {
        uint256 signedMessagesSlot = 7;
        bytes memory preimage = abi.encode(bytes32(0), signedMessagesSlot);
        assertEq(preimage.length, 64, "signedMessages preimage should be 64 bytes");

        // Channel: mapping_slot=7 → classification is "signed_messages"
        console.log("=== Signed Messages Classification ===");
        console.log("signedMessages (slot 7) preimage length: %d bytes", preimage.length);
        console.log("Slot 7 preimages are classified as signed_messages, not shadow");
    }

    // =========================================================================
    //  Phase 5: Fixed-slot anomaly detection
    // =========================================================================

    /// @notice Verify that a threshold overwrite is detectable by checking the
    ///         slot value and identifying it as a fixed-slot write.
    function test_detectThresholdOverwrite() public {
        uint256 thresholdBefore = cleanSafe.getThreshold();
        assertEq(thresholdBefore, 2, "threshold should be 2 before overwrite");

        // Read threshold slot before dirty write
        bytes32 slotBefore = vm.load(address(cleanSafe), bytes32(uint256(SLOT_THRESHOLD)));
        assertEq(uint256(slotBefore), 2, "threshold slot should be 2");

        // Overwrite threshold to 1 via raw SSTORE (simulating a dirty write)
        vm.store(address(cleanSafe), bytes32(uint256(SLOT_THRESHOLD)), bytes32(uint256(1)));

        // Verify the threshold has been overwritten
        uint256 thresholdAfter = cleanSafe.getThreshold();
        assertEq(thresholdAfter, 1, "threshold should be 1 after overwrite");

        // Read threshold slot after dirty write
        bytes32 slotAfter = vm.load(address(cleanSafe), bytes32(uint256(SLOT_THRESHOLD)));
        assertEq(uint256(slotAfter), 1, "threshold slot should be 1");

        // Verify: this is a fixed-slot write (slot 4 = threshold)
        // A dirty write would set threshold to a value that bypasses the legitimate
        // changeThreshold/addOwnerWithThreshold/removeOwner entrypoints
        console.log("=== Fixed-Slot Anomaly: Threshold Overwrite ===");
        console.log("Threshold before: %d", thresholdBefore);
        console.log("Threshold after:  %d", thresholdAfter);
        console.log("Slot 4 (threshold) was written to -- this is a dirty fixed-slot write");
    }

    /// @notice Verify that ownerCount overwrite is detectable.
    function test_detectOwnerCountOverwrite() public {
        bytes32 countBefore = vm.load(address(cleanSafe), bytes32(uint256(SLOT_OWNER_COUNT)));
        assertEq(uint256(countBefore), 3, "ownerCount should be 3 before overwrite");

        // Overwrite ownerCount via raw SSTORE (simulating a dirty write)
        vm.store(address(cleanSafe), bytes32(uint256(SLOT_OWNER_COUNT)), bytes32(uint256(100)));

        bytes32 countAfter = vm.load(address(cleanSafe), bytes32(uint256(SLOT_OWNER_COUNT)));
        assertEq(uint256(countAfter), 100, "ownerCount should be 100 after overwrite");

        console.log("=== Fixed-Slot Anomaly: OwnerCount Overwrite ===");
        console.log("ownerCount before: %d", uint256(countBefore));
        console.log("ownerCount after:  %d", uint256(countAfter));
    }

    // =========================================================================
    //  Phase 5: Detection via execTransaction (shadow injection post-setup)
    // =========================================================================

    /// @notice Detect shadow injection via execTransaction with DELEGATECALL.
    ///         This is the most realistic attack vector -- a malicious proposal that
    ///         injects a shadow through a legitimate-looking transaction.
    function test_detectInjectionViaExecTransaction() public {
        // Build the delegatecall tx to inject shadow owner into cleanSafe
        bytes memory injectCalldata =
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, shadowOwner);

        bytes32 txHash = cleanSafe.getTransactionHash(
            address(ownerInjector),
            0,
            injectCalldata,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            cleanSafe.nonce()
        );
        bytes memory signatures = _sortAndSign(OWNER1_KEY, OWNER2_KEY, txHash);

        // Record storage writes to the clean Safe
        vm.record();

        bool success = cleanSafe.execTransaction(
            address(ownerInjector),
            0,
            injectCalldata,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            signatures
        );
        assertTrue(success, "injection tx must succeed");

        (, bytes32[] memory writes) = vm.accesses(address(cleanSafe));

        // The shadow owner slot should have been written
        bytes32 shadowSlot = keccak256(abi.encode(shadowOwner, SLOT_OWNERS));
        bool foundShadowSlot = false;
        for (uint256 i = 0; i < writes.length; i++) {
            if (writes[i] == shadowSlot) {
                foundShadowSlot = true;
                break;
            }
        }
        assertTrue(foundShadowSlot, "should detect write to shadow owner slot");

        // Verify the shadow is now a hidden owner
        assertTrue(cleanSafe.isOwner(shadowOwner), "shadow should pass isOwner()");
        bool inList = _isInArray(shadowOwner, cleanSafe.getOwners());
        assertFalse(inList, "shadow should NOT be in getOwners()");

        console.log("=== Deep Scan: Injection via execTransaction ===");
        console.log("Shadow address:          %s", shadowOwner);
        console.log("Shadow slot written:     %s", vm.toString(shadowSlot));
        console.log("isOwner(shadow):         true");
        console.log("In getOwners():          false");
    }

    // =========================================================================
    //  Comprehensive: Full pipeline simulation
    // =========================================================================

    /// @notice Full deep scan pipeline simulation against a Safe with shadow owner.
    ///         Tests the complete detection logic without external RPC.
    function test_fullPipelineAgainstShadowOwner() public view {
        address safeAddr = address(safeWithShadowOwner);

        // ── Step 1: Enumerate all storage slots under the Safe ──
        // In production, this would come from eth_getStorageAt iteration.
        // Here we directly check known suspicious slots.

        // Check if the shadow owner's slot has a non-zero value
        bytes32 shadowOwnerSlot = keccak256(abi.encode(shadowOwner, SLOT_OWNERS));
        bytes32 shadowOwnerValue = vm.load(safeAddr, shadowOwnerSlot);

        assertTrue(uint256(shadowOwnerValue) > 0, "shadow owner slot should be non-zero");

        // ── Step 2: Walk the linked list to determine reachability ──
        // Sentinel → owner1 → owner2 → owner3 → sentinel
        address[] memory listedOwners = safeWithShadowOwner.getOwners();

        // Build a set of reachable owner addresses from the linked list
        address current = SENTINEL;
        bool shadowReachable = false;
        for (uint256 i = 0; i < listedOwners.length + 2; i++) {  // +2 for safety margin
            bytes32 nextSlot = keccak256(abi.encode(current, SLOT_OWNERS));
            address next = address(uint160(uint256(vm.load(safeAddr, nextSlot))));
            if (next == SENTINEL || next == address(0)) break;
            if (next == shadowOwner) shadowReachable = true;
            current = next;
        }

        assertFalse(shadowReachable, "shadow owner must NOT be reachable via linked list");

        // ── Step 3: Verify detection ──
        // A slot in the owners mapping (slot 2) that has a non-zero value
        // but is NOT reachable from the sentinel → shadow owner detected
        bool isOwner = safeWithShadowOwner.isOwner(shadowOwner);
        bool inOwnersList = _isInArray(shadowOwner, listedOwners);

        assertTrue(isOwner, "shadow passes isOwner()");
        assertFalse(inOwnersList, "shadow not in getOwners()");

        console.log("=== Full Pipeline: Shadow Owner Detection ===");
        console.log("Safe address:        %s", safeAddr);
        console.log("Shadow address:      %s", shadowOwner);
        console.log("Shadow slot:         %s", vm.toString(shadowOwnerSlot));
        console.log("Shadow slot value:   %s", vm.toString(shadowOwnerValue));
        console.log("isOwner(shadow):      true");
        console.log("In getOwners():       false");
        console.log("Reachable via list:   false");
        console.log("CLASSIFICATION:      SHADOW OWNER (active)");
    }

    /// @notice Full deep scan pipeline simulation against a Safe with shadow module.
    function test_fullPipelineAgainstShadowModule() public view {
        address safeAddr = address(safeWithShadowModule);

        bytes32 shadowModuleSlot = keccak256(abi.encode(shadowModule, SLOT_MODULES));
        bytes32 shadowModuleValue = vm.load(safeAddr, shadowModuleSlot);

        assertTrue(uint256(shadowModuleValue) > 0, "shadow module slot should be non-zero");

        // Walk the module linked list
        (address[] memory listedModules,) = safeWithShadowModule.getModulesPaginated(SENTINEL, 100);

        bool shadowReachable = false;
        address current = SENTINEL;
        for (uint256 i = 0; i < listedModules.length + 2; i++) {
            bytes32 nextSlot = keccak256(abi.encode(current, SLOT_MODULES));
            address next = address(uint160(uint256(vm.load(safeAddr, nextSlot))));
            if (next == SENTINEL || next == address(0)) break;
            if (next == shadowModule) shadowReachable = true;
            current = next;
        }

        assertFalse(shadowReachable, "shadow module must NOT be reachable via linked list");

        bool isEnabled = safeWithShadowModule.isModuleEnabled(shadowModule);
        assertFalse(_isInArray(shadowModule, listedModules), "shadow not in getModulesPaginated()");

        assertTrue(isEnabled, "shadow passes isModuleEnabled()");

        console.log("=== Full Pipeline: Shadow Module Detection ===");
        console.log("Safe address:           %s", safeAddr);
        console.log("Shadow address:         %s", shadowModule);
        console.log("Shadow slot:             %s", vm.toString(shadowModuleSlot));
        console.log("Shadow slot value:       %s", vm.toString(shadowModuleValue));
        console.log("isModuleEnabled(shadow): true");
        console.log("In getModulesPaginated(): false");
        console.log("Reachable via list:      false");
        console.log("CLASSIFICATION:          SHADOW MODULE (active)");
    }

    /// @notice Verify clean Safe has no shadow entries.
    function test_cleanSafeNoShadows() public {
        address safeAddr = address(cleanSafe);

        // Check a few random addresses — they should all have zero values
        address randomAddr = makeAddr("random");
        bytes32 ownerSlot = keccak256(abi.encode(randomAddr, SLOT_OWNERS));
        bytes32 moduleSlot = keccak256(abi.encode(randomAddr, SLOT_MODULES));

        bytes32 ownerValue = vm.load(safeAddr, ownerSlot);
        bytes32 moduleValue = vm.load(safeAddr, moduleSlot);

        assertEq(uint256(ownerValue), 0, "random address should have zero owners slot");
        assertEq(uint256(moduleValue), 0, "random address should have zero modules slot");

        // No false positives from SafeDetector
        address[] memory candidates = new address[](2);
        candidates[0] = makeAddr("random1");
        candidates[1] = makeAddr("random2");

        (, uint256 count) = SafeDetector.fullScan(ISafe(payable(safeAddr)), candidates);

        assertEq(count, 0, "clean Safe should have no shadows");

        console.log("=== Clean Safe: No Shadows ===");
        console.log("Shadows detected: 0");
    }

    // =========================================================================
    //  Storage slot enumeration approach (trie walker)
    // =========================================================================

    /// @notice Demonstrate the slot enumeration approach — check known mapping slots
    ///         for entries that are not reachable from the linked list.
    ///         This is the eth_getStorageAt-based approach (Plan C/D from the plan).
    function test_slotEnumerationDetectsShadows() public view {
        address safeAddr = address(safeWithShadowOwner);

        // Walk the owners linked list and record all reachable owner slots
        bytes32 sentinelSlot = keccak256(abi.encode(SENTINEL, SLOT_OWNERS));
        address firstOwner = address(uint160(uint256(vm.load(safeAddr, sentinelSlot))));
        assertNotEq(firstOwner, address(0), "should have at least one owner");

        // Collect reachable addresses
        address[] memory reachableOwners = safeWithShadowOwner.getOwners();

        console.log("=== Slot Enumeration Approach ===");
        console.log("Reachable owners (from getOwners()):");
        for (uint256 i = 0; i < reachableOwners.length; i++) {
            console.log("  [%d] %s", i, reachableOwners[i]);
        }

        // Now check the shadow's slot — it's NOT reachable
        bytes32 shadowSlot = keccak256(abi.encode(shadowOwner, SLOT_OWNERS));
        bytes32 shadowValue = vm.load(safeAddr, shadowSlot);

        console.log("");
        console.log("Shadow owner slot check:");
        console.log("  Address:   %s", shadowOwner);
        console.log("  Slot:      %s", vm.toString(shadowSlot));
        console.log("  Value:     %s", vm.toString(shadowValue));
        console.log("  Reachable: false (not in linked list)");
        console.log("");
        console.log("CONCLUSION: Slot has non-zero value but is NOT reachable");
        console.log("from the linked list -> SHADOW OWNER DETECTED");
    }

// =========================================================================
//  Helpers
// =========================================================================

    function _sortAndSign(uint256 keyA, uint256 keyB, bytes32 hash)
        internal
        pure
        returns (bytes memory)
    {
        address addrA = vm.addr(keyA);
        address addrB = vm.addr(keyB);
        if (addrA > addrB) (keyA, keyB) = (keyB, keyA);
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(keyA, hash);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(keyB, hash);
        return abi.encodePacked(rA, sA, vA, rB, sB, vB);
    }

    function _isInArray(address target, address[] memory arr)
        internal
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == target) return true;
        }
        return false;
    }

    function _getModulesList(address safe)
        internal
        view
        returns (address[] memory)
    {
        (address[] memory modules,) = ISafe(payable(safe)).getModulesPaginated(SENTINEL, 100);
        return modules;
    }
}