// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {ISafe} from "@safe/interfaces/ISafe.sol";
import {SafeDetector} from "../src/SafeDetector.sol";
import {ShadowOwnerInjector} from "../src/ShadowOwnerInjector.sol";
import {ShadowModuleInjector} from "../src/ShadowModuleInjector.sol";

contract DeepScanScript is Script {
    uint256 constant SLOT_MODULES = 1;
    uint256 constant SLOT_OWNERS = 2;
    uint256 constant SLOT_OWNER_COUNT = 3;
    uint256 constant SLOT_THRESHOLD = 4;
    address constant SENTINEL = address(0x1);

    function run() external {
        uint256 deployerKey =
            vm.envOr("PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));

        vm.startBroadcast(deployerKey);

        console.log("============================================================");
        console.log("  DEEP SCAN: Full 6-Phase Dirty Storage Detection Pipeline");
        console.log("============================================================");
        console.log("");

        Safe singleton = new Safe();
        SafeProxyFactory factory = new SafeProxyFactory();
        ShadowOwnerInjector ownerInjector = new ShadowOwnerInjector();
        ShadowModuleInjector moduleInjector = new ShadowModuleInjector();

        address owner1 = vm.addr(0xA001);
        address owner2 = vm.addr(0xA002);
        address owner3 = vm.addr(0xA003);
        address shadowOwner = vm.addr(0xDEAD);
        address shadowModule = vm.addr(0xBAAD);

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        console.log("--- PHASE 1: Transaction Recording ---");
        console.log("");

        Safe safeWithShadowOwner = _deployShadowOwnerSafe(singleton, factory, ownerInjector, owners, shadowOwner);
        vm.deal(address(safeWithShadowOwner), 1 ether);

        vm.record();
        Safe safeWithShadowModule = _deployShadowModuleSafe(singleton, factory, moduleInjector, owners, shadowModule);
        (, bytes32[] memory moduleWrites) = vm.accesses(address(safeWithShadowModule));
        vm.deal(address(safeWithShadowModule), 1 ether);

        vm.stopBroadcast();

        Safe cleanSafe = _deployCleanSafe(singleton, factory, owners);
        vm.deal(address(cleanSafe), 1 ether);

        console.log("Safe with shadow owner:   %s", address(safeWithShadowOwner));
        console.log("Shadow owner:             %s", shadowOwner);
        console.log("isOwner(shadow):          %s", safeWithShadowOwner.isOwner(shadowOwner) ? "true" : "false");
        console.log("");

        console.log("--- PHASE 3: Storage Write Analysis ---");
        console.log("");

        bytes32 ownerSlot = keccak256(abi.encode(shadowOwner, SLOT_OWNERS));
        bytes32 moduleSlot = keccak256(abi.encode(shadowModule, SLOT_MODULES));
        bytes32 ownerVal = vm.load(address(safeWithShadowOwner), ownerSlot);
        bytes32 moduleVal = vm.load(address(safeWithShadowModule), moduleSlot);

        console.log("Shadow owner slot:  %s", vm.toString(ownerSlot));
        console.log("Shadow owner value: %s", vm.toString(ownerVal));
        console.log("Shadow module slot: %s", vm.toString(moduleSlot));
        console.log("Shadow module value:%s", vm.toString(moduleVal));

        bool found = false;
        for (uint256 i = 0; i < moduleWrites.length; i++) {
            if (moduleWrites[i] == moduleSlot) found = true;
        }
        console.log("Module slot in writes: %s", found ? "YES" : "NO");
        console.log("");

        console.log("--- PHASE 4: Classification ---");
        console.log("");
        _classify(address(safeWithShadowOwner), shadowOwner);
        _classify(address(safeWithShadowModule), shadowModule);
        _classify(address(cleanSafe), shadowOwner);

        console.log("");
        console.log("--- PHASE 5: Fixed-Slot Anomaly Detection ---");
        console.log("");
        _checkFixedSlots(address(safeWithShadowOwner));
        _checkFixedSlots(address(safeWithShadowModule));
        _checkFixedSlots(address(cleanSafe));

        console.log("");
        console.log("--- PHASE 6: Report ---");
        console.log("");

        bool isO = safeWithShadowOwner.isOwner(shadowOwner);
        bool inO = _isInArray(shadowOwner, safeWithShadowOwner.getOwners());
        if (isO && !inO) {
            console.log("!! SHADOW OWNER DETECTED: %s", shadowOwner);
        }
        bool isM = safeWithShadowModule.isModuleEnabled(shadowModule);
        (address[] memory mods,) = safeWithShadowModule.getModulesPaginated(SENTINEL, 100);
        bool inM = _isInArray(shadowModule, mods);
        if (isM && !inM) {
            console.log("!! SHADOW MODULE DETECTED: %s", shadowModule);
        }
        bytes32 oc = vm.load(address(safeWithShadowOwner), bytes32(uint256(SLOT_OWNER_COUNT)));
        console.log("ownerCount: %d, listed: %d", uint256(oc), safeWithShadowOwner.getOwners().length);
    }

    function _deployShadowOwnerSafe(Safe s, SafeProxyFactory f, ShadowOwnerInjector inj, address[] memory o, address sh) internal returns (Safe) {
        bytes memory init = abi.encodeWithSelector(
            Safe.setup.selector, o, uint256(2), address(inj),
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, sh),
            address(0), address(0), uint256(0), payable(address(0))
        );
        return Safe(payable(address(f.createProxyWithNonce(address(s), init, 0))));
    }

    function _deployShadowModuleSafe(Safe s, SafeProxyFactory f, ShadowModuleInjector inj, address[] memory o, address sh) internal returns (Safe) {
        bytes memory init = abi.encodeWithSelector(
            Safe.setup.selector, o, uint256(2), address(inj),
            abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, sh),
            address(0), address(0), uint256(0), payable(address(0))
        );
        return Safe(payable(address(f.createProxyWithNonce(address(s), init, 1))));
    }

    function _deployCleanSafe(Safe s, SafeProxyFactory f, address[] memory o) internal returns (Safe) {
        bytes memory init = abi.encodeWithSelector(
            Safe.setup.selector, o, uint256(2), address(0), "",
            address(0), address(0), uint256(0), payable(address(0))
        );
        return Safe(payable(address(f.createProxyWithNonce(address(s), init, 2))));
    }

    function _classify(address safeAddr, address suspect) internal view {
        ISafe safe = ISafe(payable(safeAddr));
        bool isO = safe.isOwner(suspect);
        bool inO = _isInArray(suspect, safe.getOwners());
        bool isM = safe.isModuleEnabled(suspect);
        (address[] memory mods,) = safe.getModulesPaginated(SENTINEL, 100);
        bool inM = _isInArray(suspect, mods);

        console.log("  %s: isOwner=%s inOwnersList=%s", suspect, isO ? "T" : "F", inO ? "T" : "F");
        console.log("  %s: isModule=%s inModulesList=%s", suspect, isM ? "T" : "F", inM ? "T" : "F");

        if (isO && !inO) console.log("    -> SHADOW OWNER");
        if (isM && !inM) console.log("    -> SHADOW MODULE");
    }

    function _checkFixedSlots(address safeAddr) internal view {
        ISafe safe = ISafe(payable(safeAddr));
        bytes32 oc = vm.load(safeAddr, bytes32(uint256(SLOT_OWNER_COUNT)));
        bytes32 th = vm.load(safeAddr, bytes32(uint256(SLOT_THRESHOLD)));
        console.log("  ownerCount=%d (listed=%d) threshold=%d", uint256(oc), safe.getOwners().length, uint256(th));
    }

    function _isInArray(address t, address[] memory a) internal pure returns (bool) {
        for (uint256 i = 0; i < a.length; i++) { if (a[i] == t) return true; }
        return false;
    }
}

contract DeepScanAudit is Script {
    uint256 constant SLOT_OWNERS = 2;
    uint256 constant SLOT_OWNER_COUNT = 3;
    address constant SENTINEL = address(0x1);

    function run() external view {
        address safeAddr = vm.envAddress("SAFE_ADDRESS");
        ISafe safe = ISafe(payable(safeAddr));

        console.log("============================================================");
        console.log("  DEEP SCAN AUDIT: Safe %s", safeAddr);
        console.log("============================================================");

        address[] memory owners = safe.getOwners();
        (address[] memory modules,) = safe.getModulesPaginated(SENTINEL, 100);

        console.log("Owners (%d):", owners.length);
        for (uint256 i = 0; i < owners.length; i++) {
            console.log("  [%d] %s", i, owners[i]);
        }
        console.log("Threshold: %d", safe.getThreshold());

        // Build and probe candidates
        address[] memory candidates = _buildCandidates(safe, owners, modules);
        (SafeDetector.ShadowResult[] memory shadows, uint256 sc) = SafeDetector.fullScan(safe, candidates);

        if (sc > 0) {
            console.log("!! %d SHADOW(s) DETECTED:", sc);
            for (uint256 i = 0; i < sc; i++) {
                if (shadows[i].isShadowOwner) console.log("  SHADOW OWNER: %s", shadows[i].candidate);
                if (shadows[i].isShadowModule) console.log("  SHADOW MODULE: %s", shadows[i].candidate);
            }
        } else {
            console.log("No shadows detected from candidate probing.");
        }

        // Fixed-slot checks
        bytes32 oc = vm.load(safeAddr, bytes32(uint256(SLOT_OWNER_COUNT)));
        if (uint256(oc) != owners.length) {
            console.log("!! ANOMALY: ownerCount=%d != listed=%d", uint256(oc), owners.length);
        }

        // Linked-list walk
        console.log("Owners linked-list walk:");
        address current = SENTINEL;
        for (uint256 i = 0; i < 50; i++) {
            bytes32 slot = keccak256(abi.encode(current, SLOT_OWNERS));
            current = address(uint160(uint256(vm.load(safeAddr, slot))));
            if (current == SENTINEL || current == address(0)) break;
            console.log("  [%d] %s", i, current);
        }
    }

    function _buildCandidates(ISafe safe, address[] memory owners, address[] memory modules) internal view returns (address[] memory) {
        bytes memory setupData = vm.envOr("SETUP_DATA", bytes(""));
        uint256 count = 0;
        uint256 maxC = 100;
        address[] memory temp = new address[](maxC);

        for (uint256 i = 0; i < owners.length && count < maxC; i++) temp[count++] = owners[i];
        for (uint256 i = 0; i < modules.length && count < maxC; i++) temp[count++] = modules[i];

        if (setupData.length > 0) {
            (address[] memory ext, uint256 ec) = SafeDetector.extractAddressesFromCalldata(setupData);
            for (uint256 i = 0; i < ec && count < maxC; i++) temp[count++] = ext[i];
        }

        address[] memory candidates = new address[](count);
        for (uint256 i = 0; i < count; i++) candidates[i] = temp[i];
        return candidates;
    }
}