// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {Enum} from "@safe/libraries/Enum.sol";
import {ISafe} from "@safe/interfaces/ISafe.sol";
import {SafeDetector} from "../src/SafeDetector.sol";
import {ShadowOwnerInjector} from "../src/ShadowOwnerInjector.sol";
import {ShadowModuleInjector} from "../src/ShadowModuleInjector.sol";

/// @title DetectShadows
/// @notice Foundry script that deploys a compromised PoC Safe on Anvil, then runs
///         the combined Plan 1+2+4 detection strategy using SafeDetector.
///
/// @dev Usage:
///   # Start Anvil in another terminal:
///   anvil
///
///   # Run the detection script:
///   forge script script/DetectShadows.s.sol --rpc-url http://localhost:8545 --broadcast -vvvv
///
///   To audit an EXISTING Safe (e.g. on a mainnet fork), set SAFE_ADDRESS env var:
///   SAFE_ADDRESS=0x... forge script script/DetectShadows.s.sol:AuditExistingSafe \
///       --rpc-url http://localhost:8545 -vvvv
contract DetectShadows is Script {
    function run() external {
        uint256 deployerKey =
            vm.envOr("PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)); // Anvil default key 0
        vm.startBroadcast(deployerKey);

        // =====================================================================
        //  PHASE 1: Deploy the compromised PoC Safe
        // =====================================================================
        console.log("========================================");
        console.log("  PHASE 1: Deploy Compromised PoC Safe");
        console.log("========================================");

        Safe singleton = new Safe();
        SafeProxyFactory factory = new SafeProxyFactory();
        ShadowOwnerInjector ownerInjector = new ShadowOwnerInjector();
        ShadowModuleInjector moduleInjector = new ShadowModuleInjector();

        // Create 3 legitimate owners + 1 shadow
        address owner1 = vm.addr(0xA001);
        address owner2 = vm.addr(0xA002);
        address owner3 = vm.addr(0xA003);
        address shadowOwner = vm.addr(0xBEEF);

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        // Deploy Safe with shadow owner injected during setup
        bytes memory initializer = abi.encodeWithSelector(
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

        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), initializer, 0);
        Safe safe = Safe(payable(address(proxy)));

        console.log("Safe deployed at:        %s", address(safe));
        console.log("Shadow owner:            %s", shadowOwner);
        console.log("Owner injector:          %s", address(ownerInjector));
        console.log("");

        vm.stopBroadcast();

        // =====================================================================
        //  PHASE 2: Run Detection (read-only, no broadcast needed)
        // =====================================================================
        _runDetection(ISafe(payable(address(safe))), address(ownerInjector), shadowOwner);
    }

    function _runDetection(ISafe safe, address setupDelegatecallTarget, address knownShadow) internal view {
        console.log("========================================");
        console.log("  PHASE 2: Detection Scan");
        console.log("========================================");

        // -----------------------------------------------------------------
        //  Plan 2: Analyze setup delegatecall
        // -----------------------------------------------------------------
        console.log("");
        console.log("--- Plan 2: Setup Delegatecall Analysis ---");
        (bool suspicious, bool isOwner, bool isModule) =
            SafeDetector.analyzeSetupDelegatecall(safe, setupDelegatecallTarget);

        console.log("Setup delegatecall target: %s", setupDelegatecallTarget);
        console.log("Is owner:    %s", isOwner ? "true" : "false");
        console.log("Is module:   %s", isModule ? "true" : "false");
        console.log("Suspicious:  %s", suspicious ? "YES - one-shot injector pattern" : "no");

        // -----------------------------------------------------------------
        //  Plan 3: Probe candidate addresses
        // -----------------------------------------------------------------
        console.log("");
        console.log("--- Plan 3: Candidate Probing ---");

        // Build candidate list from the delegatecall calldata
        bytes memory injectorCalldata =
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, knownShadow);
        (address[] memory extractedAddrs, uint256 extractedCount) =
            SafeDetector.extractAddressesFromCalldata(injectorCalldata);

        console.log("Addresses extracted from delegatecall data: %d", extractedCount);
        for (uint256 i = 0; i < extractedCount; i++) {
            console.log("  candidate[%d]: %s", i, extractedAddrs[i]);
        }

        // Probe all extracted candidates
        (SafeDetector.ShadowResult[] memory shadows, uint256 shadowCount) = SafeDetector.fullScan(safe, extractedAddrs);

        console.log("");
        console.log("--- RESULTS ---");
        if (shadowCount == 0) {
            console.log("No shadow owners or modules detected.");
        } else {
            console.log("DETECTED %d shadow(s):", shadowCount);
            for (uint256 i = 0; i < shadowCount; i++) {
                string memory kind = shadows[i].isShadowOwner ? "SHADOW OWNER" : "SHADOW MODULE";
                console.log("  [%s] %s", kind, shadows[i].candidate);
            }
        }

        // -----------------------------------------------------------------
        //  Summary
        // -----------------------------------------------------------------
        console.log("");
        console.log("========================================");
        console.log("  DETECTION SUMMARY");
        console.log("========================================");
        console.log("Listed owners:");
        address[] memory listedOwners = safe.getOwners();
        for (uint256 i = 0; i < listedOwners.length; i++) {
            console.log("  [%d] %s", i, listedOwners[i]);
        }
        console.log("Threshold: %d", safe.getThreshold());

        if (shadowCount > 0) {
            console.log("");
            console.log("WARNING: This Safe has hidden entries that pass");
            console.log("authorization checks but are invisible in the UI.");
        }
    }
}

/// @title AuditExistingSafe
/// @notice Audits an existing Safe at a known address with a list of candidate addresses.
/// @dev Usage:
///   SAFE_ADDRESS=0x... CANDIDATES=0xaaa,0xbbb,0xccc \
///     forge script script/DetectShadows.s.sol:AuditExistingSafe --rpc-url <RPC> -vvvv
///
///   If you have the setup() calldata from the proxy creation tx, pass it as SETUP_DATA
///   to automatically extract candidate addresses:
///   SAFE_ADDRESS=0x... SETUP_DATA=0x... \
///     forge script script/DetectShadows.s.sol:AuditExistingSafe --rpc-url <RPC> -vvvv
contract AuditExistingSafe is Script {
    function run() external view {
        address safeAddr = vm.envAddress("SAFE_ADDRESS");
        ISafe safe = ISafe(payable(safeAddr));

        console.log("========================================");
        console.log("  Auditing Safe: %s", safeAddr);
        console.log("========================================");

        // List current owners
        address[] memory listedOwners = safe.getOwners();
        console.log("");
        console.log("Listed owners (%d):", listedOwners.length);
        for (uint256 i = 0; i < listedOwners.length; i++) {
            console.log("  [%d] %s", i, listedOwners[i]);
        }
        console.log("Threshold: %d", safe.getThreshold());

        // Build candidate list
        address[] memory candidates = _buildCandidateList(safe);

        console.log("");
        console.log("Probing %d candidates...", candidates.length);

        // Run full scan
        (SafeDetector.ShadowResult[] memory shadows, uint256 shadowCount) = SafeDetector.fullScan(safe, candidates);

        console.log("");
        console.log("========================================");
        console.log("  RESULTS");
        console.log("========================================");

        if (shadowCount == 0) {
            console.log("No shadow owners or modules detected from candidate list.");
            console.log("NOTE: This does not guarantee the Safe is clean. Shadow");
            console.log("entries can only be detected if the candidate address is known.");
        } else {
            console.log("DETECTED %d shadow(s):", shadowCount);
            for (uint256 i = 0; i < shadowCount; i++) {
                string memory ownerTag = shadows[i].isShadowOwner ? " [SHADOW OWNER]" : "";
                string memory moduleTag = shadows[i].isShadowModule ? " [SHADOW MODULE]" : "";
                console.log("  %s%s%s", shadows[i].candidate, ownerTag, moduleTag);
            }
        }
    }

    /// @dev Build a candidate list from env vars and/or calldata extraction.
    function _buildCandidateList(ISafe safe) internal view returns (address[] memory) {
        // Try to get explicit candidates from env
        string memory candidatesStr = vm.envOr("CANDIDATES", string(""));
        bytes memory setupData = vm.envOr("SETUP_DATA", bytes(""));

        // Count how many candidates we might have
        uint256 maxCandidates = 100; // upper bound
        address[] memory tempCandidates = new address[](maxCandidates);
        uint256 count = 0;

        // If SETUP_DATA is provided, extract addresses from it
        if (setupData.length > 0) {
            console.log("Extracting candidates from SETUP_DATA (%d bytes)...", setupData.length);
            (address[] memory extracted, uint256 extractedCount) = SafeDetector.extractAddressesFromCalldata(setupData);
            for (uint256 i = 0; i < extractedCount && count < maxCandidates; i++) {
                tempCandidates[count++] = extracted[i];
            }
        }

        // If CANDIDATES env var provided, parse comma-separated addresses
        if (bytes(candidatesStr).length > 0) {
            // For simplicity, try to parse single address (comma parsing is complex in Solidity)
            // In practice, you'd pass multiple via a JSON file or repeated calls
            address candidate = vm.parseAddress(candidatesStr);
            if (candidate != address(0) && count < maxCandidates) {
                tempCandidates[count++] = candidate;
            }
        }

        // Also add listed owners as candidates (they should NOT trigger, but good baseline)
        address[] memory owners = safe.getOwners();
        for (uint256 i = 0; i < owners.length && count < maxCandidates; i++) {
            tempCandidates[count++] = owners[i];
        }

        // Trim to actual size
        address[] memory candidates = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            candidates[i] = tempCandidates[i];
        }
        return candidates;
    }
}
