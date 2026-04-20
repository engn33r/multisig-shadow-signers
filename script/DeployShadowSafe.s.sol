// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {ISafe} from "@safe/interfaces/ISafe.sol";
import {ShadowOwnerInjector} from "../src/ShadowOwnerInjector.sol";
import {ShadowModuleInjector} from "../src/ShadowModuleInjector.sol";
import {ShadowBothInjector} from "../src/ShadowBothInjector.sol";

/// @title DeployShadowSafe
/// @notice Deploys a Safe multisig with a shadow owner and/or shadow module injected during setup().
///         Works against a local anvil fork and against real chains (Base, mainnet, etc.).
///
/// @dev Quick usage:
///   # Local anvil fork of mainnet:
///   anvil --fork-url $MAINNET_RPC
///   forge script script/DeployShadowSafe.s.sol --rpc-url http://localhost:8545 --broadcast -vvvv
///
///   # Deploy to Base:
///   PRIVATE_KEY=0x... \
///     forge script script/DeployShadowSafe.s.sol \
///     --rpc-url $BASE_RPC --broadcast --verify -vvvv
///
/// @dev Env vars (all optional unless noted):
///   PRIVATE_KEY       Deployer key. Defaults to anvil key 0.
///   SHADOW_MODE       "owner" | "module" | "both" | "none". Default: "both".
///   SHADOW_OWNER      Address to inject as a hidden owner. Default: vm.addr(0xBEEF).
///   SHADOW_MODULE     Address to inject as a hidden module. Default: vm.addr(0xBAAD).
///   THRESHOLD         Signature threshold. Default: 2.
///   OWNER_1..OWNER_N  Explicit owner addresses. If unset, derives 3 owners from keys 0xA001..0xA003.
///   SAFE_SINGLETON    Reuse an existing Safe singleton (skips deploy).
///   SAFE_FACTORY      Reuse an existing SafeProxyFactory (skips deploy).
///   OWNER_INJECTOR    Reuse an existing ShadowOwnerInjector (skips deploy).
///   MODULE_INJECTOR   Reuse an existing ShadowModuleInjector (skips deploy).
///   BOTH_INJECTOR     Reuse an existing ShadowBothInjector (skips deploy).
///   SALT_NONCE        Proxy deployment salt nonce. Default: block.timestamp.
contract DeployShadowSafe is Script {
    enum Mode {
        None,
        Owner,
        Module,
        Both
    }

    struct DeployConfig {
        address[] owners;
        uint256 threshold;
        address shadowOwner;
        address shadowModule;
        Mode mode;
        uint256 saltNonce;
    }

    struct Infra {
        Safe singleton;
        SafeProxyFactory factory;
        ShadowOwnerInjector ownerInjector;
        ShadowModuleInjector moduleInjector;
        ShadowBothInjector bothInjector;
    }

    function run() external {
        uint256 deployerKey =
            vm.envOr("PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
        address deployer = vm.addr(deployerKey);

        console.log("=== DeployShadowSafe ===");
        console.log("Chain id:  %d", block.chainid);
        console.log("Deployer:  %s", deployer);
        console.log("Balance:   %d wei", deployer.balance);
        console.log("");

        DeployConfig memory cfg = _loadConfig();
        _logConfig(cfg);

        vm.startBroadcast(deployerKey);
        Infra memory infra = _resolveInfra(cfg.mode);
        Safe safe = _deploySafe(infra, cfg);
        vm.stopBroadcast();

        _logResult(infra, safe, cfg);
    }

    // ─────────────────────────────────────────────────────────────
    // Config loading
    // ─────────────────────────────────────────────────────────────

    function _loadConfig() internal view returns (DeployConfig memory cfg) {
        cfg.mode = _parseMode(vm.envOr("SHADOW_MODE", string("both")));
        cfg.threshold = vm.envOr("THRESHOLD", uint256(2));
        cfg.saltNonce = vm.envOr("SALT_NONCE", block.timestamp);
        cfg.shadowOwner = vm.envOr("SHADOW_OWNER", vm.addr(0xBEEF));
        cfg.shadowModule = vm.envOr("SHADOW_MODULE", vm.addr(0xBAAD));
        cfg.owners = _loadOwners();

        require(cfg.owners.length > 0, "No owners configured");
        require(cfg.threshold > 0 && cfg.threshold <= cfg.owners.length, "Bad threshold");
    }

    function _loadOwners() internal view returns (address[] memory) {
        // Count explicit OWNER_i env vars (1-indexed).
        uint256 n;
        for (uint256 i = 1; i <= 32; i++) {
            address a = vm.envOr(string.concat("OWNER_", vm.toString(i)), address(0));
            if (a == address(0)) break;
            n++;
        }

        if (n == 0) {
            // Default: 3 deterministic test owners.
            address[] memory o = new address[](3);
            o[0] = vm.addr(0xA001);
            o[1] = vm.addr(0xA002);
            o[2] = vm.addr(0xA003);
            return o;
        }

        address[] memory owners = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            owners[i] = vm.envAddress(string.concat("OWNER_", vm.toString(i + 1)));
        }
        return owners;
    }

    function _parseMode(string memory s) internal pure returns (Mode) {
        bytes32 h = keccak256(bytes(s));
        if (h == keccak256("owner")) return Mode.Owner;
        if (h == keccak256("module")) return Mode.Module;
        if (h == keccak256("both")) return Mode.Both;
        if (h == keccak256("none")) return Mode.None;
        revert("SHADOW_MODE must be owner|module|both|none");
    }

    // ─────────────────────────────────────────────────────────────
    // Infrastructure (singleton / factory / injectors)
    // ─────────────────────────────────────────────────────────────

    function _resolveInfra(Mode mode) internal returns (Infra memory infra) {
        address existingSingleton = vm.envOr("SAFE_SINGLETON", address(0));
        address existingFactory = vm.envOr("SAFE_FACTORY", address(0));
        address existingOwnerInjector = vm.envOr("OWNER_INJECTOR", address(0));
        address existingModuleInjector = vm.envOr("MODULE_INJECTOR", address(0));
        address existingBothInjector = vm.envOr("BOTH_INJECTOR", address(0));

        infra.singleton = existingSingleton == address(0) ? new Safe() : Safe(payable(existingSingleton));
        infra.factory = existingFactory == address(0) ? new SafeProxyFactory() : SafeProxyFactory(existingFactory);

        if (mode == Mode.Owner) {
            infra.ownerInjector = existingOwnerInjector == address(0)
                ? new ShadowOwnerInjector()
                : ShadowOwnerInjector(existingOwnerInjector);
        } else if (mode == Mode.Module) {
            infra.moduleInjector = existingModuleInjector == address(0)
                ? new ShadowModuleInjector()
                : ShadowModuleInjector(existingModuleInjector);
        } else if (mode == Mode.Both) {
            infra.bothInjector = existingBothInjector == address(0)
                ? new ShadowBothInjector()
                : ShadowBothInjector(existingBothInjector);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Safe deployment
    // ─────────────────────────────────────────────────────────────

    function _deploySafe(Infra memory infra, DeployConfig memory cfg) internal returns (Safe) {
        (address to, bytes memory data) = _injectionTarget(infra, cfg);

        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            cfg.owners,
            cfg.threshold,
            to,
            data,
            address(0), // fallbackHandler
            address(0), // paymentToken
            uint256(0), // payment
            payable(address(0)) // paymentReceiver
        );

        SafeProxy proxy = infra.factory.createProxyWithNonce(address(infra.singleton), initializer, cfg.saltNonce);
        return Safe(payable(address(proxy)));
    }

    /// @dev Build the (to, data) pair passed to Safe.setup() for delegatecall.
    ///      For Mode.Both we use ShadowBothInjector, which writes both the shadow
    ///      owner and the shadow module in a single delegatecall.
    function _injectionTarget(Infra memory infra, DeployConfig memory cfg)
        internal
        pure
        returns (address to, bytes memory data)
    {
        if (cfg.mode == Mode.None) {
            return (address(0), "");
        }
        if (cfg.mode == Mode.Owner) {
            return (
                address(infra.ownerInjector),
                abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, cfg.shadowOwner)
            );
        }
        if (cfg.mode == Mode.Module) {
            return (
                address(infra.moduleInjector),
                abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, cfg.shadowModule)
            );
        }
        // Mode.Both
        return (
            address(infra.bothInjector),
            abi.encodeWithSelector(ShadowBothInjector.injectBoth.selector, cfg.shadowOwner, cfg.shadowModule)
        );
    }

    // ─────────────────────────────────────────────────────────────
    // Logging
    // ─────────────────────────────────────────────────────────────

    function _logConfig(DeployConfig memory cfg) internal pure {
        console.log("Mode:       %s", _modeName(cfg.mode));
        console.log("Threshold:  %d", cfg.threshold);
        console.log("Salt nonce: %d", cfg.saltNonce);
        console.log("Owners (%d):", cfg.owners.length);
        for (uint256 i = 0; i < cfg.owners.length; i++) {
            console.log("  [%d] %s", i, cfg.owners[i]);
        }
        if (cfg.mode == Mode.Owner || cfg.mode == Mode.Both) {
            console.log("Shadow owner:  %s", cfg.shadowOwner);
        }
        if (cfg.mode == Mode.Module || cfg.mode == Mode.Both) {
            console.log("Shadow module: %s", cfg.shadowModule);
        }
        console.log("");
    }

    function _logResult(Infra memory infra, Safe safe, DeployConfig memory cfg) internal view {
        console.log("");
        console.log("=== Deployed ===");
        console.log("Safe:            %s", address(safe));
        console.log("Singleton:       %s", address(infra.singleton));
        console.log("ProxyFactory:    %s", address(infra.factory));
        if (address(infra.ownerInjector) != address(0)) {
            console.log("OwnerInjector:   %s", address(infra.ownerInjector));
        }
        if (address(infra.moduleInjector) != address(0)) {
            console.log("ModuleInjector:  %s", address(infra.moduleInjector));
        }
        if (address(infra.bothInjector) != address(0)) {
            console.log("BothInjector:    %s", address(infra.bothInjector));
        }

        console.log("");
        console.log("=== Post-deploy verification ===");
        address[] memory listed = ISafe(payable(address(safe))).getOwners();
        console.log("Listed owners (%d):", listed.length);
        for (uint256 i = 0; i < listed.length; i++) {
            console.log("  [%d] %s", i, listed[i]);
        }
        console.log("Threshold: %d", ISafe(payable(address(safe))).getThreshold());

        if (cfg.mode == Mode.Owner || cfg.mode == Mode.Both) {
            bool hidden = ISafe(payable(address(safe))).isOwner(cfg.shadowOwner);
            console.log("isOwner(shadowOwner):       %s", hidden ? "true (HIDDEN)" : "false");
        }
        if (cfg.mode == Mode.Module || cfg.mode == Mode.Both) {
            bool hidden = ISafe(payable(address(safe))).isModuleEnabled(cfg.shadowModule);
            console.log("isModuleEnabled(shadowMod): %s", hidden ? "true (HIDDEN)" : "false");
        }
    }

    function _modeName(Mode m) internal pure returns (string memory) {
        if (m == Mode.Owner) return "owner";
        if (m == Mode.Module) return "module";
        if (m == Mode.Both) return "both";
        return "none";
    }
}
