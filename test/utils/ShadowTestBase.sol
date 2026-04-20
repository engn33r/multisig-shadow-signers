// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {ISafe} from "@safe/interfaces/ISafe.sol";
import {ShadowOwnerInjector} from "../../src/ShadowOwnerInjector.sol";
import {ShadowModuleInjector} from "../../src/ShadowModuleInjector.sol";

/// @title ShadowTestBase
/// @notice Shared base contract for all shadow detection tests.
///         Provides common constants, setup logic, and helper functions
///         to eliminate duplication across test files.
abstract contract ShadowTestBase is Test {
    // ── Safe storage layout constants ──
    uint256 constant SLOT_SINGLETON = 0;
    uint256 constant SLOT_MODULES = 1;
    uint256 constant SLOT_OWNERS = 2;
    uint256 constant SLOT_OWNER_COUNT = 3;
    uint256 constant SLOT_THRESHOLD = 4;
    uint256 constant SLOT_NONCE = 5;
    uint256 constant SLOT_DOMAIN_SEP = 6;
    uint256 constant SLOT_SIGNED_MSGS = 7;
    uint256 constant SLOT_APPROVED_HASHES = 8;
    address constant SENTINEL = address(0x1);

    // Safe fixed bytes32 storage slots
    bytes32 constant FALLBACK_HANDLER_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 constant MODULE_GUARD_STORAGE_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    // ── Test keys ──
    uint256 constant OWNER1_KEY = 0xA001;
    uint256 constant OWNER2_KEY = 0xA002;
    uint256 constant OWNER3_KEY = 0xA003;
    uint256 constant SHADOW_OWNER_KEY = 0xBEEF;
    uint256 constant SHADOW_MODULE_KEY = 0xBAAD;

    // ── Shared contracts (deployed in setUp) ──
    Safe public singleton;
    SafeProxyFactory public factory;
    ShadowOwnerInjector public ownerInjector;
    ShadowModuleInjector public moduleInjector;

    // ── Test addresses (set in setUp) ──
    address owner1;
    address owner2;
    address owner3;
    address shadowOwner;
    address shadowModule;

    // ── Virtual setUp hook ──
    // Tests that inherit ShadowTestBase must call _setUpBase() in their own setUp().
    function _setUpBase() internal {
        owner1 = vm.addr(OWNER1_KEY);
        owner2 = vm.addr(OWNER2_KEY);
        owner3 = vm.addr(OWNER3_KEY);
        shadowOwner = vm.addr(SHADOW_OWNER_KEY);
        shadowModule = vm.addr(SHADOW_MODULE_KEY);

        singleton = new Safe();
        factory = new SafeProxyFactory();
        ownerInjector = new ShadowOwnerInjector();
        moduleInjector = new ShadowModuleInjector();
    }

    // ── Deployment helpers ──

    function _deploySafeWithShadowOwner(address[] memory owners, uint256 threshold, address shadow)
        internal
        returns (Safe)
    {
        bytes memory init = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            threshold,
            address(ownerInjector),
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, shadow),
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );
        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), init, _nextNonce());
        return Safe(payable(address(proxy)));
    }

    function _deploySafeWithShadowModule(address[] memory owners, uint256 threshold, address shadow)
        internal
        returns (Safe)
    {
        bytes memory init = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            threshold,
            address(moduleInjector),
            abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, shadow),
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );
        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), init, _nextNonce());
        return Safe(payable(address(proxy)));
    }

    function _deployCleanSafe(address[] memory owners, uint256 threshold) internal returns (Safe) {
        bytes memory init = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            threshold,
            address(0),
            "",
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );
        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), init, _nextNonce());
        return Safe(payable(address(proxy)));
    }

    uint256 private _nonce = 0;
    function _nextNonce() internal returns (uint256) {
        return _nonce++;
    }

    // ── Default owners array (3 owners with threshold 2) ──

    function _defaultOwners() internal view returns (address[] memory) {
        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;
        return owners;
    }

    // ── Signature helpers ──

    function _sortAndSign(uint256 keyA, uint256 keyB, bytes32 hash) internal pure returns (bytes memory) {
        address addrA = vm.addr(keyA);
        address addrB = vm.addr(keyB);
        if (addrA > addrB) {
            (keyA, keyB) = (keyB, keyA);
        }
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(keyA, hash);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(keyB, hash);
        return abi.encodePacked(rA, sA, vA, rB, sB, vB);
    }

    // ── Array helpers ──

    function _isInArray(address target, address[] memory arr) internal pure returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == target) return true;
        }
        return false;
    }

    function _getModulesList(address safeAddr) internal view returns (address[] memory) {
        (address[] memory modules,) = ISafe(payable(safeAddr)).getModulesPaginated(SENTINEL, 100);
        return modules;
    }
}