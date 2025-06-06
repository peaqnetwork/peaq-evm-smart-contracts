// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Errors} from "../libs/Errors.sol";
import {Events} from "../libs/Events.sol";
import {Constants} from "../libs/Constants.sol";

contract GasRefundFactory is EIP712, AccessControl {
    using SafeERC20 for IERC20;

    // This role approves refundable transactions
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    // The target address which tx are approved to be refunded
    bytes32 public constant REFUNDABLE_TARGET_CALL_ROLE = keccak256("REFUNDABLE_TARGET_CALL_ROLE");

    // EIP-712 type hashes

    bytes32 private constant TRANSFER_BALANCE_TYPEHASH =
        keccak256("TransferBalance(address recipient,uint256 nonce)");

    bytes32 private constant EXECUTE_TRANSACTION_TYPEHASH =
        keccak256("ExecuteTransaction(address target,bytes data,uint256 nonce)");

    mapping(uint256 => bool) private usedNonces;

    constructor(address admin, address manager) EIP712("GasRefundFactory", "1") {
        if (admin == address(0)) revert Errors.ZeroAddress();
        if (manager == address(0)) revert Errors.ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MANAGER_ROLE, manager);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_DID);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_RBAC);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_STORAGE);
    }

    /**
     * @dev Transfer the contract balance to a recipient: useful in the event this contract is deprecated.
     * @param recipient The recipient address
     * @param signature The signature verifying the contract manager tx approval.
     */
    function transferBalance(address recipient, uint256 nonce, bytes calldata signature)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (Constants.FUNDING_TOKEN == address(0)) revert Errors.ZeroAddress();
        if (recipient == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 structHash = keccak256(abi.encode(TRANSFER_BALANCE_TYPEHASH, recipient, nonce));

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce);
        }
        usedNonces[nonce] = true;

        uint256 contractBalance = IERC20(Constants.FUNDING_TOKEN).balanceOf(address(this));
        IERC20(Constants.FUNDING_TOKEN).safeTransfer(recipient, contractBalance);

        emit Events.MachineStationBalanceTransferred(
            address(this), recipient, contractBalance, nonce
        );
    }

    /**
     * @dev Execute a transaction via the gas refund factory contract.
     * The target contract address that will trigger the final target call
     * @param target The target contract address where the call data will be executed
     * @param data The calldata for the transaction sent to the target contract address
     * @param signature The signature verifying the owner's tx approval.
     */
    function executeTransaction(address target, bytes calldata data, uint256 nonce, bytes calldata signature)
        external
    {
        if (target == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 structHash = keccak256(abi.encode(EXECUTE_TRANSACTION_TYPEHASH, target, keccak256(data), nonce));

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce);
        }

        usedNonces[nonce] = true;
        (bool success,) = target.call(data);

        if (!success) {
            revert Errors.TargetCallFailed(target);
        }

        emit Events.TransactionExecuted(target, data, nonce, msg.sender);
    }

    function getDomainSeparator() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev Verify the owner signature.
     * @param structHash The hash of the signed message.
     * @param signature The signature to verify.
     * @param nonce Protects against replay attack.
     */
    function _verifySignature(bytes32 structHash, bytes memory signature, uint256 nonce) internal view returns (bool) {
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);

        return hasRole(DEFAULT_ADMIN_ROLE, signer);
    }

    /**
     * @dev Hash the bytes[] data
     * @param data The calldata to hash
     */
    function _hashData(bytes[] calldata data) private pure returns (bytes32) {
        bytes32[] memory encoded = new bytes32[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            encoded[i] = keccak256(data[i]);
        }
        return keccak256(abi.encodePacked(encoded));
    }

    

    // Note: "Unable to determine contract standard" error is throw during native token transfer
    // to the contract address when using metamask (other wallet provider not tested though)
    // receive() and fallback() is added to adhere to contract standard
    // A receive function to accept native tokens
    receive() external payable {
        emit Events.OnReceivedCall();
    }

    // A fallback function to handle other unexpected calls
    fallback() external payable {
        emit Events.OnFailbackCall();
    }
}
