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
    bytes32 public constant REFUNDABLE_TARGET_CALL_ROLE =
        keccak256("REFUNDABLE_TARGET_CALL_ROLE");
    bytes32 public constant TX_FEE_REFUND_AMOUNT_KEY =
        keccak256("TX_FEE_REFUND_AMOUNT_KEY");

    // EIP-712 type hashes

    bytes32 private constant EXECUTE_TRANSACTION_TYPEHASH =
        keccak256(
            "ExecuteTransaction(address target,bytes data,uint256 nonce)"
        );
    bytes32
        private constant EXECUTE_TRANSACTION_WITH_CUSTOM_REFUND_AMOUNT_TYPEHASH =
        keccak256(
            "ExecuteTransactionWithCustomRefundAmount(address target,bytes data,uint256 nonce,uint256 refundAmount)"
        );

    mapping(uint256 => bool) private usedNonces;
    mapping(bytes32 => uint256) public configs;

    constructor(
        address admin,
        address manager,
        uint256 _refundAmount
    ) EIP712("GasRefundFactory", "1") {
        if (admin == address(0)) revert Errors.ZeroAddress();
        if (manager == address(0)) revert Errors.ZeroAddress();

        configs[TX_FEE_REFUND_AMOUNT_KEY] = _refundAmount;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MANAGER_ROLE, admin);
        _grantRole(MANAGER_ROLE, manager);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_DID);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_RBAC);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_STORAGE);
    }

    function updateConfigs(bytes32 key, uint256 value)
        external
        onlyRole(MANAGER_ROLE)
    {
        configs[key] = value;
    }

    /**
     * @dev Transfer the contract balance to a recipient: useful in the event this contract is deprecated.
     * @param recipient The recipient address
     */
    function transferBalance(address recipient, uint256 nonce)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (Constants.FUNDING_TOKEN == address(0)) revert Errors.ZeroAddress();
        if (recipient == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        usedNonces[nonce] = true;

        uint256 contractBalance = IERC20(Constants.FUNDING_TOKEN).balanceOf(
            address(this)
        );
        IERC20(Constants.FUNDING_TOKEN).safeTransfer(
            recipient,
            contractBalance
        );

        emit Events.MachineStationBalanceTransferred(
            address(this),
            recipient,
            contractBalance,
            nonce
        );
    }

    /**
     * @dev Execute a transaction via the gas refund factory contract.
     * The target contract address that will trigger the final target call
     * @param target The target contract address where the call data will be executed
     * @param data The calldata for the transaction sent to the target contract address
     * @param signature The signature verifying the owner's tx approval.
     */
    function executeTransaction(
        address target,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        if (target == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_TRANSACTION_TYPEHASH,
                target,
                keccak256(data),
                nonce
            )
        );

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce);
        }

        _refundTxFees(msg.sender, configs[TX_FEE_REFUND_AMOUNT_KEY]);

        usedNonces[nonce] = true;
        (bool success, ) = target.call(data);

        if (!success) {
            revert Errors.TargetCallFailed(target);
        }

        emit Events.TransactionExecuted(target, data, nonce, msg.sender);
    }

    /**
     * @dev Execute a transaction via the gas refund factory contract.
     * The target contract address that will trigger the final target call
     * @param target The target contract address where the call data will be executed
     * @param data The calldata for the transaction sent to the target contract address
     * @param signature The signature verifying the owner's tx approval.
     */
    function executeTransactionWithCustomRefundAmount(
        address target,
        bytes calldata data,
        uint256 nonce,
        uint256 refundAmount,
        bytes calldata signature
    ) external {
        if (target == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_TRANSACTION_WITH_CUSTOM_REFUND_AMOUNT_TYPEHASH,
                target,
                keccak256(data),
                nonce,
                refundAmount
            )
        );

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce);
        }

        _refundTxFees(msg.sender, refundAmount);

        usedNonces[nonce] = true;
        (bool success, ) = target.call(data);

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
    function _verifySignature(
        bytes32 structHash,
        bytes memory signature,
        uint256 nonce
    ) internal view returns (bool) {
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);

        return (hasRole(DEFAULT_ADMIN_ROLE, signer) ||
            hasRole(MANAGER_ROLE, signer));
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

    function _refundTxFees(address sender, uint256 amount) private {
        // Transfer tokens with balance validation
        // This transfer is only done if fundding token is not null and refund amount is > 0
        if (Constants.FUNDING_TOKEN != address(0) && amount > 0) {
            // Fetch sender's balance
            uint256 senderBalance = IERC20(Constants.FUNDING_TOKEN).balanceOf(sender);

            // Check if the sender balance is less than tx fee amount before refund
            if (senderBalance <= amount) {
                // Refund the sender address
                IERC20(Constants.FUNDING_TOKEN).safeTransfer(sender, amount);
            }
        }
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
