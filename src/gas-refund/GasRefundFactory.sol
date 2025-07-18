// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Errors} from "../libs/Errors.sol";
import {Events} from "../libs/Events.sol";
import {Constants} from "../libs/Constants.sol";

contract GasRefundFactory is EIP712, AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // This role approves refundable transactions
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    // The target address which tx are approved to be refunded
    bytes32 public constant REFUNDABLE_TARGET_CALL_ROLE = keccak256("REFUNDABLE_TARGET_CALL_ROLE");
    bytes32 public constant TX_FEE_REFUND_AMOUNT_KEY = keccak256("TX_FEE_REFUND_AMOUNT");
    bytes32 public constant IS_REFUND_ENABLED_KEY = keccak256("IS_REFUND_ENABLED");
    bytes32 public constant CHECK_REFUND_MIN_BALANCE_KEY = keccak256("CHECK_REFUND_MIN_BALANCE");

    // EIP-712 type hashes

    bytes32 private constant EXECUTE_TRANSACTION_TYPEHASH =
        keccak256("ExecuteTransaction(address target,bytes data,uint256 nonce,uint256 refundAmount)");

    mapping(uint256 => bool) private usedNonces;
    mapping(bytes32 => uint256) public configs;

    constructor(address admin, address manager, uint256 _refundAmount) EIP712("GasRefundFactory", "1") {
        if (admin == address(0)) revert Errors.ZeroAddress();
        if (manager == address(0)) revert Errors.ZeroAddress();

        // set the refund amount per tx
        configs[TX_FEE_REFUND_AMOUNT_KEY] = _refundAmount;
        // enable refund by default. set this to 0 to disable refund
        configs[IS_REFUND_ENABLED_KEY] = 1;
        // enable refund minimum balance check by default.
        // Set this to 0 to disable balance check before applying tx fee refund
        configs[CHECK_REFUND_MIN_BALANCE_KEY] = 0;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MANAGER_ROLE, admin);
        _grantRole(MANAGER_ROLE, manager);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_DID);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_RBAC);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_STORAGE);
    }

    function updateConfigs(bytes32 key, uint256 value) external onlyRole(MANAGER_ROLE) {
        configs[key] = value;
    }

    /**
     * @dev Transfer the contract balance to a recipient: useful in the event this contract is deprecated.
     * @param recipient The recipient address
     */
    function transferBalance(address recipient, uint256 nonce) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (Constants.FUNDING_TOKEN == address(0)) revert Errors.ZeroAddress();
        if (recipient == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        usedNonces[nonce] = true;

        uint256 contractBalance = IERC20(Constants.FUNDING_TOKEN).balanceOf(address(this));
        IERC20(Constants.FUNDING_TOKEN).safeTransfer(recipient, contractBalance);

        emit Events.MachineStationBalanceTransferred(address(this), recipient, contractBalance, nonce);
    }

    /**
     * @dev Execute a transaction via the gas refund factory contract.
     * The target contract address that will trigger the final target call
     * @param target The target contract address where the call data will be executed
     * @param data The calldata for the transaction sent to the target contract address
     * @param nonce Protects against replay attack.
     * @param refundAmount Used to set custom tx refund amount
     * @param signature The signature verifying the owner's tx approval.
     */
    function executeTransaction(
        address target,
        bytes calldata data,
        uint256 nonce,
        uint256 refundAmount,
        bytes calldata signature
    ) external nonReentrant {
        if (target == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 structHash =
            keccak256(abi.encode(EXECUTE_TRANSACTION_TYPEHASH, target, keccak256(data), nonce, refundAmount));

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce);
        }

        usedNonces[nonce] = true;
        uint256 txFeeRefundAmount = refundAmount;

        // use default refund amount if custom refund amount is not supplied
        if (txFeeRefundAmount < 1) {
            txFeeRefundAmount = configs[TX_FEE_REFUND_AMOUNT_KEY];
        }
        _refundTxFees(msg.sender, txFeeRefundAmount);

        (bool success,) = target.call(data);
        if (!success) {
            revert Errors.TargetCallFailed(target, data);
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

        return (hasRole(DEFAULT_ADMIN_ROLE, signer) || hasRole(MANAGER_ROLE, signer));
    }

    function _refundTxFees(address sender, uint256 amount) private {
        //  only refund tx fees if enabled
        if (configs[IS_REFUND_ENABLED_KEY] > 0) {
            // Transfer tokens with balance validation
            // This transfer is only done if fundding token is not null and refund amount is > 0
            if (Constants.FUNDING_TOKEN != address(0) && amount > 0) {
                uint256 senderBalance;
                // check if sender has enough balance only when the feature is enabled
                if (configs[CHECK_REFUND_MIN_BALANCE_KEY] > 0) {
                    // Fetch sender's balance
                    senderBalance = IERC20(Constants.FUNDING_TOKEN).balanceOf(sender);
                }
                // Check if the sender balance is less than tx fee amount before refund
                if (senderBalance <= amount) {
                    // Refund the sender address
                    IERC20(Constants.FUNDING_TOKEN).safeTransfer(sender, amount);
                }
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
