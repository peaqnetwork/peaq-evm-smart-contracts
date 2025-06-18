// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {MachineSmartAccount} from "./MachineSmartAccount.sol";
import {Errors} from "../libs/Errors.sol";
import {Events} from "../libs/Events.sol";
import {Constants} from "../libs/Constants.sol";

contract MachineStationFactory is EIP712, AccessControl {
    using SafeERC20 for IERC20;

    bytes32 public constant STATION_MANAGER_ROLE = keccak256("STATION_MANAGER_ROLE");
    bytes32 public constant REQUIRED_STORAGE_DEPOSIT_FEE_ROLE = keccak256("REQUIRED_STORAGE_DEPOSIT_FEE_ROLE");
    // The target address which tx are approved to be refunded
    bytes32 public constant REFUNDABLE_TARGET_CALL_ROLE =
        keccak256("REFUNDABLE_TARGET_CALL_ROLE");
    bytes32 public constant TX_FEE_REFUND_AMOUNT_KEY =
        keccak256("TX_FEE_REFUND_AMOUNT");
    bytes32 public constant IS_REFUND_ENABLED_KEY =
        keccak256("IS_REFUND_ENABLED");

    // EIP-712 type hashes
    bytes32 private constant DEPLOY_MACHINE_TYPEHASH =
        keccak256("DeployMachineSmartAccount(address machineOwner,uint256 nonce)");

    bytes32 private constant TRANSFER_BALANCE_TYPEHASH =
        keccak256("TransferMachineStationBalance(address newMachineStationAddress,uint256 nonce)");

    bytes32 private constant EXECUTE_TRANSACTION_TYPEHASH =
        keccak256("ExecuteTransaction(address target,bytes data,uint256 nonce)");

    bytes32 private constant EXECUTE_MACHINE_TRANSACTION_TYPEHASH =
        keccak256("ExecuteMachineTransaction(address machineAddress,address target,bytes data,uint256 nonce)");

    bytes32 private constant EXECUTE_MACHINE_BATCH_TRANSACTIONS_TYPEHASH = keccak256(
        "ExecuteMachineBatchTransactions(address[] machineAddresses,address[] targets,bytes[] data,uint256 nonce,uint256[] machineNonces)"
    );

    bytes32 private constant EXECUTE_MACHINE_TRANSFER_TYPEHASH =
        keccak256("ExecuteMachineTransferBalance(address machineAddress,address recipientAddress,uint256 nonce)");

    mapping(uint256 => bool) private usedNonces;
    mapping(bytes32 => uint256) public configs;

    constructor(address admin, address stationManager, uint256 _txRefundAmount) EIP712("MachineStationFactory", "1") {
        if (admin == address(0)) revert Errors.ZeroAddress();
        if (stationManager == address(0)) revert Errors.ZeroAddress();

        // set the refund amount per tx
        configs[TX_FEE_REFUND_AMOUNT_KEY] = _txRefundAmount;
        // enable refund by default. set this to 0 to disable refund
        configs[IS_REFUND_ENABLED_KEY] = 1;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(STATION_MANAGER_ROLE, admin);
        _grantRole(STATION_MANAGER_ROLE, stationManager);
        _grantRole(REQUIRED_STORAGE_DEPOSIT_FEE_ROLE, Constants.PEAQ_DID);
        _grantRole(REQUIRED_STORAGE_DEPOSIT_FEE_ROLE, Constants.PEAQ_RBAC);
        _grantRole(REQUIRED_STORAGE_DEPOSIT_FEE_ROLE, Constants.PEAQ_STORAGE);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_DID);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_RBAC);
        _grantRole(REFUNDABLE_TARGET_CALL_ROLE, Constants.PEAQ_STORAGE);
    }

    function updateConfigs(bytes32 key, uint256 value)
        external
        onlyRole(STATION_MANAGER_ROLE)
    {
        configs[key] = value;
    }

    /**
     * @dev Deploy a new Machine Smart account contract via the machine station factory contract.
     * @param machineOwner The user (machine owner) on whose behalf the transaction is executed.
     * @param signature The signature verifying the owner's tx approval.
     */
    function deployMachineSmartAccount(address machineOwner, uint256 nonce, bytes calldata signature)
        external
        onlyRole(STATION_MANAGER_ROLE)
        returns (address)
    {
        if (machineOwner == address(0)) revert Errors.ZeroAddress();

        bytes32 structHash = keccak256(abi.encode(DEPLOY_MACHINE_TYPEHASH, machineOwner, nonce));

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce);
        }

        usedNonces[nonce] = true;

        // Deploy a new instance of MachineSmartAccount
        MachineSmartAccount newMachineSmartAccount = new MachineSmartAccount(machineOwner, address(this));

        // fund the machine owner with the first tx fee needed to trigger the first tx
        _refundTxFees(machineOwner, configs[TX_FEE_REFUND_AMOUNT_KEY]);
        
        emit Events.MachineSmartAccountDeployed(address(newMachineSmartAccount));
        return address(newMachineSmartAccount);
    }

    /**
     * @dev Transfer machine station balance to a new machine station in the event this machine station is deprecated.
     * @param newMachineStationAddress The new machine station address that will replace this current machine station
     * @param signature The signature verifying the owner's tx approval.
     */
    function transferMachineStationBalance(address newMachineStationAddress, uint256 nonce, bytes calldata signature)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (Constants.FUNDING_TOKEN == address(0)) revert Errors.ZeroAddress();
        if (newMachineStationAddress == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 structHash = keccak256(abi.encode(TRANSFER_BALANCE_TYPEHASH, newMachineStationAddress, nonce));

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce);
        }
        usedNonces[nonce] = true;

        uint256 machineStationBalance = IERC20(Constants.FUNDING_TOKEN).balanceOf(address(this));
        IERC20(Constants.FUNDING_TOKEN).safeTransfer(newMachineStationAddress, machineStationBalance);

        emit Events.MachineStationBalanceTransferred(
            address(this), newMachineStationAddress, machineStationBalance, nonce
        );
    }

    /**
     * @dev Execute a transaction via the machine station factory contract.
     * The Machine Station contract will trigger the final target call
     * @param target The target contract address where the call data will be executed
     * @param data The calldata for the transaction sent to the target contract address
     * @param signature The signature verifying the owner's tx approval.
     */
    function executeTransaction(address target, bytes calldata data, uint256 nonce, uint256 refundAmount, bytes calldata signature)
        external
    {
        if (target == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 structHash = keccak256(abi.encode(EXECUTE_TRANSACTION_TYPEHASH, target, keccak256(data), nonce));

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
            revert Errors.TargetCallFailed(target);
        }

        emit Events.TransactionExecuted(target, data, nonce, msg.sender);
    }

    /**
     * @dev Execute a machine transaction via the machine station factory contract.
     * @param machineAddress The Machine Smart Account will trigger the final target call
     * @param target The target contract address where the call data will be executed
     * @param data The calldata for the transaction sent to the target contract address
     * @param signature The signature verifying the owner's tx approval.
     * @param machineOwnerSignature The signature verifying the machineOwner (machine owner) tx approval.
     */
    function executeMachineTransaction(
        address machineAddress,
        address target,
        bytes calldata data,
        uint256 nonce,
        uint256 refundAmount,
        bytes calldata signature,
        bytes calldata machineOwnerSignature
    ) external {
        if (machineAddress == address(0)) revert Errors.ZeroAddress(); // Machine address cannot be zero
        if (target == address(0)) revert Errors.ZeroAddress(); // Target address cannot be zero
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce); // Nonce already used

        // Verify the owner's signature
        bytes32 structHash =
            keccak256(abi.encode(EXECUTE_MACHINE_TRANSACTION_TYPEHASH, machineAddress, target, keccak256(data), nonce));

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce); // Invalid Machine Station Owner signature
        }

        usedNonces[nonce] = true;
        uint256 txFeeRefundAmount = refundAmount;

        // use default refund amount if custom refund amount is not supplied
        if (txFeeRefundAmount < 1) {
            txFeeRefundAmount = configs[TX_FEE_REFUND_AMOUNT_KEY];
        }
        _refundTxFees(msg.sender, txFeeRefundAmount);

        _fundStorageDepositFees(machineAddress, target);

        // Forward the call to the machine account to execute the target tx
        MachineSmartAccount(machineAddress).execute(target, data, nonce, machineOwnerSignature);
    }

    /**
     * @dev Execute machine batch transactions via the machine station factory contract.
     * @param machineAddresses The Machine Smart Account will trigger the final target call
     * @param targets The target contract address where the call data will be executed
     * @param data The calldata for the transaction sent to the target contract address
     * @param signature The signature verifying the owner's tx approval.
     * @param machineOwnerSignatures The signature verifying the machineOwner (machine owner) tx approval.
     */
    function executeMachineBatchTransactions(
        address[] memory machineAddresses,
        address[] memory targets,
        bytes[] calldata data,
        uint256 nonce,
        uint256 refundAmount,
        uint256[] memory machineNonces,
        bytes calldata signature,
        bytes[] calldata machineOwnerSignatures
    ) external {
        if (machineAddresses.length < 1) revert Errors.ZeroAddress(); // Machine address cannot be zero
        if (targets.length < 1) revert Errors.ZeroAddress(); // Target addresses cannot be zero
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce); // Nonce already used
        if (machineAddresses.length != targets.length || machineAddresses.length != data.length) {
            revert Errors.InvalidMachineAddressTargetsDataLength();
        }
        // Verify the owner's signature
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTE_MACHINE_BATCH_TRANSACTIONS_TYPEHASH,
                keccak256(abi.encodePacked(machineAddresses)),
                keccak256(abi.encodePacked(targets)),
                _hashData(data),
                nonce,
                keccak256(abi.encodePacked(machineNonces))
            )
        );

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce); // Invalid Machine Station Owner signature
        }

        usedNonces[nonce] = true;
        uint256 txFeeRefundAmount = refundAmount;

        // use default refund amount if custom refund amount is not supplied
        if (txFeeRefundAmount < 1) {
            txFeeRefundAmount = configs[TX_FEE_REFUND_AMOUNT_KEY];
        }
        _refundTxFees(msg.sender, txFeeRefundAmount);

        for (uint256 i = 0; i < machineAddresses.length; i++) {
            _fundStorageDepositFees(machineAddresses[i], targets[i]);
            // Forward the call to the machine account to execute the target tx
            try MachineSmartAccount(machineAddresses[i]).execute(
                targets[i], data[i], machineNonces[i], machineOwnerSignatures[i]
            ) {} catch {
                emit Events.BatchMachineTransactionFailed(machineAddresses[i], i);
            }
        }
    }

    /**
     * @dev Execute a machine transaction via the machine station factory contract.
     * The Machine Smart Account will trigger the final target call
     * @param machineAddress The machine smart account address
     * @param recipientAddress The recipient of the tokens
     * @param nonce Protects against replay attack.
     * @param signature The signature verifying the Machine Station owner's tx approval.
     * @param machineOwnerSignature The signature verifying the machine owner tx approval.
     */
    function executeMachineTransferBalance(
        address machineAddress,
        address recipientAddress,
        uint256 nonce,
        bytes calldata signature,
        bytes calldata machineOwnerSignature
    ) external onlyRole(STATION_MANAGER_ROLE) {
        if (machineAddress == address(0)) revert Errors.ZeroAddress(); // Machine address cannot be zero
        if (recipientAddress == address(0)) revert Errors.ZeroAddress(); // recipient address cannot be zero
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce); // Nonce already used

        // Verify the owner's signature
        bytes32 structHash =
            keccak256(abi.encode(EXECUTE_MACHINE_TRANSFER_TYPEHASH, machineAddress, recipientAddress, nonce));

        if (!_verifySignature(structHash, signature, nonce)) {
            revert Errors.InvalidOwnerSignature(structHash, nonce); // Invalid Machine Station Owner signature
        }

        usedNonces[nonce] = true;

        // Forward the call to the machine account to execute the transfer tx
        MachineSmartAccount(machineAddress).transferMachineBalance(recipientAddress, nonce, machineOwnerSignature);
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

    function _fundStorageDepositFees(address machineAddress, address target) private {
        // Transfer tokens with balance validation
        // This transfer is only done if the target address is peaq did, rbac or storage contract call
        if (Constants.FUNDING_TOKEN != address(0) && hasRole(REQUIRED_STORAGE_DEPOSIT_FEE_ROLE, target)) {
            // Fetch machine's balance
            uint256 machineBalance = IERC20(Constants.FUNDING_TOKEN).balanceOf(machineAddress);

            // Check if the machine balance is less than min balance before funding it
            // This is added because each machine account is required to pay a storage deposit fees by the peaq storage, rbac and did contracts
            // while using the on-chain storage
            if (machineBalance <= Constants.MIN_BALANCE) {
                // Fund the machine adress balance
                IERC20(Constants.FUNDING_TOKEN).safeTransfer(machineAddress, Constants.FUNDING_AMOUNT);
            }
        }
    }

    function _refundTxFees(address sender, uint256 amount) private {
        //  only refund tx fees if enabled
        if (configs[IS_REFUND_ENABLED_KEY] > 0) {
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
