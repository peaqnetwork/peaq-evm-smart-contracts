// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Errors} from "../libs/Errors.sol";
import {Events} from "../libs/Events.sol";
import {Constants} from "../libs/Constants.sol";

contract MachineSmartAccount is EIP712, AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public immutable owner;

    bytes32 public constant MACHINE_STATION_ROLE = keccak256("MACHINE_STATION_ROLE");

    // EIP-712 type hashes
    bytes32 private constant EXECUTE_TYPEHASH = keccak256("Execute(address target,bytes data,uint256 nonce)");
    bytes32 private constant EXECUTE_BATCH_TYPEHASH =
        keccak256("ExecuteBatch(address[] targets,bytes[] data,uint256 nonce)");
    bytes32 private constant TRANSFER_BALANCE_TYPEHASH =
        keccak256("TransferMachineBalance(address recipientAddress,uint256 nonce)");

    mapping(uint256 => bool) public usedNonces;

    constructor(address _owner, address machineStation) EIP712("MachineSmartAccount", "1") {
        if (_owner == address(0)) revert Errors.ZeroAddress(); // Owner address cannot be zero
        if (machineStation == address(0)) revert Errors.ZeroAddress(); // Machine Station cannot be zero
        owner = _owner;
        _grantRole(DEFAULT_ADMIN_ROLE, machineStation);
        _grantRole(MACHINE_STATION_ROLE, machineStation);
    }

    /**
     * @dev Verify the machine owner signature.
     * @param userOpHash The hash of the signed message.
     * @param signature The signature to verify.
     * @param nonce Protects against replay attack.
     */
    function validateUserOp(bytes32 userOpHash, bytes memory signature, uint256 nonce) public view returns (bool) {
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce); // Nonce already used

        bytes32 digest = _hashTypedDataV4(userOpHash);
        address signer = ECDSA.recover(digest, signature);

        return signer == owner;
    }

    /**
     * @dev Execute the target tx
     * @param target The target contract address where the call data will be executed
     * @param data The calldata for the transaction sent to the target contract address
     * @param signature The signature verifying the machine owner tx approval.
     * @param nonce Protects against replay attack.
     */
    function execute(address target, bytes calldata data, uint256 nonce, bytes calldata signature)
        external
        nonReentrant
    {
        if (!hasRole(MACHINE_STATION_ROLE, msg.sender) && msg.sender != owner) {
            revert Errors.NotAuthorized(msg.sender);
        }

        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce); // Nonce already used

        bytes32 userOpHash = keccak256(abi.encode(EXECUTE_TYPEHASH, target, keccak256(data), nonce));
        if (!validateUserOp(userOpHash, signature, nonce)) {
            revert Errors.InvalidMachineOwnerSignature(userOpHash, nonce); // Invalid machine owner signature
        }

        usedNonces[nonce] = true;

        (bool success,) = target.call(data);

        if (!success) {
            revert Errors.TargetCallFailed(target, data);
        }
        emit Events.MachineTransactionExecuted(msg.sender, address(this), target);
    }

    /**
     * @dev Execute batch transactions using the target addresses and their respective call data
     * @param targets The target contract addresses where the call data will be executed
     * @param data The array of calldata for the transaction sent to the target contract addresses
     * @param signature The signature verifying the machine owner tx approval.
     * @param nonce Protects against replay attack.
     */
    function executeBatch(address[] memory targets, bytes[] calldata data, uint256 nonce, bytes calldata signature)
        external
        nonReentrant
    {
        if (!hasRole(MACHINE_STATION_ROLE, msg.sender) && msg.sender != owner) {
            revert Errors.NotAuthorized(msg.sender);
        }
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce); // Nonce already used
        if (targets.length != data.length) {
            revert Errors.InvalidMachineAddressTargetsDataLength();
        }
        if (targets.length > Constants.MAX_BATCH_TRANSACTIONS) {
            revert Errors.MaxBatchTransactionExceeded(Constants.MAX_BATCH_TRANSACTIONS, targets.length);
        }

        bytes32 dataHash = _hashData(data);

        bytes32 userOpHash =
            keccak256(abi.encode(EXECUTE_BATCH_TYPEHASH, keccak256(abi.encodePacked(targets)), dataHash, nonce));
        if (!validateUserOp(userOpHash, signature, nonce)) {
            revert Errors.InvalidMachineOwnerSignature(userOpHash, nonce); // Invalid machine owner signature
        }

        usedNonces[nonce] = true;

        for (uint256 i = 0; i < targets.length; i++) {
            (bool success,) = targets[i].call(data[i]);

            emit Events.MachineBatchTransactionExecuted(address(this), i, success);
        }
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

    /**
     * @dev Transfer machine smart account balance to an account.
     * @param recipientAddress The recipient of the tokens
     * @param nonce Protects against replay attack.
     * @param signature The signature verifying the machine owner's tx approval.
     */
    function transferMachineBalance(address recipientAddress, uint256 nonce, bytes calldata signature)
        external
        nonReentrant
        onlyRole(MACHINE_STATION_ROLE)
    {
        if (Constants.FUNDING_TOKEN == address(0)) revert Errors.ZeroAddress();
        if (recipientAddress == address(0)) revert Errors.ZeroAddress();
        if (usedNonces[nonce]) revert Errors.NonceAlreadyUsed(nonce);

        bytes32 structHash = keccak256(abi.encode(TRANSFER_BALANCE_TYPEHASH, recipientAddress, nonce));

        if (!validateUserOp(structHash, signature, nonce)) {
            revert Errors.InvalidMachineOwnerSignature(structHash, nonce);
        }
        usedNonces[nonce] = true;

        uint256 machineBalance = IERC20(Constants.FUNDING_TOKEN).balanceOf(address(this));
        IERC20(Constants.FUNDING_TOKEN).safeTransfer(recipientAddress, machineBalance);

        emit Events.MachineBalanceTransferred(address(this), recipientAddress, machineBalance, nonce);
    }

    function getDomainSeparator() public view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
