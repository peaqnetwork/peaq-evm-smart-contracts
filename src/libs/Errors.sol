// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

library Errors {
    error ZeroAddress();
    error NonceAlreadyUsed(uint256 nonce);
    error InvalidOwnerSignature(bytes32 messageHash, uint256 nonce);
    error InvalidMachineOwnerSignature(bytes32 messageHash, uint256 nonce);
    error TransferFailed(address token, address recipient, uint256 amount);
    error NotAuthorized(address caller);
    error TargetCallFailed(address target, bytes data);
    error InvalidMachineAddressTargetsDataLength();
    error InvalidMachineAddressNonceSignatureLength();
    error EmptyAddressesArray();
    error MaxBatchTransactionExceeded(uint256 max, uint256 got);
    error InsufficientFactoryBalance(uint256 balance, uint256 amount);
}
