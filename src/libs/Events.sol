// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

library Events {
    event MachineTransactionExecuted(address indexed sender, address indexed machineAddress, address target);
    event MachineBatchTransactionExecuted(address indexed machineAddress, uint256 index, bool result);
    event MachineBalanceTransferred(
        address indexed machineAddress, address indexed recipientAddress, uint256 amount, uint256 nonce
    );
    event MachineSmartAccountDeployed(address indexed deployedAddress);
    event MachineStationBalanceTransferred(
        address indexed oldMachineStation, address indexed newMachineStation, uint256 amount, uint256 nonce
    );
    event MachineTransactionFailed(address indexed sender, address indexed machineAddress, address target);
    event BatchMachineTransactionFailed(address indexed machineAddress, uint256 index);
    event TransactionExecuted(address indexed target, bytes data, uint256 nonce, address indexed executor);
    event StorageDepositFeeChanged(uint256 newStorageDepositFee);
    event ConfigsUpdated(bytes32 key, uint256 value);
    event OnReceivedCall();
    event OnFailbackCall();
}
