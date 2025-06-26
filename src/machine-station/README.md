# Machine Station Factory Contract V2

## **Implementation Overview**

MachineStationFactory is a smart contract that acts as a factory and manager for creating and interacting with Machine Smart Account instances on-chain. This contract functions as the machine station for deploying Machine Smart Accounts on the network. A Machine Smart Account contract is deployed for every new machine added to the network. This serves as the on-chain representation of the machine. These smart accounts perform transactions where the machine itself is the owner and initiator.

The MachineStationFactory contract acts as both a gas station and a handler for machine account abstraction. For machine-specific transactions, the final target call is executed directly by the machine. It incorporates:

- EIP-712 signature verification
- Gas fee refunding
- Storage deposit funding
- Role-based access control

It is designed for submitting Machine transactions on peaq network.

---

## **Constructor**

### **constructor(address admin, address stationManager, uint256 _txRefundAmount)**

Initializes the factory with roles, refund configurations, and default funding parameters.

**Parameters:**

- **admin**: the main administrator
- **stationManager**: entity authorized to manage machine transactions
- **_txRefundAmount**: default token amount refunded per tx

**Behavior:**

- **Grants roles**: DEFAULT_ADMIN_ROLE, STATION_MANAGER_ROLE, REQUIRED_STORAGE_DEPOSIT_FEE_ROLE
- Sets refund & storage deposit funding configs with sensible defaults

---

## **Configuration Management**

### **updateConfigs(bytes32 key, uint256 value)**

Allows station managers to update refund/storage/funding config.

---

## **Deployment**

### **deployMachineSmartAccount(address machineOwner, uint256 nonce, bytes calldata signature)**

Deploys a new MachineSmartAccount if signed by the machine owner.

**Returns:** Address of the new smart account

**Side-effects:**

- Deploys account
- Fund the initial tx fees needed for the sender first transaction
- Emits MachineSmartAccountDeployed

---

## **Machine Station Replacement**

### **transferMachineStationBalance(address newMachineStationAddress, uint256 nonce, bytes calldata signature)**

Transfers full balance from current station to a new one.

**Access:** Admin-only

**Emits:** MachineStationBalanceTransferred

---

## **Transaction Execution**

### **executeTransaction(address target, bytes calldata data, uint256 nonce, uint256 refundAmount, bytes calldata signature)**

Executes a single transaction from the factory contract.

**Parameters:**

- **target**: Address of the contract to interact with.
- **data**: Calldata to send to the target contract.
- **nonce**: Unique value to prevent replay attacks.
- **refundAmount**: Optional custom gas refund amount (overrides default if > 0).
- **signature**: EIP-712 signature from a valid station authority.

**Emits:** TransactionExecuted

---

### **executeMachineTransaction(address machineAddress, address target, bytes calldata data, uint256 nonce, uint256 refundAmount, bytes calldata signature, bytes calldata machineOwnerSignature)**

Executes a transaction from a MachineSmartAccount, if both station and owner signatures are valid.

**Parameters:**

- machineAddress: Address of the MachineSmartAccount executing the call.
- target: Contract that will receive the call.
- data: Encoded calldata for the call.
- nonce: Unique transaction nonce.
- refundAmount: Optional refund amount in tokens.
- signature: Signature from station authority.
- machineOwnerSignature: Signature from machine owner authorizing the call.

**Emits:** Events from MachineSmartAccount

---

### **executeMachineBatchTransactions(address[] memory machineAddresses, address[] memory targets, bytes[] calldata data, uint256 nonce, uint256 refundAmount, uint256[] memory machineNonces, bytes calldata signature, bytes[] calldata machineOwnerSignatures)**

Batch version of machine transaction execution.

**Parameters:**

- machineAddresses: Array of MachineSmartAccount addresses.
- targets: Target contract addresses.
- data: Array of calldata entries, each corresponding to a target.
- nonce: Global nonce for the batch.
- refundAmount: Gas refund amount.
- machineNonces: Array of nonces, one per machine transaction.
- signature: Signature from a station authority approving the batch.
- machineOwnerSignatures: Signatures from each machine’s owner.

**Validations:**

- Ensures matching lengths of machineAddresses, targets, and data

**Tries/catches individual failures**, emitting BatchMachineTransactionFailed.

---

### **executeMachineTransferBalance(address machineAddress, address recipientAddress, uint256 nonce, bytes calldata signature, bytes calldata machineOwnerSignature)**

Transfers token balance from a smart machine account to a recipient.

**Parameters:**

- machineAddress: Address of the machine smart account holding funds.
- recipientAddress: Address to receive the token balance.
- nonce: Unique transaction identifier to prevent replay.
- signature: Signature from the station authority.
- machineOwnerSignature: Signature from the machine owner approving the transfer.

**Access:** Station manager

**Authorization:** Requires both station and machine owner signatures

**Side-effects:**

- Transfers full balance from machine to recipient
- Emits balance transfer events

---

## **Utility Functions**

### **getDomainSeparator()**

Returns EIP-712 domain separator

### **_verifySignature(bytes32 structHash, bytes memory signature, uint256 nonce)**

Verifies that the given signature is valid for the structHash, under the current domain separator, and belongs to an address with either DEFAULT_ADMIN_ROLE or STATION_MANAGER_ROLE.

**Parameters:**

- structHash: The pre-image of the EIP-712 message
- signature: Signed message bytes
- nonce: Replay protection value

**Returns:** true if signature is valid and from a privileged signer

**Reverts If:** The nonce has already been used

---

### **_hashData(bytes[] calldata data)**

Computes a deterministic hash of an array of calldata entries for batched operations.

**Parameters:**

- data: Array of bytes values representing individual encoded calls

**Returns:** keccak256 hash of the packed array of hashes for each call entry

---

## **Fee Refund and Storage Funding**

### **_fundStorageDepositFees(machineAddress, target)**

If the target is one of the REQUIRED_STORAGE_DEPOSIT_FEE_ROLE addresses and the machine has low balance, funds the machine.

### **_refundTxFees(sender, amount)**

Refunds gas fees to sender, if enabled and if sender’s balance is below threshold.

---

## **Native Token Fallback**

### **receive()**

Accepts native tokens; emits fallback events for traceability.

### **fallback()**

Accepts native tokens; emits fallback events for traceability.
