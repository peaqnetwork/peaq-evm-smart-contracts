// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MachineSmartAccount {
    using ECDSA for bytes32;

    address public owner;
    address public entryPoint;
    mapping(uint256 => bool) public usedNonces;

    constructor(address _owner, address _entryPoint) {
        require(_owner != address(0), "Owner cannot be zero");
        require(_entryPoint != address(0), "EntryPoint cannot be zero");
        owner = _owner;
        entryPoint = _entryPoint;
    }

    /**
     * @dev Verify the eoa (machine owner) signature.
     * @param userOpHash The hash of the signed message.
     * @param signature The signature to verify.
     * @param nonce Protects against replay attack.
     */
    function validateUserOp(
        bytes32 userOpHash,
        bytes memory signature,
        uint256 nonce
    ) public view returns (bool) {
        require(!usedNonces[nonce], "Nonce already used");

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(hash, signature);

        return signer == owner;
    }

    /**
     * @dev Execute the target tx
     * @param target The target contract address where the call data will be executed
     * @param data The calldata for the transaction sent to the target contract address
     * @param signature The signature verifying the eoa (machine owner) tx approval.
     * @param nonce Protects against replay attack.
     */
    function execute(
        address target,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(
            msg.sender == entryPoint || msg.sender == owner,
            "Not authorized"
        );
        require(!usedNonces[nonce], "Nonce already used");

        bytes32 userOpHash = keccak256(
            abi.encodePacked(address(this), target, data, nonce)
        );
        require(
            validateUserOp(userOpHash, signature, nonce),
            "Invalid EOA (machine owner) signature"
        );

        usedNonces[nonce] = true;

        (bool success, ) = target.call(data);
        require(success, "Target call failed");
    }
}
