// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

library Constants {
    address constant FUNDING_TOKEN = address(0x0000000000000000000000000000000000000809); // PEAQ token contract address
    address constant PEAQ_RBAC = address(0x0000000000000000000000000000000000000802); // peaq RBAC contract address
    address constant PEAQ_DID = address(0x0000000000000000000000000000000000000800); // peaq DID contract address
    address constant PEAQ_STORAGE = address(0x0000000000000000000000000000000000000801); // peaq storage contract address
    uint256 public constant MAX_BATCH_TRANSACTIONS = 200;
}
