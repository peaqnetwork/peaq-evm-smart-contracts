# PEAQ EVM Smart Contracts

This repository contains the smart contracts for PEAQ's EVM Gas Station implementation, built using Foundry.

## Overview

The Gas Station Factory enables gasless transactions for machines on the PEAQ network, allowing them to execute transactions without holding native tokens. Key features include:

- Machine Smart Account deployment
- Gasless transaction execution
- Balance management for gas station operations
- EIP-712 compliant signatures
- Role-based access control

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Environment

Copy `.env.example` to `.env` and update the values.

```
$ cp .env.example .env
```

```bash
IS_TESTNET=          # true/false - Network environment flag
PRIVATE_KEY=         # Deployer wallet private key
ADMIN_ADDRESS=       # Admin wallet address
STATION_MANAGER_ADDRESS= # Station manager contract address
```

### Deploy

```shell
$ forge script script/DeployMachineStationFactory.s.sol:DeployGasStation --broadcast --rpc-url <your_rpc_url> -- --env-file .env
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
