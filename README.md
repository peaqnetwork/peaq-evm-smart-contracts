# PEAQ EVM Smart Contracts

This repository contains the smart contracts for PEAQ's EVM Gas Station implementation, built using Foundry or Hardhat.

## Overview

The Gas Station Factory enables gasless transactions for machines on the PEAQ network, allowing them to execute transactions without holding native tokens. Key features include:

- Machine Smart Account deployment
- Gasless transaction execution
- Balance management for gas station operations
- EIP-712 compliant signatures
- Role-based access control


## Usage Forge

### Install Forge
https://getfoundry.sh/introduction/installation/

### Create and set .env file:
Look at the `.env.example` for a structure. Prefix keys and addresses with `0x`

### Compile Contracts

```shell
forge build
```
### Deploy
You have the option to either deploy on PEAQ or AGUNG networks. For testing purposes default to AGUNG.

There is a slight differentiation between the gas fees between the networks. Please use the `.env.example` defined values for generic configuration.


#### Deploy on PEAQ

```
forge script script/foundry/DeployMachineStationFactory.s.sol:DeployGasStation --rpc-url <rpc_url> --broadcast
```

#### Deploy AGUNG
```
forge script script/foundry/DeployMachineStationFactoryAGUNG.s.sol:DeployGasStation --rpc-url <rpc_url> --broadcast --gas-estimate-multiplier 300 --slow
```

## Usage HardHat
### Install Packages
```
npm install
```

### Deploy
#### Deploy on PEAQ
```
npx hardhat run script/hardhat/DeployMachineStationFactory.js --network peaq
```
#### Deploy on AGUNG
```
npx hardhat run script/hardhat/DeployMachineStationFactoryAGUNG.js --network agung
```