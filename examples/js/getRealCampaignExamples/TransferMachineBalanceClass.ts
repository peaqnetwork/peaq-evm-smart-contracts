import { AbiItem } from "web3-utils";
import { ethers } from "ethers";
import { abi } from "../MachineStationFactoryABI.json";
import { config } from "dotenv";
config();

const rpcURL = process.env.RPC_URL;
const chainID = process.env.CHAIN_ID;

if (!rpcURL || !chainID) {
  throw new Error("RPC URL or Chain ID not provided");
}

// Contract details
const MachineStationFactoryContractAddress =
  process.env.MACHINE_STATION_FACTORY_CONTRACT_ADDRESS;

if (!MachineStationFactoryContractAddress) {
  throw new Error("Machine Station Factory Contract Address not provided");
}

const contract = new ethers.ContractFactory(
  abi as AbiItem[],
  MachineStationFactoryContractAddress
);

// Wallet details
const ownerPrivateKey = process.env.CONTRACT_OWNER_PRIVATE_KEY;
const machineOwnerPrivateKey = process.env.MACHINE_OWNER_PRIVATE_KEY;

if (!ownerPrivateKey || !machineOwnerPrivateKey) {
  throw new Error("Owner or Machine Owner Private Key not provided");
}

const provider = new ethers.JsonRpcProvider(rpcURL);
const ownerAccount = new ethers.Wallet(ownerPrivateKey, provider);
const machineOwnerAccount = new ethers.Wallet(machineOwnerPrivateKey, provider);

class TransferMachineBalanceClass {
  async transferBalance() {
    let nonce = this.getRandomNonce();

    // Return the balance of the Machine Station Factory contract to the owner
    // This is useful if you are testing and deploying the contract multiple times
    const newMachineOwnerAccount = machineOwnerAccount.address;

    const signature = await this.ownerSignTypedDataTransferBalance(
      newMachineOwnerAccount,
      nonce
    );
    console.log("signature: ", signature);

    if (!signature) {
      throw new Error("Invalid signature");
    }

    await this.transferMachineStationBalance(
      newMachineOwnerAccount,
      nonce,
      signature
    );
  }

  async ownerSignTypedDataTransferBalance(
    newMachineStationAddress: string,
    nonce: BigInt
  ): Promise<string> {
    const domain = {
      name: "MachineStationFactory",
      version: "1",
      chainId: chainID,
      verifyingContract: MachineStationFactoryContractAddress,
    };

    const types = {
      TransferMachineStationBalance: [
        { name: "newMachineStationAddress", type: "address" },
        { name: "nonce", type: "uint256" },
      ],
    };

    const message = {
      newMachineStationAddress: newMachineStationAddress,
      nonce: nonce,
    };

    return await ownerAccount.signTypedData(domain, types, message);
  }

  async transferMachineStationBalance(
    newMachineStationAddress: string,
    nonce: BigInt,
    signature: string
  ): Promise<string | undefined> {
    const methodData = contract.interface.encodeFunctionData(
      "transferMachineStationBalance",
      [newMachineStationAddress, nonce, signature]
    );

    const txResponse = await this.sendTransaction(methodData);
    const receipt = await txResponse.wait();

    console.log("Transfer Balance Tx executed:", receipt?.hash);
    return receipt?.hash;
  }

  getRandomNonce(): BigInt {
    const now = BigInt(Date.now());
    const randomPart = BigInt(Math.floor(Math.random() * 1e18));
    return now * randomPart;
  }

  // Helper function to sign and send transactions
  async sendTransaction(
    methodData: string
  ): Promise<ethers.TransactionResponse> {
    const tx = {
      to: MachineStationFactoryContractAddress,
      data: methodData,
    };

    return await ownerAccount.sendTransaction(tx);
  }
}

const transferBalance = async () => {
  const transferMachineBalanceClass = new TransferMachineBalanceClass();
  try {
    await transferMachineBalanceClass.transferBalance();
  } catch (error) {
    console.error("Error transferring balance: ", error);
  }
};

transferBalance().catch(console.error);
