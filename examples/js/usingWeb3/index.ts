import { AbiItem } from 'web3-utils';
import { Sdk } from '@peaq-network/sdk';
import { mnemonicGenerate, cryptoWaitReady } from '@polkadot/util-crypto';
import { Keyring } from '@polkadot/keyring';

// Import the contract ABI
import { abi } from '../MachineStationFactoryABI.json';
import { AbiCoder, ethers } from 'ethers';

let globalMachineAddress = "0x8D5fd26b338d9f40b48eD21bBd517E0944a12D48"; // to be replaced after submitDeployMachineSmartAccountTx is triggered
let globalMachineAddress2 = "0x17420815062B03917bd89430a7eea8bFC84AC1B8"; // to be replaced after submitDeployMachineSmartAccountTx is triggered

// Web3 setup
// for agung: https://erpc-async.agung.peaq.network
// for peaq: https://peaq.api.onfinality.io/public

// chainID:
// agung: 9990
// peaq: 3338

const rpcURL = "https://erpc-async.agung.peaq.network";
const chainID = 9990;

// Contract details
const MachineStationFactoryContractAddress: string = '0x31B80DbA6806E0335Bfac6D12A5A820C32D73d68'; // Replace with the your dedicated machine station factory contract address
const contract = new ethers.ContractFactory(abi as AbiItem[], MachineStationFactoryContractAddress);

// Wallet details
const ownerPrivateKey: string | undefined = process.env.CONTRACT_OWNER_PRIVATE_KEY ?? ""; // Replace with owner wallet's private key
const machineOwnerPrivateKey: string | undefined = process.env.MACHINE_OWNER_PRIVATE_KEY ?? ""; // Replace with machine owner wallet's private key

const provider = new ethers.JsonRpcProvider(rpcURL);

const ownerAccount = new ethers.Wallet(ownerPrivateKey, provider);
const machineOwnerAccount = new ethers.Wallet(machineOwnerPrivateKey, provider);


class MachineStationFactoryExample {

  async submitDeployMachineSmartAccountTx() {

    const machineOwner = machineOwnerAccount.address;
    const nonce = this.getRandomNonce();

    const deploySignature = await this.ownerSignTypedDataDeployMachineSmartAccount(machineOwner, nonce)

    // call the deploy smart account tx and update the global machine address var
    globalMachineAddress = await this.deployMachineSmartAccount(machineOwner, nonce, deploySignature);
  }

  async submitMachineTransferBalanceTx() {
    let machineAddress = globalMachineAddress;
    const recipientAddress = machineOwnerAccount.address;
    const nonce = this.getRandomNonce();

    const machineOwnerSignature = await this.machineOwnerSignTypedDataTransferMachineBalance(machineAddress, recipientAddress, nonce)
    const ownerSignature = await this.ownerSignTypedDataTransferMachineBalance(machineAddress, recipientAddress, nonce)

    console.log("nonce:", nonce);
    await this.executeMachineTransferBalance(machineAddress, recipientAddress, nonce, ownerSignature, machineOwnerSignature);

  }

  async submitGetRealStorageTx() {
    try {
      const nonce = this.getRandomNonce();
      const target = '0x0000000000000000000000000000000000000801'; // Replace with the target contract address
      const refundAmount = BigInt(0);
      const abiCoder = new AbiCoder()

      const addItemFunctionSignature = "addItem(bytes,bytes)";
      const addItemFunctionSelector = ethers.keccak256(ethers.toUtf8Bytes(addItemFunctionSignature)).substring(0, 10);

      let now = new Date().getTime();

      const itemType = "GET-REAL-CAMPAIGN-ITEM-TYPE" + now
      const itemTypeHex = ethers.hexlify(ethers.toUtf8Bytes(itemType));
      const item = "TASK-COMPLETED"
      const itemHex = ethers.hexlify(ethers.toUtf8Bytes(item));

      const params = abiCoder.encode(
        ["bytes", "bytes"],
        [itemTypeHex, itemHex]
      );

      const calldata = params.replace("0x", addItemFunctionSelector);
      const ownerSignature = await this.ownerSignTypedDataExecuteTransaction(target, calldata, nonce, refundAmount)

      await this.executeTransaction(target, calldata, nonce, refundAmount, ownerSignature,);
    } catch (error) {
      console.error('Error:', error);
    }
  }

  async submitMachineStorageTx() {
    try {
      const machineOwner = machineOwnerAccount.address;
      let machineAddress = globalMachineAddress;
      const nonce = this.getRandomNonce();
      const refundAmount = BigInt(0);
      const target = '0x0000000000000000000000000000000000000801';

      const abiCoder = new AbiCoder()

      const addItemFunctionSignature = "addItem(bytes,bytes)";
      const addItemFunctionSelector = ethers.keccak256(ethers.toUtf8Bytes(addItemFunctionSignature)).substring(0, 10);

      let now = new Date().getTime();

      const itemType = "pqdemo_item_type-" + now
      const itemTypeHex = ethers.hexlify(ethers.toUtf8Bytes(itemType));
      const item = "peaq demo item storage"
      const itemHex = ethers.hexlify(ethers.toUtf8Bytes(item));

      const params = abiCoder.encode(
        ["bytes", "bytes"],
        [itemTypeHex, itemHex]
      );

      const data = params.replace("0x", addItemFunctionSelector);


      const machineOwnerSignature = await this.machineOwnerSignTypedDataExecuteMachine(machineAddress, target, data, nonce)
      const ownerSignature = await this.ownerSignTypedDataExecuteMachineTransaction(machineAddress, target, data, nonce, refundAmount)

      await this.executeMachineTransaction(machineAddress, target, data, nonce, refundAmount, ownerSignature, machineOwnerSignature);
    } catch (error) {
      console.error('Error:', error);
    }
  }

  async submitMachineStorageBatchTx() {
    try {
      const nonce = this.getRandomNonce();
      const refundAmount = BigInt(0);
      const abiCoder = new AbiCoder()
      let now = new Date().getTime();

      const machineNonces: BigInt[] = [];
      const machineOwnerSignatures: string[] = [];
      const machineAddresses: string[] = [globalMachineAddress, globalMachineAddress2];
      const targets = ['0x0000000000000000000000000000000000000801', '0x0000000000000000000000000000000000000801'];
      const calldata: string[] = [];

      const addItemFunctionSignature = "addItem(bytes,bytes)";
      const addItemFunctionSelector = ethers.keccak256(ethers.toUtf8Bytes(addItemFunctionSignature)).substring(0, 10);

      for (let index = 0; index < targets.length; index++) {
        const itemType = `pqdemo_item_type-${index}-${now}`
        const itemTypeHex = ethers.hexlify(ethers.toUtf8Bytes(itemType));
        const item = "peaq demo item storage"
        const itemHex = ethers.hexlify(ethers.toUtf8Bytes(item));

        let machineNonce = this.getRandomNonce()

        const params = abiCoder.encode(
          ["bytes", "bytes"],
          [itemTypeHex, itemHex]
        );

        let data = params.replace("0x", addItemFunctionSelector);
        calldata.push(data);
        machineNonces.push(machineNonce);
        const machineOwnerSignature = await this.machineOwnerSignTypedDataExecuteMachineBatch(machineAddresses[index], targets, calldata, machineNonce)

        machineOwnerSignatures.push(machineOwnerSignature);
      }

      const ownerSignature = await this.ownerSignTypedDataExecuteMachineBatchTransactions(machineAddresses, targets, calldata, nonce, refundAmount, machineNonces)

      await this.executeMachineBatchTransactions(machineOwnerSignatures, targets, calldata, nonce, refundAmount, machineNonces, ownerSignature, machineOwnerSignatures);
    } catch (error) {
      console.error('Error:', error);
    }
  }

  async submitDIDTx() {
    try {
      const nonce = this.getRandomNonce(); // Example nonce
      const refundAmount = BigInt(0);
      const target = "0x0000000000000000000000000000000000000800"; // target contract address - DID contract address
      const machineAddress = globalMachineAddress;
      const abiCoder = new AbiCoder();

      const addAttributeFunctionSignature =
        "addAttribute(address,bytes,bytes,uint32)";
      const createDidFunctionSelector = ethers
        .keccak256(ethers.toUtf8Bytes(addAttributeFunctionSignature))
        .substring(0, 10);

      let now = new Date().getTime();

      // generate a random account using polkadot util/sdk
      const { address } = await this.generateNewAddress();;
      const didName = `did:peaq:${address}#test`;
      const name = ethers.hexlify(ethers.toUtf8Bytes(didName));

      const value = await this.generateDIDHash(address);

      // converted the original did value to bytes and then hex to retain the original value during decoding
      const didVal = ethers.hexlify(ethers.toUtf8Bytes(value));

      const validityFor = 0;

      const params = abiCoder.encode(
        ["address", "bytes", "bytes", "uint32"],
        [machineAddress, name, didVal, validityFor]
      );

      const calldata = params.replace("0x", createDidFunctionSelector);

      const machineOwnerSignature = await this.machineOwnerSignTypedDataExecuteMachine(machineAddress, target, calldata, nonce);
      const ownerSignature = await this.ownerSignTypedDataExecuteMachineTransaction(machineAddress, target, calldata, nonce, refundAmount);

      await this.executeMachineTransaction(
        machineAddress,
        target,
        calldata,
        nonce,
        refundAmount,
        ownerSignature,
        machineOwnerSignature
      );
    } catch (error) {
      console.error("Error:", error);
    }
  }

  async deployMachineSmartAccount(
    machineOwner: string,
    nonce: BigInt,
    signature: string
  ): Promise<string> {
    try {
      // Encode the method call data
      const methodData = contract.interface.encodeFunctionData(
        "deployMachineSmartAccount",
        [machineOwner, nonce, signature]
      );

      // Send the transaction and get the receipt
      const txResponse = await this.sendOwnerTransaction(methodData);

      let receipt = await txResponse.wait().finally();

      const logs = receipt?.logs;

      // Compute the event signature
      const eventSignature = ethers.id("MachineSmartAccountDeployed(address)");
      console.log("eventSignature: ", eventSignature);

      // Find the relevant log
      const log = logs?.find((log) => log.topics[0] === eventSignature);

      console.log("raw log: ", log);

      if (!log) {
        throw new Error("MachineSmartAccountDeployed event not found in logs");
      }


      // The deployed address is stored as the second topic (topics[1]) in a 32-byte format
      const rawDeployedAddress = log.topics[1];
      const deployedAddress = ethers.getAddress(`0x${rawDeployedAddress.slice(26)}`); // Extract last 20 bytes

      console.log('Machine Deploy Tx executed:', receipt?.hash);
      console.log("Machine Deployed Address:", deployedAddress);
      return deployedAddress;

    } catch (error: any) {
      console.error("Transaction failed. Error:", error);

      // Check if the error is a revert error with data
      if (error.data) {
        try {
          // Decode the revert error using the contract's ABI
          const iface = new ethers.Interface(contract.interface.fragments);
          const decodedError = iface.parseError(error.data);

          console.log("Decoded Error:", decodedError);

          // Extract error name and arguments
          // const { name, args } = decodedError;
          // console.log("Error Name:", name);
          // console.log("Arguments:", args);

          // if (name === "InvalidSignature") {
          //   console.error("InvalidSignature Error Details:");
          //   console.error("structHash:", args.structHash);
          //   console.error("nonce:", args.nonce.toString());
          // }
        } catch (decodeError) {
          console.error("Failed to decode error data:", decodeError);
        }
      } else {
        console.error("Transaction failed without revert data:", error);
      }
    }
    return "";
  }

  async executeMachineTransferBalance(
    machineAddress: string,
    recipientAddress: string,
    nonce: BigInt,
    signature: string,
    machineOwnerSignature: string,
  ): Promise<void> {
    try {
      // Encode the method call data
      const methodData = contract.interface.encodeFunctionData(
        "executeMachineTransferBalance",
        [machineAddress, recipientAddress, nonce, signature, machineOwnerSignature]
      );

      // Send the transaction and get the receipt
      const txResponse = await this.sendUserTransaction(methodData);

      console.log("txResponse: ", txResponse);

      let receipt = await txResponse.wait().finally();

      console.log('Machine Balance Transfer Tx executed:', receipt?.hash);

    } catch (error: any) {
      console.error("Transaction failed. Error:", error);

      // Check if the error is a revert error with data
      if (error.data) {
        try {
          // Decode the revert error using the contract's ABI
          const iface = new ethers.Interface(contract.interface.fragments);
          const decodedError = iface.parseError(error.data);

          console.log("Decoded Error:", decodedError);

          // Extract error name and arguments
          // const { name, args } = decodedError;
          // console.log("Error Name:", name);
          // console.log("Arguments:", args);

          // if (name === "InvalidSignature") {
          //   console.error("InvalidSignature Error Details:");
          //   console.error("structHash:", args.structHash);
          //   console.error("nonce:", args.nonce.toString());
          // }
        } catch (decodeError) {
          console.error("Failed to decode error data:", decodeError);
        }
      } else {
        console.error("Transaction failed without revert data:", error);
      }
    }
  }

  async executeTransaction(
    target: string,
    data: string,
    nonce: BigInt,
    refundAmount: BigInt,
    signature: string,
  ): Promise<void> {
    try {
      // Encode the method call data
      const methodData = contract.interface.encodeFunctionData(
        "executeTransaction",
        [target, data, nonce, refundAmount, signature]
      );

      // Send the transaction and get the receipt
      const txResponse = await this.sendUserTransaction(methodData);

      let receipt = await txResponse.wait().finally();

      console.log('Normal Tx executed:', receipt?.hash);

    } catch (error: any) {
      console.error("Transaction failed. Error:", error);

      // Check if the error is a revert error with data
      if (error.data) {
        try {
          // Decode the revert error using the contract's ABI
          const iface = new ethers.Interface(contract.interface.fragments);
          const decodedError = iface.parseError(error.data);

          console.log("Decoded Error:", decodedError);

          // Extract error name and arguments
          // const { name, args } = decodedError;
          // console.log("Error Name:", name);
          // console.log("Arguments:", args);

          // if (name === "InvalidSignature") {
          //   console.error("InvalidSignature Error Details:");
          //   console.error("structHash:", args.structHash);
          //   console.error("nonce:", args.nonce.toString());
          // }
        } catch (decodeError) {
          console.error("Failed to decode error data:", decodeError);
        }
      } else {
        console.error("Transaction failed without revert data:", error);
      }
    }
  }

  async executeMachineTransaction(
    machineAddress: string,
    target: string,
    data: string,
    nonce: BigInt,
    refundAmount: BigInt,
    signature: string,
    machineOwnerSignature: string
  ): Promise<void> {
    try {

      const methodData = contract.interface.encodeFunctionData(
        "executeMachineTransaction",
        [machineAddress, target, data, nonce, refundAmount, signature, machineOwnerSignature]
      );

      // Send the transaction and get the receipt
      const txResponse = await this.sendUserTransaction(methodData);
      let receipt = await txResponse.wait().finally();

      console.log('Machine Tx executed:', receipt?.hash);

    } catch (error: any) {
      console.error("Transaction failed. Error:", error);

      // Check if the error is a revert error with data
      if (error.data) {
        try {
          // Decode the revert error using the contract's ABI
          const iface = new ethers.Interface(contract.interface.fragments);
          const decodedError = iface.parseError(error.data);

          console.log("Decoded Error:", decodedError);

          // Extract error name and arguments
          // const { name, args } = decodedError;
          // console.log("Error Name:", name);
          // console.log("Arguments:", args);

          // if (name === "InvalidSignature") {
          //   console.error("InvalidSignature Error Details:");
          //   console.error("structHash:", args.structHash);
          //   console.error("nonce:", args.nonce.toString());
          // }
        } catch (decodeError) {
          console.error("Failed to decode error data:", decodeError);
        }
      } else {
        console.error("Transaction failed without revert data:", error);
      }
    }
  }

  async executeMachineBatchTransactions(
    machineAddresses: string[],
    targets: string[],
    data: string[],
    nonce: BigInt,
    refundAmount: BigInt,
    machineNonces: BigInt[],
    signature: string,
    machineOwnerSignatures: string[]
  ): Promise<void> {
    try {

      const methodData = contract.interface.encodeFunctionData(
        "executeMachineBatchTransactions",
        [machineAddresses, targets, data, nonce, refundAmount, machineNonces, signature, machineOwnerSignatures]
      );

      // Send the transaction and get the receipt
      const txResponse = await this.sendUserTransaction(methodData);

      let receipt = await txResponse.wait().finally();
      const logs = receipt?.logs;

      console.log("logs: ", logs);
      console.log('Machine Tx executed:', receipt?.hash);

    } catch (error: any) {
      console.error("Transaction failed. Error:", error);

      // Check if the error is a revert error with data
      if (error.data) {
        try {
          // Decode the revert error using the contract's ABI
          const iface = new ethers.Interface(contract.interface.fragments);
          const decodedError = iface.parseError(error.data);

          console.log("Decoded Error:", decodedError);

          // Extract error name and arguments
          // const { name, args } = decodedError;
          // console.log("Error Name:", name);
          // console.log("Arguments:", args);

          // if (name === "InvalidSignature") {
          //   console.error("InvalidSignature Error Details:");
          //   console.error("structHash:", args.structHash);
          //   console.error("nonce:", args.nonce.toString());
          // }
        } catch (decodeError) {
          console.error("Failed to decode error data:", decodeError);
        }
      } else {
        console.error("Transaction failed without revert data:", error);
      }
    }
  }

  async ownerSignTypedDataDeployMachineSmartAccount(
    machineOwner: string,
    nonce: BigInt
  ): Promise<string> {
    // Define the EIP-712 Domain
    const domain = {
      name: "MachineStationFactory",
      version: "2",
      chainId: chainID,
      verifyingContract: MachineStationFactoryContractAddress,
    };

    console.log("machineOwner: ", machineOwner)

    // Define the type definition for the data
    const types = {
      DeployMachineSmartAccount: [
        { name: "machineOwner", type: "address" },
        { name: "nonce", type: "uint256" },
      ],
    };

    // Define the data to be signed
    const message = {
      machineOwner: machineOwner,
      nonce: nonce,
    };

    console.log("ownerAccount: ", ownerAccount.address);

    // Sign the typed data
    const signature = await ownerAccount.signTypedData(domain, types, message);

    return signature;
  }

  async ownerSignTypedDataTransferMachineBalance(
    machineAddress: string,
    recipientAddress: string,
    nonce: BigInt,
  ): Promise<string> {
    // Step 1: Define the EIP-712 Domain
    const domain = {
      name: "MachineStationFactory",
      version: "2",
      chainId: chainID,
      verifyingContract: MachineStationFactoryContractAddress,
    };

    const types = {
      ExecuteMachineTransferBalance: [
        { name: "machineAddress", type: "address" },
        { name: "recipientAddress", type: "address" },
        { name: "nonce", type: "uint256" },
      ],
    };

    console.log("machineAddress: ", machineAddress);
    console.log("recipientAddress: ", recipientAddress);
    console.log("nonce: ", nonce);

    const message = {
      machineAddress: machineAddress,
      recipientAddress: recipientAddress,
      nonce: nonce,
    };


    const signature = await ownerAccount.signTypedData(domain, types, message);

    return signature;
  }

  async machineOwnerSignTypedDataTransferMachineBalance(
    machineAddress: string,
    recipientAddress: string,
    nonce: BigInt,
  ): Promise<string> {
    // Step 1: Define the EIP-712 Domain
    const domain = {
      name: "MachineSmartAccount",
      version: "1",
      chainId: chainID,
      verifyingContract: machineAddress,
    };

    const types = {
      TransferMachineBalance: [
        { name: "recipientAddress", type: "address" },
        { name: "nonce", type: "uint256" },
      ],
    };

    const message = {
      recipientAddress: recipientAddress,
      nonce: nonce,
    };

    const signature = await machineOwnerAccount.signTypedData(domain, types, message);
    return signature;
  }

  async ownerSignTypedDataExecuteTransaction(
    target: string,
    data: string,
    nonce: BigInt,
    refundAmount: BigInt,
  ): Promise<string> {
    // Step 1: Define the EIP-712 Domain
    const domain = {
      name: "MachineStationFactory",
      version: "2",
      chainId: chainID,
      verifyingContract: MachineStationFactoryContractAddress,
    };

    const types = {
      ExecuteTransaction: [
        { name: "target", type: "address" },
        { name: "data", type: "bytes" },
        { name: "nonce", type: "uint256" },
        { name: "refundAmount", type: "uint256" },
      ],
    };

    const message = {
      target: target,
      data: data,
      nonce: nonce,
      refundAmount: refundAmount,
    };

    const signature = await ownerAccount.signTypedData(domain, types, message);

    return signature;
  }

  async machineOwnerSignTypedDataExecuteMachine(
    machineAddress: string,
    target: string,
    data: string,
    nonce: BigInt,
  ): Promise<string> {
    // Step 1: Define the EIP-712 Domain
    const domain = {
      name: "MachineSmartAccount",
      version: "1",
      chainId: chainID,
      verifyingContract: machineAddress,
    };

    const types = {
      Execute: [
        { name: "target", type: "address" },
        { name: "data", type: "bytes" },
        { name: "nonce", type: "uint256" },
      ],
    };

    const message = {
      target: target,
      data: data,
      nonce: nonce,
    };

    const signature = await machineOwnerAccount.signTypedData(domain, types, message);
    return signature;
  }

  async ownerSignTypedDataExecuteMachineTransaction(
    machineAddress: string,
    target: string,
    data: string,
    nonce: BigInt,
    refundAmount: BigInt,
  ): Promise<string> {
    // Step 1: Define the EIP-712 Domain
    const domain = {
      name: "MachineStationFactory",
      version: "2",
      chainId: chainID,
      verifyingContract: MachineStationFactoryContractAddress,
    };

    const types = {
      ExecuteMachineTransaction: [
        { name: "machineAddress", type: "address" },
        { name: "target", type: "address" },
        { name: "data", type: "bytes" },
        { name: "nonce", type: "uint256" },
        { name: "refundAmount", type: "uint256" },
      ],
    };

    const message = {
      machineAddress: machineAddress,
      target: target,
      data: data,
      nonce: nonce,
      refundAmount: refundAmount,
    };


    const signature = await ownerAccount.signTypedData(domain, types, message);

    return signature;
  }

  async machineOwnerSignTypedDataExecuteMachineBatch(
    machineAddress: string,
    targets: string[],
    data: string[],
    nonce: BigInt,
  ): Promise<string> {
    const domain = {
      name: "MachineSmartAccount",
      version: "1",
      chainId: chainID,
      verifyingContract: machineAddress,
    };

    const types = {
      ExecuteBatch: [
        { name: "targets", type: "address[]" },
        { name: "data", type: "bytes[]" },
        { name: "nonce", type: "uint256" },
      ],
    };

    const message = {
      targets: targets,
      data: data,
      nonce: nonce,
    };

    const signature = await machineOwnerAccount.signTypedData(domain, types, message);
    return signature;
  }

  async ownerSignTypedDataExecuteMachineBatchTransactions(
    machineAddresses: string[],
    targets: string[],
    data: string[],
    nonce: BigInt,
    refundAmount: BigInt,
    machineNonces: BigInt[],
  ): Promise<string> {
    // Step 1: Define the EIP-712 Domain
    const domain = {
      name: "MachineStationFactory",
      version: "2",
      chainId: chainID,
      verifyingContract: MachineStationFactoryContractAddress,
    };

    const types = {
      ExecuteMachineBatchTransactions: [
        { name: "machineAddresses", type: "address[]" },
        { name: "targets", type: "address[]" },
        { name: "data", type: "bytes[]" },
        { name: "nonce", type: "uint256" },
        { name: "refundAmount", type: "uint256" },
        { name: "machineNonces", type: "uint256[]" },
      ],
    };


    const message = {
      machineAddresses: machineAddresses,
      targets: targets,
      data: data,
      nonce: nonce,
      refundAmount: refundAmount,
      machineNonces: machineNonces,
    };


    const signature = await ownerAccount.signTypedData(domain, types, message);

    return signature;
  }

  // Helper function to sign and send transactions
  async sendOwnerTransaction(
    methodData: string
  ): Promise<ethers.TransactionResponse> {


    const tx = {
      to: MachineStationFactoryContractAddress,
      data: methodData,
    };

    return await ownerAccount.sendTransaction(tx);
  }

  async sendUserTransaction(
    methodData: string
  ): Promise<ethers.TransactionResponse> {


    const tx = {
      to: MachineStationFactoryContractAddress,
      data: methodData,
    };

    return await ownerAccount.sendTransaction(tx);
  }

  getRandomNonce(): BigInt {
    const now = BigInt(Date.now());
    const randomPart = BigInt(Math.floor(Math.random() * 1e18));
    return now * randomPart;
  }

  async generateDIDHash(randomAddress: string): Promise<string> {
    const customFields = {
      prefix: "peaq",
      controller: randomAddress,
      verifications: [
        {
          type: "Ed25519VerificationKey2020",
        },
      ],
      signature: {
        type: "Ed25519VerificationKey2020",
        issuer: "5Df42mkztLtkksgQuLy4YV6hmhzdjYvDknoxHv1QBkaY12Pg",
        hash: "0x12345", // replace with your issuer signature
      },
      services: [
        {
          id: "#emailSignature",
          type: "emailSignature",
          data: "0e816a00d228a6d215542334e51a01eb3280d202fe2324abe75bb8b4acaec4207cc00106e830d493603305f797706a0ef1952c44ea9f9b44c0b3ccc3d4bc758b", // replace with your email signature
        },
      ],
    };

    const did_hash = await Sdk.generateDidDocument({
      address: randomAddress,
      customDocumentFields: customFields,
    });
    return did_hash.value as string;
  };

  async generateNewAddress() {
    await cryptoWaitReady();
    // Generate a new mnemonic
    const mnemonic = mnemonicGenerate();

    console.log('Generated Mnemonic:', mnemonic);

    // Create a keyring instance
    const keyring = new Keyring({ type: 'sr25519' });

    // Add a new account to the keyring
    const pair = keyring.addFromMnemonic(mnemonic);

    console.log('Generated Address:', pair.address);

    return {
      mnemonic,
      address: pair.address,
    };
  }
}

const machineStationExample = new MachineStationFactoryExample();

// Example usage
(async () => {

  // deploy machine smart account
  await machineStationExample.submitDeployMachineSmartAccountTx();
  // submit get real tx
  await machineStationExample.submitGetRealStorageTx();
  // submit machine storage tx
  await machineStationExample.submitMachineStorageTx();
  // submit machine storage batch txs
  await machineStationExample.submitMachineStorageBatchTx();
  // submit machine did tx
  await machineStationExample.submitDIDTx();
  // Transfer the balance of a machine to a recipient
  await machineStationExample.submitMachineTransferBalanceTx();

})();