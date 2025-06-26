import { AbiItem } from 'web3-utils';
import { AbiCoder, ethers } from 'ethers';
import { Sdk } from '@peaq-network/sdk';
import { Keyring } from '@polkadot/keyring'
import { u8aToHex, stringToU8a } from '@polkadot/util';
import { mnemonicGenerate, cryptoWaitReady } from '@polkadot/util-crypto';
import axios from 'axios';

// Import the contract ABI
import {abi} from '../MachineStationFactoryABI.json';
import { CustomDocumentFields } from '@peaq-network/sdk/src/modules/did';

// Load environment variables
import { config } from "dotenv";
config();

// peaq RPC URL: https://peaq.api.onfinality.io/public
const rpcURL = "https://erpc-async.agung.peaq.network"; // replace with peaq RPC URL during mainnet deployment. 
const chainID = 3338;

// Contract details
// Replace with the your dedicated machine station factory contract address during deployment
const MachineStationFactoryContractAddress: string = '0x31B80DbA6806E0335Bfac6D12A5A820C32D73d68'; 
const contract = new ethers.ContractFactory(abi as AbiItem[], MachineStationFactoryContractAddress);
const abiCoder = new AbiCoder();

// Wallet details
const ownerPrivateKey: string | undefined = process.env.CONTRACT_OWNER_PRIVATE_KEY??""; // Replace with owner wallet's private key
const machineOwnerPrivateKey: string | undefined = process.env.MACHINE_OWNER_PRIVATE_KEY??""; // Replace with machine owner wallet's private key

if (!ownerPrivateKey || !machineOwnerPrivateKey) {
  throw new Error("Owner or Machine Owner Private Key not provided");
}

const provider = new ethers.JsonRpcProvider(rpcURL);
const ownerAccount = new ethers.Wallet(ownerPrivateKey, provider);
const machineOwnerAccount = new ethers.Wallet(machineOwnerPrivateKey, provider);

const DEPIN_SEED = "<DEPIN_SEED>"; // The seed phrase for DePIN Project, used for signing the DID

const PEAQ_SERVICE_URL  = "<PEAQ_SERVICE_URL>"; // URL to the peaq campaign service 
// dev URL: https://lift-off-campaign-service-jx-devbr.jx.peaq.network

const API_KEY  = "<API_KEY>"; // peaq campaign service APIKEY value added to the header of all requests
// dev APIKEY: aa69cb8e92b2e27eb26996fc9b02f6df24
// production APIKEY will be sent to you after deployment

const PROJECT_API_KEY  = "<API_KEY>"; // peaq campaign service unique APIKEY value for specific project added to the header of all requests
// dev P-APIKEY: all_0821fcaa69
// your production P-APIKEY will be sent to you after deployment


class PeaqGetRealCampaignClass {

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
      const txResponse = await this.sendTransaction(methodData);

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

    async submitDIDTx() {
      try {
        const machineOwner = machineOwnerAccount.address;
        let nonce = this.getRandomNonce();
        const target = "0x0000000000000000000000000000000000000800";
       
        // deploy a Machine Smart Account
        const deploySignature = await this.ownerSignTypedDataDeployMachineSmartAccount(machineOwner, nonce)
        const machineAddress = await this.deployMachineSmartAccount(machineOwner, nonce, deploySignature);
    
        if (machineAddress.length < 42) throw new Error("invalid machine address");
        
        const addAttributeFunctionSignature =
          "addAttribute(address,bytes,bytes,uint32)";
        const createDidFunctionSelector = ethers
          .keccak256(ethers.toUtf8Bytes(addAttributeFunctionSignature))
          .substring(0, 10);
    
        // Creating key pair for the subject of the DID from seed
        const {keyPair} = await this.generateNewDidAddress();
        const DIDSubjectPair = keyPair; 
        // Address derived from DIDSubjectPair
        const DIDAddress = DIDSubjectPair.address; 


        // Email address signature will be  created and did address will be used to track the creator
        const postdata = {
            email: "<EMAIL>",  
            did_address: DIDAddress, 
            tag: "<YOUR_CUSTOM_TASK_TAG>" // replace with your unique custom task tag
        };

        // Creating email  signature
        const emailSignature = await this.createEmailSignature(postdata);

        const didName = `did:peaq:${machineAddress}#test`;
        const name = ethers.hexlify(ethers.toUtf8Bytes(didName));
    
        const value = await this.generateDIDHash(machineOwner, DIDAddress, emailSignature);
    
        // converted the original did value to bytes and then hex to retain the original value during decoding
        const didVal = ethers.hexlify(ethers.toUtf8Bytes(value));
    
        const validityFor = 0;
    
        const params = abiCoder.encode(
          ["address", "bytes", "bytes", "uint32"],
          [machineAddress, name, didVal, validityFor]
        );
    
        const calldata = params.replace("0x", createDidFunctionSelector);
    
        nonce = this.getRandomNonce();
        const machineOwnerSignature = await this.machineOwnerSignTypedDataExecuteMachine(machineAddress, target, calldata, nonce);
        const ownerSignature = await this.ownerSignTypedDataExecuteMachineTransaction(machineAddress, target, calldata, nonce);
    
        await this.executeMachineTransaction(
          machineAddress,
          target,
          calldata,
          nonce,
          ownerSignature,
          machineOwnerSignature
        );
      } catch (error) {
        console.error("Error:", error);
      
      }
    }

    async executeMachineTransaction(
            machineAddress: string,
            target: string,
            data: string,
            nonce: BigInt,
            signature: string,
            machineOwnerSignature: string
        ): Promise<void> {
          try {
    
            const methodData = contract.interface.encodeFunctionData(
              "executeMachineTransaction",
              [machineAddress, target, data, nonce, signature, machineOwnerSignature]
            );
      
            // Send the transaction and get the receipt
            const txResponse = await this.sendTransaction(methodData);
      
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

    async ownerSignTypedDataDeployMachineSmartAccount(
        machineOwner: string,
        nonce: BigInt
      ): Promise<string> {
        const domain = {
          name: "MachineStationFactory",
          version: "1",
          chainId: chainID,
          verifyingContract: MachineStationFactoryContractAddress,
        };
    
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
    
        // Sign the typed data
        const signature = await ownerAccount.signTypedData(domain, types, message);
      
        return signature;
    }

    async machineOwnerSignTypedDataExecuteMachine(
        machineAddress: string,
        target: string,
        data: string,
        nonce: BigInt,
    ): Promise<string> {
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
      ): Promise<string> {
        // Step 1: Define the EIP-712 Domain
        const domain = {
          name: "MachineStationFactory", 
          version: "1", 
          chainId: chainID,
          verifyingContract: MachineStationFactoryContractAddress,
        };
      
        const types = {
          ExecuteMachineTransaction: [
            { name: "machineAddress", type: "address" },
            { name: "target", type: "address" },
            { name: "data", type: "bytes" },
            { name: "nonce", type: "uint256" },
          ],
        };
    
        const message = {
          machineAddress: machineAddress,
          target: target,
          data: data,
          nonce: nonce,
        };
      
      
        const signature = await ownerAccount.signTypedData(domain, types, message);
      
        return signature;
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

    getRandomNonce(): BigInt {
        const now = BigInt(Date.now());
        const randomPart = BigInt(Math.floor(Math.random() * 1e18));
        return now * randomPart;
    }

    async generateDIDHash(machineOwnerAddress: string, didAddress: string, emailSignature: string): Promise<string> {
        const keyring = new Keyring({ type: "sr25519" });
       
        // Creating key pair for the DePin from seed
        const DePinPair = keyring.addFromUri(DEPIN_SEED);

        // Generating signature using DePinSeed and DIDSubjectPair's address as data
        const issuerSignature = u8aToHex(DePinPair.sign(stringToU8a(didAddress)));
    

        const customFields: CustomDocumentFields = {
            prefix: 'peaq',
            controller: '5FEw7aWmqcnWDaMcwjKyGtJMjQfqYGxXmDWKVfcpnEPmUM7q',
            signature: {
                    type: 'Ed25519VerificationKey2020',
                    issuer: DePinPair?.address,
                    hash: issuerSignature
            },
            services: [
                {
                    id: '#emailSignature',
                    type: 'emailSignature',
                    data: emailSignature 
                },
                {
                    id: '#owner',
                    type: 'owner',
                    data: machineOwnerAddress 
                },
            ]
        }

        const did_hash = await Sdk.generateDidDocument({ address: didAddress, customDocumentFields: customFields });
        return did_hash.value;
    };

    async generateNewDidAddress() {
        await cryptoWaitReady();
        // Generate a new mnemonic
        const mnemonic = mnemonicGenerate();
      
        // Create a keyring instance
        const keyring = new Keyring({ type: 'sr25519' });
      
        // Add a new account to the keyring
        const keyPair = keyring.addFromMnemonic(mnemonic);
      
        console.log('Generated Address:', keyPair.address);
      
        return {
            keyPair,
            mnemonic,
            address: keyPair.address,
        };
      }

    // Function to create email signature
    async createEmailSignature(data:any) {
        try {


        const response = await axios.post(`${PEAQ_SERVICE_URL}/v1/sign`, data, {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'APIKEY': API_KEY,
                'P-APIKEY': PROJECT_API_KEY
            }
        })
        .then((response:any) => {
            return response.data;
        })
        .catch((err:any) => {
            console.error(err)
            throw err;
        });

        // Note: You may need to adjust the response handling based on the service's response structure
        return response.data.signature;

        } catch (error) {
        console.error("Error creating email signature", error);
        throw error;
        }
    };

}

// Main function to create DID
const createDid = async () => {
    const campaignClass = new PeaqGetRealCampaignClass();
      
    try {
      await campaignClass.submitDIDTx();
    } catch (error) {
      console.error("DID Creation Error:", error);
    }
};
createDid().catch(console.error);


