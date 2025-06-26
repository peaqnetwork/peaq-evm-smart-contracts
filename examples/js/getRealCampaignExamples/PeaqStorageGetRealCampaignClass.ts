import { AbiItem } from 'web3-utils';
import { AbiCoder, ethers } from 'ethers';
import axios from 'axios';

// Import the contract ABI
import {abi} from '../MachineStationFactoryABI.json';

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

const provider = new ethers.JsonRpcProvider(rpcURL);
const ownerAccount = new ethers.Wallet(ownerPrivateKey, provider);

const PEAQ_SERVICE_URL  = "<PEAQ_SERVICE_URL>"; // URL to the peaq campaign service 
// dev URL: https://lift-off-campaign-service-jx-devbr.jx.peaq.network

const API_KEY  = "<API_KEY>"; // peaq campaign service APIKEY value added to the header of all requests
// dev APIKEY: aa69cb8e92b2e27eb26996fc9b02f6df24
// production APIKEY will be sent to you after deployment

const PROJECT_API_KEY  = "<API_KEY>"; // peaq campaign service unique APIKEY value for specific project added to the header of all requests
// dev P-APIKEY: all_0821fcaa69
// your production P-APIKEY will be sent to you after deployment


class PeaqGetRealCampaignClass {


  async submitGetRealStorageTx() {
    try {
        const nonce = this.getRandomNonce();
        const refundAmount = BigInt(0);
        const target = '0x0000000000000000000000000000000000000801';
  
        const addItemFunctionSignature = "addItem(bytes,bytes)";
        const addItemFunctionSelector = ethers.keccak256(ethers.toUtf8Bytes(addItemFunctionSignature)).substring(0, 10);
  
        let now = new Date().getTime();

        // Send data to peaq data storage service
        // replace <YOUR_CUSTOM_TASK_TAG> with your unique task identity tag used to track your tasks on-chain.
        // all item types are required to be constructed in this format
        // [<YOUR_CUSTOM_TASK_TAG>] + [-] + [a-zA-Z0-9-_]
        // we use the dash [-] to split the item type when the event parser receives the chain events
        // ItemType has to be unique on every requests
        const itemType = "<YOUR_CUSTOM_TASK_TAG>-"+now; // e.g "GET-REAL-CAMPAIGN-ITEM-TYPE-001", "GET-REAL-CAMPAIGN-ITEM-TYPE-002"
        const postData  = {
            item_type: itemType,
            email: 'user@example.com', // replace this email with the user email address
            tag: "<YOUR_CUSTOM_TASK_TAG>",  // replace with your unique custom task tag
            tags: ["<YOUR-CUSTOM-TASK-TAG>", "<20_YOUR-CUSTOM-TASK-TAG>", "<30_YOUR-CUSTOM-TASK-TAG>"]  // replace with your unique custom task tags
        };

        // register the itemType and tag or tags
        await this.registerItemTypeAndTags(postData)

        // encode the item storage data for submission to peaq network
        const itemTypeHex = ethers.hexlify(ethers.toUtf8Bytes(itemType));
        const item = "TASK-COMPLETED"
        const itemHex = ethers.hexlify(ethers.toUtf8Bytes(item));
  
        const params = abiCoder.encode(
            ["bytes", "bytes"],
            [itemTypeHex, itemHex]
        );
  
        const calldata = params.replace("0x", addItemFunctionSelector);
        const ownerSignature = await this.ownerSignTypedDataExecuteTransaction(target, calldata, nonce, refundAmount)
  
        await this.executeTransaction(target, calldata, nonce, refundAmount,  ownerSignature,);
    } catch (error) {
        console.error('Error:', error);
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
        const txResponse = await this.sendTransaction(methodData);

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

    async ownerSignTypedDataExecuteTransaction(
      target: string,
      data: string,
      nonce: BigInt,
      refundAmount: BigInt,
    ): Promise<string> {
      // Step 1: Define the EIP-712 Domain
      const domain = {
        name: "MachineStationFactory", 
        version: "1", 
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

    // Function to register your item type and tags on campaign verification service
    async registerItemTypeAndTags(data:any) {
        try {


        const response = await axios.post(`${PEAQ_SERVICE_URL}/v1/data/store`, data, {
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
        return response.data;

        } catch (error) {
        console.error("Error registering itemType and tags on campaign verification service", error);
        throw error;
        }
    };

}

// Main function to submit get real storage tx
const submitGetRealStorageTx = async () => {
    const campaignClass = new PeaqGetRealCampaignClass();
      
    try {
      await campaignClass.submitGetRealStorageTx();
    } catch (error) {
      console.error(" storage submission failed: Error:", error);
    }
};
submitGetRealStorageTx().catch(console.error);


