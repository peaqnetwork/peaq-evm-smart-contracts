import Web3 from 'web3';
import { AbiItem } from 'web3-utils';
import { TransactionReceipt } from 'web3-types';

// Import the contract ABI
import { abi } from '../GasStationFactoryABI.json';
import { AbiCoder, ethers } from 'ethers';

// Web3 setup
const web3 = new Web3('YOUR_ETHEREUM_NODE_URL'); // Replace with your Ethereum node URL

// Contract details
const GasStationFactoryContractAddress: string = 'CONTRACT_ADDRESS'; // Replace with the deployed Gas station factory contract address
const contract = new web3.eth.Contract(abi as AbiItem[], GasStationFactoryContractAddress);

// Wallet details
const ownerPrivateKey: string = 'YOUR_PRIVATE_KEY'; // Replace with your wallet's private key
const eoaPrivateKey: string = 'YOUR_PRIVATE_KEY'; // Replace with your wallet's private key
const ownerAccount = web3.eth.accounts.privateKeyToAccount(ownerPrivateKey);
const eoaAccount = web3.eth.accounts.privateKeyToAccount(eoaPrivateKey);

// Helper function to sign and send transactions
async function sendTransaction(
    methodData: string,
    gas: number
): Promise<TransactionReceipt> {
    const tx = {
        from: ownerAccount.address,
        to: GasStationFactoryContractAddress,
        gas,
        data: methodData,
    };

    const signedTx = await web3.eth.accounts.signTransaction(tx, ownerPrivateKey);
    if (!signedTx.rawTransaction) {
        throw new Error('Failed to sign transaction');
    }

    return await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
}

// Functions to interact with the contract

async function deployMachineSmartAccount(
    eoa: string,
    nonce: number,
    signature: string
): Promise<string> {
    const methodData = contract.methods
        .deployMachineSmartAccount(eoa, nonce, signature)
        .encodeABI();

    const receipt = await sendTransaction(methodData, 300000);

    // Type assertion to ensure the correct type
    const deployedAddress = (receipt.events?.MachineSmartAccountDeployed?.returnValues?.deployedAddress as string);

    if (!deployedAddress) {
        throw new Error('Failed to retrieve deployed MachineSmartAccount address');
    }

    console.log('MachineSmartAccount deployed:', deployedAddress);
    return deployedAddress;
}

async function executeTransaction(
    eoa: string,
    machineAddress: string,
    target: string,
    data: string,
    nonce: number,
    signature: string,
    eoaSignature: string
): Promise<void> {
    const methodData = contract.methods
        .executeTransaction(eoa, machineAddress, target, data, nonce, signature, eoaSignature)
        .encodeABI();
    const receipt = await sendTransaction(methodData, 500000);
    console.log('Transaction executed:', receipt);
}

function generateOwnerSignature(eoa: string, target: string, data: string, nonce: number): string {

    const messageHash =  ethers.solidityPackedKeccak256(
        ["address", "address", "address", "bytes", "uint256"],
        [GasStationFactoryContractAddress, eoa, target, data, nonce]
    );

    const signature = ownerAccount.sign(messageHash).signature;

    return signature
}

function generateOwnerDeploySignature(eoa: string, nonce: number): string {

    const deployMessageHash =  ethers.solidityPackedKeccak256(
        ["address", "address", "uint256"],
        [GasStationFactoryContractAddress, eoa, nonce]
      );

    const signature = ownerAccount.sign(deployMessageHash).signature;

    return signature
}

function generateEoaSignature(machineAddress: string, target: string, data: string, nonce: number): string {

    const eoaMessageHash =  ethers.solidityPackedKeccak256(
        ["address", "address", "bytes", "uint256"],
        [machineAddress, target, data, nonce]
      );

    const signature = eoaAccount.sign(eoaMessageHash).signature;

    return signature
}

// Example usage
(async () => {
    try {
        const newGasStation = '0xNewGasStationAddress'; // Replace with actual address
        const eoa = '0xEOAAddress'; // Replace with actual EOA address
        const nonce = 1; // Example nonce
        const target = '0x0000000000000000000000000000000000000801'; // Replace with the target contract address

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

        const calldata = params.replace("0x", addItemFunctionSelector);
        
        const deploySignature = generateOwnerDeploySignature(eoa, nonce)
        const machineAddress = await deployMachineSmartAccount(eoa, nonce, deploySignature);

        const eoaSignature = generateEoaSignature(machineAddress, target, calldata, nonce)
        const ownerSignature = generateOwnerSignature(eoa, target, calldata, nonce)

        await executeTransaction(eoa, machineAddress, target, calldata, nonce, ownerSignature, eoaSignature);
    } catch (error) {
        console.error('Error:', error);
    }
})();