const { ethers } = require("hardhat");
require("dotenv").config();

async function main() {
    console.log("Starting MachineStationFactory deployment...");

    // Get environment variables (following foundry script pattern)
    const deployerPrivateKey = process.env.DEPLOYER_PRIVATE_KEY;
    const adminAddress = process.env.ADMIN_ADDRESS;
    const stationManager = process.env.STATION_MANAGER_ADDRESS;
    const txRefundAmount = process.env.TX_REFUND_AMOUNT;

    // Validate environment variables
    if (!deployerPrivateKey) {
        throw new Error("DEPLOYER_PRIVATE_KEY environment variable is required");
    }
    if (!adminAddress) {
        throw new Error("ADMIN_ADDRESS environment variable is required");
    }
    if (!stationManager) {
        throw new Error("STATION_MANAGER_ADDRESS environment variable is required");
    }
    if (!txRefundAmount) {
        throw new Error("TX_REFUND_AMOUNT environment variable is required");
    }

    // Create deployer signer from private key
    const deployerWallet = new ethers.Wallet(deployerPrivateKey, ethers.provider);
    console.log("Deploying with account:", deployerWallet.address);

    // Get account balance
    const balance = await ethers.provider.getBalance(deployerWallet.address);
    console.log("Account balance:", ethers.formatEther(balance), "Native Token");

    try {
        // Get the contract factory
        const MachineStationFactory = await ethers.getContractFactory("MachineStationFactory", deployerWallet);

        // Deploy the contract
        console.log("Deploying MachineStationFactory...");
        const factory = await MachineStationFactory.deploy(
            adminAddress,
            stationManager,
            txRefundAmount
        );

        // Wait for deployment
        await factory.waitForDeployment();
        const factoryAddress = await factory.getAddress();

        console.log("MachineStationFactory deployed to:", factoryAddress);
        console.log("Admin address:", adminAddress);
        console.log("Station Manager address:", stationManager);

        return factory;

    } catch (error) {
        console.error("❌ Deployment failed:", error.message);
        throw error;
    }
}

// Execute deployment
if (require.main === module) {
    main()
        .then(() => {
            console.log("🎉 Deployment completed successfully!");
            process.exit(0);
        })
        .catch((error) => {
            console.error("💥 Deployment failed:", error);
            process.exit(1);
        });
}

module.exports = main;
