require('@nomicfoundation/hardhat-ethers');
require('dotenv').config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.25",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    agung: {
      url: process.env.BASE_URL_AGUNG,
      accounts: [`${process.env.DEPLOYER_PRIVATE_KEY}`],
      chainId: 9990,
    },
    peaq: {
      url: process.env.BASE_URL_PEAQ,
      accounts: [`${process.env.DEPLOYER_PRIVATE_KEY}`],
      chainId: 3338,
    },
  },
  paths: {
    sources: "./src",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
};