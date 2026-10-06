require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true,
    },
  },
  networks: {
    hardhat: {
      // Local Hardhat Network — used for testing and compilation checks
    },
    sepolia: {
      // Set SEPOLIA_RPC_URL and DEPLOYER_PRIVATE_KEY in a .env file
      // and uncomment the lines below for live deployment:
      //
      // url: process.env.SEPOLIA_RPC_URL || "",
      // accounts: process.env.DEPLOYER_PRIVATE_KEY
      //   ? [process.env.DEPLOYER_PRIVATE_KEY]
      //   : [],
      //
      // Placeholders (compilation-safe):
      url: "",
      accounts: [],
    },
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "USD",
  },
  etherscan: {
    // apiKey: process.env.ETHERSCAN_API_KEY,
  },
  paths: {
    sources:   "./contracts",
    tests:     "./test",
    cache:     "./cache",
    artifacts: "./artifacts",
  },
};