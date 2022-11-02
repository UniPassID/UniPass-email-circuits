require("@nomiclabs/hardhat-waffle");
require('hardhat-contract-sizer');
// require("hardhat-gas-reporter");

task("ptest", "test sols").setAction(async () => {
    // console.log("Hello, hardhat");
});

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
 module.exports = {
    solidity: {
      version: "0.6.12",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    },
    
    contractSizer: {
      alphaSort: true,
      runOnCompile: false, // 这个地方推荐默认设置 false 
      disambiguatePaths: false,
    },
    // gasReporter: {
    //   currency: 'ETH',
    //   gasPrice: 21,
    //   enabled: true,
    //   onlyCalledMethods: false
    // }
  }