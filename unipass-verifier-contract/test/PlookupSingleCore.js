const { expect } = require("chai");
const fs = require('fs');
const path = require('path');
const promisify = require('util').promisify;

const open = promisify(fs.open);
const read = promisify(fs.read);
const close = promisify(fs.close);

describe("plonk contract", function () {
  before(async function () {
    [deployer] = await ethers.getSigners();
    console.log(`> [INIT] deployer.address = ${deployer.address} ...... `);

    PlonkSingle = await ethers.getContractFactory("SingleVerifierWithDeserialize");
    hardhatPlonkSingle = await PlonkSingle.deploy();

    await hardhatPlonkSingle.deployed();
    console.log(`> [DPLY] Contract deployed, addr=${hardhatPlonkSingle.address}  `);
  });

  it("part verify test", async function () {
    console.log("test start");

    const files1024 = fs.readdirSync("../test_data/inputs_1024");
    for (let i = 0; i < files1024.length; i++) {
      let data = fs.readFileSync(path.join("../test_data/inputs_1024", files1024[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {
        var res000 = await hardhatPlonkSingle.vkhash_init(
          1024,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
      }

      var res1024 = await hardhatPlonkSingle.multy_verify1024(
        contractInput.publicInputsNum,
        contractInput.domainSize,
        contractInput.vkData,
        contractInput.publicInputs,
        contractInput.proof
      );

      // wait the tx being mined
      mine_res = await res1024.wait();
      console.log(mine_res);
    }

    const files2048 = fs.readdirSync("../test_data/inputs_2048");
    for (let i = 0; i < files2048.length; i++) {
      let data = fs.readFileSync(path.join("../test_data/inputs_2048", files2048[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {
        var res000 = await hardhatPlonkSingle.vkhash_init(
          2048,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
      }

      var res2048 = await hardhatPlonkSingle.multy_verify2048(
        contractInput.publicInputsNum,
        contractInput.domainSize,
        contractInput.vkData,
        contractInput.publicInputs,
        contractInput.proof
      );

      // wait the tx being mined
      mine_res = await res2048.wait();
      console.log(mine_res);
    }
  });


});