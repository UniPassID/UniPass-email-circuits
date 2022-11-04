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

    UnipassVerifierFactory = await ethers.getContractFactory("UnipassVerifier");
    UnipassVerifier = await UnipassVerifierFactory.deploy();

    await UnipassVerifier.deployed();
    console.log(`> [DPLY] Contract deployed, addr=${UnipassVerifier.address}`);

  });

  it("should verify valid email-header-1024 proof correctly", async function () {

    const files1024 = fs.readdirSync("../test_data/inputs_1024");
    for (let i = 0; i < files1024.length; i++) {
      let data = fs.readFileSync(path.join("../test_data/inputs_1024", files1024[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {
        await UnipassVerifier.setupSRSHash(contractInput.srsHash);
        console.log(`[INFO] Setup SRS ... ok`);

        await UnipassVerifier.setupVKHash(
          1024,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
        console.log(`[INFO] Setup setupVKHash ... ok`);
      }

      let chech_tx = await UnipassVerifier.checkPublicInputs1024(
        contractInput.fromIndex,
        contractInput.fromLen,
        contractInput.publicInputs,
      )

      // wait the tx being mined
      let check_rc = await chech_tx.wait(1);
      console.log(`[Info] Check public input >>> gasUsed: ${check_rc.gasUsed}`);

      let tx = await UnipassVerifier.verifyV1024(
        contractInput.publicInputsNum,
        contractInput.domainSize,
        contractInput.vkData,
        contractInput.publicInputs,
        contractInput.proof
      );
      console.log(`[INFO] Verify ... ok`);

      // wait the tx being mined
      let rc = await tx.wait(1);
      // console.log(rc.logs);
      console.log(`    >>> gasUsed: ${rc.gasUsed}`);

      let VerifierABI = ["event Verified(address caller, uint256 success)"];
      let iface = new ethers.utils.Interface(VerifierABI);

      let ecode = -1;
      if (rc.logs.length >= 1) {
        let log = iface.parseLog(rc.logs[0]);
        ecode = log.args["success"];
      }
      if (ecode == 1) {
        console.log(`[INFO] Verification Succeed! ✅`);
      } else {
        console.log(`[INFO] Verification Failed! Ecode=${ecode} ❌`);
      }

      expect(ecode).to.equal(1);
    }
  });

  it("should verify valid email-header-2048 proof correctly", async function () {

    const files2048 = fs.readdirSync("../test_data/inputs_2048");
    for (let i = 0; i < files2048.length; i++) {
      let data = fs.readFileSync(path.join("../test_data/inputs_2048", files2048[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {

        await UnipassVerifier.setupSRSHash(contractInput.srsHash);
        console.log(`[INFO] Setup SRS ... ok`);

        await UnipassVerifier.setupVKHash(
          2048,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
        console.log(`[INFO] Setup setupVKHash ... ok`);
      }

      let chech_tx = await UnipassVerifier.checkPublicInputs2048(
        contractInput.fromIndex,
        contractInput.fromLen,
        contractInput.publicInputs,
      )

      // wait the tx being mined
      let check_rc = await chech_tx.wait(1);
      console.log(`[Info] Check public input >>> gasUsed: ${check_rc.gasUsed}`);

      let tx = await UnipassVerifier.verifyV2048(
        contractInput.publicInputsNum,
        contractInput.domainSize,
        contractInput.vkData,
        contractInput.publicInputs,
        contractInput.proof
      );
      console.log(`[INFO] Verify ... ok`);

      // wait the tx being mined
      let rc = await tx.wait(1);
      // console.log(rc.logs);
      console.log(`    >>> gasUsed: ${rc.gasUsed}`);

      let VerifierABI = ["event Verified(address caller, uint256 success)"];
      let iface = new ethers.utils.Interface(VerifierABI);

      let ecode = -1;
      if (rc.logs.length >= 1) {
        let log = iface.parseLog(rc.logs[0]);
        ecode = log.args["success"];
      }
      if (ecode == 1) {
        console.log(`[INFO] Verification Succeed! ✅`);
      } else {
        console.log(`[INFO] Verification Failed! Ecode=${ecode} ❌`);
      }

      expect(ecode).to.equal(1);
    }

  });
});