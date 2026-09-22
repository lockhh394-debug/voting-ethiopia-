const { expect } = require("chai");
const { ethers } = require("hardhat");
const snarkjs = require("snarkjs");
const circomlib = require("circomlibjs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const WASM = path.join(ROOT, "build/zk/VoteValidity_js/VoteValidity.wasm");
const ZKEY = path.join(ROOT, "build/zk/VoteValidity.zkey");

let poseidon;
let F;

function asBigInt(value) {
  return BigInt(value.toString());
}

function hash(values) {
  return asBigInt(F.toObject(poseidon(values.map(BigInt))));
}

async function deployGovernanceVoting(memberAddresses, threshold) {
  const verifierFactory = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await verifierFactory.deploy();
  await verifier.waitForDeployment();

  const poseidonFactory = await ethers.getContractFactory("PoseidonT3");
  const poseidonLibrary = await poseidonFactory.deploy();
  await poseidonLibrary.waitForDeployment();

  const votingFactory = await ethers.getContractFactory("ZKVoting", {
    libraries: {
      PoseidonT3: await poseidonLibrary.getAddress()
    }
  });
  const voting = await votingFactory.deploy(
    await verifier.getAddress(),
    memberAddresses,
    threshold
  );
  await voting.waitForDeployment();

  return voting;
}

function treeRoot(leaf, siblings, indices) {
  let node = leaf;
  for (let i = 0; i < siblings.length; i += 1) {
    node = indices[i] === 0
      ? hash([node, siblings[i]])
      : hash([siblings[i], node]);
  }
  return node;
}

function merkleTree(credentials) {
  let level = credentials.map((credential) => hash([credential]));
  const levels = [level];

  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(hash([level[i], level[i + 1]]));
    }
    level = next;
    levels.push(level);
  }

  return {
    root: level[0],
    pathFor(index) {
      const siblings = [];
      const indices = [];
      let position = index;
      for (let depth = 0; depth < levels.length - 1; depth += 1) {
        siblings.push(levels[depth][position ^ 1]);
        indices.push(position % 2);
        position = Math.floor(position / 2);
      }
      return { siblings, indices };
    }
  };
}

function candidateMerkleTree(candidateIds) {
  const sorted = [...candidateIds].map(BigInt).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (sorted.length === 0 || sorted.length > 8) throw new Error("candidateIds must contain 1..8 ids");
  if (sorted.some((id) => id === 0n)) throw new Error("candidate id cannot be zero");
  for (let i = 1; i < sorted.length; i += 1) {
    if (sorted[i] === sorted[i - 1]) throw new Error("duplicate candidate id");
  }

  let level = Array.from({ length: 8 }, (_, i) =>
    i < sorted.length ? hash([sorted[i], 0n]) : 0n
  );
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(hash([level[i], level[i + 1]]));
    level = next;
    levels.push(level);
  }

  return {
    root: level[0],
    pathFor(candidateId) {
      const index = sorted.findIndex((id) => id === BigInt(candidateId));
      if (index < 0) throw new Error("candidate is not registered");
      const siblings = [];
      const indices = [];
      let position = index;
      for (let depth = 0; depth < 3; depth += 1) {
        siblings.push(levels[depth][position ^ 1]);
        indices.push(position % 2);
        position = Math.floor(position / 2);
      }
      return { siblings, indices };
    }
  };
}

async function makeBallot({
  credential,
  electionId,
  candidateChoice,
  voteSalt,
  siblings,
  indices,
  candidateIds = [7n, 8n, 9n]
}) {
  const eligibilityRoot = treeRoot(hash([credential]), siblings, indices);
  const candidates = candidateMerkleTree(candidateIds);
  const candidatePath = candidates.pathFor(candidateChoice);
  const scopeRoot = hash([eligibilityRoot, candidates.root]);
  const input = {
    credential: credential.toString(),
    electionId: electionId.toString(),
    candidateChoice: candidateChoice.toString(),
    voteSalt: voteSalt.toString(),
    eligibilityRoot: eligibilityRoot.toString(),
    eligibilityPathElements: siblings.map((x) => x.toString()),
    eligibilityPathIndices: indices.map((x) => x.toString()),
    candidateRoot: candidates.root.toString(),
    candidatePathElements: candidatePath.siblings.map((x) => x.toString()),
    candidatePathIndices: candidatePath.indices.map((x) => x.toString()),
    scopeRoot: scopeRoot.toString()
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const calldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, signals] = JSON.parse(`[${calldata}]`);
  return {
    a,
    b,
    c,
    signals,
    eligibilityRoot,
    candidateRoot: candidates.root,
    scopeRoot,
    voteCommitment: hash([candidateChoice, voteSalt]),
    nullifierHash: hash([credential, electionId])
  };
}
describe("ZKVoting adversarial audit findings", function () {
  let voting;
  let governanceMember1;
  let governanceMember2;
  let governanceMember3;
  let attacker;
  let validBallot;

  const credential = 123456789n;
  const siblings = [11n, 22n, 33n];
  const indices = [0, 1, 0];

  before(async function () {
    poseidon = await circomlib.buildPoseidon();
    F = poseidon.F;
  });

  beforeEach(async function () {
    [
      governanceMember1,
      governanceMember2,
      governanceMember3,
      attacker
    ] = await ethers.getSigners();

    voting = await deployGovernanceVoting(
      [
        governanceMember1.address,
        governanceMember2.address,
        governanceMember3.address
      ],
      2
    );

    const now = (await ethers.provider.getBlock("latest")).timestamp;
    validBallot = await makeBallot({
      credential,
      electionId: 1n,
      candidateChoice: 7n,
      voteSalt: 888n,
      siblings,
      indices
    });

    await voting.proposeElection(
      "Federal council",
      validBallot.eligibilityRoot,
      now + 10,
      now + 1000,
      [7n, 8n, 9n]
    );
    await voting.connect(governanceMember1).approveElection(1);
    await voting.connect(governanceMember2).approveElection(1);
  });

  async function advance(seconds) {
    await ethers.provider.send("evm_increaseTime", [seconds]);
    await ethers.provider.send("evm_mine");
  }

  async function activateElection(electionId = 1) {
    await advance(11);
    await voting.activateElection(electionId);
  }

  it("rejects candidate proofs outside the governed candidate set and rejects unregistered reveals", async function () {
    await activateElection();

    const arbitraryCandidate = 999999n;
    let proofRejected = false;
    try {
      await makeBallot({
        credential,
        electionId: 1n,
        candidateChoice: arbitraryCandidate,
        voteSalt: 424242n,
        siblings,
        indices
      });
    } catch (_) {
      proofRejected = true;
    }
    expect(proofRejected).to.equal(true);

    await voting.castPrivateVote(
      1,
      validBallot.a,
      validBallot.b,
      validBallot.c,
      validBallot.signals
    );
    await advance(1001);
    await voting.endElection(1);

    await expect(voting.connect(attacker).revealVote(1, arbitraryCandidate, 888n))
      .to.be.revertedWith("Candidate not registered");
    expect(await voting.getVoteCount(1, arbitraryCandidate)).to.equal(0n);
  });

  it("shows that any address can submit a valid credential proof for another voter", async function () {
    await activateElection();

    await voting.connect(attacker).castPrivateVote(
      1,
      validBallot.a,
      validBallot.b,
      validBallot.c,
      validBallot.signals
    );

    expect((await voting.elections(1)).acceptedBallots).to.equal(1n);
  });

  it("shows that two credentials in one root can produce two ballots with no issuer or person binding", async function () {
    const credentialA = 111111n;
    const credentialB = 222222n;
    const tree = merkleTree([
      credentialA,
      credentialB,
      300001n,
      300002n,
      300003n,
      300004n,
      300005n,
      300006n
    ]);

    const now = (await ethers.provider.getBlock("latest")).timestamp;
    await voting.proposeElection("Credential duplication", tree.root, now + 10, now + 1000, [7n, 8n]);
    await voting.connect(governanceMember1).approveElection(2);
    await voting.connect(governanceMember2).approveElection(2);
    await advance(11);
    await voting.activateElection(2);

    const pathA = tree.pathFor(0);
    const pathB = tree.pathFor(1);
    const ballotA = await makeBallot({
      credential: credentialA,
      electionId: 2n,
      candidateChoice: 7n,
      voteSalt: 700n,
      candidateIds: [7n, 8n],
      siblings: pathA.siblings,
      indices: pathA.indices
    });
    const ballotB = await makeBallot({
      credential: credentialB,
      electionId: 2n,
      candidateChoice: 8n,
      voteSalt: 800n,
      candidateIds: [7n, 8n],
      siblings: pathB.siblings,
      indices: pathB.indices
    });

    await voting.connect(attacker).castPrivateVote(
      2,
      ballotA.a,
      ballotA.b,
      ballotA.c,
      ballotA.signals
    );
    await voting.connect(attacker).castPrivateVote(
      2,
      ballotB.a,
      ballotB.b,
      ballotB.c,
      ballotB.signals
    );

    expect((await voting.elections(2)).acceptedBallots).to.equal(2n);
  });

  it("confirms that the ZK proof hides the credential but proves only root membership, not identity uniqueness", async function () {
    await activateElection();
    const tx = await voting.castPrivateVote(
      1,
      validBallot.a,
      validBallot.b,
      validBallot.c,
      validBallot.signals
    );
    const receipt = await tx.wait();
    const accepted = receipt.logs
      .map((log) => {
        try { return voting.interface.parseLog(log); } catch (_) { return null; }
      })
      .find((log) => log && log.name === "VoteAccepted");

    expect(accepted.args.length).to.equal(3);
    expect(accepted.args).to.not.have.property("credential");
    expect(validBallot.signals).to.have.length(4);
    expect(validBallot.signals).to.not.include(credential.toString());
  });

  it("shows that proposal, activation, ending, and reveal are permissionless after approval", async function () {
    const now = (await ethers.provider.getBlock("latest")).timestamp;
    await voting.connect(attacker).proposeElection(
      "Permissionless lifecycle",
      validBallot.eligibilityRoot,
      now + 20,
      now + 1000,
      [7n, 8n, 9n]
    );
    await voting.connect(governanceMember1).approveElection(2);
    await voting.connect(governanceMember2).approveElection(2);

    await advance(21);
    await voting.connect(attacker).activateElection(2);
    expect((await voting.elections(2)).votingStarted).to.equal(true);

    await advance(980);
    await voting.connect(attacker).endElection(2);
    expect((await voting.elections(2)).ended).to.equal(true);

    await expect(voting.connect(attacker).finalizeElection(2))
      .to.be.revertedWith("Reveal period active");

    const functionNames = voting.interface.fragments
      .filter((fragment) => fragment.type === "function")
      .map((fragment) => fragment.name);
    expect(functionNames).to.include("finalizeElection");
  });

  it("keeps the election open for reveals until the reveal deadline, then finalizes once", async function () {
    await activateElection();
    await voting.castPrivateVote(1, validBallot.a, validBallot.b, validBallot.c, validBallot.signals);
    await advance(1001);
    await voting.endElection(1);

    await voting.revealVote(1, 7n, 888n);
    expect((await voting.elections(1)).revealedBallots).to.equal(1n);

    await expect(voting.finalizeElection(1)).to.be.revertedWith("Reveal period active");
    await advance(24 * 60 * 60 + 1);
    await voting.finalizeElection(1);
    expect((await voting.elections(1)).finalized).to.equal(true);

    await expect(voting.revealVote(1, 7n, 888n)).to.be.revertedWith("Finalized");
    await expect(voting.finalizeElection(1)).to.be.revertedWith("Already finalized");
  });

  it("counts an approval from a removed member in an election that is still pending", async function () {
    const now = (await ethers.provider.getBlock("latest")).timestamp;
    await voting.proposeElection(
      "Pending election",
      validBallot.eligibilityRoot,
      now + 100,
      now + 2000,
      [7n, 8n, 9n]
    );
    await voting.connect(governanceMember1).approveElection(2);

    await voting.connect(governanceMember2)
      .proposeGovernanceMemberChange(governanceMember1.address, false);
    await voting.connect(governanceMember2).approveGovernanceMemberChange(1);
    await voting.connect(governanceMember3).approveGovernanceMemberChange(1);
    expect(await voting.isGovernanceMember(governanceMember1.address)).to.equal(false);

    // The removed member's old approval remains in the threshold count.
    await voting.connect(governanceMember3).approveElection(2);
    expect((await voting.elections(2)).proposalApproved).to.equal(true);
    expect(await voting.electionApprovalCount(2)).to.equal(2n);
  });

  it("counts an approval from a removed member in a pending membership change", async function () {
    await voting.connect(governanceMember1)
      .proposeGovernanceMemberChange(attacker.address, true);
    await voting.connect(governanceMember1).approveGovernanceMemberChange(1);

    await voting.connect(governanceMember2)
      .proposeGovernanceMemberChange(governanceMember1.address, false);
    await voting.connect(governanceMember2).approveGovernanceMemberChange(2);
    await voting.connect(governanceMember3).approveGovernanceMemberChange(2);
    expect(await voting.isGovernanceMember(governanceMember1.address)).to.equal(false);

    // A current member can combine with the removed member's old approval.
    await voting.connect(governanceMember3).approveGovernanceMemberChange(1);
    expect(await voting.isGovernanceMember(attacker.address)).to.equal(true);
  });

  it("does not expose a governed threshold-change operation", async function () {
    const functionNames = voting.interface.fragments
      .filter((fragment) => fragment.type === "function")
      .map((fragment) => fragment.name);

    expect(await voting.approvalThreshold()).to.equal(2n);
    expect(functionNames).to.not.include("setApprovalThreshold");
    expect(functionNames).to.not.include("proposeThresholdChange");
  });

  it("keeps the removal floor when concurrent removals would cross the threshold", async function () {
    await voting.connect(governanceMember1)
      .proposeGovernanceMemberChange(governanceMember3.address, false);
    await voting.connect(governanceMember1)
      .proposeGovernanceMemberChange(governanceMember2.address, false);

    await voting.connect(governanceMember1).approveGovernanceMemberChange(1);
    await voting.connect(governanceMember1).approveGovernanceMemberChange(2);
    await voting.connect(governanceMember2).approveGovernanceMemberChange(1);
    expect(await voting.isGovernanceMember(governanceMember3.address)).to.equal(false);

    await expect(
      voting.connect(governanceMember2).approveGovernanceMemberChange(2)
    ).to.be.revertedWith("Cannot remove below threshold");
    expect(await voting.isGovernanceMember(governanceMember2.address)).to.equal(true);
    expect(await voting.isGovernanceMember(governanceMember1.address)).to.equal(true);
  });
});


