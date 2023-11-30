# Frenrug Smart Contracts

[![Tests](https://github.com/frenrug/contracts/actions/workflows/test_contracts.yml/badge.svg)](https://github.com/frenrug/contracts/actions/workflows/test_contracts.yml)

[Frenrug](https://frenrug.com) is an on-chain AI agent that lives in a [friend.tech](https://friend.tech) chatroom managing a portfolio of keys. Behind the scenes, Frenrug is powered by [Ritual](https://ritual.net).

These smart contracts implement the [Infernet SDK](https://github.com/ritual-net/infernet-sdk) to power the on-chain components of Frenrug.

> [!IMPORTANT]
> You can find the complete documentation of these smart contracts in the [Frenrug docs](https://frenrug.com/docs/smart-contracts).

> [!WARNING]
> The Frenrug smart contracts have not been audited, and while we won’t rug you, you may rug yourself. We recommend proceeding with caution.

## Local deployment and usage

First, ensure you have [Foundry installed locally](https://book.getfoundry.sh/getting-started/installation). A simple way to install is to run to the following command:

```bash
# Install foundryup, follow instructions
curl -L https://foundry.paradigm.xyz | bash
```

### Building and running

To build, run, or execute other commands, you can reference the [Makefile](./Makefile).

The default target (`make`) will:

- Clean existing build outputs
- Install all dependencies
- Format code
- Build code and copy compiled artifacts
- Run test suite

### Deploying

There are also two scripts provided for convenience ([./scripts/Deploy.sol](./scripts/Deploy.sol) and [./scripts/UpdateVerifier.sol](./scripts/UpdateVerifier.sol)) that can be used to deploy the contracts and update the ZK proof verifier, respectively.

## Deployed contracts

The live, deployed contracts can be found as follows:

- Infernet Coordinator contract ([deployed by the Ritual team](https://docs.ritual.net/infernet/sdk/introduction#deployed-contracts)): [0x8D871Ef2826ac9001fB2e33fDD6379b6aaBF449c](https://basescan.org/address/0x8d871ef2826ac9001fb2e33fdd6379b6aabf449c)
- Frenrug contract: [0x5bfe1Ed1741c690eC3e42795cf06a4c38Ed3BC0c](https://basescan.org/address/0x5bfe1Ed1741c690eC3e42795cf06a4c38Ed3BC0c)
- Data Attestation contract: [0xe768F5cf207c4A9919e2259c36Ad289bf26C1439](https://basescan.org/address/0xe768F5cf207c4A9919e2259c36Ad289bf26C1439)
- ZK Proof Verification contract: [0xc4C748261cE010CcB482640e1Ab9a6869af1766F](https://basescan.org/address/0xc4C748261cE010CcB482640e1Ab9a6869af1766F)

You can see `MessageResponse` events emitted by the Frenrug contract [via BaseScan](https://basescan.org/address/0x5bfe1Ed1741c690eC3e42795cf06a4c38Ed3BC0c#events).

> [!WARNING]
> Users cannot interface with these contracts directly (as they are called by
> Infernet nodes processing friend.tech chatroom messages), and as such, you
> should never find yourself in a situation where you need to send a transaction
> to these contracts directly. Do not listen to anyone that suggests otherwise
> and do your own research.

## License

[MIT](./LICENSE)
