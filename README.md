# Proof of Kernel Work Ethereum Client

## What is Proof of Kernel Work

Proof-of-Kernel-Work (PoKW) is a democratic and low-energy consumption consensus mechanism for distributed access-control protocols. It should be stressed that PoKW does not rely on the use of a particular blockchain technology stack, making PoKW applicable within a broad range of blockchain solutions.

One of the most critical components of a blockchain protocol is its chosen consensus mechanism. Many such mechanisms exist today, including those that rest on classical Byzantine fault tolerant consensus protocols, yet most of these approaches either have severe scalability issues or fail to adequately address concerns such as the ability of insiders to maliciously or unintentionally facilitate an attack of the decentralised data management system.

### Why PoKW?

The Proof-of-Work (PoW) consensus protocol, as currently used in Bitcoin and Ethereum, has been very successful as a consensus mechanism for cryptocurrencies and blockchain systems to date. In simplified terms, the idea behind PoW is that miners within the network race each other to solve a simple cryptographic puzzle for which a solution can only be found by brute-force (trying all possible combinations).

A major concern of this approach, however, is that solving a PoW puzzle is power hungry as many hashes have to be computed before a solution may be found. Moreover, incentive structures for puzzle solving may result in more and more nodes joining such mining races, leading to an even greater consumption of energy on the network in order to sustain a PoW consensus mechanism.

A good example thereof is Bitcoin, where application-specific integrated circuits for PoW were developed in record time and are widely available commercially. This meant that the PoW mining race was no longer democratic as only such high-end hardware made it viable to compete in the race, and only if individual devices/agents would pool their resources in such races. This, combined with the speculation around Bitcoin trading platforms, means that the Bitcoin network can consume as much energy as entire nations. PoW mining races in Bitcoin, therefore, seem to be undemocratic and contribute to global warming.

These issues motivated us to ask ourselves whether one could retain the strong aspects of PoW (notably its resilient and random manner of choosing the leader for the next block), while also weakening or eliminating the disadvantages of PoW discussed above.

Our contributions in this project are a result of trying to answer this question and are as follows:

- we propose a variant of PoW, Proof of Kernel Work (PoKW), based on Cryptographic Sortition that dynamically reduces the mining race to a small kernel of randomly selected nodes
- we show how our PoKW reduces the energy demands of puzzle solving whilst also not increasing abilities of an attacker in an enterprise network
- we identify pertinent attack vectors for blockchains based on PoKW and mitigation measures for such attacks
- we sketch possible ways of realising PoKW-based public networks, in order to create more democratic yet resilient infrastructures for blockchain-facilitated services, and
- we adjust an Ethereum technology stack to accommodate this novel consensus mechanism and report insights from a real-world use case of that system.

### How does it work?

In our approach, the process of electing a leader—who can propose the next block on the chain—relies on PoW. However, we restrict the PoW mining race for the next block by two control mechanisms:

- A dynamic White List which is authenticated on the blockchain and maintains those public keys that are, in principle, eligible to participate in a PoW mining race.
- An adaptive node selection mechanism based on Cryptographic Sortition which determines the superset of nodes that may be eligible to participate in specific tasks of blockchain construction and management. Such tasks may include mining, machine learning, and management of the White List.

![](a.png)

![](b.png)

## Go Ethereum

This work is based on the official Golang implementation of the Ethereum protocol.

[![API Reference](
https://camo.githubusercontent.com/915b7be44ada53c290eb157634330494ebe3e30a/68747470733a2f2f676f646f632e6f72672f6769746875622e636f6d2f676f6c616e672f6764646f3f7374617475732e737667
)](https://godoc.org/github.com/ethereum/go-ethereum)
[![Go Report Card](https://goreportcard.com/badge/github.com/ethereum/go-ethereum)](https://goreportcard.com/report/github.com/ethereum/go-ethereum)

Please refer to the [go-ethereum](https://github.com/ethereum/go-ethereum) for documentation about installing and running the Geth client.


## License

This work and the go-ethereum library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in our repository in the `COPYING.LESSER` file.

The go-ethereum binaries (i.e. all code inside of the `cmd` directory) is licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also
included in our repository in the `COPYING` file.
