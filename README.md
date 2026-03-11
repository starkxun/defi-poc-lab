# DeFi PoC Lab

A practical research repository for **DeFi security vulnerabilities and attack patterns**.

This project systematically demonstrates common **DeFi exploits** through fully reproducible **Proof-of-Concept (PoC)** implementations, including attack contracts, testing environments, and detailed explanations.

The goal is to help **smart contract developers, auditors, and security researchers** understand how real-world DeFi attacks work and how to defend against them.

---

# Overview

DeFi PoC Lab is a **hands-on vulnerability research library** focused on attack modeling and exploit reproduction in decentralized finance protocols.

Each vulnerability is implemented as a **self-contained PoC**, allowing researchers to observe and analyze attack flows under controlled conditions.

The repository focuses on:

• DeFi attack patterns  
• Economic exploit mechanisms  
• Smart contract vulnerabilities  
• Flash loan based attack chains  
• MEV strategies  

All PoCs are implemented with **Foundry**, enabling deterministic testing and easy reproducibility.

---

# Repository Statistics

Current coverage includes:

- **50+ attack patterns**
- **100+ Foundry tests**
- **12+ vulnerability categories**
- Multiple **cross-protocol exploit scenarios**

---

# Attack Categories

The repository currently covers the following vulnerability classes:

---

## Reentrancy Attacks

- Single-function reentrancy
- Cross-function reentrancy
  - DEX reentrancy
  - Lending protocol reentrancy
- Cross-contract reentrancy
  - Router-based reentrancy
  - Oracle reentrancy
  - ERC777 callback reentrancy

---

## Read-Only Attacks

Exploiting read-only functions to manipulate protocol state or extract value.

---

## Delegatecall Hijacking

- Storage collision
- Malicious implementation takeover

---

## Arithmetic Vulnerabilities

- Integer overflow / underflow
- Signed integer misuse
- Unchecked blocks
- Incorrect multiplication/division order
- Precision scaling mismatch

---

## Precision Loss Exploits

- Rounding leakage
- Invariant drift
- Share inflation
- Accounting desynchronization

---

## Oracle Manipulation

- Spot price manipulation
- TWAP manipulation
- Stale price exploitation
- Chainlink heartbeat bypass
- Flash-loan price distortion

---

## Flash Loan Attack Chains

- Basic flash loan attacks
- Flash loan + price manipulation
- Flash loan + reentrancy
- Nested flash loans
- Flash minting
- Cross-protocol exploit chains

---

## AMM-Specific Attacks

- Constant product manipulation (x*y=k)
- Invariant manipulation
- LP share inflation
- Dust attacks
- Fee accounting bugs

---

## MEV Attacks

- Sandwich attacks
- Front-running
- Back-running
- JIT liquidity attacks
- MEV bundles

---

## Access Control Exploits

- Incorrect function visibility
- Missing access control
- Uninitialized proxy
- UUPS upgrade hijacking
- Constructor/initializer confusion

---

## ERC20 Non-Standard Behavior

- Fee-on-transfer tokens
- Elastic supply tokens
- Pausable token accounting issues
- Non-standard return values
- ERC777 callbacks
- Manipulated balanceOf behavior

---

## Economic & Logical Design Flaws

- Missing precondition checks
- Broken invariant assumptions
- Reward debt miscalculation
- Inflationary emission exploits
- Liquidation incentive abuse
- Share dilution attacks

---

## Cross-Chain & Bridge Attacks

- Message replay
- Signature forgery
- Domain separator misuse
- Verification bypass
- Guardian majority compromise
- ChainId replay attacks

---

# Project Structure
```bash
- src/ — PoC source code and tests：
  - EVM-Level Exploits
  - Arithmetic & Precision Attacks
  - Oracle Exploits
  - Flashloan-Based Attack Chains
  - AMM-Specific Attacks
  - Access Control
  - ERC20 Edge Cases
  - Economic Design Bugs
  - Cross-Chain Attacks
```


Each PoC contains:

• Attack contract  
• Vulnerable protocol mock  
• Foundry test  
• Documentation  

---

# Getting Started

Clone the repository:
```shell
git clone https://github.com/starkxun/defi-poc-lab
```

Install dependencies:
```shell
forge install
```

Run tests:
```shell
forge test -vv
```


---

# Why This Repository Exists

Most DeFi vulnerabilities are **not simple coding mistakes**.

They often arise from:

• Economic design flaws  
• Precision issues  
• Oracle assumptions  
• Cross-protocol interactions  

This repository focuses on **attack modeling**, helping auditors identify exploit patterns more effectively.

---

# Intended Audience

This project is useful for:

• Smart contract auditors  
• Security researchers  
• DeFi protocol developers  
• Blockchain security students  

---

# Educational Use Only

All content is provided strictly for **educational and research purposes**.

Do **NOT** use these PoCs against production protocols.

---

# Future Work

Planned additions include:

- Governance attacks
- Layer2-specific vulnerabilities
- Advanced MEV strategies
- Multi-protocol exploit chains
- Real-world incident reproductions

---

# Author

StarkXun

Web3 Security Researcher  
Smart Contract Auditor  

GitHub  
https://github.com/starkxun

---

# License

MIT
