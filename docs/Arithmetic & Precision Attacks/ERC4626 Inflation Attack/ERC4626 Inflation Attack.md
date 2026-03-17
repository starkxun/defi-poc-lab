# HAL-01: ERC4626 Inflation Attack — PoC

## 概述

演示 ERC4626 Vault 的 Inflation Attack（通胀攻击 / 捐款攻击），以及 virtual shares 防御机制如何消除该漏洞。

## 快速开始

```bash

# 1. 运行全部 Scene
forge test -vv --match-contract InflationAttackPoC

# 2. 只跑攻击场景
forge test -vv --match-test test_InflationAttack_VulnerableVault

# 3. 只跑防御场景
forge test -vv --match-test test_InflationAttack_SafeVault_Defended

# 4. 只跑数学推导
forge test -vv --match-test test_MathWalkthrough
```

## 攻击原理

### ERC4626 shares 计算公式

```
shares = assets_deposited * totalSupply / totalAssets   ← 整数除法
```

### 攻击步骤

```
Step 1  attacker.deposit(1 wei)
        → shares = 1, totalSupply = 1, totalAssets = 1

Step 2  attacker.transfer(vault, 10000e18 - 1)          ← 直接转账，不走 deposit
        → totalAssets = 10000e18, totalSupply 不变 = 1
        → share 价格 = 10000e18 / 1 = 10000e18

Step 3  victim.deposit(19999e18)
        → shares = 19999e18 * 1 / 10000e18 = 1.9999...
        → 整数截断 → victim 只得到 1 share !!

Step 4  vault 状态: totalAssets = 29999e18, totalSupply = 2

Step 5  attacker.redeem(1 share)
        → assets = 1 * 29999e18 / 2 = 14999e18
        → 攻击者净赚 ~4999e18
        → victim 损失约 5000e18
```

### Virtual Shares 防御

```
安全公式:
  shares = assets * (totalSupply + VIRTUAL_SHARES) / (totalAssets + VIRTUAL_ASSETS)

即使攻击者捐 10000e18，分母里的 VIRTUAL_ASSETS 使得:
  share价格 ≈ (10000e18 + 1) / (1 + 1000) ≈ 9990e15   ← 远低于攻击阈值

victim 能拿到正常数量的 shares，攻击失败。
```

## 文件结构

```
src/Arithmetic & Precision Attacks/ERC4626 Inflation Attack/
  VulnerableVault.sol   — 无保护的 ERC4626 vault（原始整数除法）
  SafeVault.sol         — 带 virtual shares 的安全 vault
test/
  InflationAttackPoC.t.sol — 三个 Scene 的完整 PoC
```

## 预期输出摘要

```
Scene 1 (攻击成功):
  victim shares received  = 1          ← 被截断
  victim net loss         ≈ 5000e18
  attacker net profit     ≈ 4999e18

Scene 2 (防御成功):
  victim shares received  >> 1         ← 正常数量
  attacker net gain       = 0

Scene 3 (数学验证):
  纯 pure 函数，无状态修改，验证公式
```

## 参考

- [EIP-4626](https://eips.ethereum.org/EIPS/eip-4626)
- [OpenZeppelin ERC4626 Virtual Offset](https://docs.openzeppelin.com/contracts/4.x/erc4626)
- [Trail of Bits: ERC4626 Inflation Attacks](https://blog.trailofbits.com/2022/12/06/the-dangers-of-price-oracles-in-smart-contracts/)
