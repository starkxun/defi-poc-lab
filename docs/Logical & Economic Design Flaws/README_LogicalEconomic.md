# 逻辑与经济设计缺陷 - 完整学习指南


前几个模块的漏洞（重入、精度损失、非标准代币）通常需要技术层面的"技巧"才能利用。
而**逻辑与经济设计缺陷**是最危险的一类——它们往往在代码本身没有明显错误的情况下存在，
漏洞藏在**协议的经济逻辑**或**隐含假设**中，审计工具扫不出来，只有深度理解协议才能发现。

**这也是区分"写 PoC 的学生"和"真正的安全研究员"的关键技能。**

### 与 Balancer V2 研究的关联

```
场景1 前置条件缺失  → joinPool/exitPool 的 minBptOut 不可为零（滑点保护）
场景2 不变量错误    → BPT 初始化的 MINIMUM_BPT 死亡份额机制
场景3 奖励债务错误  → gauge 的 integrate_fraction 等价于 accRPS，错误 = 重复 claim BAL
场景4 排放通胀      → veBAL 时间加权投票权防止即时追溯历史排放
场景5 清算奖励滥用  → Balancer 价格失真时的外部清算奖励设计
场景6 份额稀释      → ComposableStablePool 初始化 MINIMUM_BPT = 1e6
```

**模块覆盖损失：超过 $600M 真实案例**

---

## 快速开始

```bash
# 运行所有测试
forge test --match-contract LogicalEconomicTest -vv

# 单场景测试
forge test --match-test testMissingPrecondition -vvv
forge test --match-test testInvariantFirstDeposit -vvv
forge test --match-test testRewardDebtDoubleHarvest -vvv
forge test --match-test testEmissionInflation -vvv
forge test --match-test testLiquidationBonusAbuse -vvv
forge test --match-test testShareDilution -vvv

# 安全实现验证
forge test --match-test testSafe -vvv
```

---

## 6 大核心场景

---

### 场景 1：缺失前置条件检查 (Missing Precondition Checks)

#### 什么是前置条件？

前置条件（precondition）是函数在执行前**必须为真**的条件。
缺少前置条件检查，函数会在无效输入下继续执行，产生意外状态。

#### 五大常见遗漏

| 遗漏类型 | 漏洞效果 | 防御方式 |
|----------|----------|----------|
| 非零金额检查 | 零额操作绕过副作用（如重置时间锁）| `require(amount > 0)` |
| 时间锁检查 | 立即提取应锁定资产 | `require(block.timestamp >= lockUntil)` |
| 滑点保护 | 价格操纵后用户损失 | `require(amountOut >= minOut)` |
| 零地址检查 | 永久失去合约控制权 | `require(addr != address(0))` |
| 余额一致性 | 迁移/提款超出实际余额 | `require(balance >= totalLocked)` |

#### 真实案例

**Uranium Finance（2021年4月，损失 $50M）**
```
漏洞：迁移合约时，计算公式写成 amount * 10000 而非 amount * 100
      等效于"缺少对迁移金额的正确验证"
结果：所有流动性被一次性转走
```

**Harvest Finance（2020年10月，损失 $34M）**
```
漏洞：rebalance 函数忽略了 minOut 滑点参数
      价格预言机被操控后，rebalance 以极差价格执行
结果：攻击者操控 USDC/USDT Curve 池，反复 deposit/withdraw 套利
```

#### 攻击流程

```
目标：绕过 7 天时间锁，立即提款

Step 1: deposit(1000 tokens) → lockUntil = now + 7 days
Step 2: withdraw(1000 tokens) ← 缺少时间锁检查，直接成功
Step 3: 资金被提走，时间锁形同虚设

次级攻击：
Step 1: deposit(1000 tokens) → lockUntil = now + 7 days
Step 2: deposit(0 tokens)    → lockUntil 被重置为 now + 7 days（但副作用可用）
         ↑ 零额 deposit 可用于触发其他状态重置，如 snapshot 更新、奖励结算等
```

#### 核心防御代码

```solidity
function withdraw(uint256 amount) external {
    require(amount > 0,                               "Zero amount");    // ✓ 非零
    require(balances[msg.sender] >= amount,           "Insufficient");   // ✓ 余额
    require(block.timestamp >= lockUntil[msg.sender], "Still locked");   // ✓ 时间锁
    // ...
}
```

---

### 场景 2：不变量假设错误 (Incorrect Invariant Assumptions)

#### 什么是协议不变量？

协议不变量是"在任何正常操作后都应该保持为真的条件"。
例如：`totalShares * assetPerShare == totalAssets`

错误的不变量假设是：**"totalShares > 0 时，新存款的汇率合理"**

#### 首存攻击（First Depositor Attack）

这是 ERC-4626 Vault 最经典的不变量漏洞：

```
初始状态：totalShares = 0, totalAssets = 0

Step 1：攻击者存入 1 wei
  shareMinted = 1 (totalShares == 0 时直接等于 assets)
  totalShares = 1, totalAssets = 1

Step 2：攻击者直接向合约转入 100,000 tokens（不通过 deposit）
  totalAssets 变为 100,001（同步后）
  totalShares 仍为 1
  汇率：1 share = 100,001 tokens

Step 3：受害者存入 50,000 tokens
  shareMinted = (50,000 * 1) / 100,001 = 0  ← 取整为 0
  require(shares > 0) → revert！受害者存款失败

  或者：受害者存入 100,001 tokens
  shareMinted = (100,001 * 1) / 100,001 = 1  ← 只得到 1 share
  但攻击者赎回 1 share = (1 * 200,002) / 2 = 100,001
  攻击者净赚 ≈ 50,000 tokens
```

#### 真实案例

**多个 ERC-4626 Vault（2022-2023，数百万美元损失）**
```
协议：各种 Yield Vault 实现
漏洞：未实现虚拟偏移量或死亡份额
结果：首次部署后被机器人监控，立即执行首存攻击
```

**Mango Markets（2022年10月，损失 $116M）**
```
不变量假设：自身 MNGO 代币价格不可被单人控制
攻击者：同时在两个账户开多空仓
       操控 MNGO 预言机价格 → 抵押品价值虚高 → 借走 $116M
```

#### 核心防御：虚拟偏移量（OpenZeppelin ERC-4626）

```solidity
uint256 private constant VIRTUAL_SHARES = 1e3;
uint256 private constant VIRTUAL_ASSETS = 1;

// totalShares 初始化为 VIRTUAL_SHARES，永远不会为 0
constructor() {
    totalShares = VIRTUAL_SHARES;
    totalAssets = VIRTUAL_ASSETS;
}

function deposit(uint256 assets) external {
    // 虚拟偏移量使攻击成本 = donateAmount * VIRTUAL_SHARES 才能操控 1 share
    uint256 shares = assets * (totalShares + VIRTUAL_SHARES)
                            / (totalAssets  + VIRTUAL_ASSETS);
    // ...
}
```

---

### 场景 3：奖励债务计算错误 (Reward Debt Miscalculation)

#### MasterChef 奖励公式

```
全局变量：
  accRPS += (新区块奖励 * PRECISION) / totalStaked  // 每次有操作时更新

用户变量：
  pending    = user.amount * accRPS / PRECISION - user.rewardDebt
  rewardDebt = user.amount * accRPS / PRECISION    // 操作后必须重设
```

`rewardDebt` 的本质：**"假设用户从第 0 个区块就参与了，应该已经领取了多少奖励"**
通过减去这个虚构的"已领取"量，得到用户实际应得的增量奖励。

#### 三种常见错误

```solidity
//  错误1：deposit 时用 += 而非 = 更新 rewardDebt
u.rewardDebt += (amount * accRPS) / PREC;
// 正确：u.rewardDebt = u.amount * accRPS / PREC;

//  错误2：withdraw 后忘记更新 rewardDebt
u.amount -= amount;
// 遗漏：u.rewardDebt = u.amount * accRPS / PREC;

//  错误3：harvest 未更新 rewardDebt（最严重，可无限复现）
function harvest() external {
    uint256 pending = u.amount * accRPS / PREC - u.rewardDebt;
    // 遗漏：u.rewardDebt = u.amount * accRPS / PREC;
    rewardToken.transfer(msg.sender, pending);
    // 下次调用，pending 相同，可以无限领取
}
```

#### 无限 Harvest 攻击流程

```
Step 1: stake(1000 tokens) → deposit 记录 rewardDebt
Step 2: 等待 100 个区块，积累 100 * 1e18 奖励
Step 3: harvest() → pending = 100e18，但 rewardDebt 未更新
Step 4: harvest() → pending 仍 = 100e18（因为 rewardDebt 未变）
Step 5: 重复 N 次 → 提取 N * 100e18 奖励
```

#### 真实案例

**Pancake Bunny（2021年5月，损失 $45M）**
```
奖励计算结合价格操纵：
  闪电贷大量 BNB → 推高 BUNNY 价格
  BUNNY 奖励按价格计算 → 奖励数量虚高
  领取虚高奖励 → 抛售 BUNNY → 价格崩溃
```

#### 核心防御

```solidity
// 每个操作后的标准模式：
function harvest() external {
    _update();
    uint256 pending = (u.amount * accRPS) / PREC - u.rewardDebt;
    u.rewardDebt = (u.amount * accRPS) / PREC;  // ✓ 必须更新！
    if (pending > 0) rewardToken.transfer(msg.sender, pending);
}
```

---

### 场景 4：通胀型排放攻击 (Emission Inflation)

#### 两种奖励分配模式对比

```
模式A：快照分配（ 有漏洞）
  每隔一段时间，按"当前质押比例"分配积累的奖励
  问题：攻击者等待大量奖励积累 → 瞬间质押大量代币 → 按新比例独吞历史奖励

模式B：MasterChef accRPS（安全）
  每区块更新 accRPS（全局累计每份额奖励）
  用户入场时记录当前 accRPS 为 rewardDebt
  pending = amount * currentAccRPS - rewardDebt
  新用户无法追溯历史 accRPS → 无法吃历史排放
```

#### 攻击流程

```
场景：系统运行 200 个区块，totalStaked = 1000（alice 独自质押）
积累奖励 = 200 blocks * 100e18/block = 20,000e18 tokens

攻击者操作（第 201 区块）：
  stake(999,000 tokens) → 质押比例 = 999000/(999000+1000) = 99.9%
  claim()               → 获得 20,000e18 * 99.9% = 19,980e18
  unstake(999,000)      → 立即退出，仅持仓 1 个区块

结果：攻击者 0 贡献，拿走 99.9% 的历史积累奖励
```

#### 真实案例

**Compound 奖励分发 Bug（2021年9月）**
```
bug：comptroller 中的 COMP 分发基于错误快照
结果：约 $90M COMP 被错误分发给部分用户
     Compound 紧急呼吁用户归还（大部分被归还）
```

#### 防御原则

```
时间加权 > 快照
accRPS 模式天然防排放通胀：
  - 用户入场时，rewardDebt 锁定当前 accRPS
  - 历史 accRPS 的增长已被 rewardDebt 捕获
  - 无论何时入场，都只能从入场时刻开始累积奖励
```

---

### 场景 5：清算奖励滥用 (Liquidation Bonus Abuse)

#### 清算机制设计原则

清算奖励的目标：**激励外部清算者，快速清除不良仓位，保证协议偿付能力**

**奖励过低** → 无人愿意清算 → 不良仓位积累 → 协议资不抵债
**奖励过高** → 攻击者主动制造可清算仓位 → 协议损失

#### 四大设计缺陷

| 缺陷 | 后果 | 修复 |
|------|------|------|
| 奖励过高（>10%）| 攻击者操控价格制造清算，套取奖励 | 奖励 ≤ 5-8% |
| 无最小债务阈值 | Dust 仓位反复清算刷奖励（Gas 套利）| `require(repay >= MIN_DEBT)` |
| 允许自我清算 | 攻击者建仓后故意让自己被清算套利 | `require(msg.sender != borrower)` |
| 全量清算无上限 | 单次大额清算冲击市场价格 | 最大 50% 部分清算 |

#### 自我清算攻击流程

```
场景：清算奖励 = 15%，价格预言机可被操控

Step 1: 存入 10,000 COL 作为抵押品
Step 2: 借出 7,500 DEBT（75% LTV）
Step 3: 操控 COL 价格下跌 20%
        → 抵押品价值 = 8,000，债务 = 7,500，超过 80% 清算阈值
Step 4: 自我清算：还款 7,500 → 获取 8,625 价值的抵押品（15% 奖励）
Step 5: 净利润 = 8,625 - 7,500 = 1,125 DEBT 价值
```

#### 真实案例

**Euler Finance（2023年3月，损失 $197M）**
```
漏洞：donateToReserves 函数结合清算奖励设计
攻击：攻击者创建特殊仓位，利用 donateToReserves 使仓位变为可清算
      然后通过关联地址清算，套取超额奖励
结果：$197M 损失（后来被攻击者归还）
```

**Inverse Finance（2022年4月，损失 $15.6M）**
```
漏洞：使用操控的 TWAP 价格作为清算判断
      价格预言机被闪贷瞬间操控
结果：用户仓位被错误清算
```

---

### 场景 6：份额稀释攻击 (Share Dilution)

#### 两种稀释路径

**路径 A：LP 份额稀释（= 首存攻击的经济视角）**
```
首存 1 wei → 捐赠拉高汇率 → 后续 LP 获得极少份额 → 攻击者兑现极高价值
```

**路径 B：治理份额稀释（Beanstalk 模式）**
```
获得 admin 权限 → 增发治理份额 → 超过 50% 阈值
→ 立即提交恶意提案 → 立即投票通过 → 无时间锁立即执行 → 转走所有资产
```

#### Beanstalk 攻击复现（2022年4月，损失 $182M）

```
背景：Beanstalk 是算法稳定币协议，使用 Snapshot 治理
     任何 Stalk 持有者可提交提案，67% 多数可执行

攻击流程（单笔交易）：
  1. 闪电贷借入 $1B 等值资产
  2. 将资产存入 Beanstalk → 获得 Stalk（治理份额）
  3. 此时攻击者持有约 67% 的 Stalk（超过超级多数）
  4. 立即对已提交的恶意提案投票（提案在攻击前已提交）
  5. 提案立即执行（无时间锁）：转走所有协议资产
  6. 归还闪贷
  7. 净利：$182M

关键漏洞：
  - 使用当前区块余额作为投票权（无快照锁定）
  - 无时间锁（有时间锁就无法用闪贷）
  - 无超级多数冷却期
```

#### 防御体系

```solidity
// 三重防御
// 1. 超级多数阈值（67%，高于简单多数）
require(p.votesFor * 10000 > totalGovShares * 6700, "Need supermajority");

// 2. 强制时间锁（防闪贷：借款只在单笔交易内有效，无法等 2 天）
require(block.timestamp >= p.createdAt + 2 days, "Timelock active");

// 3. 投票权快照（投票时使用历史快照，而非当前余额）
// 如 Compound Governor Bravo 使用过去区块的余额快照
```

---

## 防御完整检查清单

```
前置条件检查：
- [ ] 所有 amount 参数检查 > 0
- [ ] 所有 address 参数检查 != address(0)
- [ ] 时间锁函数检查 block.timestamp
- [ ] swap/exit 函数实现 minOut 滑点保护
- [ ] 迁移函数验证余额一致性

不变量保护：
- [ ] ERC-4626 Vault 使用虚拟偏移量（VIRTUAL_SHARES/VIRTUAL_ASSETS）
- [ ] 或使用死亡份额（铸造给 address(0xdead)）
- [ ] 直接转入资产也应更新 totalAssets（receive() 函数）
- [ ] 关键不变量有链上验证（assert 或 invariant test）

奖励债务：
- [ ] rewardDebt 更新使用 = 而非 +=
- [ ] deposit/withdraw/harvest 三个函数都更新 rewardDebt
- [ ] 公式：rewardDebt = amount * accRPS / PRECISION（不是累加）

排放分配：
- [ ] 使用 MasterChef accRPS 时间加权模式
- [ ] 不使用快照比例分配积累奖励
- [ ] 新质押者的 rewardDebt 锁定当前 accRPS

清算设计：
- [ ] 清算奖励 ≤ 8%
- [ ] 设置最小清算债务阈值
- [ ] 禁止自我清算（msg.sender != borrower）
- [ ] 部分清算限制（最大 50% 每次）
- [ ] 清算价格来源需防操控（TWAP/Chainlink）

份额稀释防御：
- [ ] LP Vault 使用虚拟偏移量（OpenZeppelin ERC-4626）
- [ ] 治理增发有上限（≤ 10% per tx）
- [ ] 提案执行有时间锁（≥ 2 天）
- [ ] 投票权使用历史快照而非当前余额
- [ ] 超级多数阈值（≥ 67%）
```

---


---

## 与 Balancer V2 的深度连接

### 前置条件 → ComposableStablePool

```solidity
// Balancer 的 joinPool 实现了滑点保护
function joinPool(
    bytes32 poolId,
    address sender,
    address recipient,
    JoinPoolRequest memory request
) external {
    // request.limits = minAmountsOut（不可为零！）
    // 若 limits[i] = 0，攻击者可在同一区块操控价格后以极差条件执行
}
```

### 奖励债务 → Gauge 系统

```
Balancer gauge 的 integrate_fraction 等价于 MasterChef 的 accRPS
每个 checkpoint 后必须更新 integrate_checkpoint_of[user]
若 integrate_checkpoint_of 未更新 → 用户可重复领取 BAL 奖励
```

### 份额稀释 → BPT 初始化

```
ComposableStablePool._onInitializePool：
  MINIMUM_BPT = 1e6（死亡份额，铸造给 address(0)）
  这防止了 BPT 首存攻击
  如果 MINIMUM_BPT 过小 → 攻击者可操控初始 BPT/token 汇率
  使后续 LP 获得过少 BPT，影响 amplificationParameter 计算精度
```

### 不变量 D → 场景2的对应

```
ComposableStablePool 的核心不变量：
  "调用 _getAmplifiedInvariant() 后的 D 值应稳定收敛"
  错误假设："初始 balances 合理时，D 的迭代一定收敛"
  实际上：balances 被 FOT 代币或 rebase 破坏后，D 值计算可能发散
  这正是 Balancer 2025年1月攻击的核心机制
```

