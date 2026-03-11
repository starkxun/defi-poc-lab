# ERC20 非标准行为攻击 - 完整学习指南

## 为什么这个重要？

ERC20 标准定义了代币应该"如何行为"，但现实中大量代币以各种方式偏离标准。
DeFi 协议如果假设所有代币都完全符合 ERC20 标准，就会在与非标准代币交互时产生严重漏洞。

**与你的 Balancer 研究的关联：**

```
Balancer V2 Vault 的核心假设：
  "发送的代币数量 = 接收的代币数量"

当这个假设被打破时：

收费代币   → joinPool 时 amountIn 记账错误 → 池子内部份额失真
Rebase 代币 → balances[] 快照与实际余额偏离 → swap 计算 D 值时精度损失
ERC777 钩子 → exitPool 时触发回调 → 只读重入 → getBPTRate() 虚高
balanceOf 操控 → BPT 价格计算失真 → 跨协议抵押品虚高
```

**非标准 ERC20 漏洞历史损失：超过 $50M**

---

## 快速开始

```bash
# 运行所有测试
forge test --match-contract ERC20NonStandardTest -vv

# 测试单个场景
forge test --match-test testFeeOnTransferExploit -vvv
forge test --match-test testRebaseTokenPriceDistortion -vvv
forge test --match-test testPauseAccountingBreakage -vvv
forge test --match-test testNonStandardReturnExploit -vvv
forge test --match-test testERC777ReentrancyAttack -vvv
forge test --match-test testBalanceOfManipulation -vvv

# 测试安全实现
forge test --match-test testSafe -vvv

# 完整调用追踪
forge test --match-test testFeeOnTransferExploit -vvvv
```

---

## 6大核心场景

---

### 1. 转账收费代币 (Fee-on-Transfer Tokens)

#### 原理

标准 ERC20 的 transfer/transferFrom 假设：
接收者收到的金额 = 发送者指定的金额

收费代币打破这个假设：
接收者收到的金额 = amount × (1 - feeRate)

常见费率：0.1% ~ 10%（SAFEMOON 高达 10%）

#### 攻击流程

```
受害者协议的 deposit(amount) 函数：
  1. 调用 transferFrom(user, vault, amount)
  2. 记录: deposits[user] += amount       ← 记录的是 amount
  3. 但 vault 实际收到: amount * 99%      ← 实际余额少 1%

攻击者利用此差异：
  1. 存入 amount → 记录 amount，实际收到 amount*99%
  2. 提取 amount → 提走 amount（拿走了别人存入的代币）
  3. 金库逐渐被掏空（每次存取都有 1% 的偏差累积）
```

#### 真实案例

**STA 代币攻击 Balancer（2020年6月，损失 $500K）**
```
时间：   2020.06
损失：   $500K
代币：   Statera (STA)，1% 销毁型收费代币
方法：   反复在 Balancer 多资产池中 swap STA
         每次 swap 后池子 STA 余额少于记录的数量
         利用价格偏差套利，逐步掏空池子
```

**Cream Finance（2021年，损失 $18.8M）**
```
时间：   2021.08
损失：   $18.8M
方法：   AMP 代币（收费代币）存入 Cream
         重入 + 收费代币组合攻击
```

#### 防御

```solidity
// 错误：信任入参 amount
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    deposits[msg.sender] += amount; // 可能记录了虚高的金额
}

// 正确：前后余额差
function deposit(uint256 amount) external {
    uint256 before = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 actualReceived = token.balanceOf(address(this)) - before;
    deposits[msg.sender] += actualReceived; // 记录实际收到的量
}
```

#### 检查清单
- [ ] 所有 deposit/addLiquidity 使用前后余额差记录实际到账量
- [ ] 不要直接信任 transfer 的 amount 参数
- [ ] 考虑明确禁止收费代币（在 whitelist 中排除）
- [ ] Balancer V2 Vault 已有此保护：检查实现方式

---

### 2. 弹性供应代币 (Rebase Tokens)

#### 原理

弹性供应代币内部用"份额"(shares)记账，
外部 balanceOf 返回的"余额"(balance)会随总供应量变化而等比例变化。

```
balance = shares × (totalSupply / totalShares)

正向 rebase（+10% 供应量）：
  持有者份额不变
  但 balanceOf 增加 10%
  所有地址的余额等比例增加

负向 rebase（-10% 供应量）：
  持有者份额不变
  但 balanceOf 减少 10%
  所有地址的余额等比例减少
```

#### 攻击流程

```
AMM 池用快照储备量记账（reserveRebase = 快照）：
  1. 池子持有 100,000 AMPL，快照 = 100,000
  2. 正向 rebase +50%
  3. 池子实际余额 = 150,000，快照仍 = 100,000
  4. getPrice() 基于快照 100,000 计算 → 价格"正常"
  5. swapEthForToken() 基于快照计算输出 → 用 100K 的价格买到 150K 的量
  6. 套利者提取多余的 50,000 AMPL
```

#### 真实案例

**Ampleforth (AMPL) 在各 AMM 的持续套利**
```
时间：   2020年至今（持续问题）
损失：   每次 rebase 后数千至数万美元套利
代币：   AMPL（Ampleforth），每天根据目标价格 rebase
方法：   rebase 发生后，快照储备量与实际余额之间存在窗口
         MEV 机器人在区块内套利
现状：   大多数 AMM 已排除 AMPL 或使用特殊适配器
```

**stETH 在 Curve 的精度问题**
```
代币：   stETH（流动性质押 ETH）
问题：   每天 rebase（质押奖励），导致池子份额计算出现微小偏差
影响：   长期积累导致 LP 份额价值微量偏离预期
```

#### 防御

```solidity
// 错误：使用快照储备量
uint256 public reserveRebase; // 过期快照

function getPrice() external view returns (uint256) {
    return (reserveEth * 1e18) / reserveRebase; // 使用过期数据
}

// 正确：使用实时 balanceOf
function getPrice() external view returns (uint256) {
    uint256 liveBalance = token.balanceOf(address(this)); // 实时余额
    return (reserveEth * 1e18) / liveBalance;
}

// 或者：使用份额而非余额记账（推荐）
function sharesOf(address account) external view returns (uint256) {
    return _shares[account]; // 不受 rebase 影响
}
```

#### 检查清单
- [ ] 不使用快照储备量持有 rebase 代币
- [ ] 如必须持有，每次操作前调用 sync() 更新储备量
- [ ] 考虑使用 shares-based 包装代币（如 wstETH）
- [ ] Balancer 已排除直接的 rebase 代币：了解 wstETH 适配器

---

### 3. 暂停机制导致记账错误 (Pause Mechanism Accounting Breakage)

#### 原理

许多 ERC20 代币（特别是稳定币）有暂停功能：
暂停后所有 transfer/transferFrom 会 revert。

当 DeFi 协议持有这类代币时，暂停会破坏协议的关键操作：
- **借贷协议**：用户无法还款，坏账持续积累
- **清算**：清算者无法执行，不良仓位无法被清除
- **AMM**：流动性提供者无法提取，套利者无法平衡池子

```
暂停期间：
  利息计算   ← 继续累积
  价格变化   ← 继续发生
  清算条件   ← 可能触发
  实际操作   ← 全部阻塞

恢复后：
  大量积压操作同时执行
  清算潮 → 价格崩溃 → 更多清算 → 协议坏账
```

#### 真实案例

**Compound cUSDC 暂停风险（2023年讨论）**
```
时间：   2023年社区讨论
风险：   Circle 可以随时暂停 USDC
         Compound 大量 cUSDC 仓位无法清算
         潜在损失：数亿美元
```

**Aave 冻结机制（设计决策）**
```
Aave 有"冻结"(freeze)机制，类似暂停
冻结时只能还款/清算，不能借款/存款
设计上比完全暂停更安全
```

#### 防御

```solidity
// 暂停时记录待处理意图，而非直接失败
function repay(uint256 amount) external {
    require(borrowed[msg.sender] >= amount, "Not borrowed");
    if (token.paused()) {
        // 记录意图，暂停结束后可补偿
        pendingRepay[msg.sender] += amount;
    } else {
        uint256 total = amount + pendingRepay[msg.sender];
        pendingRepay[msg.sender] = 0;
        token.transferFrom(msg.sender, address(this), total);
        borrowed[msg.sender] -= total;
    }
}

// 清算前检查代币状态
function liquidate(address borrower) external {
    require(!token.paused(), "Cannot liquidate during pause");
    // ...
}
```

#### 检查清单
- [ ] 分析协议使用的所有代币是否有暂停机制
- [ ] USDC, USDT, BUSD 等稳定币均有暂停/黑名单功能
- [ ] 暂停期间的坏账处理预案
- [ ] 清算必须检查代币是否可转账

---

### 4. 非标准返回值 (Non-Standard Return Values)

#### 原理

标准 ERC20：
```solidity
function transfer(address to, uint256 amount) external returns (bool);
function transferFrom(address from, address to, uint256 amount) external returns (bool);
```

非标准行为：
- **无返回值**（类似早期 USDT）：函数签名中没有返回类型
- **返回 false 而非 revert**（类似 BNB）：失败时返回 false 而不是回滚
- **不一致行为**（类似 OMG）：某些情况下失败的方式不可预期

```
问题一：无返回值
  Solidity 对无返回值函数的 ABI 解码会失败
  或者接收到 32 字节的 0（被解释为 false）

问题二：返回 false 而非 revert
  协议代码：bool success = token.transferFrom(...)
  如果不检查 success，转账失败但代码继续执行
  结果：记录了存款，但没有真实的代币转入
```

#### 真实案例

**早期 Uniswap V1 与 USDT**
```
时间：   2018-2019
问题：   USDT 早期版本 transfer() 没有返回值
         调用 IERC20(usdt).transfer() 会因 ABI 解码失败 revert
修复：   OpenZeppelin 的 SafeERC20 库
         现代合约必须使用 SafeERC20
```

**BNB 在多个 DeFi 协议的问题**
```
代币：   BNB（早期版本）
问题：   transferFrom 不足额时返回 false 而非 revert
影响：   未检查返回值的协议会记录虚假存款
```

#### 防御

```solidity
// 错误：不检查返回值
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount); // 可能静默失败
    deposits[msg.sender] += amount;
}

// 方法一：手动检查返回值
function deposit(uint256 amount) external {
    bool success = token.transferFrom(msg.sender, address(this), amount);
    require(success, "Transfer failed");
    deposits[msg.sender] += amount;
}

// 方法二：使用 SafeERC20（推荐）
// SafeERC20 处理：无返回值 + false 返回 + revert
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;
token.safeTransferFrom(msg.sender, address(this), amount);
```

**SafeERC20 内部实现原理：**
```solidity
// 低级 call，同时兼容有/无返回值的代币
(bool success, bytes memory data) = address(token).call(
    abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount)
);
require(
    success && (data.length == 0 || abi.decode(data, (bool))),
    "SafeERC20: ERC20 operation did not succeed"
);
```

#### 检查清单
- [ ] 所有 ERC20 交互使用 SafeERC20
- [ ] 永远不要忽略 transfer/transferFrom 的返回值
- [ ] 结合前后余额差检查（双重保护）
- [ ] Balancer Vault 使用 SafeERC20：确认所有 token 路径

---

### 5. ERC777 回调钩子 (ERC777 Callbacks)

#### 原理

ERC777 是 ERC20 的扩展标准（EIP-777），增加了两个钩子：
- `tokensToSend()`：发送方在代币被发出**之前**被调用
- `tokensReceived()`：接收方在代币收到**之后**被调用

这些钩子通过 ERC1820 注册表自动发现和调用。

```
正常 ERC20 transfer 流程：
  balanceOf[from] -= amount
  balanceOf[to] += amount
  ← 完成，无外部调用

ERC777 transfer 流程：
  [可选] 调用 from 的 tokensToSend 钩子    ← 重入点 1
  balanceOf[from] -= amount
  balanceOf[to] += amount
  [可选] 调用 to 的 tokensReceived 钩子    ← 重入点 2
  ← 完成

问题：钩子中可以重入调用触发 transfer 的协议
```

#### 攻击流程

```
攻击者注册 tokensReceived 钩子

pool.removeLiquidity(shares) 执行：
  1. 计算 tokenAmount = shares * reserve / totalShares
  2. token.transfer(attacker, tokenAmount)  ← 触发 ERC777 钩子
     ↓ 在此期间，pool 状态尚未更新
  3. [钩子] attacker.tokensReceived() 被调用
  4. [钩子内] 再次调用 pool.removeLiquidity(shares)  ← 重入！
  5. 第二次提取成功（因为份额未被扣减）
  6. 重复 N 次
  7. 钩子返回，pool 才更新状态
  8. 攻击者提取了 N 倍份额对应的代币
```

#### 真实案例

**imBTC 攻击 Uniswap V1（2020年4月，损失 $25M）**
```
时间：   2020.04.18
损失：   $25M
代币：   imBTC（ERC777 包装的比特币代币）
方法：   Uniswap V1 没有重入保护
         利用 tokensToSend 钩子在 ETH 发出前重入
         多次触发 tokenToEthSwapInput
攻击交易：0x32c83905db...
```

**Akropolis（2020年11月，损失 $2M）**
```
时间：   2020.11
损失：   $2M DAI
代币：   DAI（其依赖的 dSAVE 有 ERC777 特性）
方法：   利用 ERC777 回调重入 Akropolis savingsModule
```

#### 防御

```solidity
// 重入锁
uint256 private _unlocked = 1;
modifier nonReentrant() {
    require(_unlocked == 1, "Reentrant call");
    _unlocked = 2;
    _;
    _unlocked = 1;
}

// CEI 模式（Check-Effects-Interactions）
function removeLiquidity(uint256 shares) external nonReentrant {
    require(liquidityShares[msg.sender] >= shares, "Insufficient");

    // Effects（先改状态）
    uint256 tokenAmount = shares * tokenReserve / totalShares;
    liquidityShares[msg.sender] -= shares;
    totalShares -= shares;
    tokenReserve -= tokenAmount;

    // Interactions（再与外部合约交互）
    token.transfer(msg.sender, tokenAmount); // ERC777 钩子在此触发
    // 此时状态已更新，重入无效
}
```

**Balancer 与 ERC777 的关联：**
只读重入 + ERC777 钩子 = 最危险的组合：
```
exitPool(bptAmount) 触发 token.transfer()
→ ERC777 钩子被调用
→ 外部协议在钩子中读取 getBPTRate()
→ 此时 BPT totalSupply 已减少，但 balances 未减少
→ getBPTRate() 虚高
→ 外部协议计算抵押品价值虚高
→ 超额借款
```

#### 检查清单
- [ ] 所有池子/金库操作使用 nonReentrant 修饰符
- [ ] 严格遵循 CEI 模式：先改状态，再与外部交互
- [ ] 了解持有的代币是否实现 ERC777 接口
- [ ] 只读重入保护：关键视图函数在 lock 状态时 revert

---

### 6. balanceOf 操控 (balanceOf Manipulation)

#### 原理

某些代币的 `balanceOf` 返回值不是简单的存储值，
而是根据外部可变因素动态计算的：

```
正常 ERC20：
  balanceOf[user] = storage_value（固定的存储槽）

可操控的代币：
  cToken:   balanceOf = shares × exchangeRate（exchangeRate 每区块增长）
  xSUSHI:   balanceOf = shares × (sushiReserve / totalShares)
  aToken:   balanceOf = principalShares × liquidityIndex（随利率变化）
  本 PoC:   balanceOf = shares × (ethReserve / totalShares)

如果 ethReserve 可以被外部操控（如接受任意 ETH 转账），
则 balanceOf 可以被攻击者瞬间放大
```

#### 攻击流程

```
借贷协议使用 balanceOf 计算抵押品价值：
  maxBorrow = token.balanceOf(collateralPool) * LTV / 10000

攻击者：
  1. 存入少量抵押品（正常操作）
  2. 向代币合约强制转入大量 ETH（操控 exchangeRate）
  3. token.balanceOf(collateralPool) 虚高
  4. maxBorrow 计算结果大幅增加
  5. 超额借款，拿走协议资金
  6. 不还款（超过抵押品价值的借款无需还）
```

#### 真实案例

**Rari Capital Fuse（2022年4月，损失 $80M）**
```
时间：   2022.04
损失：   $80M
方法：   使用 WETH 在 Fuse pool 中的价格操控
         结合 ERC777 重入和 balanceOf 操控
         在单个区块内多次修改 exchangeRate
```

**多个 cToken 利用 exchangeRate 操控**
```
攻击模式：
  1. 向 cToken 的底层代币合约直接转入代币
  2. exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply
  3. totalCash 增加 → exchangeRate 增加 → balanceOf 增加
  4. 基于 balanceOf 的借款上限被放大
```

#### 防御

```solidity
// 错误：使用 balanceOf 作为价格源
function getCollateralValue(address pool) external view returns (uint256) {
    return token.balanceOf(pool); // 可被操控
}

// 方法一：使用份额 + 可信预言机价格
function getCollateralValue(address user) external view returns (uint256) {
    uint256 shares = token.sharesOf(user);
    uint256 pricePerShare = oracle.getPrice(address(token));
    return shares * pricePerShare / 1e18;
}

// 方法二：使用 TWAP 价格（时间加权平均）
function getPrice() external view returns (uint256) {
    return twapOracle.consult(tokenAddress, 1e18);
}

// 方法三：使用 Chainlink 价格预言机
AggregatorV3Interface chainlink = AggregatorV3Interface(feedAddress);
(, int256 price, , ,) = chainlink.latestRoundData();
```

#### 检查清单
- [ ] 不使用 balanceOf 作为价格或抵押品价值的来源
- [ ] 使用 Chainlink / TWAP / 链上不变量计算价格
- [ ] cToken/aToken/xToken 的余额需要用对应的 exchangeRate 换算
- [ ] Balancer BPT 价格来自链上不变量，而非 balanceOf

---

## 防御完整检查清单

```
收费代币 (FOT)：
- [ ] 所有 deposit 使用前后余额差
- [ ] 协议文档明确声明不支持 FOT 代币，或有特殊处理
- [ ] addLiquidity/joinPool 使用余额差记录实际注入量

弹性供应代币 (Rebase)：
- [ ] 使用实时 balanceOf，而非快照储备量
- [ ] 或使用 shares-based 包装代币（如 wstETH 代替 stETH）
- [ ] AMM 池的 sync() 在每次操作时被调用

暂停机制：
- [ ] 分析所有持有代币的暂停风险
- [ ] 有暂停期间的应急处理方案
- [ ] 清算函数检查代币是否可转账

非标准返回值：
- [ ] 所有 ERC20 调用使用 SafeERC20
- [ ] 没有忽略 transfer 返回值的代码
- [ ] 结合余额差检查

ERC777 回调：
- [ ] 所有状态修改函数有 nonReentrant 保护
- [ ] 严格 CEI 模式
- [ ] 只读重入防护（锁定期间拒绝外部读取关键状态）

balanceOf 操控：
- [ ] 不使用 balanceOf 作为价格源
- [ ] 使用可信预言机（Chainlink/TWAP）
- [ ] cToken/aToken 用 exchangeRate 换算后再使用
```



## 与 Balancer 研究的深度连接

**ERC20 非标准行为如何影响 Balancer 攻击链：**

```
Phase 1：闪电贷 + 价格操纵（不变）
Phase 2：[FOT] joinPool 时记账错误 → 内部 balances[] 与实际余额偏离
Phase 3：[Rebase] balances[] 快照与实际余额偏离 → D 值计算有误
Phase 4：[ERC777] exitPool 触发钩子 → 只读重入 → getBPTRate() 虚高
Phase 5：[balanceOf] 外部协议基于虚高 BPT 价格借款 → 超额借款
Phase 6：还款 + 获利

Balancer Vault 的保护机制：
  joinPool:     余额差验证（防 FOT）
  exitPool:     锁定保护（防重入）
  getRate():    基于不变量计算（防 balanceOf 操控）

绕过方案（研究方向）：
  1. 找到 Vault 余额差验证的边界条件
  2. 分析 rebase 代币在 ComposableStablePool 中的长期漂移
  3. ERC777 钩子 + Vault 外部调用时序分析
```

---



**工具推荐：**
```bash
# 检查代币是否是 FOT
cast call <token> "transfer(address,uint256)(bool)" <to> 1000
# 比较发送前后余额差

# 检查 ERC777 钩子注册
cast call 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24 \
  "getInterfaceImplementer(address,bytes32)" <addr> \
  0xb281fc8c12954d22544db45de3159a39272895b169a852b314f9cc762e44c53b
```


---

