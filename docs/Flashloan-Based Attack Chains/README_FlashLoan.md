# 闪电贷组合攻击 - 完整实战指南


**这是DeFi攻击的核心工具**

```
真实DeFi攻击 = Flash Loan + 其他漏洞

前面学过的所有攻击都可以用Flash Loan放大：
├─ Flash Loan + Reentrancy = 数百万美元损失
├─ Flash Loan + Price Manipulation = 最常见攻击
├─ Flash Loan + Precision Loss = Balancer研究
└─ Flash Loan + Read-only Reentrancy = 组合攻击
```

**BlockSec分析的几乎每个案例都涉及Flash Loan！**

## 快速开始

```bash
# 1. 基础闪电贷
forge test --match-test testBasicFlashLoan -vvv

# 2. 价格操纵攻击
forge test --match-test testPriceManipulation -vvv

# 3. 嵌套闪电贷
forge test --match-test testNestedFlashLoans -vvv

# 4. ERC3156闪电铸币
forge test --match-test testFlashMint -vvv

# 5. 完整Balancer攻击
forge test --match-test testCompleteBalancerAttack -vvv
```

## 六大核心技术

### 1. Basic Flash Loan（基础闪电贷）

#### 工作原理

```
单笔交易内的借贷：

开始 → 借款 → 使用资金 → 还款 → 结束
        ↓                    ↑
        └──── 所有在一个交易中 ────┘

失败 → 整个交易回滚（就像没发生过）
```

#### Aave风格接口

```solidity
interface IFlashLoanProvider {
    function flashLoan(
        address receiver,      // 借款人地址
        uint256 amount,        // 借款金额
        bytes calldata data    // 额外数据
    ) external;
}

interface IFlashLoanReceiver {
    function executeOperation(
        address pool,          // 池子地址
        uint256 amount,        // 借到的金额
        uint256 fee,           // 需要支付的费用
        address initiator,     // 发起人
        bytes calldata params  // 额外参数
    ) external;
}
```

#### 费用对比

```
协议            费用        可借金额
Aave V3        0.09%      数亿美元
dYdX           0%         数千万（某些资产）
Uniswap V2     0.3%       取决于流动性
Balancer       0.01%      取决于池子
```

#### 为什么强大？

```
无需本金攻击示例：

攻击者资金: 0 ETH
↓
借款: 10,000 ETH (闪电贷)
↓
执行攻击 (操纵/套利/清算)
↓
获利: 500 ETH
↓
还款: 10,009 ETH (10,000 + 0.09%)
↓
净利润: 491 ETH

起始资金: 0
最终获利: 491 ETH
```

### 2. Flash Loan + Price Manipulation

#### 攻击链

```
Step 1: Flash Loan 借入巨额资金
        ↓
Step 2: 大量买入某token
        └─ 价格被推高
        
Step 3: 其他协议读取价格
        └─ 看到虚高价格
        
Step 4: 基于错误价格操作
        └─ 借款/清算/铸造
        
Step 5: Swap回来恢复价格
        ↓
Step 6: 还款并获利
```

#### 真实案例：Mango Markets ($110M)

```solidity
// 2022年10月攻击流程

// Step 1: 借入大量USDC
flashLoan(100M USDC)

// Step 2: 大量买入MNGO代币
// MNGO价格: $0.03 → $0.90 (30倍！)

// Step 3: Mango使用oracle价格
// Oracle看到MNGO = $0.90

// Step 4: 用虚高的MNGO抵押借款
// 按$0.90计价，借出110M USDC

// Step 5: 还闪电贷
// 还100M，留下10M利润

// Step 6: MNGO崩盘
// 价格回到$0.03，Mango坏账110M
```

#### 为什么成功？

```
问题1: 使用单一价格源
- Mango只依赖一个DEX的价格
- 没有TWAP（时间加权平均）
- 没有多源验证

问题2: 低流动性资产
- MNGO流动性只有几百万
- 100M就能操纵价格
- 缺乏深度保护

问题3: 即时结算
- 价格立即生效
- 没有延迟或确认
- 单笔交易完成攻击
```

### 3. Flash Loan + Reentrancy

#### 为什么组合？

**问题：**传统重入攻击受限于攻击者的资金
```
重入攻击：
- 需要先存款才能触发
- 损失 = 攻击者存款金额
- 小资金 = 小损失
```

**解决：**用闪电贷放大
```
Flash Loan + 重入：
- 借10000 ETH
- 存入触发重入
- 提取30000 ETH（重入3次）
- 还10000.9 ETH
- 净利润19999.1 ETH
```

#### 攻击流程

```solidity
function attack() {
    // 1. 借巨款
    flashLoan(10000 ether);
}

function executeOperation() {
    // 2. 存入vulnerable vault
    vault.deposit(10000 ether);
    
    // 3. 触发重入withdraw
    attacking = true;
    vault.withdraw(10000 ether);
    // → 在receive()中重入2-3次
    // → 总共提取30000 ether
    
    // 4. 还款
    repay(10009 ether);
    
    // 5. 利润 = 30000 - 10009 = ~20000 ether
}
```

### 4. Nested Flash Loans（嵌套闪电贷）

#### 为什么要嵌套？

**原因1：流动性限制**
```
单个协议: Aave最多能借 100M USDC
需求: 攻击需要 200M USDC

解决: Aave借100M + Compound借100M = 200M
```

**原因2：费用优化**
```
协议A: 费用 0.09%
协议B: 费用 0.05%

策略: 
- 从B借大部分（费用低）
- 从A借补充（更多选择）
- 总费用 < 只用A
```

**原因3：多资产需求**
```
需要: 
- 1000 ETH（在Aave借）
- 100 WBTC（在dYdX借）  
- 1M USDC（在Balancer借）

必须嵌套才能同时拥有
```

#### 嵌套结构

```
Level 0: 攻击者 attack()
  ↓
Level 1: flashLoan(Protocol A, 100M)
  ├─ 收到100M
  ├─ Level 2: flashLoan(Protocol B, 50M)
  │   ├─ 收到50M
  │   ├─ 总共150M可用！
  │   ├─ 执行攻击
  │   └─ 还Protocol B (50M + fee)
  └─ 还Protocol A (100M + fee)
```

#### 真实案例：Cream Finance ($130M)

```
攻击使用了多层嵌套：

Layer 1: 从Aave借18000 ETH
  ↓
Layer 2: 存入Cream获得crETH
  ↓
Layer 3: 借出AMP代币
  ↓
Layer 4: AMP转账触发回调（重入）
  ↓ (在回调中)
Layer 5: 再次借AMP（状态未更新）
  ↓
重复Layer 3-5多次
  ↓
还Aave，获利离场
```

### 5. ERC3156 Flash Mint（闪电铸币）

#### 概念

**传统闪电贷：**
```
借现有的代币
受限于池子流动性
```

**闪电铸币：**
```
临时铸造新代币
理论上无限量
交易结束时销毁
```

#### ERC3156标准

```solidity
interface IERC3156FlashLender {
    function maxFlashLoan(address token) 
        external view returns (uint256);
    
    function flashFee(address token, uint256 amount) 
        external view returns (uint256);
    
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool);
}
```

#### 攻击场景

**场景1：操纵投票权**
```
项目: DAO投票
漏洞: 按代币余额计票

攻击:
1. Flash mint 1B 治理代币
2. 投票通过恶意提案
3. 销毁代币
4. 提案执行（已经生效）
```

**场景2：操纵流动性挖矿**
```
项目: 流动性挖矿
奖励: 按份额分配

攻击:
1. Flash mint 1B 代币
2. 提供巨额流动性
3. 获得99.99%的奖励
4. 移除流动性
5. 销毁代币
```

**场景3：清算操纵**
```
借贷协议使用代币作为抵押

攻击:
1. Flash mint代币
2. 大量存入借贷协议
3. 触发其他用户清算
4. 获得清算奖励
5. 销毁代币
```

#### 真实风险

**Maker DAO的防御：**
```solidity
// Maker不允许闪电铸币被用于治理
function vote(uint256 amount) external {
    require(
        balanceOf[msg.sender] >= amount,
        "Insufficient balance"
    );
    
    // 检查余额的来源
    require(
        !isFlashMint(msg.sender),
        "Flash mint not allowed"
    );
}
```

### 6. Cross-Protocol Composability Abuse

#### 协议互依赖

```
协议生态图：

     Aave
      ↓ (提供价格)
    Compound
      ↓ (cToken作为抵押)
    Liquity  
      ↓ (流动性挖矿)
    Curve
      ↓ (LP代币)
    Convex
```

**问题：下游协议假设上游是安全的**

#### 攻击模式

**模式A：价格传递**
```
Uniswap (源头)
  ↓ getPrice()
Compound (使用价格)
  ↓ cToken价值
Maker (使用cToken)
  ↓ 抵押品价值
用户 (被清算)

攻击: 操纵Uniswap → 影响整条链
```

**模式B：份额通胀**
```
Curve (源头池子)
  ↓ LP代币
Convex (包装LP)
  ↓ cvxLP代币
Aave (接受cvxLP抵押)
  ↓ 借款限额
攻击者 (超额借款)

攻击: 通胀Curve LP → 虚高cvxLP → 超额借款
```

**模式C：重入传播**
```
Pool A (有重入漏洞)
  ↓ withdraw()触发回调
攻击者合约
  ↓ 调用Pool B
Pool B (信任Pool A的状态)
  ↓ 基于错误状态操作
攻击者 (获利)

攻击: A的重入 → B读到错误状态
```

#### 真实案例分析

**bZx攻击 ($8M, 2020.02)**

```
攻击链：

1. Compound: 借2298 ETH
   ↓
2. dYdX: Flash loan 10000 ETH
   ↓
3. Fulcrum: 存5500 ETH借112 WBTC
   ↓
4. Uniswap: 卖112 WBTC换ETH
   └─ WBTC价格下跌
   
5. Fulcrum再次借款
   └─ 基于被操纵的WBTC价格
   └─ 借到更多ETH
   
6. 还dYdX和Compound
7. 获利离场

关键：
- 4个协议互相依赖
- Fulcrum信任Uniswap价格
- 单笔交易完成整个攻击链
```

## 完整Balancer攻击链

### 研究culmination

```
╔══════════════════════════════════════════════════════╗
║  Complete Balancer Attack                           ║
║  Flash Loan + Precision + Manipulation + Reentrancy ║
╚══════════════════════════════════════════════════════╝

Phase 1: 准备（Flash Loan）
├─ 借入10000 ETH
└─ 零成本获得巨额资金

Phase 2: 操纵（Manipulation）
├─ 大额swap制造池子不平衡
├─ balances = [500, 1500] (instead of [1000, 1000])
└─ StableMath在不平衡状态计算误差更大

Phase 3: 累积（Precision Loss）
├─ 执行100次小额swap
├─ 每次损失100-200 wei
├─ 累积损失: 10000-20000 wei
└─ 池子状态越来越差

Phase 4: 触发（Read-only Reentrancy）
├─ 调用exitPool(bptAmount)
├─ 在回调中:
│   ├─ totalSupply已减少
│   ├─ balances未减少
│   └─ getBPTRate() = inflated value
└─ 虚高10-20%

Phase 5: 利用（Exploit）
├─ 其他协议调用getBPTRate()
├─ 看到虚高的BPT价值
├─ 允许超额借款
└─ 借出比实际抵押品多10-20%的资金

Phase 6: 还款（Repay）
├─ 还Flash Loan: 10009 ETH
├─ 成本: 9 ETH (fee)
└─ 利润: 超额借款 - 费用

Example Numbers:
- Flash Loan: 10000 ETH
- Fee: 9 ETH  
- BPT inflation: 15%
- Extra borrowed: 1500 ETH
- Net profit: 1491 ETH
```

### 代码实现要点

```solidity
function completeAttack() external {
    // Phase 1
    flashLoan(10000 ether);
}

function executeOperation(...) external {
    // Phase 2: Manipulate
    pool.swap(5000 ether);  // 制造不平衡
    
    // Phase 3: Accumulate loss
    for (uint i = 0; i < 100; i++) {
        pool.swap(10 ether);  // 每次损失精度
    }
    
    // Phase 4 & 5: Reentrancy + Exploit
    attacking = true;
    pool.exitPool(bptAmount);  // 触发重入
    
    // Phase 6: Repay
    repay(10009 ether);
}

receive() external payable {
    if (attacking) {
        // 在这里getBPTRate()返回虚高值
        uint256 inflatedRate = pool.getBPTRate();
        
        // 基于虚高价值借款
        lending.borrow(calculateMaxFromInflated(inflatedRate));
    }
}
```

## 防御策略

### 协议层面

**1. 价格保护**
```solidity
// 使用TWAP而不是即时价格
function getPrice() external view returns (uint256) {
    return oracle.getTWAP(30 minutes);  // 时间加权
}

// 多源价格验证
function getPrice() external view returns (uint256) {
    uint256 price1 = chainlink.getPrice();
    uint256 price2 = uniswapV3.getTWAP();
    
    require(
        abs(price1 - price2) < price1 / 100,  // 1%误差
        "Price deviation"
    );
    
    return (price1 + price2) / 2;
}
```

**2. 重入保护**
```solidity
// 对view函数也加保护
uint256 private _status = NOT_ENTERED;

function exitPool() external nonReentrant {
    _status = ENTERED;
    // ... logic
    _status = NOT_ENTERED;
}

function getBPTRate() external view returns (uint256) {
    require(_status != ENTERED, "No reentrancy");
    return calculateRate();
}
```

**3. 流动性限制**
```solidity
// 单笔交易限额
uint256 public maxSwapAmount = 1000 ether;

function swap(uint256 amount) external {
    require(amount <= maxSwapAmount, "Exceeds limit");
    // ...
}

// 价格影响限制
function swap(uint256 amountIn) external {
    uint256 priceBefore = getPrice();
    
    _executeSwap(amountIn);
    
    uint256 priceAfter = getPrice();
    require(
        abs(priceAfter - priceBefore) < priceBefore / 10,  // 10%
        "Price impact too high"
    );
}
```

**4. 延迟确认**
```solidity
// 价格/操作需要多个区块确认
mapping(bytes32 => uint256) public proposedActions;

function proposeWithdraw(uint256 amount) external {
    bytes32 actionId = keccak256(abi.encode(msg.sender, amount));
    proposedActions[actionId] = block.number;
}

function executeWithdraw(uint256 amount) external {
    bytes32 actionId = keccak256(abi.encode(msg.sender, amount));
    require(
        block.number >= proposedActions[actionId] + 5,  // 5个区块后
        "Too soon"
    );
    // ...
}
```

### 测试策略

```solidity
// Invariant testing
function invariant_priceStability() public {
    uint256 price = pool.getPrice();
    
    // 任何操作后价格变化不应超过5%
    pool.swap(100 ether);
    
    uint256 newPrice = pool.getPrice();
    assertApproxEqRel(price, newPrice, 0.05e18);
}

// Flash loan simulation testing
function testFlashLoanAttack() public {
    // 模拟攻击者获得巨额资金
    vm.deal(attacker, 100000 ether);
    
    // 尝试各种攻击
    vm.prank(attacker);
    // ... attack logic
    
    // 验证协议状态一致性
    assertEq(pool.invariant(), expectedInvariant);
}
```

## 总结：完整知识体系

```
DeFi攻击完整技能树：

基础漏洞
├─ Reentrancy (全系列) 
├─ Read-only Reentrancy 
├─ Delegatecall Hijacking 
├─ Arithmetic Boundaries 
└─ Precision Loss 

高级组合
├─ Flash Loan (刚完成) 
│   ├─ + Price Manipulation
│   ├─ + Reentrancy
│   ├─ + Precision Loss
│   └─ + Cross-protocol
└─ 完整攻击链 

实战案例理解
├─ Curve vyper ($73M) 
├─ Parity wallet ($150M) 
├─ Mango Markets ($110M) 
├─ Cream Finance ($130M) 
└─ Balancer攻击模式 

```

