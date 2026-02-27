# MEV攻击 - 完整实战指南

## 什么是MEV？

**MEV = Maximal Extractable Value（最大可提取价值）**

```
以前叫 Miner Extractable Value
现在叫 Maximal Extractable Value (PoS后)

定义：
通过控制交易顺序、包含、排除
而能从区块链中提取的价值
```

**规模：**
```
2020: ~$300M
2021: ~$700M  
2022: ~$600M
2023: ~$400M

总计: $2B+ 已被提取
```

## 快速开始

```bash
# 1. 三明治攻击
forge test --match-test testSandwichAttack -vvv

# 2. 抢跑攻击
forge test --match-test testFrontRunning -vvv

# 3. 尾随攻击  
forge test --match-test testBackRunning -vvv

# 4. JIT流动性攻击
forge test --match-test testJITLiquidity -vvv

# 5. MEV Bundle
forge test --match-test testMEVBundle -vvv
```

## 四大核心攻击

### 1. Sandwich Attack（三明治攻击）

#### 攻击流程

```
Mempool状态：
├─ 受害者的交易：Swap 100 ETH for tokens
├─ 设置滑点保护：minOut = 95 tokens
└─ Gas价格：50 gwei

攻击者行动：
┌─ Transaction 1 (Front-run): Gas 100 gwei
│  └─ Buy tokens (推高价格)
│
├─ Transaction 2 (Victim): Gas 50 gwei  
│  └─ Victim买入（高价）
│
└─ Transaction 3 (Back-run): Gas 100 gwei
   └─ Sell tokens (获利)

最终区块顺序：
Block N:
  Tx 1: Attacker buy   ← 第一个执行
  Tx 2: Victim buy     ← 第二个执行  
  Tx 3: Attacker sell  ← 第三个执行
```

#### 数学分析

**池子状态演变：**
```
初始: [1000 ETH, 1000 TOKEN], price = 1.0

After Tx1 (攻击者买50 ETH):
reserves = [1050, 952.4]
price = 0.907
attacker holds = 47.6 TOKEN

After Tx2 (受害者买100 ETH):  
reserves = [1150, 869.1]
price = 0.756
victim gets = 83.3 TOKEN (预期95+)

After Tx3 (攻击者卖47.6 TOKEN):
reserves = [1098.2, 916.7]
price = 0.835
attacker gets = 51.8 ETH

攻击者利润 = 51.8 - 50 = 1.8 ETH
受害者损失 = 95 - 83.3 = 11.7 TOKEN
```

#### 真实案例

**Indexed Finance攻击（2021.10）：**
```
攻击者: 0x8d112...
受害者: 多个大额交易者
方法: Sandwich attacks
利润: $2M+ in 1 day

策略：
- 监控所有Uniswap交易
- 识别>$10K的大额swap
- 执行三明治攻击
- 每个受害者损失2-5%
- 累积利润巨大
```

### 2. Front-running（抢跑）

#### 适用场景

**场景A：套利机会**
```
Victim发现：
Token X价格：
- Uniswap: $100
- SushiSwap: $105

Victim提交套利交易

Attacker看到：
- 复制受害者交易
- 更高gas抢先执行
- 获得套利利润

Victim结果：
- 交易revert（机会已被抢）
- 浪费gas费
```

**场景B：清算**
```
协议：借贷协议
状态：用户A抵押不足，可被清算
奖励：清算奖励5%

Victim看到机会，提交清算交易

Attacker：
- 监控所有清算交易
- 复制交易逻辑
- 更高gas抢先
- 获得清算奖励

Victim：
- 交易失败
- 损失gas
```

**场景C：NFT铸造**
```
项目方：发布新NFT系列
价格：0.1 ETH
稀有度：前100个有特殊属性

Victim：尝试铸造稀有NFT

Attacker：
- 监控铸造交易
- 批量提交1000笔交易
- 全部使用高gas
- 抢先铸造所有稀有NFT

结果：
- 攻击者获得所有稀有NFT
- 普通用户只能铸造普通NFT
```

#### Gas拍卖机制

**优先级费用（EIP-1559后）：**
```
Transaction费用 = Base Fee + Priority Fee

Base Fee: 网络自动调整，烧毁
Priority Fee: 付给矿工/验证者，排序依据

Front-running竞争 = Priority Fee竞争

例子：
Victim: 50 gwei priority fee
Attacker: 100 gwei priority fee
→ Attacker优先

极端情况：
某次NFT铸造，priority fee飙升到
10,000+ gwei (正常是1-2 gwei)
```

### 3. Back-running（尾随）

#### 与Front-running的区别

```
Front-running:
目标：在目标交易前执行
需求：更高gas竞争
风险：可能被他人front-run

Back-running:
目标：在目标交易后执行
需求：只需包含在同一区块
风险：低，不需要gas竞争
```

#### 套利场景

**Oracle更新套利：**
```
时刻T0:
- Chainlink Oracle price = $100
- Uniswap pool price = $100

时刻T1 (Oracle更新交易提交):
- Oracle将更新价格到$95

Back-runner策略：
1. 监控Oracle更新交易
2. 计算新价格后的套利机会
3. 提交交易紧跟在Oracle更新后
4. 在Uniswap以$100卖出
5. 在外部市场以$95买回
6. 利润 = $5 per unit

优势：
- 无需竞争（确定性获利）
- Gas成本低
- 风险小
```

**新池子创建套利：**
```
Event: Uniswap V3新池子创建
Token: 新代币XYZ
初始价格: $1.00

Back-runner：
1. 看到新池子创建交易
2. 立即在同一区块买入
3. 抢在其他人之前
4. 价格迅速上涨到$1.50
5. 立即卖出

利润：50% in one block
```

### 4. JIT Liquidity Attack（即时流动性攻击）

#### Uniswap V3的特性

**集中流动性：**
```
传统AMM (Uniswap V2):
- 流动性分布在整个价格曲线
- 资本效率低

Uniswap V3:
- LP可以选择价格区间
- 集中流动性→资本效率高
- 但也引入了JIT攻击向量
```

#### 攻击机制

**完整流程：**
```
T0 - Mempool:
Victim准备大额swap: 1000 ETH

T1 - Attacker前置交易:
addLiquidity(10000 ETH)
→ 攻击者控制90%流动性

T2 - Victim交易执行:
swap(1000 ETH)
→ 产生3 ETH费用
→ 攻击者获得2.7 ETH (90%)
→ 原LP只获得0.3 ETH (10%)

T3 - Attacker后置交易:
removeLiquidity()
→ 取回10000 ETH + 2.7 ETH
→ 利润2.7 ETH
→ LP时长 < 1 block
```

#### 数学计算

```
原池子状态：
- Liquidity: 1000 ETH
- 原LP份额: 100%

攻击者添加：
- Liquidity: 9000 ETH  
- 总Liquidity: 10000 ETH
- 攻击者份额: 90%

大额交易：
- Amount: 1000 ETH
- Fee (0.3%): 3 ETH
- 攻击者获得: 3 * 90% = 2.7 ETH
- 原LP获得: 3 * 10% = 0.3 ETH

正常情况下原LP应得: 3 ETH
损失: 3 - 0.3 = 2.7 ETH
```

#### 真实案例

**Uniswap V3 on Polygon：**
```
2023年观察到的JIT攻击：

攻击者: 0x5c69...
方法: 
- 监控>$100K的大额交易
- 在前一个区块添加巨额流动性
- 大额交易执行
- 立即移除流动性

统计：
- 成功攻击次数: 200+
- 平均利润/次: $500-2000
- 总获利: ~$200K

受害者: Uniswap V3上的普通LP
```

### 5. MEV Bundle（Flashbots）

#### Flashbots解决什么问题？

**传统MEV的问题：**
```
1. 公开mempool竞争
   - Gas war浪费资源
   - 网络拥堵
   - 失败交易浪费gas

2. 不确定性
   - 不知道能否成功
   - 可能被其他人front-run
   
3. 失败成本
   - 支付gas但交易失败
   - 每次尝试都要付费
```

**Flashbots的解决方案：**
```
Bundle = 一组原子交易

特点：
1. 私密：不进入公开mempool
2. 原子：全部成功或全部失败
3. 模拟：可以预先模拟利润
4. 无风险：只有成功才付费

直接提交给区块构建者
```

#### Bundle结构

```typescript
// MEV Bundle 例子
const bundle = {
  transactions: [
    {
      // Tx 0: 攻击者front-run
      signer: attacker,
      transaction: {
        to: uniswap,
        data: swapExactTokensForTokens(...),
        gasLimit: 200000
      }
    },
    {
      // Tx 1: 受害者的交易（直接从mempool）
      signedTransaction: victimSignedTx,
      canRevert: false  // 受害者交易必须成功
    },
    {
      // Tx 2: 攻击者back-run
      signer: attacker,
      transaction: {
        to: uniswap,
        data: swapExactTokensForTokens(...),
        gasLimit: 200000
      }
    }
  ],
  
  blockNumber: targetBlock,
  minTimestamp: ...,
  maxTimestamp: ...,
  
  // 最低利润要求
  revertingTxHashes: [tx0, tx2],  // 这些可以revert
  minProfit: parseEther("0.05")   // 必须>0.05 ETH
};

// 提交bundle
await flashbotsProvider.sendBundle(bundle);
```

#### 优势分析

**对攻击者：**
```
优势：
- 无失败成本
- 利润保证
- 无gas竞争
- 可模拟测试

例子：
传统方式：
- 尝试100次
- 成功1次
- 浪费99次gas
- Gas成本 >> 利润

Flashbots：
- 模拟100次
- 提交1次（确定成功的）
- 零失败成本
- 利润最大化
```

**对用户：**
```
保护交易：
- 用户可以直接提交bundle
- 避免被front-run
- 但需要支付额外费用

例子：
大额交易者使用Flashbots Protect：
- 交易不进入公开mempool
- 避免被三明治攻击
- 但仍可能被区块构建者MEV
```

## 防御策略

### 用户层面

**1. 设置合理滑点：**
```solidity
// 错误：滑点过大
amm.swap(100 ether, 50 ether);  // 允许50%滑点！

// 正确：紧密滑点
amm.swap(100 ether, 98 ether);  // 只允许2%滑点
```

**2. 使用私密交易：**
```
工具：
- Flashbots Protect
- MEV Blocker
- CoW Protocol (batch auctions)

效果：
- 交易不进入公开mempool
- 减少被三明治攻击
```

**3. 拆分大额交易：**
```
//  一次性大额
swap(1000 ETH)  // 巨大的价格影响

// 拆分多次
for i in 0..9:
    swap(100 ETH)  // 每次价格影响小
    wait(1 block)
```

### 协议层面

**1. JIT防护（时间锁）：**
```solidity
// Uniswap V3 Oracle观察期
contract Pool {
    mapping(address => uint256) lastProvideTime;
    
    function addLiquidity() external {
        lastProvideTime[msg.sender] = block.number;
    }
    
    function removeLiquidity() external {
        // 必须至少持有1个区块
        require(
            block.number > lastProvideTime[msg.sender],
            "Too soon"
        );
    }
}
```

**2. Batch拍卖（CoW Protocol）：**
```
传统AMM：
- 连续交易
- 每笔独立定价
- 容易被MEV

Batch拍卖：
- 收集一段时间内的所有订单
- 统一清算价格
- 订单之间互相匹配
- 剩余才去AMM
→ 减少MEV空间
```

**3. 最小交易金额：**
```solidity
// 防止粉尘套利
require(amountIn >= MIN_SWAP, "Too small");
```

## 真实MEV Bot示例

**简化的三明治Bot伪代码：**

```python
# MEV Bot 主循环
while True:
    # 1. 监控mempool
    pending_txs = mempool.get_pending()
    
    for tx in pending_txs:
        # 2. 识别有利可图的交易
        if is_profitable_swap(tx):
            victim_amount = parse_swap_amount(tx)
            
            # 3. 计算最优攻击参数
            frontrun_amount = calculate_optimal_frontrun(victim_amount)
            
            # 4. 模拟攻击
            profit = simulate_sandwich(frontrun_amount, tx)
            
            # 5. 如果有利可图，构造bundle
            if profit > MIN_PROFIT + gas_cost:
                bundle = create_sandwich_bundle(
                    frontrun_amount,
                    tx,
                    profit
                )
                
                # 6. 提交bundle
                flashbots.send_bundle(bundle)
                
                log(f"Sandwich attempt: {profit} ETH")
```

## 统计数据

**MEV提取历史：**
```
2023年数据：

三明治攻击：
- 占比：40%
- 总额：~$160M
- 受害交易：200K+

套利：
- 占比：35%
- 总额：~$140M

清算：
- 占比：15%
- 总额：~$60M

其他：
- 占比：10%
- 总额：~$40M
```

**Flashbots使用率：**
```
Bundle提交：
2021: 50K/day
2022: 200K/day
2023: 300K/day

成功率：
- 早期：~5%
- 现在：~15%
- 竞争激烈
```
