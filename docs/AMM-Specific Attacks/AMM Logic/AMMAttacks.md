# AMM专项攻击 - 深度学习指南


**Balancer就是一个复杂的AMM**

```
Balancer攻击 = 这里所有技术的组合

Balancer ComposableStablePool:
├─ Constant Product (加权池)
├─ Invariant (D值计算)
├─ LP Share (BPT铸造)
├─ Precision Loss (舍入误差)
└─ Fee Accounting (协议费用)
```


## 快速开始

```bash
# 1. 恒定乘积滥用
forge test --match-test testConstantProductAbuse -vvv

# 2. 不变量操纵
forge test --match-test testInvariantManipulation -vvv

# 3. LP份额通胀
forge test --match-test testLPShareInflation -vvv

# 4. 粉尘攻击
forge test --match-test testDustAttack -vvv

# 5. 费用记账漏洞
forge test --match-test testFeeAccountingFlaw -vvv
```

## 五大核心攻击

### 1. Constant Product Abuse（恒定乘积滥用）

#### 原理

**Uniswap的核心公式：**
```
x * y = k

其中：
x = reserve0（代币0数量）
y = reserve1（代币1数量）
k = 恒定乘积（应该保持不变）
```

**问题：**
```solidity
// 错误的检查
require(newX * newY >= k, "K violated");

// 这允许k增长
// newX * newY = k + 100 ← 通过检查
// 但k不应该变化
```

#### 攻击机制

```
初始状态：
x = 1000, y = 1000
k = 1,000,000

Swap 1: 
输入10, 费用0.3%
输出 = (10 * 0.997 * 1000) / (1000 + 10 * 0.997)
     = 9.97 (向下舍入为9)

新状态：
x = 1010, y = 991
k = 1,000,910 ← k增加了910！

重复100次：
k可能增加到 1,100,000
增长10%！
```

#### 影响

**对LP的影响：**
```
k增加 → 池子总价值增加
→ LP每份额价值增加
→ LP获益（trader损失）

k减少 → 池子总价值减少  
→ LP每份额价值减少
→ LP损失（可能被攻击）
```

**真实案例：**
```
Bancor V2早期：
- k漂移累积
- LP获得意外收益
- Trader损失未被注意
- 修复：严格k检查
```

#### 防御

```solidity
// 正确的实现（Uniswap V2）
uint balance0 = IERC20(token0).balanceOf(address(this));
uint balance1 = IERC20(token1).balanceOf(address(this));

// 减去储备得到输入量
uint amount0In = balance0 > _reserve0 - amount0Out ? 
                 balance0 - (_reserve0 - amount0Out) : 0;
                 
// 严格检查k
uint balance0Adjusted = balance0 * 1000 - amount0In * 3;
uint balance1Adjusted = balance1 * 1000 - amount1In * 3;

require(
    balance0Adjusted * balance1Adjusted >= 
    uint(_reserve0) * _reserve1) * (1000**2),
    "K"
);
```

### 2. Invariant Manipulation（不变量操纵）

#### StableMath的D值

**Curve/Balancer的不变量：**
```
对于StableSwap：
A * n^n * sum(x_i) + D = A * n^n * D + D^(n+1) / (n^n * prod(x_i))

其中：
A = 放大系数
n = 代币数量
x_i = 各代币余额
D = 不变量
```

**计算过程：**
```python
# 迭代求解D
def calculate_D(balances, A):
    S = sum(balances)
    D = S
    Ann = A * len(balances)
    
    for i in range(255):  # 最多255次迭代
        D_P = D
        for balance in balances:
            D_P = D_P * D / (balance * len(balances))  # ← 舍入点1
        
        D_prev = D
        D = ((Ann * S + D_P * len(balances)) * D) / \
            ((Ann - 1) * D + (len(balances) + 1) * D_P)  # ← 舍入点2
        
        # 检查收敛
        if abs(D - D_prev) <= 1:
            break
    
    return D
```

#### 攻击向量

**策略1：制造不平衡**
```
均衡状态：[1000, 1000, 1000]
D = 3000 (大约)
迭代次数：3-5次

不平衡：[2500, 500, 500]  
D = 3000 (应该相同)
但实际计算：
- 迭代次数：20-30次
- 每次迭代都有舍入
- 累积误差 = D ± 10-50

放大倍数 = Amp参数
Amp = 100 → 误差放大100倍
```

**策略2：小额操作累积**
```
大额swap 1次：误差 = 10
小额swap 100次：累积误差 = 100

原因：
- 每次除法向下舍入
- 100次 = 100个舍入点
- 累积效应显著
```

#### 真实影响

**Balancer的例子：**
```
2023年ComposableStablePool攻击：

初始D = 1,000,000 * 1e18
攻击步骤：
1. 大额swap制造不平衡
2. 100次小额swap
3. D漂移到 1,000,100 * 1e18

结果：
- D增加0.01%
- 在exitPool时getBPTRate()虚高
- 结合read-only reentrancy
- 损失：数十万美元
```

### 3. LP Share Inflation（LP份额通胀）

#### 攻击流程

```
Step 1: 首个存款
addLiquidity(1 wei, 1 wei)
shares = sqrt(1 * 1) = 1
totalSupply = 1

Step 2: 捐赠（不通过addLiquidity）
transfer(10000 ether)
reserve0 = 10000 ether + 1 wei
reserve1 = 1 wei
totalSupply = 1 (不变)

Step 3: 份额价值
shareValue = (reserve0 + reserve1) / totalSupply
           = ~10000 ether / 1
           = 10000 ether per share

Step 4: 受害者存款
addLiquidity(1 ether, 1 ether)
shares = min(
    1 ether * 1 / 10000 ether,
    1 ether * 1 / 1 wei
) = 0 (向下舍入)

受害者得0份额，损失1 ether！

Step 5: 攻击者退出
removeLiquidity(1)
得到 ~10001 ether
净利润 = 1 ether
```

#### 为什么危险？

**成本低，收益高：**
```
攻击成本：
- 初始存款：1 wei
- 捐赠：10000 ether
- 总计：~10000 ether

受害者损失：
- 第一个：1 ether
- 第二个：2 ether  
- 第三个：5 ether
- ...
- 总计可能超过攻击成本
```

#### Uniswap V2的防御

**永久锁定最小流动性：**
```solidity
function mint(address to) external returns (uint liquidity) {
    ...
    if (_totalSupply == 0) {
        liquidity = Math.sqrt(amount0.mul(amount1)).sub(MINIMUM_LIQUIDITY);
        _mint(address(0), MINIMUM_LIQUIDITY); // ← 关键：永久销毁1000 wei
    }
    ...
}

uint public constant MINIMUM_LIQUIDITY = 10**3;
```

**为什么有效：**
```
攻击者尝试：
addLiquidity(1 wei, 1 wei)
shares = sqrt(1 * 1) = 1
但1000 wei被永久锁定
攻击者得到 0

要攻击需要：
addLiquidity(1000000 wei, 1000000 wei)
成本增加100万倍！
使攻击不经济
```

### 4. Dust Attack（粉尘攻击）

#### 粉尘的定义

```
粉尘 = 极小金额交易
通常 < 1000 wei
目的：利用舍入误差或绕过检查
```

#### 攻击场景

**场景A：免费swap**
```solidity
function swap(uint amountIn) external {
    uint fee = (amountIn * 3) / 1000;
    // 如果amountIn < 334 wei
    // fee = 0
    // 免费swap！
}
```

**场景B：获取份额**
```solidity
function addLiquidity(uint amount) external {
    uint shares = (amount * totalSupply) / reserves;
    // 如果amount很小但totalSupply更小
    // 可能得到超比例的份额
}
```

**场景C：Gas griefing**
```solidity
// 攻击者创建1000个粉尘交易
for (uint i = 0; i < 1000; i++) {
    pool.swap(1 wei);
}

// 每个操作：
// - 触发事件
// - 更新storage
// - 消耗区块gas
// 降低网络性能
```

#### 防御

```solidity
uint public constant MINIMUM_SWAP = 1000;
uint public constant MINIMUM_LIQUIDITY = 10000;

function swap(uint amountIn) external {
    require(amountIn >= MINIMUM_SWAP, "Amount too small");
    // ...
}

function addLiquidity(uint amount) external {
    require(amount >= MINIMUM_LIQUIDITY, "Amount too small");
    // ...
}
```

### 5. Fee Accounting Flaw（费用记账漏洞）

#### 问题模式

**模式A：双重计费**
```solidity
function swap(uint amountIn) external {
    uint fee = amountIn * 3 / 1000;
    
    // 错误1：费用加入reserve
    reserve += amountIn;  // 包含费用
    
    // 错误2：费用单独记录
    accumulatedFees += fee;
    
    // 结果：费用被计算了两次
}

function withdrawFees() external {
    // 错误3：从reserve扣除
    reserve -= accumulatedFees;
    
    // 但fee已经在reserve里了
    // 这会导致reserve错误减少
}
```

**模式B：费用丢失**
```solidity
function swap(uint amountIn) external {
    uint fee = amountIn * 3 / 1000;
    uint amountAfterFee = amountIn - fee;
    
    // 只更新净值
    reserve += amountAfterFee;
    
    // ✗ 费用去哪了？
    // 费用留在合约但不在reserve中
    // 无法提取，永久锁定
}
```

**模式C：舍入累积**
```solidity
function swap(uint amountIn) external {
    // 小额swap，费用舍入为0
    uint fee = (amountIn * 3) / 1000;
    if (amountIn < 334) {
        fee = 0;  // 舍入
    }
    
    // 协议应得费用丢失
    // 累积100次 = 损失100-300 wei
}
```

#### 正确的费用模型

**Uniswap V2的方案：**
```solidity
contract UniswapV2Pair {
    uint112 private reserve0;
    uint112 private reserve1;
    uint32  private blockTimestampLast;
    
    // 协议费用通过铸造LP份额收取
    function _mintFee(uint112 _reserve0, uint112 _reserve1) 
        private returns (bool feeOn) 
    {
        address feeTo = IUniswapV2Factory(factory).feeTo();
        feeOn = feeTo != address(0);
        
        uint _kLast = kLast;
        if (feeOn) {
            if (_kLast != 0) {
                uint rootK = Math.sqrt(uint(_reserve0).mul(_reserve1));
                uint rootKLast = Math.sqrt(_kLast);
                
                if (rootK > rootKLast) {
                    uint numerator = totalSupply.mul(rootK.sub(rootKLast));
                    uint denominator = rootK.mul(5).add(rootKLast);
                    uint liquidity = numerator / denominator;
                    
                    if (liquidity > 0) _mint(feeTo, liquidity);
                }
            }
        }
    }
}
```

**优点：**
```
1. 费用不从reserve扣除
2. 通过LP份额稀释收取
3. 不影响k值
4. 清晰透明
```

## 综合案例：完整的Balancer攻击

### 攻击链分解

```
Phase 1: Invariant Manipulation
├─ 大额swap制造不平衡
├─ balances = [2000, 500, 500]
└─ D开始漂移

Phase 2: Constant Product Abuse  
├─ 多次小额swap
├─ 每次k增加一点点
└─ 累积k drift

Phase 3: Precision Loss
├─ 迭代计算D
├─ 每次迭代舍入误差
└─ 累积D drift

Phase 4: LP Share Inflation (Read-only Reentrancy)
├─ exitPool触发回调
├─ totalBPT减少，balances未减少
├─ getBPTRate() = inflated
└─ 虚高的BPT价值

Phase 5: Exploit
├─ 其他协议读取虚高BPT rate
├─ 允许超额借款
└─ 攻击者获利
```

### 数学分析

**正常情况：**
```
Pool: [1000, 1000, 1000] DAI/USDC/USDT
D = 3000
BPT = 3000
Rate = 1.0

exitPool(100 BPT):
- Remove [33.33, 33.33, 33.33]
- New balances: [966.67, 966.67, 966.67]
- New D = 2900
- New BPT = 2900
- Rate still = 1.0 ✓
```

**攻击情况：**
```
After manipulation:
Pool: [2000, 500, 500]
D = 3000 (应该不变)
D actual = 3010 (漂移+10)
BPT = 3000

exitPool(100 BPT) + Reentrancy:
在回调中：
- BPT = 2900 (已减少)
- balances = [2000, 500, 500] (未减少)
- D = 3010 (虚高)
- Rate = 3010 / 2900 = 1.038 (虚高3.8%!)

用虚高的rate借款：
- 存100 BPT抵押品
- 按1.038计算 = $103.8价值
- 实际只值 $100
- 超额借款 $3.8
- 放大1000次 = $3800利润
```

## 防御完整检查清单

### AMM合约审计要点

```markdown
## 1. 不变量检查
- [ ] k值是否严格验证（== 而不是 >=）
- [ ] D值计算是否有收敛检查
- [ ] 迭代次数是否有上限
- [ ] 精度损失是否可接受

## 2. 份额计算
- [ ] 是否有最小流动性锁定
- [ ] 首次存款是否特殊处理
- [ ] 份额计算是否防溢出
- [ ] 舍入方向是否一致

## 3. 费用模型
- [ ] 费用如何记录
- [ ] 费用如何提取
- [ ] 是否有双重计费风险
- [ ] 小额交易费用是否正确

## 4. 最小金额
- [ ] swap最小金额
- [ ] 添加流动性最小金额
- [ ] 移除流动性最小金额
- [ ] 防止粉尘攻击

## 5. 精度处理
- [ ] 除法舍入方向
- [ ] 是否有精度常数
- [ ] 跨代币精度转换
- [ ] 累积误差是否可控
```
