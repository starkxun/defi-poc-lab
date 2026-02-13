# 算术边界漏洞


**审计中最常见的漏洞类型：**
- 每个DeFi协议都涉及算术计算
- 精度损失导致的资金损失可能很隐蔽
- Scaling factor问题极难发现

**BlockSec关注的重点：**
- 复杂的价格计算
- 多代币精度处理
- Unchecked块的安全使用
- 数学库的正确性

## 快速开始

```bash
# 1. Unchecked溢出测试
forge test --match-test testOverflowInUnchecked -vvvv

# 2. 有符号整数误用
forge test --match-test testSignedIntegerConversion -vvvv

# 3. 精度损失演示
forge test --match-test testPrecisionLoss -vvvv

# 4. Scaling factor错误
forge test --match-test testScalingFactorMismatch -vvvv
```

## 五大核心问题

### 1. Overflow / Underflow（溢出/下溢）

#### Solidity版本差异

**Solidity <0.8:**
```solidity
uint256 a = 100;
uint256 b = 200;
uint256 c = a - b;  // 下溢！c = 2^256 - 100

// 没有任何错误，静默失败
```

**Solidity 0.8+:**
```solidity
uint256 a = 100;
uint256 b = 200;
uint256 c = a - b;  // 自动revert
```

#### 现代风险：Unchecked块

**危险场景：**
```solidity
function riskyBatch(uint256[] amounts) external {
    uint256 total;
    
    unchecked {
        for (uint i = 0; i < amounts.length; i++) {
            total += amounts[i];  // ✗ 可能溢出！
        }
    }
    
    require(balance >= total);  // total可能已经溢出成小数
    // ...
}
```

**攻击：**
```solidity
amounts = [
    type(uint256).max - 50,  // 巨大的数
    100                      // 小数
]

// 在unchecked中：
// total = (2^256-51) + 100 = 49 (溢出)
// 只需49的余额就能转账巨额！
```

**安全使用unchecked：**
```solidity
// 循环计数器
for (uint i = 0; i < array.length; ) {
    // ... 逻辑
    
    unchecked {
        i++;  // 安全：i不会溢出到0，循环会退出
    }
}

// 数学保证不溢出的场景
function safe(uint256 a) external pure returns (uint256) {
    require(a <= 1000);
    unchecked {
        return a * 2;  // 安全：最大2000，不会溢出
    }
}

// 用户输入
function unsafe(uint256 a, uint256 b) external pure returns (uint256) {
    unchecked {
        return a + b;  // 危险：a和b不受控
    }
}
```

### 2. Signed Integer Misuse（有符号整数误用）

#### 负数转无符号数

**问题：**
```solidity
int256 balance = -1 ether;
uint256 unsignedBalance = uint256(balance);

// unsignedBalance = 2^256 - 1 (巨大的正数！)
```

**真实攻击场景：**
```solidity
contract Vulnerable {
    mapping(address => int256) balances;
    
    function withdraw(uint256 amount) external {
        // ✗ 如果balances[msg.sender]是负数
        // 转换为uint会变成巨大正数，绕过检查
        require(uint256(balances[msg.sender]) >= amount);
        
        balances[msg.sender] -= int256(amount);
        // ...
    }
    
    function adjustBalance(int256 delta) external {
        balances[msg.sender] += delta;  // 可以传负数！
    }
}
```

**攻击步骤：**
```
1. 正常deposit 1 ether → balance = 1e18
2. adjustBalance(-2e18) → balance = -1e18
3. withdraw(巨额)
   → require(uint256(-1e18) >= amount)
   → uint256(-1e18) = 2^256 - 1e18 (通过！)
```

#### abs()实现陷阱

**错误实现：**
```solidity
function abs(int256 x) public pure returns (int256) {
    return x < 0 ? -x : x;  // ✗ 危险！
}

// 问题：
int256 min = type(int256).min;  // -2^255
int256 result = abs(min);        // -(-2^255) 溢出！
// 因为正数最大是 2^255 - 1
```

**正确实现：**
```solidity
function abs(int256 x) public pure returns (uint256) {
    // 返回uint256，避免溢出
    return x < 0 ? uint256(-x) : uint256(x);
}
```

#### 有符号除法陷阱

**向零取整 vs 向下取整：**
```solidity
int256 a = -5;
int256 b = 2;
int256 result = a / b;  // -2 (向零取整)

// 注意：不是-3（向下取整）
// 这可能不是期望的行为
```

### 3. Unchecked Blocks（未检查块）

#### 何时使用unchecked

**安全场景：**

1. **循环计数器**
```solidity
for (uint i = 0; i < n; ) {
    // ... 
    unchecked { i++; }  // 安全：i不会溢出
}
```

2. **数学保证的操作**
```solidity
// Uniswap V3的例子
unchecked {
    // 这里的数学已经证明不会溢出
    amountIn = (amountRemaining * sqrtPriceX96) >> 96;
}
```

3. **递减操作（有下界检查）**
```solidity
require(balance >= amount);
unchecked {
    balance -= amount;  // 安全：已检查过
}
```

**危险场景：**

1. **用户输入的算术**
```solidity
unchecked {
    return userInput * multiplier;  // 危险！
}
```

2. **累加未知大小的数组**
```solidity
unchecked {
    for (uint i = 0; i < amounts.length; i++) {
        total += amounts[i];  // 危险！
    }
}
```

3. **外部数据的计算**
```solidity
unchecked {
    return externalContract.getValue() * 2;  // 危险！
}
```

### 4. Multiplication/Division Order（乘除顺序）

#### 精度损失的根源

**问题示例：**
```solidity
// 计算1.5%的费用
uint256 amount = 1000;
uint256 rate = 15;  // 代表1.5%

// 错误：先除后乘
uint256 fee = (amount / 100) * rate;
// 1000 / 100 = 10
// 10 * 15 = 150  ← 错误！丢失了小数

// 正确：先乘后除  
uint256 fee = (amount * rate) / 100;
// 1000 * 15 = 15000
// 15000 / 100 = 150  ← 正确
```

**为什么重要？**
```
对于小额交易，精度损失可能达到100%！

例如：amount = 99, rate = 15
错误：(99/100)*15 = 0*15 = 0
正确：(99*15)/100 = 1485/100 = 14

损失了14个单位（100%错误！）
```

#### DeFi中的常见错误

**价格计算：**
```solidity
// 错误
function getPrice(uint reserve0, uint reserve1, uint amount) 
    external pure returns (uint) 
{
    // 先除后乘：精度损失
    return (amount / reserve0) * reserve1;
}

// 正确
function getPrice(uint reserve0, uint reserve1, uint amount) 
    external pure returns (uint) 
{
    // 先乘后除：保持精度
    return (amount * reserve1) / reserve0;
}
```

**多重计算：**
```solidity
// 每步都损失精度
uint step1 = amount / 3;
uint step2 = step1 / 5;
uint step3 = step2 * 7;

// 合并计算，只损失一次
uint result = (amount * 7) / (3 * 5);
```

#### 真实案例：Uniswap V2

**正确实现：**
```solidity
function getAmountOut(
    uint amountIn, 
    uint reserveIn, 
    uint reserveOut
) public pure returns (uint amountOut) {
    require(amountIn > 0);
    require(reserveIn > 0 && reserveOut > 0);
    
    // 先乘后除
    uint amountInWithFee = amountIn * 997;
    uint numerator = amountInWithFee * reserveOut;
    uint denominator = reserveIn * 1000 + amountInWithFee;
    
    amountOut = numerator / denominator;
}
```

### 5. Scaling Factor Mismatch（精度因子不匹配）

#### 不同代币的小数位

**常见代币精度：**
```
USDT:  6位小数 (1 USDT = 1,000,000)
USDC:  6位小数 (1 USDC = 1,000,000)  
WBTC:  8位小数 (1 WBTC = 100,000,000)
DAI:   18位小数 (1 DAI = 1,000,000,000,000,000,000)
WETH:  18位小数 (1 WETH = 10^18)
```

**问题场景：**
```solidity
// 错误：假设所有代币都是18位
function swap(uint usdcAmount, uint wethPrice) 
    external pure returns (uint wethAmount) 
{
    // usdcAmount = 1000 USDC = 1000 * 10^6
    // wethPrice = 2000 (1 WETH = 2000 USDC)
    
    wethAmount = usdcAmount / wethPrice;
    // = (1000 * 10^6) / 2000
    // = 500,000
    
    // 但应该是：0.5 WETH = 0.5 * 10^18
    // 错了 10^12 倍！
}
```

**正确处理：**
```solidity
// 正确：标准化精度
function swap(uint usdcAmount, uint wethPrice) 
    external pure returns (uint wethAmount) 
{
    // USDC(6位) → WETH(18位)
    // 需要乘以 10^(18-6) = 10^12
    
    wethAmount = (usdcAmount * 1e12) / wethPrice;
    // = (1000 * 10^6 * 10^12) / 2000
    // = (1000 * 10^18) / 2000
    // = 0.5 * 10^18 ✓
}
```

#### Vault的精度管理

**错误实现：**
```solidity
contract BadVault {
    uint public totalAssets;  // ✗ 混合了不同精度的代币
    
    function deposit(address token, uint amount) external {
        totalAssets += amount;  // ✗ 直接累加，没有标准化
    }
    
    function withdraw(uint shares) external {
        uint amount = shares * totalAssets / totalSupply;
        // ✗ 如果totalAssets混合了USDC(6位)和WETH(18位)
        // 计算会完全错误
    }
}
```

**正确实现：**
```solidity
contract GoodVault {
    uint public totalAssets;  // 标准化到18位精度
    uint constant PRECISION = 1e18;
    
    function deposit(address token, uint amount) external {
        uint8 decimals = IERC20Metadata(token).decimals();
        uint normalized = normalize(amount, decimals);
        
        totalAssets += normalized;  // 统一精度
    }
    
    function normalize(uint amount, uint8 decimals) 
        internal pure returns (uint) 
    {
        if (decimals < 18) {
            return amount * 10**(18 - decimals);
        } else if (decimals > 18) {
            return amount / 10**(decimals - 18);
        }
        return amount;
    }
}
```

#### 真实案例：Yearn Finance

**2023年的bug（简化）：**
```solidity
// Vault接受不同精度的代币
// 但没有标准化就混合计算

// 用户A存入 1 WETH (18位) = 1 * 10^18
// shares_A = 1 * 10^18

// 用户B存入 1000 USDC (6位) = 1000 * 10^6  
// shares_B = (1000 * 10^6 * shares_A) / totalAssets
//          = (1000 * 10^6 * 10^18) / (10^18)
//          = 1000 * 10^6

// 问题：
// WETH价值 $2000，获得 10^18 shares
// USDC价值 $1000，获得 10^9 shares
// 但USDC的价值只有WETH的一半
// 却获得了更多的shares（如果按单位计算）
```

## 审计检查清单

### 第1步：识别算术操作

```markdown
- [ ] 列出所有算术运算（+, -, *, /, %）
- [ ] 标记用户可控的输入
- [ ] 识别unchecked块
- [ ] 找出类型转换（int ↔ uint）
```

### 第2步：Overflow/Underflow检查

```markdown
- [ ] Unchecked块中的算术是否安全？
- [ ] 循环累加是否可能溢出？
- [ ] 有无Solidity 0.7-合约（无自动检查）？
- [ ] 递减操作前是否检查下界？
```

### 第3步：有符号整数检查

```markdown
- [ ] int转uint的场景？
- [ ] 是否可能产生负数绕过检查？
- [ ] abs()实现是否正确？
- [ ] 有符号除法是否符合预期？
```

### 第4步：精度损失检查

```markdown
- [ ] 乘除顺序是否正确？
- [ ] 是否先除后乘？
- [ ] 多重除法是否合并？
- [ ] 小额交易是否损失100%？
```

### 第5步：精度因子检查

```markdown
- [ ] 是否处理多种代币？
- [ ] 各代币的小数位数？
- [ ] 是否标准化到统一精度？
- [ ] 计算中精度转换是否正确？
```

## 防御最佳实践

### 方案1: 使用SafeMath（0.7-）

```solidity
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract Safe {
    using SafeMath for uint256;
    
    function calculate(uint a, uint b) external pure returns (uint) {
        return a.add(b).mul(100).div(3);
    }
}
```

### 方案2: 避免unchecked（除非确定安全）

```solidity
// 危险
unchecked {
    return userInput * multiplier;
}

// 安全
return userInput * multiplier;  // 让Solidity检查

// 安全的unchecked使用
for (uint i = 0; i < n; ) {
    // ...
    unchecked { i++; }  // 循环计数器安全
}
```

### 方案3: 使用高精度库

```solidity
import "prb-math/PRBMathUD60x18.sol";

function highPrecision(uint a, uint b) external pure returns (uint) {
    // PRBMath提供18位定点数
    return PRBMathUD60x18.mul(a, b);
}
```

### 方案4: 标准化代币精度

```solidity
contract Vault {
    uint constant NORMALIZED_DECIMALS = 18;
    
    function normalize(uint amount, uint8 decimals) 
        internal pure returns (uint) 
    {
        if (decimals == NORMALIZED_DECIMALS) return amount;
        
        if (decimals < NORMALIZED_DECIMALS) {
            return amount * 10**(NORMALIZED_DECIMALS - decimals);
        } else {
            return amount / 10**(decimals - NORMALIZED_DECIMALS);
        }
    }
    
    function denormalize(uint amount, uint8 decimals)
        internal pure returns (uint)
    {
        // 反向转换
        if (decimals == NORMALIZED_DECIMALS) return amount;
        
        if (decimals < NORMALIZED_DECIMALS) {
            return amount / 10**(NORMALIZED_DECIMALS - decimals);
        } else {
            return amount * 10**(decimals - NORMALIZED_DECIMALS);
        }
    }
}
```

### 方案5: 先乘后除

```solidity
// 错误
function bad(uint a, uint b, uint c) external pure returns (uint) {
    return (a / b) * c;
}

// 正确
function good(uint a, uint b, uint c) external pure returns (uint) {
    return (a * c) / b;
}

// 更好：检查溢出
function better(uint a, uint b, uint c) external pure returns (uint) {
    require(a <= type(uint256).max / c, "Overflow in multiply");
    return (a * c) / b;
}
```

## 常见错误模式

### 模式1: 费用计算精度损失

```solidity
// 常见错误
function calculateFee(uint amount) external pure returns (uint) {
    return (amount / 10000) * 30;  // 0.3%
    // 小额交易会损失所有费用
}

// 正确
function calculateFee(uint amount) external pure returns (uint) {
    return (amount * 30) / 10000;
}
```

### 模式2: 分数计算

```solidity
// 整数除法丢失小数
uint half = 5 / 2;  // = 2, not 2.5

// 使用定点数
uint constant PRECISION = 1e18;
uint half = (5 * PRECISION) / 2;  // = 2.5 * 10^18
```

### 模式3: 百分比计算

```solidity
// 先除后乘
uint result = (amount / 100) * percentage;

// 先乘后除
uint result = (amount * percentage) / 100;

// 更好：使用基点（basis points）
uint constant BPS = 10000;
uint result = (amount * percentageInBps) / BPS;
```

## 测试策略

### 边界值测试

```solidity
function testBoundaries() public {
    // 测试最大值
    uint max = type(uint256).max;
    
    // 测试最小值
    uint min = 0;
    
    // 测试溢出边界
    uint almostMax = type(uint256).max - 1;
    
    // 测试精度损失
    uint tiny = 1;
    
    // 测试有符号边界
    int maxInt = type(int256).max;
    int minInt = type(int256).min;
}
```

### Fuzz测试

```solidity
function testFuzz_noOverflow(uint a, uint b) public {
    // Foundry会用随机值测试
    vm.assume(a <= type(uint128).max);
    vm.assume(b <= type(uint128).max);
    
    uint result = a + b;
    assertTrue(result >= a && result >= b);
}
```

### 不变量测试

```solidity
function invariant_totalSupplyMatchesBalances() public {
    uint sum = 0;
    for (uint i = 0; i < users.length; i++) {
        sum += token.balanceOf(users[i]);
    }
    
    assertEq(sum, token.totalSupply());
}
```
