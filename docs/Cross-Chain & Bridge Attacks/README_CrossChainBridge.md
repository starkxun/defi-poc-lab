# 跨链与桥接攻击 - 完整学习指南

## 为什么跨链桥是最大的攻击面？

跨链桥是 DeFi 中**损失最大的单一攻击类别**。本模块覆盖 5 个真实案例，合计损失 $1.876B+：

| 协议 | 时间 | 损失 | 漏洞类型 |
|------|------|------|---------|
| Ronin Bridge | 2022.03 | $625M | 守护者密钥泄露（场景5）|
| Wormhole | 2022.02 | $320M | 签名验证绕过（场景2）|
| Nomad Bridge | 2022.08 | $190M | 验证绕过 + 消息重放（场景1+4）|
| Multichain | 2023.07 | $130M | 域分隔符缺 chainId（场景3）|
| Meter Passport | 2022.02 | $4.4M | chainId 重放（场景6）|

与链上漏洞不同，跨链攻击路径跨越两条链，一旦消息被接受几乎无法撤销。

### 与 Balancer V2 的关联

```
场景1 消息重放     → Balancer 跨链 gauge 奖励消息去重机制
场景2 签名伪造     → CrossChainAuthorizer 的 guardian 签名验证
场景3 域分隔符     → veBAL 跨链投票权同步的 EIP-712 绑定
场景4 验证绕过     → L1→L2 消息的 Merkle proof 验证
场景5 守护者妥协   → TimelockAuthorizer 的多签设计
场景6 chainId 重放 → omnichain gauge 的目标链 ID 验证
```

---

## 快速开始

```bash
forge test --match-contract CrossChainBridgeTest -vv
forge test --match-test testMessageReplay -vvv
forge test --match-test testSigForgeryZeroGuardian -vvv
forge test --match-test testValidationBypass -vvv
forge test --match-test testGuardianMajorityCompromise -vvv
forge test --match-test testChainIdReplay -vvv
```

---

## 6 大核心场景

---

### 场景1：消息重放 (Message Replay)

**Nomad Bridge（2022.08，$190M）**

跨链消息处理后如果不标记为"已处理"，相同消息可以被无限次提交执行。

Nomad 的特殊性：`confirmAt[bytes32(0)] = 1` 被错误地设置在构造函数中。
`messages[anyUnknownHash]` 的默认值是 `bytes32(0)`，而 `acceptableRoot(bytes32(0)) = true`。
因此**任意消息哈希都通过验证**，不需要真正的 Merkle proof。

最初只有发现者在利用，90 分钟后链上 calldata 被复制，全网开始抢跑，变成"公开劫持"。

```solidity
//  漏洞：处理消息后不标记
function processMessage(...) external {
    require(acceptableRoot(messages[msgHash]), "Bad root");
    token.transfer(recipient, amount);
    // 缺少：processedMessages[msgHash] = true
}

//  防御：处理后立即标记
require(!processedMessages[msgHash], "Already processed");
processedMessages[msgHash] = true;
```

---

### 场景2：签名伪造 (Signature Forgery)

**Wormhole（2022.02，$320M）**

三种常见签名漏洞：

**漏洞A：ecrecover 返回 address(0)**

`ecrecover()` 在签名无效时返回 `address(0)`。若 `guardian` 本身是 `address(0)`（未初始化），则任意无效签名都通过。

```solidity
//  危险：未检查返回值
require(ecrecover(hash, v, r, s) == guardian, "Bad sig");
// guardian = address(0) => 任意无效签名都通过

//  安全：显式检查非零
address recovered = ecrecover(hash, v, r, s);
require(recovered != address(0), "Invalid signature");
require(recovered == guardian,   "Not guardian");
```

**漏洞B：签名可延展性**

ECDSA 中，对任意有效签名 `(v, r, s)`，`(v ^ 1, r, secp256k1.n - s)` 也是该消息的有效签名。若用签名字节本身去重，延展性变体能绕过检查。

防御：限制 s 值在低半区（OpenZeppelin ECDSA 标准）。

**漏洞C：签名长度不检查**

不检查 `sig.length == 65` 时，攻击者可在后面附加字节，使签名"看起来不同"但提取的 `(r, s, v)` 相同，从而绕过基于签名字节的去重。

---

### 场景3：域分隔符不当 (Improper Domain Separation)

**Multichain（2023.07，$130M）**

EIP-712 域分隔符必须包含四要素，缺少任何一项都会产生重放漏洞：

```solidity
//  完整的四要素域分隔符
DOMAIN_SEPARATOR = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256("BridgeName"),  // ① 协议名：区分不同协议
    keccak256("1"),           // ② 版本：升级后旧签名失效
    block.chainid,           // ③ 链 ID：防跨链重放
    address(this)            // ④ 合约地址：防同链跨合约重放
));
```

| 缺少要素 | 攻击路径 |
|----------|----------|
| chainId | ETH 签名在 BSC 重用 |
| verifyingContract | 升级后旧签名仍有效 |
| version | 漏洞修复后无法使旧签名失效 |

额外防御：消息体中同时包含 `srcChainId` 和 `dstChainId`，执行时验证 `dstChainId == block.chainid`（业务层双重保护）。

---

### 场景4：验证绕过 (Validation Bypass)

**Nomad Bridge（根本原因）**

核心漏洞：**mapping 的默认值被验证函数接受为有效**。

```solidity
//  Nomad 的构造函数错误
confirmAt[bytes32(0)] = 1;  // 零值根被设为有效

// messages[未知哈希] = bytes32(0)（mapping 默认值）
// acceptableRoot(bytes32(0)) = confirmAt[0] != 0 = true
// => 任意消息哈希都通过！

//  防御：显式拒绝零值
function acceptableRoot(bytes32 root) public view returns (bool) {
    if (root == bytes32(0)) return false;  // 必须显式拒绝
    ...
}
```

正确的消息验证顺序（Optimistic Bridge 模式）：
1. `prove(msgHash, merkleProof)` — 先证明消息存在于 Merkle 树中
2. 等待欺诈证明窗口（30 分钟）
3. `process(message)` — 验证已证明 + 已过窗口 + 未处理

---

### 场景5：守护者多数妥协 (Guardian Majority Compromise)

**Ronin Bridge（2022.03，$625M）**

**攻击时间线：**
- 2021.11：Sky Mavis 申请 Axie DAO 临时节点授权（应急用）
- 2022.01：该授权被 Axie DAO 遗忘，未撤销
- 2022.03.23：攻击者钓鱼获得 Sky Mavis 4 个节点私钥
- 发现遗忘的第 5 个授权 → 5/9 阈值达成
- 签名 2 笔提款，取走 $625M
- **6 天后才被发现（无实时监控）**

**守护者机制安全对比：**

| 安全措施 | Ronin（被攻击）| 安全设计 |
|----------|---------------|---------|
| 签名阈值 | 5/9 (55%) | ≥ 7/11 (64%) |
| 执行延迟 | 无 | 24 小时 |
| 速率限制 | 无 | 每日 $1M |
| 守护者新增 | 无延迟 | 7 天延迟 |
| 授权到期 | 无 | 自动过期 |
| 监控告警 | 无 | 实时警报 |

执行延迟的关键意义：攻击者无论如何都必须等待 24 小时，安全团队有时间检测并暂停合约。

---

### 场景6：跨链 ChainId 重放 (Cross-chain ChainId Replay)

**Meter Passport（2022.02，$4.4M）**

常见的三种 chainId 错误：

**错误1：dstChainId 字段存在但不验证**
消息中携带 `dstChainId` 参数，但执行时没有 `require(dstChainId == block.chainid)`。
消息在目标链 A 签名，可以在链 B 上执行。

**错误2：硬编码 chainId**
```solidity
uint256 public constant CHAIN_ID = 1;  //  分叉后仍是 1
// 应该是：block.chainid（动态获取）
```
链发生分叉后，新链的 block.chainid 变化，但硬编码的 CHAIN_ID 不变，签名在两条链上均有效。

**错误3：ResourceID 不含 chainId**
跨链资产标识符（ResourceID）若不绑定 chainId，在所有链上代表同一资产，消息可任意跨链重用。

**三层 chainId 保护（缺一不可）：**
```
第一层（加密）：EIP-712 域分隔符包含 block.chainid
第二层（消息）：消息体包含 srcChainId + dstChainId
第三层（执行）：require(dstChainId == block.chainid)
```

---

## 防御完整检查清单

```
消息去重：
- [ ] processedMessages mapping，处理后立即标记
- [ ] 消息 ID 包含所有唯一字段（nonce/txHash/msgId）

签名验证：
- [ ] require(recovered != address(0))
- [ ] require(guardian != address(0)) （构造函数）
- [ ] sig.length == 65 检查
- [ ] s 值限制在低半区（防延展性）
- [ ] 使用消息内容去重，而非签名字节去重

域分隔符：
- [ ] EIP-712 四要素：name + version + chainId + verifyingContract
- [ ] 消息体中额外包含 srcChainId + dstChainId
- [ ] 执行时 require(dstChainId == block.chainid)

消息验证：
- [ ] 默认值（bytes32(0)）被显式拒绝
- [ ] 零值根不可被接受（不在构造函数设置）
- [ ] prove() 先于 process()，两步流程
- [ ] 欺诈证明窗口

守护者设计：
- [ ] 阈值 ≥ 67%
- [ ] 执行延迟 ≥ 24 小时
- [ ] 每日速率限制
- [ ] 新增守护者 ≥ 7 天延迟
- [ ] 定期审查历史授权

chainId 绑定：
- [ ] 使用 block.chainid，禁止硬编码
- [ ] ResourceID 包含链信息
- [ ] 三层绑定：域 + 消息 + 执行
```

---

## 完整系列总结（11 个模块）

```
模块1：重入攻击          4 种变体    $500M+
模块2：Delegatecall 劫持 2 场景     $150M+
模块3：算术边界          5 类       ---
模块4：精度损失          5 场景     $128M+
模块5：闪电贷攻击        6 技术     $600M+
模块6：AMM 攻击          5 核心     $300M+
模块7：MEV 攻击          4 种       ---
模块8：访问控制与升级    6 场景     $1B+
模块9：ERC20 非标准行为  6 场景     $100M+
模块10：逻辑与经济设计   6 场景     $600M+
模块11：跨链与桥接攻击   6 场景     $1.876B+

总代码量：~18,000 行 Solidity
真实案例：40+
覆盖损失：$7B+
Foundry 测试：60+
```

---

*Starkxun | Web3 安全研究 | 2026.03*
