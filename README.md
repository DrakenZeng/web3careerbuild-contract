# web3careerbuild-contract

Web3 Career Build 证书与徽章模块合约库，用于平台证书、徽章 NFT 的铸造与管理。

## 合约说明

- `src/BadgeNFT.sol`
  - 基于 ERC-1155 的徽章合约（同一徽章类型可发给多个用户）。
  - 默认禁止用户之间转移（不可自由买卖）。
  - 外部 `safeTransferFrom` / `safeBatchTransferFrom` 已禁用，仅保留受控迁移入口 `adminTransfer`。
  - 支持签名铸造 `mintWithSig` 与后台铸造 `adminMint`。
  - 支持软吊销与复效：`revokeAward` / `reinstateAward` / `isRevoked`。
  - 支持按 `awardIdHash` 查询当前归属：`awardOwner`。
  - 强约束同一地址同一 `badgeTypeId` 只能持有 1 枚。
  - 支持元数据冻结：`freezeBadgeURI` / `freezeDefaultURI`。
  - 权限模型：`DEFAULT_ADMIN_ROLE`（角色管理、元数据与签名方配置）与 `OPERATOR_ROLE`（业务操作）。
  - 业务唯一标识使用 `bytes32 awardIdHash`（通常由后端 `keccak256(awardId)` 生成）。

- `src/CertificateNFT.sol`
  - 基于 ERC-721 的证书合约。
  - 默认禁止用户之间转移（不可自由买卖）。
  - 官方可通过 `adminTransfer` 执行地址迁移（`onlyOwner`）。
  - 仅支持签名铸造：`mintWithSig`。
  - 通过 `certificateId` 防止重复铸造。
  - `tokenURI` 采用 `baseURI + certificateId(hex)` 动态计算（不按 token 单独存储 URI）。
  - 支持吊销：`revokeCertificate` / `isRevoked`。
  - 构造函数支持显式传入 `initialOwner` 与 `certificateBaseURI`。

## 签名铸造模型

两个合约都采用：

- EIP-712 Typed Data 签名
- 中心化可信签名地址 `trustedSigner`
- 防重放 nonce（`usedNonces`，支持乱序 nonce 使用）
- 过期时间 `deadline`
- 领取人绑定（`auth.to == msg.sender`）

`BadgeNFT` 的签名载荷核心字段：

- `to`
- `badgeTypeId`
- `awardIdHash`（`bytes32`）
- `nonce`
- `deadline`

流程：

1. 后端生成授权参数 `auth`。
2. 后端用 `trustedSigner` 私钥签名。
3. 用户调用 `mintWithSig(auth, signature)` 上链领取。
4. 合约校验签名、nonce、deadline 与唯一性约束后铸造。

## 吊销与迁移规则

- `BadgeNFT`：
  - `revokeAward(awardIdHash, reason)` 为软吊销（仅状态变更，不销毁 NFT）。
  - 吊销后该 `awardIdHash` 不允许执行 `adminTransfer`。
  - 重新发放通过 `reinstateAward(to, awardIdHash, reason, requestId)` 复效（可原地址复效，或迁移后复效）。
  - `adminTransfer` 以 `awardIdHash` 为唯一标识迁移 1 枚对应徽章，不再使用 `amount`。
  - 上述业务操作由 `OPERATOR_ROLE` 执行。

- `CertificateNFT`：
  - `revokeCertificate(certificateId, reason)` 用于吊销指定证书。
  - 吊销后该证书不允许再执行 `adminTransfer` 迁移。

- `reason` / `requestId` 当前为 `string`，用于保留完整审计信息（避免 `bytes32` 截断）。

## 环境准备

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

安装依赖：

```bash
forge install
```

## 常用命令

```bash
forge build
forge test
forge fmt
```

Gas 报表示例：

```bash
forge test --gas-report --match-path test/BadgeNFT.t.sol
```

## 部署

### 1) 环境变量

通用：

- `PRIVATE_KEY`：部署私钥
- `MINT_TRUSTED_SIGNER_ADDRESS`：mint 签名方地址（BadgeNFT 与 CertificateNFT 共用）

`script/DeployBadgeNFT.s.sol`：

- `BADGE_OWNER`（可选，默认部署者地址）
- `BADGE_BASE_URI`（可选，默认 `ipfs://badge-default/{id}.json`）

`script/DeployCertificateNFT.s.sol`：

- `CERTIFICATE_OWNER`（可选，默认部署者地址）
- `CERTIFICATE_NAME`（可选）
- `CERTIFICATE_SYMBOL`（可选）
- `CERTIFICATE_BASE_URI`（可选，默认 `ipfs://certificate/`）

### 2) 部署 BadgeNFT

```bash
forge script script/DeployBadgeNFT.s.sol:DeployBadgeNFT \
  --rpc-url <RPC_URL> \
  --broadcast
```

### 3) 部署 CertificateNFT

```bash
forge script script/DeployCertificateNFT.s.sol:DeployCertificateNFT \
  --rpc-url <RPC_URL> \
  --broadcast
```

## 目录结构

```text
src/
  BadgeNFT.sol
  CertificateNFT.sol
script/
  DeployBadgeNFT.s.sol
  DeployCertificateNFT.s.sol
test/
  BadgeNFT.t.sol
  CertificateNFT.t.sol
```

## 备注

- 当前是“用户自领取 + 后台可铸造”的混合模式（`mintWithSig` + `adminMint`）。
- 用户之间默认不可转移；换地址由官方操作员（`OPERATOR_ROLE`）执行迁移。
- 验证有效性时应同时检查是否已吊销（`isRevoked(awardIdHash)`），不要仅依赖 `balanceOf`。
- 建议后端统一维护 `awardId -> awardIdHash` 映射并以 `awardIdHash` 作为链上主键。
