# web3careerbuild-contract

Web3 Career Build 证书与徽章模块合约库，用于平台证书、徽章 NFT 的铸造与管理。

## 合约说明

- `src/BadgeNFT.sol`
  - 基于 ERC-1155 的徽章合约（同一徽章类型可发给多个用户）。
  - 默认禁止用户之间转移（不可自由买卖）。
  - 官方可通过 `adminTransfer` 按 `awardId` 精确执行地址迁移（`onlyOwner`）。
  - 仅支持签名铸造：`mintWithSig`。
  - 支持吊销：`revokeAward` / `isRevoked`。
  - 支持按 `awardId` 查询当前归属：`awardOwner`。
  - 支持元数据冻结：`freezeBadgeURI` / `freezeDefaultURI`。
  - `awardId` 格式限制：仅允许小写字母、数字、`-`、`_`（例如：`award-001`）。

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

流程：

1. 后端生成授权参数 `auth`。
2. 后端用 `trustedSigner` 私钥签名。
3. 用户调用 `mintWithSig(auth, signature)` 上链领取。
4. 合约校验签名、nonce、deadline 与唯一性约束后铸造。

## 吊销与迁移规则

- `BadgeNFT`：
  - `revokeAward(awardId, reason)` 用于吊销指定徽章记录。
  - 吊销后该 `awardId` 不允许再执行 `adminTransfer` 迁移。
  - `adminTransfer` 以 `awardId` 为唯一标识迁移 1 枚对应徽章，不再使用 `amount`。

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

`script/DeployBadgeNFT.s.sol`：

- `BADGE_MINT_TRUSTED_SIGNER`：徽章 mint 签名方（脚本读取）
- `BADGE_OWNER`（可选，默认部署者地址）
- `BADGE_BASE_URI`（可选，默认 `ipfs://badge-default/{id}.json`）

`script/DeployCertificateNFT.s.sol`：

- `MINT_TRUSTED_SIGNER_ADDRESS`：证书 mint 签名方地址（脚本读取）
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

- 当前是“用户自领取”的签名铸造模式。
- 用户之间默认不可转移；换地址由官方（owner）执行迁移。
- 当前版本未开启“多地址批量空投 mint”接口。
