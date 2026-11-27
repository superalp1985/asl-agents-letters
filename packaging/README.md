# ASL 发布包

仓库包含两条独立发布链：

| 目标 | 构建入口 | 发布说明 |
| --- | --- | --- |
| Windows x64 桌面/Agent 便携包 | `scripts/package-windows.ps1` | `packaging/windows/README.md`、`packaging/windows/RELEASE.md` |
| Linux x86_64/aarch64 `asl-infra` | `scripts/package-linux-infra.sh` | `packaging/linux/README.md` |

正式发布共同要求：

- 在干净工作树中构建，产物文件名包含产品、平台、架构和版本。
- 包内提供 `SHA256SUMS`、`THIRD-PARTY`、CycloneDX SBOM、适用时的 MPL 源码包和 `BUILD-INFO`。
- Windows EXE 使用 Authenticode；Windows 更新另需严格 Ed25519 manifest、detached signature 和可独立公布的公钥。
- Linux 包使用独立 Ed25519 domain-separated detached signature。
- 包内散列清单只使用相对路径和固定顺序；Linux tar/gzip、MPL 源码包及 Windows ZIP 使用 `SOURCE_DATE_EPOCH` 归一化时间。
- 发布私钥位于仓库外；仓库、日志、ZIP、SBOM 和文档不得包含私钥。
- 发布密钥不复用 Agent identity root、libp2p peer key、TLS key 或链上 controller key。

## Windows

```powershell
$releaseRoot = Join-Path $env:ASL_HOME 'release'
.\scripts\package-windows.ps1 `
  -OutputZip (Join-Path $releaseRoot 'asl-windows-x86_64-1.0.0.zip') `
  -AuthenticodeThumbprint '<thumbprint>' `
  -SignToolPath '<signtool.exe>' `
  -TimestampUrl '<operator-approved HTTPS timestamp service>'
.\scripts\sign-windows-package.ps1 `
  -Package (Join-Path $releaseRoot 'asl-windows-x86_64-1.0.0.zip') `
  -Version '1.0.0' `
  -ReleasePrivateKey '<external key.pem>' `
  -OutputDirectory $releaseRoot `
  -VerifierCore '<previous release>\asl-core.exe'
```

Windows 更新清单字段、签名原文和失败条件见 `packaging/windows/RELEASE.md`。没有有效 Authenticode 和旧版 Core 复验的包不得标记为正式发行。

## Linux

```bash
ASL_INFRA_TARGET=x86_64-unknown-linux-gnu ./scripts/package-linux-infra.sh <release-output-directory>
bash ./scripts/sign-release-artifact.sh \
  <external-release-key.pem> \
  <release-output-directory>/asl-infra-linux-x86_64-1.0.0.tar.gz \
  ASL-LINUX-INFRA-RELEASE-v1 \
  <release-output-directory>
```

使用已信任源码树中的 verifier 和通过独立渠道核验的 raw-key SHA-256 指纹离线验包：

```bash
bash packaging/linux/verify-offline-release.sh \
  asl-infra-linux-x86_64-1.0.0.tar.gz \
  asl-infra-linux-x86_64-1.0.0.tar.gz.sig \
  asl-infra-linux-x86_64-1.0.0.tar.gz.release-key.pem \
  asl-infra-linux-x86_64-1.0.0.tar.gz.sha256 \
  <independently-pinned-public-key-sha256>
```

Linux 包含版本化 systemd 安装、升级、回滚、离线验签和安全归档检查工具。首次验签必须使用已信任源码/系统副本；不能从未验签的压缩包运行其自带工具。首次安装后，已持久化的工具目录中的 `upgrade.sh` 会重复验签并原子切换当前版本；`rollback.sh` 只切换二进制，不回滚配置或状态。

Windows 可选发布签名网络 seed：使用 `scripts/network-seeds.py` 处理由运营者提供的 V1 payload，再向 `scripts/package-windows.ps1` 传入种子文件、公钥文件和网络 ID。包内清单覆盖两个 seed 文件；用户 profile 仍须 pin 对应 key 和 network ID。

完整外部部署、生产 seed 签发和离线发布步骤见 [外部部署与发布流程](../docs/external-deployment-release.md)。

## 外部输入

正式出包仍需要维护者提供：Authenticode 证书和 `signtool.exe`、仓库外 provision 的 Ed25519 私钥、可信 HTTPS 时间戳服务、旧版 Core 验证器、发布公钥核验渠道，以及实际可访问的 Linux 基础设施域名/IP。真实链部署、资金/赞助、生产 RPC、bootstrap/relay 和 Linux 实机 systemd 证据也仍是外部待办。脚本不会生成、创建或托管这些秘密与外部资源。

# ASL Release Packaging

Windows and Linux have separate package paths. Official Windows artifacts need
Authenticode on every executable plus an Ed25519 update receipt verifiable by
the previous trusted Core. Linux infrastructure packages need a domain-separated
Ed25519 detached signature. Release private keys stay outside the repository
and are never reused from Agent, peer, TLS, or chain identities.
