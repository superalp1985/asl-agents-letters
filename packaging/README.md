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
- 发布私钥位于仓库外；仓库、日志、ZIP、SBOM 和文档不得包含私钥。
- 发布密钥不复用 Agent identity root、libp2p peer key、TLS key 或链上 controller key。

## Windows

```powershell
$releaseRoot = Join-Path $env:ASL_HOME 'release'
.\scripts\package-windows.ps1 `
  -OutputZip (Join-Path $releaseRoot 'asl-windows-x86_64-1.0.0.zip') `
  -AuthenticodeThumbprint '<thumbprint>' `
  -SignToolPath '<signtool.exe>'
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
ASL_INFRA_ARCH=x86_64 ./scripts/package-linux-infra.sh /srv/asl-release
bash ./scripts/sign-release-artifact.sh \
  /secure/release-key.pem \
  /srv/asl-release/asl-infra-linux-x86_64-1.0.0.tar.gz \
  ASL-LINUX-INFRA-RELEASE-v1 \
  /srv/asl-release
```

下载方先执行：

```bash
sha256sum -c asl-infra-linux-x86_64-1.0.0.tar.gz.sha256
bash ./verify-release.sh \
  asl-infra-linux-x86_64-1.0.0.tar.gz \
  asl-infra-linux-x86_64-1.0.0.tar.gz.sig \
  asl-infra-linux-x86_64-1.0.0.tar.gz.release-key.pem \
  ASL-LINUX-INFRA-RELEASE-v1
```

`packaging/linux/verify-release.sh` 随源码发布，不自动打进 infra 二进制包；发布方可把它与公钥、`.sha256` 和 `.sig` 一并发布。

## 外部输入

正式出包仍需要维护者提供：Authenticode 证书和 `signtool.exe`、仓库外 Ed25519 私钥、可信时间戳服务、旧版 Core 验证器、发布公钥核验渠道，以及实际可访问的 Linux 基础设施域名/IP。脚本不会创建或托管这些秘密与外部资源。

# ASL Release Packaging

Windows and Linux have separate package paths. Official Windows artifacts need
Authenticode on every executable plus an Ed25519 update receipt verifiable by
the previous trusted Core. Linux infrastructure packages need a domain-separated
Ed25519 detached signature. Release private keys stay outside the repository
and are never reused from Agent, peer, TLS, or chain identities.
