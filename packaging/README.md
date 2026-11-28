# ASL 发布包

仓库包含两条独立发布链：

| 目标 | 构建入口 | 发布说明 |
| --- | --- | --- |
| Windows x64 桌面/Agent 便携包 | `scripts/package-windows.ps1` | `packaging/windows/README.md`、`packaging/windows/RELEASE.md` |
| Ubuntu x86_64/aarch64 完整桌面客户端 | `scripts/package-linux-client.sh` | `packaging/linux/client/README.md`、`docs/linux-client-release.md` |
| Linux x86_64/aarch64 `asl-infra` | `scripts/package-linux-infra.sh` | `packaging/linux/README.md` |

正式发布共同要求：

- 在干净工作树中构建，产物文件名包含产品、平台、架构和版本。
- 包内提供 `SHA256SUMS`、`THIRD-PARTY`、CycloneDX SBOM、适用时的 MPL 源码包和 `BUILD-INFO`。
- Windows EXE 使用 Authenticode；Windows 更新另需严格 Ed25519 manifest、detached signature 和可独立公布的公钥。
- Linux 包使用独立 Ed25519 domain-separated detached signature。
- GitHub RC/测试发布统一使用 RSA-4096 签名 `asl-release-manifest.json`；平台引导器在校验签名和 SHA-256 前不得执行包内容。
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
Windows 便携包自带 Microsoft 签名的 `vcruntime140.dll`，并把该 DLL 纳入
`SHA256SUMS.txt`、SBOM 和离线更新成员集，干净系统不需要另装 VC++ 运行库。

没有 Authenticode 证书时，RC 发布应使用 PowerShell 引导脚本：它校验 RSA
发布清单和客户端 ZIP，清除解压文件的 Mark-of-the-Web，再调用现有客户端。
不要另发一个未签名 PyInstaller EXE 作为 Windows 主引导器。

RSA 清单、密钥指纹、引导器生成和验签命令见
`packaging/release/README.md`。

## Ubuntu 完整客户端

在 Ubuntu 22.04 构建机（推荐作为 glibc 基线）执行：

```bash
sudo bash ./scripts/prepare-linux-client-deps.sh \
  --output-dir "$PWD/target/ubuntu-22.04-amd64-deps"

bash ./scripts/package-linux-client.sh \
  --apt-deps-dir "$PWD/target/ubuntu-22.04-amd64-deps" \
  --output-dir "$PWD/target/linux-client-release" \
  --offline
```

默认同时产出：

```text
asl-client-linux-x86_64-<version>.tar.gz
asl-client-linux-x86_64-<version>.tar.gz.sha256
asl-client_<version>_amd64.deb
asl-client_<version>_amd64.deb.sha256
```

tar 包包含全部六个客户端可执行文件、桌面文件、图标、默认环境示例、
systemd `--user` 单元以及安装/升级/卸载/验证脚本。使用 `--apt-deps-dir`
时还包含同版本 Ubuntu 和 CPU 架构的完整 `.deb` 依赖闭包，安装命令为
`./install.sh --install-system-dependencies`。安装用户不需要 Rust 或 Cargo。
不打包系统依赖时，deb 和 tar 都可通过 APT 在线安装同一份包清单。tar 安装
支持自定义前缀和 `ASL_HOME`，deb 固定安装到 `/opt/asl` 并由 `apt/dpkg`
管理。

构建时需要 Rust、Python 3、GNU tar、gzip、strip 和 `dpkg-deb`。正式包应在
干净工作树构建；`--allow-dirty` 只用于本地测试包。

Linux 平台自适应引导器：

```bash
bash ./scripts/build-bootstrap.sh \
  "$PWD/target/asl-bootstrap-linux"
```

Windows 引导器：

```powershell
.\scripts\build-windows-bootstrap.ps1 `
  -OutputDirectory (Join-Path $PWD 'target\asl-bootstrap-windows')
```

## asl-infra

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
