# Windows 正式发布流程

Windows 发布有两条独立信任链，不能互相替代：

1. **Authenticode** 证明 PE 文件签名者身份，供 Windows 和用户查看。
2. **ASL Ed25519 update manifest** 证明 ZIP、版本、长度和 SHA-256，并由已安装的 ASL 更新器独立验证。产品更新不依赖购买 Authenticode 证书。

发布私钥必须位于仓库外。仓库和构建产物只能包含公钥。
当前便携包布局为 `asl-windows-layout-v3`；Ed25519 更新清单格式仍为 v1。

## 构建和 Authenticode

在已设置 `ASL_HOME`、`CARGO_HOME`、`RUSTUP_HOME` 和 `CARGO_TARGET_DIR` 的 PowerShell 7 会话中：

```powershell
$releaseRoot = Join-Path $env:ASL_HOME 'release'
.\scripts\package-windows.ps1 `
  -OutputZip (Join-Path $releaseRoot 'asl-windows-x86_64-1.2.0.zip') `
  -AuthenticodeThumbprint '<certificate thumbprint from CurrentUser\My or LocalMachine\My>' `
  -SignToolPath '<absolute path to signtool.exe>' `
  -TimestampUrl '<operator-approved HTTPS timestamp service>' `
  -Offline
```

脚本只使用证书存储中的私钥，不接受 PFX 密码或仓库内私钥路径。时间戳服务没有内置默认值，必须由运营者显式提供。它会逐个签署六个运行时 EXE，执行 Authenticode 验证，然后才生成 `SHA256SUMS.txt`、`THIRD-PARTY.txt`、`MPL-SOURCES.zip` 和 `sbom.cdx.json`。未设置 `-AuthenticodeThumbprint` 的包只能作为内部测试包。

## Ed25519 更新清单

专用 Ed25519 发布私钥必须由组织批准的外部密钥管理流程预先 provision。仓库工具只接收已有密钥，不生成生产密钥：

```powershell
.\scripts\sign-windows-package.ps1 `
  -Package '<absolute package ZIP>' `
  -Version '1.2.0' `
  -ReleasePrivateKey '<external release-key.pem>' `
  -OutputDirectory '<release output directory>'
```

脚本生成：

```text
<package>.manifest.json
<package>.manifest.sig
<package>.release-key.ed25519
<package>.release-key.pem
<package>.sha256
```

清单严格只包含：

```json
{"format_version":1,"version":"1.2.0","platform":"windows-x86_64","archive_bytes":0,"sha256":"<64 lowercase hex>"}
```

实际 `archive_bytes` 必须等于 ZIP 长度。签名原文是 ASCII `ASL-WINDOWS-UPDATE-v1`、一个 NUL 字节和清单原始字节。不要把清单重新格式化后再验签。

正式发布前，使用上一版已发布的 `asl-core.exe` 复验：

```powershell
.\scripts\sign-windows-package.ps1 `
  -Package '<package ZIP>' `
  -Version '1.2.0' `
  -ReleasePrivateKey '<external release-key.pem>' `
  -OutputDirectory '<new empty release output directory>' `
  -VerifierCore '<previous release>\asl-core.exe'
```

`-VerifierCore` 必须是低于新版本且受信任的旧版 `asl-core.exe`。同版本二进制按设计不能把同版本包当成升级包。

## 离线复核

从受信任的源码树或已核验的旧版安装运行独立验签脚本，不要从尚未验签的 ZIP 中运行脚本。公钥指纹为 raw 32-byte key 的 SHA-256，并须通过独立渠道固定：

```powershell
.\scripts\verify-windows-release.ps1 `
  -Package '<package ZIP>' `
  -Manifest '<manifest.json>' `
  -Signature '<manifest.sig>' `
  -PublicKeyRaw '<32-byte raw public key>' `
  -TrustedKeySha256 '<independently-pinned raw-key SHA-256>' `
  -VerifierCore '<previous trusted release>\asl-core.exe' `
  -RequireAuthenticode `
  -ScratchRoot '<local verification scratch directory>'
```

验证调用上一版 Core 的 `--verify-update`，不构建、不联网、不修改安装资料。已有受信任安装时，也可只传 `-TrustedInstallRoot '<protected root>'`，由 verifier 使用该根目录的固定公钥和旧版 Core；布局验证器优先来自当前受信任源码树，单文件分发时才回退到该安装根。它同时严格校验 ZIP 相对路径、固定成员集合、清单顺序、SBOM 合约和每个包内 SHA-256。`-RequireAuthenticode` 把六个 EXE 临时释放到指定本地目录并使用本机信任/吊销状态复核；生产验收仍须保存证书和时间戳服务的外部证据。

## 可选签名网络入口

生产 seed 仅来自运营者实际运行并独立核验的入口清单。签名工具不生成密钥；专用 Ed25519 私钥须经组织批准的密钥管理流程在仓库外 provision。它验证 V1 payload、时间范围、两个以上不同 operator、PeerId 后缀绑定、角色和数量限制，然后按运行时要求对 compact JSON payload 签名：

```text
python3 scripts/network-seeds.py sign \
  --payload <operator-prepared-payload.json> \
  --private-key <external-release-key.pem> \
  --output <release-staging>/network-seeds.json \
  --public-key-output <release-staging>/network-seeds.public-key.hex

python3 scripts/network-seeds.py verify \
  --seeds <release-staging>/network-seeds.json \
  --public-key-file <release-staging>/network-seeds.public-key.hex \
  --network-id <expected-network-id>
```

将上述已验签文件纳入 ZIP：

```powershell
.\scripts\package-windows.ps1 `
  -OutputZip '<release ZIP>' `
  -Offline `
  -NetworkSeeds '<release-staging>\network-seeds.json' `
  -NetworkSeedPublicKey '<release-staging>\network-seeds.public-key.hex' `
  -NetworkSeedNetworkId '<expected-network-id>' `
  -AuthenticodeThumbprint '<certificate thumbprint>' `
  -SignToolPath '<signtool.exe>'
```

打包器会重新验签、检查 network ID，并将 seed envelope 和公钥纳入包内 `SHA256SUMS.txt` 及后续 Ed25519 manifest。用户的本机 `network-settings-v1.json` 仍需配置相同的 `network_seed_public_key` 和 `network_seed_network_id`。签名不是可达性证明；真实入口必须由运营者独立测试。

## 发布和更新

发布目录至少包含 ZIP、`manifest.json`、`manifest.sig` 和独立公布的 32 字节公钥。首次使用时由用户独立核对公钥并固定：

```powershell
.\Update-ASL.ps1 -PinReleaseKey '<verified release-key.ed25519>'
.\Update-ASL.ps1 -Package '<new ZIP>' -Manifest '<manifest.json>' -Signature '<manifest.sig>'
```

固定公钥不在普通更新中替换。密钥轮换需要带外发布新公钥和新的完整性说明；当前更新布局不提供自动信任根轮换。私钥丢失不能通过更新流程恢复，只能重新核验完整发行包并建立新安装。

成功更新会原子写入 `active-release.txt`，并生成 `rollback-release.json` 保存一层旧/新指针及包和清单 SHA-256。`Rollback-ASL.ps1 -ConfirmDataCompatibility` 只切换二进制指针，不恢复数据；执行前必须退出 ASL 并确认旧版兼容当前资料。`Update-ASL.ps1` 和回切脚本都支持显式 `-InstallRoot`。

`SOURCE_DATE_EPOCH` 未设置时使用 Git 提交时间。包内散列清单按固定相对路径顺序生成，MPL 源码 ZIP 和外层 ZIP 统一时间戳及条目顺序。Authenticode 的外部时间戳签名本身由证书服务决定，不应被虚构为可复现证据。

## 发布拒绝条件

- 工作树包含未提交修改，或产物来自未知源。
- Authenticode 状态不是 `Valid`。
- ZIP 长度、SHA-256 或内层 `asl-core.exe --version` 与清单不一致。
- 清单包含未知字段、预发布版本或平台不是 `windows-x86_64`。
- 新版本不高于当前版本。
- 私钥位于仓库、ZIP、日志或发布说明中。
- `sudo` 不适用于 Windows；本流程不需要管理员权限，除非证书私钥只存在于本机证书存储。

# ASL Windows Official Release

Authenticode and the ASL Ed25519 update receipt are independent trust layers.
Build the portable ZIP with `scripts/package-windows.ps1` and a certificate
thumbprint, then create the update manifest with
`scripts/sign-windows-package.ps1`. The release private key must remain outside
the repository. A package without a valid Authenticode signature is a test
package, not an official release.

The update manifest is strict JSON with only `format_version`, `version`,
`platform`, `archive_bytes`, and `sha256`. Sign the ASCII domain
`ASL-WINDOWS-UPDATE-v1`, one NUL byte, and the exact manifest bytes. Verify the
receipt with the previous trusted `asl-core.exe` before publishing. Publish the
ZIP, manifest, detached signature, and raw 32-byte public key. The pinned
release key is bootstrap state and is not replaced by ordinary updates.
