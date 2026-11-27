# Windows 正式发布流程

Windows 发布有两条独立信任链，不能互相替代：

1. **Authenticode** 证明 PE 文件签名者身份，供 Windows 和用户查看。
2. **ASL Ed25519 update manifest** 证明 ZIP、版本、长度和 SHA-256，并由已安装的 ASL 更新器独立验证。产品更新不依赖购买 Authenticode 证书。

发布私钥必须位于仓库外。仓库和构建产物只能包含公钥。

## 构建和 Authenticode

在已设置 `ASL_HOME`、`CARGO_HOME`、`RUSTUP_HOME` 和 `CARGO_TARGET_DIR` 的 PowerShell 7 会话中：

```powershell
$releaseRoot = Join-Path $env:ASL_HOME 'release'
.\scripts\package-windows.ps1 `
  -OutputZip (Join-Path $releaseRoot 'asl-windows-x86_64-1.2.0.zip') `
  -AuthenticodeThumbprint '<certificate thumbprint from CurrentUser\My or LocalMachine\My>' `
  -SignToolPath '<absolute path to signtool.exe>' `
  -Offline
```

脚本只使用证书存储中的私钥，不接受 PFX 密码或仓库内私钥路径。它会逐个签署六个运行时 EXE，执行 Authenticode 验证，然后才生成 `SHA256SUMS.txt`、`THIRD-PARTY.txt`、`MPL-SOURCES.zip` 和 `sbom.cdx.json`。未设置 `-AuthenticodeThumbprint` 的包只能作为内部测试包。

## Ed25519 更新清单

建议使用 OpenSSL 3 创建专用 Ed25519 发布密钥，并把私钥保存在仓库外：

```powershell
openssl genpkey -algorithm ED25519 -out '<external release-key.pem>'
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

## 发布和更新

发布目录至少包含 ZIP、`manifest.json`、`manifest.sig` 和独立公布的 32 字节公钥。首次使用时由用户独立核对公钥并固定：

```powershell
.\Update-ASL.ps1 -PinReleaseKey '<verified release-key.ed25519>'
.\Update-ASL.ps1 -Package '<new ZIP>' -Manifest '<manifest.json>' -Signature '<manifest.sig>'
```

固定公钥不在普通更新中替换。密钥轮换需要带外发布新公钥和新的完整性说明；当前更新布局不提供自动信任根轮换。私钥丢失不能通过更新流程恢复，只能重新核验完整发行包并建立新安装。

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
