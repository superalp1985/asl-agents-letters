# A信 ASL Linux 发布包

本目录包含两条独立发布链：

| 包 | 内容 | 入口 |
| --- | --- | --- |
| `asl-client` 完整桌面客户端 | `asl`、`asl-core`、`asl-net`、`asl-worker`、`asl-extractor`、`asl-ui`、桌面文件、图标和用户服务 | `scripts/package-linux-client.sh` |
| `asl-infra` 公网中继 | 仅 `asl-infra` 系统服务 | `scripts/package-linux-infra.sh` |

完整客户端支持 Ubuntu 22.04 LTS 及更新版本，产出 `.tar.gz` 和 `.deb`。
安装用户不需要 Rust、Cargo 或编译器；图形、Wayland/X11、OpenSSL 和 Python
系统库通过 APT 声明。详细构建、安装、升级和离线边界见
源码仓库中的 `packaging/linux/client/README.md` 与
`docs/linux-client-release.md`。本基础设施包不会携带这两个客户端文档。

## asl-infra 基础设施包

该包只包含可替换的 bootstrap/relay 基础设施 `asl-infra`，不包含桌面 Agent、用户身份密钥、目录授权或模型配置。

## 安装

发布包解压后应包含：

```text
asl-infra
asl-infra.service.in
infra.example.toml
install.sh
upgrade.sh
rollback.sh
release-common.sh
verify-release.sh
verify-offline-release.sh
release_archive.py
README.md
LICENSE
THIRD-PARTY.txt
sbom.cdx.json
MPL-SOURCES.zip
BUILD-INFO.json
SHA256SUMS
```

在解压目录执行：

```bash
sudo ./install.sh
sudo editor /etc/asl-infra/infra.toml
sudo systemctl enable --now asl-infra
sudo systemctl status asl-infra
```

安装器默认使用 `/usr/local/bin/asl-infra`、`/etc/asl-infra/infra.toml`、`/var/lib/asl-infra` 和 `/etc/systemd/system/asl-infra.service`，并在安装时把实际 `BIN_PATH`、`CONFIG_PATH` 和 `STATE_PATH` 写入生成的 unit。目录可由 `ASL_INFRA_PREFIX`、`ASL_INFRA_BIN_DIR`、`ASL_INFRA_CONFIG_DIR`、`ASL_INFRA_STATE_DIR`、`ASL_INFRA_SYSTEMD_DIR`、`ASL_INFRA_RELEASE_DIR` 和 `ASL_INFRA_TOOLS_DIR` 覆盖。路径必须是无空格、无符号链接穿越的规范绝对路径。已有配置和状态不会被覆盖。

首次安装会把解析后的六个目录写入工具目录中的 root-owned `install-layout.conf`。以后直接运行该目录中的 `upgrade.sh`/`rollback.sh` 即可；不需要再次提供环境变量，冲突的覆盖值会被拒绝。

首次安装器校验包内 `SHA256SUMS`，使用 root-owned 版本目录和稳定 launcher symlink 安装二进制。它拒绝覆盖已有 service、launcher 或部署工具目录；已有部署不要重复运行首次安装器。

`infra.example.toml` 中的 `203.0.113.1` 是文档地址，不能直接用于公网。公网部署必须填写实际可达的 `external_addresses`，并根据主机防火墙开放 TCP/UDP 4001 或配置中的实际端口。

服务以无登录权限的 `asl-infra` 用户运行，状态目录只对该用户和组可写。身份文件位于状态目录内，不得复制进共享打包目录或提交到仓库。

## 发布签名

`SHA256SUMS` 只检查包内完整性，不证明发布者身份。正式发布还必须提供独立 Ed25519 发布密钥的 detached signature、原始 32 字节公钥或 PEM 公钥，并在下载后先核验签名再执行 `install.sh`。

签名私钥必须保存在仓库外。可使用 `scripts/sign-release-artifact.sh`，发布域名为 `ASL-LINUX-INFRA-RELEASE-v1`。不要复用 Agent、节点或 TLS 私钥。

下载方使用已独立认证的源码 verifier 或现有系统安装中的 verifier，不从尚未验证的 tar 包运行验签脚本。`verify-offline-release.sh` 固定 Linux 发布域，要求带外核验的公钥指纹，并检查 tar 内容与每个包内 SHA-256：

```bash
bash packaging/linux/verify-offline-release.sh \
  asl-infra-linux-x86_64-<version>.tar.gz \
  asl-infra-linux-x86_64-<version>.tar.gz.sig \
  asl-infra-linux-x86_64-<version>.tar.gz.release-key.pem \
  asl-infra-linux-x86_64-<version>.tar.gz.sha256 \
  <independently-pinned-public-key-sha256>
```

签名、哈希和内容校验全程离线完成，不会获取或替换信任根。
验签主机需要 OpenSSL 3、Python 3、GNU `sha256sum` 和可信的 verifier 副本；这些工具由系统管理员预先提供，包不会联网安装依赖。

## 升级与回滚

首次安装会把升级、回滚和验签工具放到配置的 root-owned 工具目录（默认 `/usr/local/libexec/asl-infra`）。升级会再次核验签名、公钥指纹和包内容，在版本目录中暂存二进制、保留旧版本并原子切换 `current`。配置、身份和状态数据不会被覆盖或回滚。安装时固定的 verifier/升级工具属于部署信任根，普通二进制升级不会替换它们；发布工具格式变化时使用经过独立核验的完整安装流程。

```bash
sudo /usr/local/libexec/asl-infra/upgrade.sh \
  asl-infra-linux-x86_64-<version>.tar.gz \
  asl-infra-linux-x86_64-<version>.tar.gz.sig \
  asl-infra-linux-x86_64-<version>.tar.gz.release-key.pem \
  asl-infra-linux-x86_64-<version>.tar.gz.sha256 \
  <independently-pinned-public-key-sha256>

sudo /usr/local/libexec/asl-infra/rollback.sh
```

若活动服务升级后未保持 systemd `active`，升级器恢复旧指针并尝试重启旧二进制；原本 inactive 的服务不会被擅自启动。回滚只检查 systemd 活动状态，不检查公网或业务健康，也不会恢复状态目录。回滚前需确认旧版兼容当前持久状态。历史二进制目录不会自动清理。

## 审计与卸载

`THIRD-PARTY.txt` 列出运行时依赖和许可证；`sbom.cdx.json` 是 CycloneDX 1.6 SBOM；`MPL-SOURCES.zip` 保存需要提供源码的 MPL 组件原始 crate。`BUILD-INFO.json` 记录版本、Git 提交、目标平台和可复现的 source date。

正式构建可显式设置 `SOURCE_DATE_EPOCH` 和 `ASL_INFRA_TARGET`。目标只接受 x86_64/aarch64 Linux triple；包名架构、构建目标和 `BUILD-INFO.json` 必须一致。tar/gzip、MPL ZIP 和散列清单使用固定时间与路径顺序。

停止并卸载：

```bash
sudo systemctl disable --now asl-infra
sudo rm -f /etc/systemd/system/asl-infra.service /usr/local/bin/asl-infra
sudo systemctl daemon-reload
```

卸载不会删除 `/etc/asl-infra` 或 `/var/lib/asl-infra`。确认不再需要配置、身份和本地数据后，由管理员手动处理。

# ASL Linux Package Family

`scripts/package-linux-client.sh` builds the complete Ubuntu desktop client
as tar.gz and deb artifacts. The client bundle contains all six ASL
executables, XDG desktop integration, icons, a user service and management
scripts. Ubuntu 22.04 LTS or newer is supported. The `.deb` lets APT resolve
system libraries online. A tar.gz built with `--apt-deps-dir` also carries the
matching Ubuntu `.deb` dependency closure and can install without an APT
source. Users do not install Rust or Cargo.

`scripts/package-linux-infra.sh` remains the separate repairable relay package.
The rest of this document describes that infrastructure package.

This package contains only replaceable bootstrap/relay infrastructure. It does
not contain a desktop Agent, user identity key, directory grant, or model
configuration.

Verify the detached signature, pinned key fingerprint, and package checksums
with `packaging/linux/verify-offline-release.sh` from a trusted source checkout
or the installed verifier, then run `sudo ./install.sh`. Edit
`/etc/asl-infra/infra.toml` before enabling the service. The example
`203.0.113.1` address is documentation-only. A public deployment must supply
the real reachable addresses and firewall rules.

The SHA-256 manifest checks package integrity only. Official releases also
require a detached Ed25519 signature from a release key kept outside the
repository. Do not reuse Agent, peer, or TLS keys. The release domain is
`ASL-LINUX-INFRA-RELEASE-v1`.

The offline verifier checks the detached signature, independently authenticated
public-key fingerprint, archive layout, metadata, and all package checksums.
It does not use the network or fetch a trust root.

`THIRD-PARTY.txt`, `sbom.cdx.json`, `MPL-SOURCES.zip`, and `BUILD-INFO.json`
provide dependency, license, source-offer, and build provenance records.
`install.sh` renders `asl-infra.service.in` with the selected paths before it
installs `/etc/systemd/system/asl-infra.service`. Later upgrades use the
installed root-owned layout metadata and `upgrade.sh`; `rollback.sh` switches to the retained prior binary
without rolling back config or state. Its readiness check is systemd active
state, not public reachability.
