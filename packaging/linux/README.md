# A信 ASL Linux 基础设施包

该包只包含可替换的 bootstrap/relay 基础设施 `asl-infra`，不包含桌面 Agent、用户身份密钥、目录授权或模型配置。

## 安装

发布包解压后应包含：

```text
asl-infra
asl-infra.service.in
infra.example.toml
install.sh
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
sha256sum -c SHA256SUMS
sudo ./install.sh
sudo editor /etc/asl-infra/infra.toml
sudo systemctl enable --now asl-infra
sudo systemctl status asl-infra
```

安装器默认使用 `/usr/local/bin/asl-infra`、`/etc/asl-infra/infra.toml`、`/var/lib/asl-infra` 和 `/etc/systemd/system/asl-infra.service`，并在安装时把实际 `BIN_PATH`、`CONFIG_PATH` 和 `STATE_PATH` 写入生成的 unit。目录可由 `ASL_INFRA_PREFIX`、`ASL_INFRA_BIN_DIR`、`ASL_INFRA_CONFIG_DIR`、`ASL_INFRA_STATE_DIR` 和 `ASL_INFRA_SYSTEMD_DIR` 覆盖。已有配置不会被覆盖。

`infra.example.toml` 中的 `203.0.113.1` 是文档地址，不能直接用于公网。公网部署必须填写实际可达的 `external_addresses`，并根据主机防火墙开放 TCP/UDP 4001 或配置中的实际端口。

服务以无登录权限的 `asl-infra` 用户运行，状态目录只对该用户和组可写。身份文件位于状态目录内，不得复制进共享打包目录或提交到仓库。

## 发布签名

`SHA256SUMS` 只检查包内完整性，不证明发布者身份。正式发布还必须提供独立 Ed25519 发布密钥的 detached signature、原始 32 字节公钥或 PEM 公钥，并在下载后先核验签名再执行 `install.sh`。

签名私钥必须保存在仓库外。可使用 `scripts/sign-release-artifact.sh`，发布域名为 `ASL-LINUX-INFRA-RELEASE-v1`。不要复用 Agent、节点或 TLS 私钥。

下载方在 tar 包和签名文件同一目录执行：

```bash
sha256sum -c asl-infra-linux-x86_64-<version>.tar.gz.sha256
bash verify-release.sh \
  asl-infra-linux-x86_64-<version>.tar.gz \
  asl-infra-linux-x86_64-<version>.tar.gz.sig \
  asl-infra-linux-x86_64-<version>.tar.gz.release-key.pem \
  ASL-LINUX-INFRA-RELEASE-v1 \
  asl-infra-linux-x86_64-<version>.tar.gz.sha256
```

`verify-release.sh` 属于源码发布物料，不放入已解压的 tar 包内。先从独立渠道核对发布公钥指纹，再信任该 PEM。

## 审计与卸载

`THIRD-PARTY.txt` 列出运行时依赖和许可证；`sbom.cdx.json` 是 CycloneDX 1.6 SBOM；`MPL-SOURCES.zip` 保存需要提供源码的 MPL 组件原始 crate。`BUILD-INFO.json` 记录版本、Git 提交、目标平台和可复现的 source date。

停止并卸载：

```bash
sudo systemctl disable --now asl-infra
sudo rm -f /etc/systemd/system/asl-infra.service /usr/local/bin/asl-infra
sudo systemctl daemon-reload
```

卸载不会删除 `/etc/asl-infra` 或 `/var/lib/asl-infra`。确认不再需要配置、身份和本地数据后，由管理员手动处理。

# ASL Linux Infrastructure Package

This package contains only replaceable bootstrap/relay infrastructure. It does
not contain a desktop Agent, user identity key, directory grant, or model
configuration.

Verify `SHA256SUMS` first, then run `sudo ./install.sh`. Edit
`/etc/asl-infra/infra.toml` before enabling the service. The example
`203.0.113.1` address is documentation-only. A public deployment must supply
the real reachable addresses and firewall rules.

The SHA-256 manifest checks package integrity only. Official releases also
require a detached Ed25519 signature from a release key kept outside the
repository. Do not reuse Agent, peer, or TLS keys. The release domain is
`ASL-LINUX-INFRA-RELEASE-v1`.

Verify the `.sha256` and detached signature with
`packaging/linux/verify-release.sh` from the source distribution before
executing the installer. Authenticate the public-key fingerprint through an
independent channel.

`THIRD-PARTY.txt`, `sbom.cdx.json`, `MPL-SOURCES.zip`, and `BUILD-INFO.json`
provide dependency, license, source-offer, and build provenance records.
`install.sh` renders `asl-infra.service.in` with the selected paths before it
installs `/etc/systemd/system/asl-infra.service`.
