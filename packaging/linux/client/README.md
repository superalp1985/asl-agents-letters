# A信 ASL Ubuntu 完整客户端

该包包含 `asl`、`asl-core`、`asl-net`、`asl-worker`、`asl-extractor` 和
`asl-ui`。桌面界面使用 `eframe/egui`。用户不需要安装 Rust、Cargo 或编译器。

支持 Ubuntu 22.04 LTS 及更新版本，提供 x86_64 与 aarch64 包。为保证旧版
Ubuntu 可运行，正式二进制应在 Ubuntu 22.04 构建机上生成。

本打包链只负责构建、封装、安装和维护文件，不修改 Rust 平台实现。只有
构建出的 `asl-ui`、`asl-core` 及相关进程本身具备 Linux 能力时，图形界面、
群聊、授权和文件传输才算可验收；归档存在不能替代实机运行。

## 系统依赖

包目录的 `APT-PACKAGES.txt` 是系统依赖的固定清单。普通安装器会先检查已
解析的动态库；缺失时停止，不会尝试在不说明的情况下修改系统。

带离线依赖的 tar 包已经把同版本 Ubuntu 的完整 `.deb` 依赖放进
`payload/apt-deps`。安装时使用一个参数，先安装依赖，再安装 ASL：

```bash
tar -xzf asl-client-linux-x86_64-<version>.tar.gz
cd asl-client-linux-x86_64-<version>
./install.sh --install-system-dependencies
```

离线安装器会核对目标必须为相同 Ubuntu 版本和 CPU 架构，校验每个 `.deb`
的 SHA-256，跳过已安装且版本相同或更新的包，再用 `dpkg` 安装其余包。

不带依赖的 tar 包也可联网安装。执行：

```bash
./install-deps.sh
```

ASL 六个可执行文件始终在包内。用户不需要 Rust、Cargo、源码或 crates.io。
系统图形和 Wayland/X11 库属于 Ubuntu 桌面运行环境，不能把 22.04 的库
复制到 24.04 冒充通用运行时。

## tar.gz 安装

默认安装到当前用户的 `$HOME/.local`，数据默认放在
`${XDG_DATA_HOME:-$HOME/.local/share}/asl`：

```bash
tar -xzf asl-client-linux-x86_64-<version>.tar.gz
cd asl-client-linux-x86_64-<version>
./install.sh
```

自定义安装前缀和 `ASL_HOME`：

```bash
./install.sh \
  --prefix "$HOME/.local/asl-runtime" \
  --asl-home "$HOME/ASL-Profile"
```

安装器会校验包内 `SHA256SUMS`、检查动态库、初始化缺失的 ASL 资料目录、
安装稳定启动器、桌面文件、图标和可选 systemd `--user` 单元。已有资料不会
被覆盖。

启用后台 Core 用户服务：

```bash
./install.sh --enable-user-service
```

不启用服务时，桌面启动器会在需要时后台启动 Core，然后打开 GUI。资料目录
由安装时记录，不会因当前工作目录变化而漂移。用户可在
`${XDG_CONFIG_HOME:-$HOME/.config}/asl/asl.env` 中覆盖 `ASL_HOME`。

启动：

```bash
"$HOME/.local/bin/asl-launch"
```

也可从应用菜单选择 ASL。首次启动会要求选择中文或 English，中文为默认语言。

## .deb 安装与升级

`.deb` 固定安装到 `/opt/asl`，命令入口位于 `/usr/bin`，桌面和图标位于
标准 XDG 路径，用户级 unit 位于 `/usr/lib/systemd/user/asl-core.service`。
systemd unit 安装但不默认启用。`.deb` 由 APT/DPKG 管理，不使用 tar 包的
自定义前缀安装器。

```bash
sudo apt-get update
sudo apt install ./asl-client_<version>_amd64.deb
```

APT 会声明并安装运行库依赖。升级使用新的 `.deb` 重新执行 `apt install`；
需要系统后台服务时，由目标桌面用户显式启用：

```bash
systemctl --user daemon-reload
systemctl --user enable --now asl-core.service
```

卸载与清除：

```bash
sudo apt remove asl-client
sudo apt purge asl-client
```

`remove` 和 `purge` 不删除用户资料。用户的 `ASL_HOME` 需要单独备份或删除。

## 校验、升级与卸载

验证 tar.gz 或 .deb：

```bash
./verify.sh asl-client-linux-x86_64-<version>.tar.gz
./verify.sh asl-client_<version>_amd64.deb
```

`.sha256` 和包内 `SHA256SUMS` 只证明文件完整性，不证明发布者身份。正式
分发仍应通过独立渠道公布并核对 SHA-256，或在后续发布流程中增加独立签名；
不要只因为包内清单自洽就信任来源不明的压缩包。

tar 安装的升级入口保存在安装前缀的 `libexec/asl/upgrade.sh`：

```bash
"$HOME/.local/libexec/asl/upgrade.sh" \
  asl-client-linux-x86_64-<new-version>.tar.gz
```

升级会重新验证包内容和内部 SHA-256，保留 `ASL_HOME`，原子切换
`lib/asl/releases/current`，并按需要重启已启用的用户服务。

卸载 tar 安装：

```bash
"$HOME/.local/libexec/asl/uninstall.sh"
```

默认保留配置和 `ASL_HOME`。只有明确不需要身份、群组、授权和聊天资料时，
才执行 `--purge-config --purge-data`。

## 离线边界

- 包内包含全部 ASL 可执行文件、桌面文件、图标、默认环境示例、用户
  service、安装/升级/卸载/验证脚本和 SHA-256 清单。
- 使用 `prepare-linux-client-deps.sh` 和 `--apt-deps-dir` 构建的 tar 包还
  包含同版本 Ubuntu、同 CPU 架构的完整 `.deb` 依赖闭包；首次安装不需要
  访问 APT 源。`.deb` 客户端本身仍通过 APT 在线解析系统依赖。
- 图形驱动、桌面会话、输入法和用户资料不属于包内容。
- 不要求用户安装 Rust、编译源码或访问 crates.io。
- 本包验证不替代 Windows/Ubuntu 实机互联、NAT、群聊和文件传输验收。
