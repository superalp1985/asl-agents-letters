# ASL Ubuntu 完整客户端发布

本文只描述 Linux 桌面客户端打包、安装和依赖边界。Windows/Ubuntu 双机
互联、NAT、群聊、授权和文件传输仍需真实主机验收，打包成功不能替代这些
网络证据。

## 交付标准

完整 Ubuntu 客户端必须包含：

- `asl`、`asl-core`、`asl-net`、`asl-worker`、`asl-extractor`、`asl-ui`
- `eframe/egui` 桌面二进制 `asl-ui`
- XDG `.desktop` 文件、可缩放 SVG 图标和 256x256 PNG 图标
- `ASL_HOME` 默认环境示例和稳定 GUI 启动器
- 可选 systemd `--user` 后台 Core 单元
- tar 安装器的安装、卸载、升级、内容校验脚本
- `SHA256SUMS`、`THIRD-PARTY.txt`、CycloneDX SBOM、MPL 源码和
  `BUILD-INFO.json`
- tar.gz 与 deb 两种发布产物

支持 Ubuntu 22.04 LTS、24.04 LTS 及更新版本，架构为 64 位 x86_64 或
aarch64。正式二进制应在 Ubuntu 22.04 构建，以 22.04 的 glibc 和系统库作为
最低基线。不要在更新版本上构建后宣称为 22.04 兼容。

该打包链不修改 Rust 平台层。它封装当前 release build 实际产出的二进制；
Linux GUI、密钥存储、子进程、托盘和通知是否工作，仍由 Rust 平台实现和
真实 Ubuntu 运行决定。不能在 `asl-ui` 仍为占位实现时把“包构建成功”写成
“Ubuntu 客户端验收通过”。

## 构建

构建机需要 Rust 1.95+、Python 3、GNU tar、gzip、`strip` 和 `dpkg-deb`。
这些是构建依赖，不是最终用户依赖。

```bash
ASL_CARGO_OFFLINE=1 \
bash ./scripts/package-linux-client.sh \
  --offline \
  --output-dir "$PWD/target/linux-client-release"
```

要交付“首次安装不需要 APT 源”的完整 tar 包，先在相同 Ubuntu 版本和 CPU
架构的构建机生成依赖闭包，再把目录交给打包脚本：

```bash
sudo bash ./scripts/prepare-linux-client-deps.sh \
  --output-dir "$PWD/target/ubuntu-22.04-amd64-deps"

ASL_CARGO_OFFLINE=1 \
bash ./scripts/package-linux-client.sh \
  --offline \
  --apt-deps-dir "$PWD/target/ubuntu-22.04-amd64-deps" \
  --output-dir "$PWD/target/linux-client-release"
```

依赖准备脚本使用空的 APT dpkg 状态计算完整依赖闭包，下载当前 Ubuntu 仓库
匹配版本的 `.deb`，拒绝混入其他发行版或架构。已有同版本 APT 缓存时可用
`--seed-cache /var/cache/apt/archives`；无网络构建可加 `--offline`，但缓存
必须完整。

脚本默认使用 `rustc` 主机目标，也可显式指定：

```bash
bash ./scripts/package-linux-client.sh \
  --target x86_64-unknown-linux-gnu \
  --output-dir "$PWD/target/linux-client-release"
```

正式发布要求干净工作树。`--allow-dirty` 或
`ASL_RELEASE_ALLOW_DIRTY=1` 只用于本地测试包。`SOURCE_DATE_EPOCH` 未设置时
使用 Git 提交时间，tar/gzip 和归档内清单按固定顺序生成。

deb 的 `libc6` 最低版本默认从本机 glibc 推导，最低为 2.35。交叉构建或使用
固定 sysroot 时，可由构建者显式设置 `ASL_DEB_LIBC6_MIN=2.35`；该值必须与
实际目标 sysroot 一致，不能为了扩大兼容范围伪造。

## 产物

```text
asl-client-linux-x86_64-<version>.tar.gz
asl-client-linux-x86_64-<version>.tar.gz.sha256
asl-client_<version>_amd64.deb
asl-client_<version>_amd64.deb.sha256
```

aarch64 输出对应 `aarch64` 和 `arm64` 名称。

tar 包可直接交给用户，也可解压后运行：

```bash
./verify.sh asl-client-linux-x86_64-<version>.tar.gz
./install.sh \
  --prefix "$HOME/.local" \
  --asl-home "$HOME/.local/share/asl" \
  --install-system-dependencies
```

带依赖的 tar 包会先校验目标 Ubuntu 版本、架构和每个 `.deb` 的 SHA-256，
跳过不高于已安装版本的包，再用 `dpkg` 安装缺少的依赖。不带依赖的 tar 包
可通过 `./install-deps.sh` 在线执行同一份 `APT-PACKAGES.txt` 清单。

`.sha256` 和内部 `SHA256SUMS` 只用于完整性和传输入侵检测，不是发布者身份
证明。正式发布还应通过独立渠道公布校验值，或增加与现有基础设施发布密钥
分离的 Linux 客户端签名流程。

tar 安装使用稳定 symlink 指向版本目录。自定义前缀不能与该用户已有的其他
ASL 布局冲突。升级只切换客户端版本，不替换 `ASL_HOME`。

deb 固定使用：

```text
/opt/asl/bin
/usr/bin/asl*
/usr/share/applications/asl.desktop
/usr/share/icons/hicolor
/usr/lib/systemd/user/asl-core.service
/etc/xdg/asl/asl.env
```

```bash
sudo apt install ./asl-client_<version>_amd64.deb
```

deb 的安装、升级、卸载由 APT/DPKG 负责。tar 包的自定义前缀安装器不会
修改 dpkg 状态。

## 用户资料与启动

tar 默认 `ASL_HOME` 为 `${XDG_DATA_HOME:-$HOME/.local/share}/asl`。deb
默认值相同，并可由 `/etc/xdg/asl/asl.env` 或用户
`${XDG_CONFIG_HOME:-$HOME/.config}/asl/asl.env` 覆盖。`ASL_HOME` 必须使用
绝对本地路径并单独备份。

首次安装会调用：

```bash
ASL_HOME=<absolute-path> /path/to/asl-core --initialize-profile --json
```

已有 `state/asl.sqlite3` 时保留资料。安装器不会覆盖身份、授权、群组或历史。

未启用用户服务时，`asl-launch` 在后台启动 Core 后打开 GUI。启用用户服务：

```bash
./install.sh --enable-user-service
```

用户服务安装到用户 systemd 配置目录。deb 包提供系统级 unit 模板但不自动
为每个登录用户启用。systemd 服务不是桌面 GUI 的必要条件，只用于更明确的
后台生命周期和日志管理。deb 用户可执行：

```bash
systemctl --user daemon-reload
systemctl --user enable --now asl-core.service
```

tar 安装的 `asl-launch` 与 systemd service 使用同一环境解析顺序，因此
`/etc/xdg/asl/asl.env`、用户 `~/.config/asl/asl.env` 和 `ASL_HOME` 不会在
两种启动方式间产生不同默认目录。

## APT 运行依赖

`.deb` 和在线安装器从 `packaging/linux/client/apt-packages.txt` 生成依赖，
当前清单为：

```text
ca-certificates libc6 libgcc-s1 libssl3 libx11-6 libx11-xcb1 libxcb1 libxcb-render0
libxcb-randr0 libxcb-shape0 libxcb-shm0 libxcb-xfixes0 libxcb-xkb1
libxkbcommon0 libxkbcommon-x11-0 libxcursor1 libxrandr2
libxi6 libxinerama1 libwayland-client0 libwayland-cursor0 libwayland-egl1
libegl1 libgl1 libfontconfig1 python3
```

deb 的 `Depends` 字段负责声明这些包。tar 安装器读取
`APT-DEPENDENCIES.txt` 并用 `ldd` 检查未解析库。无依赖 tar 包可在线安装：

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates libc6 libgcc-s1 libssl3 libx11-6 libx11-xcb1 \
  libxcb1 libxcb-randr0 libxcb-render0 libxcb-shape0 libxcb-shm0 \
  libxcb-xfixes0 libxcb-xkb1 libxkbcommon0 libxkbcommon-x11-0 \
  libxcursor1 libxrandr2 libxi6 libxinerama1 \
  libwayland-client0 libwayland-cursor0 libwayland-egl1 libegl1 \
  libgl1 libfontconfig1 python3
```

包内包含全部 ASL 可执行文件，不包含 Rust 工具链，也不要求 crates.io。

## 离线边界

所有客户端 tar 包都不要求 Rust、Cargo、源码编译或联网拉取 ASL crate。
使用 `--apt-deps-dir` 构建的 tar 包还包含完整 Ubuntu 系统依赖闭包，可在
没有 APT 源的机器上执行 `./install.sh --install-system-dependencies`。

完全离线安装仍需要已通过独立渠道核验的 ASL 包。`.deb` 客户端使用 APT
在线解析系统依赖；需要完全离线时交付带依赖的 tar 包，或使用同版本
Ubuntu 离线 APT 镜像。

不要把 22.04 包内的库复制到 24.04 或其他发行版作为通用运行时。系统库、
图形驱动、输入法和桌面会话不属于 ASL 包。

## 升级、卸载与验证

tar 安装：

```bash
"$HOME/.local/libexec/asl/upgrade.sh" \
  asl-client-linux-x86_64-<new-version>.tar.gz
"$HOME/.local/libexec/asl/verify.sh" \
  asl-client-linux-x86_64-<new-version>.tar.gz
"$HOME/.local/libexec/asl/uninstall.sh"
```

卸载默认保留配置和 `ASL_HOME`。只有明确放弃身份和数据时才可添加
`--purge-config --purge-data`。

deb 更新与卸载：

```bash
sudo apt install ./asl-client_<new-version>_amd64.deb
sudo apt remove asl-client
sudo apt purge asl-client
```

`remove` 和 `purge` 都不删除用户资料。

## 验收边界

打包脚本可以证明归档成员、内部 SHA-256、元数据、deb 结构和安装脚本语法；
不能证明以下事项：

- Ubuntu 实机上的 GUI 渲染、托盘、通知和输入法
- Windows 与 Ubuntu 的双向发现、授权、群聊和文件传输
- 不同 NAT、防火墙、relay 或教育网环境下的连通性
- 长期运行、升级中断恢复和多用户桌面环境

这些必须在真实 Ubuntu 主机和真实 Windows 主机上另行记录通过证据。
