# ASL art source

中文

这些图标、吉祥物、头像和状态图都是本仓库 `scripts/generate-art.py` 用 Pillow 直接绘制的原创像素图，没有使用生成式素材服务，也没有引入第三方图片。

运行时只读取 `crates/asl-app/assets/` 中随二进制编译进去的 PNG。SVG 仅作为可编辑源和文档展示，不从网络加载。

生成工具：Python 3.14.3 + Pillow 12.1.1，2026-11-23 离线生成。全部为代码绘制，没有提示词，也没有对外部图片做修改。

| 资产 | 文件（`crates/asl-app/assets/`） | 运行时用途 |
|---|---|---|
| 产品图标 | `icons/asl-icon-{16,32,48,64,128,256}.png`、`asl-icon.ico`、`asl-icon.svg` | 256 px PNG 用作窗口图标；ICO 留给打包 |
| 吉祥物 | `mascot/mascot-{idle,message,transfer,waiting,done,warning}-{64,128,256}.png` 及 SVG | idle 256 px 用作空状态和本机头像缺省图；其余 5 种 128 px 随本机状态显示在顶栏 |
| 讲解小剧场 | `mascot/anim-{idle,message,transfer,waiting,done,warning,browse,silent,answer}-{0..3}-128.png` | 概览页「看懂 ASL」：9 个场景各有独立角色（机器人、邮差鸟、小熊搬运工、举牌猫、青蛙、灯塔守、猫头鹰、熊猫、狐狸），每场 4 帧 |
| 头像 | `avatars/avatar-01…12-*-{64,128}.png` 及 SVG | 128 px 编译进程序，作为本机预设头像；每个头像衣服配色和图案不同 |
| 空节点 / 空联系人 / 空群组 | `states/empty-{node,contacts,group}-64.png` | 对应页面的空状态 |
| 传输完成 | `states/transfer-complete-64.png` | 传输页无待处理项 |
| 等待批准 | `states/awaiting-approval-64.png` | 审批状态行的内联图标 |
| 匿名 / 公开身份 | `states/identity-{anonymous,public}-64.png` | 身份资料披露说明 |
| 只浏览 | `states/mode-browse-only-64.png` | 直连「只浏览（不回答）」按钮 |
| 不回答 | `states/mode-no-answer-64.png` | 群组「只浏览，不回答」提示 |
| 网络离线 | `states/network-offline-64.png` | 网络隐私设置中的离线 / 未启用提示 |

`docs/assets/` 中的 `asl-pixel-icon.svg`、`asl-pixel-icon-256.png`、`asl-pixel-mascot.svg` 和 `asl-*-preview.png` 由本脚本输出，属于设计预览，不是产品截图。`asl-product-icon.svg` 与 `asl-agent-mascot.svg` 不由本脚本生成或修改。`asl-explainer-scenes-preview.png` 是 9 个讲解场景的拼图预览。

侧栏导航图标不是资产文件：由 `crates/asl-app/src/ui/nav_icon.rs` 在运行时用 8×8 像素图案绘制。

许可：这些资产随 ASL 仓库使用 MIT 许可。若仓库根目录的许可证文件有更具体的资产条款，以根目录许可证为准。

English

The icons, mascot, avatars, and state glyphs are original pixel art drawn directly by `scripts/generate-art.py` with Pillow. No generative asset service and no third-party images are involved.

At runtime the application reads only the PNGs compiled in from `crates/asl-app/assets/`. The SVGs are editable sources and documentation previews, not networked assets.

Tool: Python 3.14.3 + Pillow 12.1.1, generated offline on 2026-11-23. Everything is drawn in code; there is no prompt and no modification of an external image.

| Asset | Files (`crates/asl-app/assets/`) | Runtime use |
|---|---|---|
| Product icon | `icons/asl-icon-{16,32,48,64,128,256}.png`, `asl-icon.ico`, `asl-icon.svg` | The 256 px PNG is the window icon; the ICO is for packaging |
| Mascot | `mascot/mascot-{idle,message,transfer,waiting,done,warning}-{64,128,256}.png` and SVGs | Idle at 256 px is the empty state and fallback avatar; the other five at 128 px follow local state in the top bar |
| Explainer scenes | `mascot/anim-{idle,message,transfer,waiting,done,warning,browse,silent,answer}-{0..3}-128.png` | "Understand ASL" on the overview: each of the 9 scenes has its own character (robot, postman bird, bear mover, sign-holding cat, frog, lighthouse keeper, owl, panda, fox), 4 frames each |
| Avatars | `avatars/avatar-01…12-*-{64,128}.png` and SVGs | The 128 px set is compiled in as local presets; every avatar has its own outfit colours and pattern |
| Empty node / contacts / group | `states/empty-{node,contacts,group}-64.png` | Empty state of the matching page |
| Transfer complete | `states/transfer-complete-64.png` | Transfers page with nothing pending |
| Awaiting approval | `states/awaiting-approval-64.png` | Inline icon on an approval status row |
| Anonymous / public identity | `states/identity-{anonymous,public}-64.png` | Disclosure note on the identity profile |
| Browse only | `states/mode-browse-only-64.png` | Button for the direct "browse only, no answers" mode |
| No answer | `states/mode-no-answer-64.png` | Hint for the group "browse only, no answers" state |
| Network offline | `states/network-offline-64.png` | Offline / disabled hint in the network privacy settings |

The `asl-pixel-icon.svg`, `asl-pixel-icon-256.png`, `asl-pixel-mascot.svg` and `asl-*-preview.png` files under `docs/assets/` come from this script and are design previews, not product screenshots. `asl-product-icon.svg` and `asl-agent-mascot.svg` are neither generated nor modified by this script. `asl-explainer-scenes-preview.png` is a contact sheet of the 9 explainer scenes.

The sidebar navigation icons are not asset files: `crates/asl-app/src/ui/nav_icon.rs` draws them at runtime from 8×8 pixel patterns.

License: these assets follow the MIT license of the ASL repository. If the repository root states a more specific asset term, that root license controls.
