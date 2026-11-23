"""Generate the original ASL pixel art set offline.

Everything here is drawn with Pillow from code in this repository: no
external generator, no downloaded art, no font files. The output is intended
to be committed and loaded at runtime with include_bytes!, so the running
application never depends on Python or this script.

Run: python scripts/generate-art.py
"""

import colorsys
import shutil
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
ASSET = ROOT / "crates" / "asl-app" / "assets"
DOCS = ROOT / "docs" / "assets"

INK = (33, 43, 49, 255)
TEAL = (25, 118, 108, 255)
TEAL_DEEP = (18, 99, 90, 255)
CREAM = (251, 250, 243, 255)
PAPER = (252, 253, 252, 255)
CORAL = (252, 180, 104, 255)
CORAL_DEEP = (214, 120, 64, 255)
SKY = (108, 153, 178, 255)
SKIN = (249, 216, 187, 255)
BLUSH = (235, 143, 143, 255)
DANGER = (160, 58, 40, 255)
WHITE = (255, 255, 255, 255)
CLEAR = (0, 0, 0, 0)


class Canvas:
    def __init__(self, size):
        self.size = size
        self.cells = {}

    def dot(self, x, y, color):
        if color[3] and 0 <= x < self.size and 0 <= y < self.size:
            self.cells[(x, y)] = color

    def rect(self, x, y, w, h, color):
        for py in range(y, y + h):
            for px in range(x, x + w):
                self.dot(px, py, color)

    def hline(self, x, y, w, color):
        self.rect(x, y, w, 1, color)

    def vline(self, x, y, h, color):
        self.rect(x, y, 1, h, color)

    def outline_rect(self, x, y, w, h, color):
        self.hline(x, y, w, color)
        self.hline(x, y + h - 1, w, color)
        self.vline(x, y, h, color)
        self.vline(x + w - 1, y, h, color)

    def image(self, scale):
        image = Image.new("RGBA", (self.size * scale, self.size * scale), CLEAR)
        for (x, y), color in self.cells.items():
            image.paste(color, (x * scale, y * scale, (x + 1) * scale, (y + 1) * scale))
        return image


def grid(rows, palette):
    canvas = Canvas(len(rows))
    for y, row in enumerate(rows):
        for x, char in enumerate(row):
            canvas.dot(x, y, palette.get(char, CLEAR))
    return canvas


def envelope(mark, mark_color):
    canvas = Canvas(16)
    canvas.rect(2, 1, 12, 2, TEAL)
    canvas.rect(1, 3, 14, 11, TEAL)
    canvas.rect(2, 4, 12, 9, TEAL_DEEP)
    canvas.rect(3, 4, 10, 2, CREAM)
    for i in range(5):
        canvas.rect(3 + i, 6 + i, 1, 1, INK)
        canvas.rect(12 - i, 6 + i, 1, 1, INK)
    canvas.rect(7, 10, 2, 1, INK)
    canvas.rect(3, 12, 10, 1, CREAM)
    canvas.rect(11, 9, 3, 4, mark_color)
    canvas.rect(12, 10, 1, 2, mark)
    return canvas


HAIR = (58, 118, 150, 255)
HAIR_DARK = (40, 86, 112, 255)


def mascot(expression, accent, prop):
    """Chibi agent girl: blue bob hair, teal dress, antenna clip, state prop."""
    canvas = Canvas(24)
    canvas.vline(15, 0, 2, INK)
    canvas.dot(15, 0, accent)
    canvas.rect(8, 2, 8, 1, HAIR_DARK)
    canvas.rect(6, 3, 12, 3, HAIR)
    canvas.rect(5, 5, 2, 9, HAIR)
    canvas.rect(17, 5, 2, 9, HAIR)
    canvas.rect(7, 5, 10, 8, SKIN)
    canvas.rect(7, 5, 10, 1, HAIR)
    canvas.rect(7, 6, 2, 1, HAIR)
    canvas.rect(15, 6, 2, 1, HAIR)
    canvas.vline(4, 7, 6, HAIR_DARK)
    canvas.vline(19, 7, 6, HAIR_DARK)
    canvas.rect(16, 3, 2, 2, accent)
    canvas.rect(8, 7, 2, 2, INK)
    canvas.rect(14, 7, 2, 2, INK)
    canvas.dot(9, 7, WHITE)
    canvas.dot(15, 7, WHITE)
    canvas.rect(7, 10, 2, 1, BLUSH)
    canvas.rect(15, 10, 2, 1, BLUSH)
    canvas.rect(8, 13, 8, 1, SKIN)
    canvas.rect(7, 14, 10, 1, CREAM)
    canvas.rect(6, 15, 12, 5, TEAL)
    canvas.rect(11, 15, 2, 1, CORAL)
    canvas.rect(7, 19, 10, 1, TEAL_DEEP)
    canvas.rect(5, 16, 1, 3, SKIN)
    canvas.rect(18, 16, 1, 3, SKIN)
    canvas.rect(8, 20, 2, 2, SKIN)
    canvas.rect(14, 20, 2, 2, SKIN)
    canvas.rect(8, 22, 2, 1, INK)
    canvas.rect(14, 22, 2, 1, INK)
    for shape in expression + prop:
        canvas.rect(*shape)
    return canvas


EXPRESSIONS = {
    "idle": ([(11, 11, 2, 1, INK)], []),
    "message": (
        [(11, 11, 2, 1, INK), (11, 12, 2, 1, BLUSH)],
        [(19, 15, 5, 4, CREAM), (19, 15, 5, 1, TEAL), (20, 16, 1, 1, TEAL), (22, 16, 1, 1, TEAL), (21, 17, 1, 1, TEAL)],
    ),
    "transfer": (
        [(11, 11, 2, 1, INK)],
        [(20, 14, 1, 1, TEAL), (21, 15, 1, 1, TEAL), (22, 16, 1, 1, TEAL), (21, 17, 1, 1, TEAL), (20, 18, 1, 1, TEAL), (0, 16, 3, 1, TEAL_DEEP)],
    ),
    "waiting": (
        [(10, 11, 4, 1, CORAL_DEEP)],
        [(20, 13, 3, 1, CORAL_DEEP), (22, 14, 1, 2, CORAL_DEEP), (21, 16, 1, 1, CORAL_DEEP), (21, 18, 1, 1, CORAL_DEEP)],
    ),
    "done": (
        [(10, 11, 1, 1, INK), (13, 11, 1, 1, INK), (11, 12, 2, 1, INK)],
        [(19, 16, 1, 1, TEAL_DEEP), (20, 17, 1, 1, TEAL_DEEP), (21, 16, 1, 1, TEAL_DEEP), (22, 15, 1, 1, TEAL_DEEP), (23, 14, 1, 1, TEAL_DEEP)],
    ),
    "warning": (
        [(11, 11, 2, 2, DANGER)],
        [(21, 13, 1, 4, DANGER), (21, 18, 1, 1, DANGER)],
    ),
}

def glyph(kind, tone):
    canvas = Canvas(16)
    canvas.outline_rect(1, 1, 14, 14, tone)
    canvas.rect(2, 2, 12, 12, (*tone[:3], 40))
    if kind == "node":
        canvas.rect(7, 3, 2, 2, tone)
        canvas.rect(3, 10, 2, 2, tone)
        canvas.rect(11, 10, 2, 2, tone)
        canvas.hline(5, 10, 6, tone)
        canvas.vline(7, 5, 5, tone)
    elif kind == "people":
        canvas.rect(4, 4, 3, 3, tone)
        canvas.rect(9, 4, 3, 3, tone)
        canvas.rect(3, 9, 5, 3, tone)
        canvas.rect(8, 9, 5, 3, tone)
    elif kind == "group":
        canvas.rect(6, 3, 4, 3, tone)
        canvas.rect(3, 9, 4, 3, tone)
        canvas.rect(9, 9, 4, 3, tone)
    elif kind == "done":
        canvas.rect(4, 8, 2, 2, tone)
        canvas.rect(6, 6, 2, 2, tone)
        canvas.rect(8, 4, 2, 2, tone)
        canvas.rect(10, 4, 2, 2, tone)
    elif kind == "waiting":
        canvas.rect(7, 3, 2, 6, tone)
        canvas.rect(7, 10, 2, 2, tone)
    elif kind == "offline":
        canvas.hline(4, 7, 8, tone)
        canvas.hline(4, 9, 8, tone)
        canvas.vline(4, 7, 3, tone)
        canvas.vline(11, 7, 3, tone)
    elif kind == "anonymous":
        canvas.rect(5, 4, 6, 4, tone)
        canvas.rect(4, 6, 2, 2, WHITE)
        canvas.rect(10, 6, 2, 2, WHITE)
        canvas.rect(6, 11, 4, 2, tone)
    elif kind == "public":
        canvas.outline_rect(4, 3, 8, 6, tone)
        canvas.rect(6, 9, 4, 4, tone)
        canvas.rect(7, 5, 2, 2, tone)
    elif kind == "browse":
        canvas.outline_rect(3, 5, 10, 6, tone)
        canvas.hline(5, 7, 6, tone)
        canvas.hline(5, 9, 4, tone)
    elif kind == "silent":
        canvas.outline_rect(4, 4, 8, 6, tone)
        canvas.hline(6, 6, 4, tone)
        canvas.rect(6, 11, 4, 1, tone)
    return canvas


GLYPHS = {
    "empty-node": ("node", TEAL),
    "empty-contacts": ("people", TEAL),
    "empty-group": ("group", TEAL),
    "transfer-complete": ("done", TEAL_DEEP),
    "awaiting-approval": ("waiting", CORAL_DEEP),
    "network-offline": ("offline", DANGER),
    "identity-anonymous": ("anonymous", SKY),
    "identity-public": ("public", TEAL),
    "mode-browse-only": ("browse", SKY),
    "mode-no-answer": ("silent", CORAL_DEEP),
}


def face(hair, accent, feature):
    canvas = Canvas(16)
    canvas.rect(4, 1, 8, 2, hair)
    canvas.rect(3, 3, 10, 9, SKIN)
    canvas.rect(3, 3, 10, 2, hair)
    canvas.rect(3, 5, 1, 4, hair)
    canvas.rect(12, 5, 1, 4, hair)
    canvas.rect(4, 12, 8, 2, TEAL)
    canvas.rect(5, 14, 6, 2, TEAL_DEEP)
    canvas.rect(5, 6, 2, 2, INK)
    canvas.rect(9, 6, 2, 2, INK)
    canvas.rect(6, 7, 1, 1, WHITE)
    canvas.rect(10, 7, 1, 1, WHITE)
    canvas.rect(4, 9, 2, 1, BLUSH)
    canvas.rect(10, 9, 2, 1, BLUSH)
    for shape in feature:
        canvas.rect(*shape)
    canvas.rect(13, 1, 2, 2, accent)
    return canvas


AVATARS = [
    ("01-teal-bob", (25, 118, 108, 255), CORAL, []),
    ("02-ink-cap", INK, CREAM, [(4, 1, 8, 1, INK), (3, 2, 10, 1, INK)]),
    ("03-sky-glasses", SKY, TEAL, [(4, 6, 8, 1, INK)]),
    ("04-coral-band", CORAL_DEEP, SKY, [(4, 3, 8, 1, CORAL)]),
    ("05-headphones", (70, 104, 122, 255), CORAL, [(2, 6, 1, 3, INK), (13, 6, 1, 3, INK), (3, 5, 1, 2, INK), (12, 5, 1, 2, INK)]),
    ("06-cream-bun", CREAM, TEAL, [(6, 0, 4, 2, CREAM), (5, 1, 6, 1, INK)]),
    ("07-antenna", TEAL_DEEP, CORAL, [(7, 0, 2, 2, TEAL), (6, 0, 4, 1, CORAL)]),
    ("08-visor", (47, 72, 92, 255), SKY, [(4, 6, 8, 2, (150, 214, 206, 255))]),
    ("09-freckles", (122, 86, 64, 255), CREAM, [(4, 8, 1, 1, CORAL_DEEP), (11, 8, 1, 1, CORAL_DEEP)]),
    ("10-side-part", (236, 232, 214, 255), TEAL_DEEP, [(7, 3, 1, 3, SKIN)]),
    ("11-earpiece", SKY, CORAL_DEEP, [(13, 7, 2, 2, CORAL), (14, 6, 1, 1, INK)]),
    ("12-round-badge", (18, 99, 90, 255), CORAL, [(12, 11, 2, 2, CREAM), (12, 12, 2, 1, TEAL)]),
]


def shift(color, amount):
    r, g, b, a = color
    h, l, s = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    l = min(1, max(0, l + amount))
    rr, gg, bb = colorsys.hls_to_rgb(h, l, s)
    return (round(rr * 255), round(gg * 255), round(bb * 255), a)


def save_scaled(canvas, path, scales):
    for scale in scales:
        canvas.image(scale).save(path.with_name(f"{path.stem}-{canvas.size * scale}.png"))


def fit(canvas, size):
    """Largest whole-pixel scale that fits, centered on a transparent square."""
    scale = max(1, size // canvas.size)
    art = canvas.image(scale)
    out = Image.new("RGBA", (size, size), CLEAR)
    offset = (size - art.width) // 2
    out.paste(art, (offset, offset), art)
    return out


def save_fit(canvas, path, sizes):
    for size in sizes:
        fit(canvas, size).save(path.with_name(f"{path.stem}-{size}.png"))


def write_svg(canvas, path):
    size = canvas.size
    rects = "\n".join(
        f'  <rect x="{x}" y="{y}" width="1" height="1" fill="#{color[0]:02x}{color[1]:02x}{color[2]:02x}"/>'
        for (x, y), color in sorted(canvas.cells.items())
    )
    path.write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" shape-rendering="crispEdges">\n{rects}\n</svg>\n',
        encoding="utf-8",
    )


def contact_sheet(items, cell, columns, labels=False):
    rows = (len(items) + columns - 1) // columns
    label_h = 18 if labels else 0
    sheet = Image.new("RGBA", (columns * (cell + 16) + 16, rows * (cell + label_h + 16) + 16), PAPER)
    for index, (name, image) in enumerate(items):
        x = 16 + (index % columns) * (cell + 16)
        y = 16 + (index // columns) * (cell + label_h + 16)
        fitted = image.resize((cell, cell), Image.Resampling.NEAREST)
        sheet.paste(fitted, (x, y), fitted)
    return sheet


def checker(image, cell):
    background = Image.new("RGBA", (cell, cell), PAPER)
    dark = shift(TEAL, -0.42)
    tile = 8
    for y in range(0, cell, tile):
        for x in range(0, cell, tile):
            if (x // tile + y // tile) % 2:
                background.paste(dark, (x, y, min(x + tile, cell), min(y + tile, cell)))
    fitted = image.resize((cell, cell), Image.Resampling.NEAREST)
    background.alpha_composite(fitted)
    return background


def main():
    if ASSET.exists():
        shutil.rmtree(ASSET)
    for sub in ("icons", "mascot", "avatars", "states"):
        (ASSET / sub).mkdir(parents=True)
    DOCS.mkdir(parents=True, exist_ok=True)

    icon = envelope(TEAL, CORAL)
    write_svg(icon, ASSET / "icons" / "asl-icon.svg")
    shutil.copyfile(ASSET / "icons" / "asl-icon.svg", DOCS / "asl-pixel-icon.svg")
    save_scaled(icon, ASSET / "icons" / "asl-icon.png", [1, 2, 3, 4, 8, 16])
    icon.image(16).save(DOCS / "asl-pixel-icon-256.png")
    icon.image(16).save(
        ASSET / "icons" / "asl-icon.ico",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )

    mascot_items = []
    for name, (expression, prop) in EXPRESSIONS.items():
        canvas = mascot(expression, CORAL if name != "warning" else DANGER, prop)
        folder = ASSET / "mascot"
        write_svg(canvas, folder / f"mascot-{name}.svg")
        save_fit(canvas, folder / f"mascot-{name}.png", [64, 128, 256])
        mascot_items.append((name, canvas.image(8)))
    shutil.copyfile(ASSET / "mascot" / "mascot-idle.svg", DOCS / "asl-pixel-mascot.svg")
    contact_sheet(mascot_items, 96, 6).save(DOCS / "asl-mascot-states-preview.png")

    avatar_items = []
    for name, hair, accent, feature in AVATARS:
        canvas = face(hair, accent, feature)
        write_svg(canvas, ASSET / "avatars" / f"avatar-{name}.svg")
        save_scaled(canvas, ASSET / "avatars" / f"avatar-{name}.png", [4, 8])
        avatar_items.append((name, canvas.image(8)))
    contact_sheet(avatar_items, 64, 6).save(DOCS / "asl-avatar-set-preview.png")
    checks = [checker(image, 72) for _, image in avatar_items]
    contact_sheet([(str(i), image) for i, image in enumerate(checks)], 72, 6).save(
        DOCS / "asl-avatar-contrast-preview.png"
    )

    state_items = []
    for name, (kind, tone) in GLYPHS.items():
        canvas = glyph(kind, tone)
        write_svg(canvas, ASSET / "states" / f"{name}.svg")
        canvas.image(4).save(ASSET / "states" / f"{name}-64.png")
        state_items.append((name, canvas.image(4)))
    contact_sheet(state_items, 64, 5).save(DOCS / "asl-state-glyphs-preview.png")

    manifest = DOCS / "ART-SOURCE.md"
    manifest.write_text(
        """# ASL art source

中文

这些图标、吉祥物、头像和状态图都是本仓库 `scripts/generate-art.py` 用 Pillow 直接绘制的原创像素图，没有使用生成式素材服务，也没有引入第三方图片。

运行时只读取 `crates/asl-app/assets/` 中随二进制编译进去的 PNG。SVG 仅作为可编辑源和文档展示，不从网络加载。

生成工具：Python 3.14.3 + Pillow 12.1.1，2026-11-23 离线生成。全部为代码绘制，没有提示词，也没有对外部图片做修改。

| 资产 | 文件（`crates/asl-app/assets/`） | 运行时用途 |
|---|---|---|
| 产品图标 | `icons/asl-icon-{16,32,48,64,128,256}.png`、`asl-icon.ico`、`asl-icon.svg` | 256 px PNG 用作窗口图标；ICO 留给打包 |
| 吉祥物 | `mascot/mascot-{idle,message,transfer,waiting,done,warning}-{64,128,256}.png` 及 SVG | 只编译 idle：无数据时的空状态和本机头像缺省图 |
| 头像 | `avatars/avatar-01…12-*-{64,128}.png` 及 SVG | 暂未编译进程序，作为本机预设头像候选 |
| 空节点 / 空联系人 / 空群组 | `states/empty-{node,contacts,group}-64.png` | 对应页面的空状态 |
| 传输完成 | `states/transfer-complete-64.png` | 传输页无待处理项 |
| 等待批准 | `states/awaiting-approval-64.png` | 审批状态行的内联图标 |
| 匿名 / 公开身份 | `states/identity-{anonymous,public}-64.png` | 身份资料披露说明 |
| 只浏览 | `states/mode-browse-only-64.png` | 直连「只浏览（不回答）」按钮 |
| 不回答 | `states/mode-no-answer-64.png` | 群组「只浏览，不回答」提示 |
| 网络离线 | `states/network-offline-64.png` | 暂未接入，没有合适的入口级网络状态 |

`docs/assets/` 中的 `asl-pixel-icon.svg`、`asl-pixel-icon-256.png`、`asl-pixel-mascot.svg` 和 `asl-*-preview.png` 由本脚本输出，属于设计预览，不是产品截图。`asl-product-icon.svg` 与 `asl-agent-mascot.svg` 不由本脚本生成或修改。

许可：这些资产随 ASL 仓库使用 MIT 许可。若仓库根目录的许可证文件有更具体的资产条款，以根目录许可证为准。

English

The icons, mascot, avatars, and state glyphs are original pixel art drawn directly by `scripts/generate-art.py` with Pillow. No generative asset service and no third-party images are involved.

At runtime the application reads only the PNGs compiled in from `crates/asl-app/assets/`. The SVGs are editable sources and documentation previews, not networked assets.

Tool: Python 3.14.3 + Pillow 12.1.1, generated offline on 2026-11-23. Everything is drawn in code; there is no prompt and no modification of an external image.

| Asset | Files (`crates/asl-app/assets/`) | Runtime use |
|---|---|---|
| Product icon | `icons/asl-icon-{16,32,48,64,128,256}.png`, `asl-icon.ico`, `asl-icon.svg` | The 256 px PNG is the window icon; the ICO is for packaging |
| Mascot | `mascot/mascot-{idle,message,transfer,waiting,done,warning}-{64,128,256}.png` and SVGs | Only idle is compiled in: the empty state when there is no data, and the fallback avatar |
| Avatars | `avatars/avatar-01…12-*-{64,128}.png` and SVGs | Not compiled in yet; reserved as local preset avatar candidates |
| Empty node / contacts / group | `states/empty-{node,contacts,group}-64.png` | Empty state of the matching page |
| Transfer complete | `states/transfer-complete-64.png` | Transfers page with nothing pending |
| Awaiting approval | `states/awaiting-approval-64.png` | Inline icon on an approval status row |
| Anonymous / public identity | `states/identity-{anonymous,public}-64.png` | Disclosure note on the identity profile |
| Browse only | `states/mode-browse-only-64.png` | Button for the direct "browse only, no answers" mode |
| No answer | `states/mode-no-answer-64.png` | Hint for the group "browse only, no answers" state |
| Network offline | `states/network-offline-64.png` | Not wired in; there is no entry-level network state for it |

The `asl-pixel-icon.svg`, `asl-pixel-icon-256.png`, `asl-pixel-mascot.svg` and `asl-*-preview.png` files under `docs/assets/` come from this script and are design previews, not product screenshots. `asl-product-icon.svg` and `asl-agent-mascot.svg` are neither generated nor modified by this script.

License: these assets follow the MIT license of the ASL repository. If the repository root states a more specific asset term, that root license controls.
""",
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {ASSET}")


if __name__ == "__main__":
    main()
