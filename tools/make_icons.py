# Regenerate the Cyber Sweeper application icons from the source logo.
#
# Run this only when the artwork changes; the generated files are committed so
# that neither the package nor its users need Pillow at run time::
#
#     python tools/make_icons.py path/to/logo.png
#
# Why two renderings?  A logo drawn for a business card falls apart at 16x16 -
# the arch becomes a grey smear and the orca disappears into the dark body.  So
# sizes at or below SMALL_MAX get a deliberately simplified mark that keeps
# the brand's silhouette, palette and arch, while larger sizes use the full
# artwork.  Windows asks for 16/20/24 px in title bars and 32/48/256 px in the
# taskbar, Alt-Tab and Explorer, and it picks the entry matching the user's
# display scaling instead of rescaling - which is exactly why the .ico has to
# carry every one of them.

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).resolve().parent.parent / "cybersweeper" / "assets"

# Sampled from the source artwork.
NAVY = (53, 50, 66, 255)
FOAM = (224, 225, 225, 255)
TEAL = (145, 206, 218, 255)
DEEP_TEAL = (99, 185, 201, 255)
WHITE = (255, 255, 255, 255)

ICO_SIZES = (16, 20, 24, 32, 48, 64, 128, 256)
PNG_SIZES = (64, 256, 512)
SMALL_MAX = 24  # at or below this, draw the simplified mark
SS = 8  # supersampling factor for the simplified mark


# --------------------------------------------------------------------------- #
# Source artwork
# --------------------------------------------------------------------------- #


# Return the logo on a transparent square canvas, trimmed and padded.
def load_artwork(path: Path) -> Image.Image:
    img = Image.open(path).convert("RGBA")
    px = img.load()
    for y in range(img.height):  # knock out the near-white studio background
        for x in range(img.width):
            r, g, b, a = px[x, y]
            if r > 245 and g > 245 and b > 245:
                px[x, y] = (r, g, b, 0)
    img = img.crop(img.getbbox())
    side = int(max(img.size) * 1.06)
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.alpha_composite(img, ((side - img.width) // 2, (side - img.height) // 2))
    return canvas


# --------------------------------------------------------------------------- #
# Simplified small mark
# --------------------------------------------------------------------------- #


# Draw the simplified mark: navy squircle, white arch, teal water.
def draw_small(size: int) -> Image.Image:
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    def box(*f: float) -> tuple[float, ...]:
        return tuple(v * s for v in f)

    body = box(0.03, 0.01, 0.97, 0.99)
    d.rounded_rectangle(body, radius=0.33 * s, fill=NAVY)

    # Water: three bands, each a chord of a wide circle so the crest curves.
    for top, colour in ((0.55, FOAM), (0.68, TEAL), (0.82, DEEP_TEAL)):
        water = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        wd = ImageDraw.Draw(water)
        wd.ellipse(box(-0.30, top, 1.30, top + 1.1), fill=colour)
        img.alpha_composite(_clip(water, body, s))

    # Arch: a capsule with its lower half squared off against the body.
    arch = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ad = ImageDraw.Draw(arch)
    ad.rounded_rectangle(box(0.23, 0.15, 0.77, 0.55), radius=0.27 * s, fill=WHITE)
    ad.rectangle(box(0.20, 0.36, 0.80, 0.60), fill=(0, 0, 0, 0))
    img.alpha_composite(arch)

    return img.resize((size, size), Image.LANCZOS)


# Keep only the part of *layer* that falls inside the squircle body.
def _clip(layer: Image.Image, body: tuple[float, ...], s: int) -> Image.Image:
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle(body, radius=0.33 * s, fill=255)
    out = layer.copy()
    out.putalpha(Image.composite(layer.getchannel("A"), Image.new("L", (s, s), 0), mask))
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def render(art: Image.Image, size: int) -> Image.Image:
    return draw_small(size) if size <= SMALL_MAX else art.resize((size, size), Image.LANCZOS)


def main(source: str) -> int:
    art = load_artwork(Path(source))
    ASSETS.mkdir(parents=True, exist_ok=True)

    frames = [render(art, n) for n in ICO_SIZES]
    frames[-1].save(ASSETS / "cybersweeper.ico", format="ICO",
                    sizes=[(n, n) for n in ICO_SIZES], append_images=frames[:-1])

    for n in PNG_SIZES:
        name = "cybersweeper.png" if n == 256 else f"cybersweeper_{n}.png"
        render(art, n).save(ASSETS / name)
    for n in (16, 24, 32, 48):  # Tk's iconphoto scales badly; give it exact sizes
        render(art, n).save(ASSETS / f"cybersweeper_{n}.png")

    print(f"wrote {ASSETS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else str(ASSETS / "cybersweeper_512.png")))
