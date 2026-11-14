"""Render docs/assets/terminal.gif: a replay of a real `secfoo run` captured
in examples/sample-output/nodegoat/, drawn frame by frame with Pillow so the
recording needs no terminal recorder and stays byte-for-byte faithful to the
captured output (only the spinner timing is compressed).

    uv run --with pillow python scripts/terminal_gif.py

The text below is the captured transcript; edit it only when re-capturing.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parents[1] / "docs" / "assets" / "terminal.gif"

COLS, ROWS = 100, 29
FONT_SIZE, LINE_H, PAD, TITLE_H = 15, 21, 18, 36
MENLO = "/System/Library/Fonts/Menlo.ttc"
SYMBOLS = "/System/Library/Fonts/Apple Symbols.ttf"  # braille spinner glyphs
BG, FG = (17, 21, 28), (215, 221, 229)
STYLES = {
    "": (FG, False),
    "bold": (FG, True),
    "dim": ((122, 132, 148), False),
    "green": ((63, 185, 80), False),
    "red": ((255, 107, 107), False),
    "cyan": ((86, 182, 194), True),
    "magenta": ((198, 120, 221), True),
    "yellow": ((227, 179, 65), False),
    "prompt": ((63, 185, 80), True),
}
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

Span = tuple[str, str]
Line = list[Span]

CMD1 = "secfoo run --skill sast --skill secret-scanning --agent claude \\"
CMD1B = "    --target https://github.com/OWASP/NodeGoat --fail-on high"
CMD2 = "secfoo findings show 14c496def1"
CMD3 = "secfoo findings export --format sarif -o nodegoat.sarif"

TABLE = [
    [("                                         Assessment results", "dim")],
    [("┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓", "")],
    [("┃ ", ""), ("Skill                 ", "bold"), (" ┃ ", ""), ("Status ", "bold"), (" ┃ ", ""), ("Duration", "bold"),
     (" ┃ ", ""), ("Findings (C/H/M/L)", "bold"), (" ┃ ", ""), (" Cost", "bold"), (" ┃ ", ""), ("Run ID               ", "bold"), (" ┃", "")],
    [("┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩", "")],
    [("│ SAST — Static Code     │ ", ""), ("success", "green"), (" │ 251.9s   │ 0/", ""), ("6", "red"), ("/5/1            │ $2.34 │ a0224a94-64d9-4966-9… │", "")],
    [("│ Analysis               │         │          │                    │       │                       │", "")],
    [("│ Secret Scanning —      │ ", ""), ("success", "green"), (" │ 135.3s   │ 0/", ""), ("3", "red"), ("/2/1            │ $1.39 │ de9487a2-3843-4674-a… │", "")],
    [("│ Code, Confluence &     │         │          │                    │       │                       │", "")],
    [("│ Docs                   │         │          │                    │       │                       │", "")],
    [("└────────────────────────┴─────────┴──────────┴────────────────────┴───────┴───────────────────────┘", "")],
    [("AI spend for this run: ", ""), ("$3.73", "cyan")],
    [("Findings gate (--fail-on high): ", ""), ("FAILED", "red"), (" -- ", ""), ("9", "cyan"), (" finding(s) at or above threshold", "")],
    [("Run ", ""), ("secfoo serve", "bold"), (" to view full reports in your browser.", "")],
]

FINDING = [
    [("Server-side JS injection via `", "bold"), ("eval", "magenta"), ("()` on POST body", "bold"), ("  (sast, ", ""), ("High", "red"), (", open)", "")],
    [("Project: NodeGoat   Fingerprint: 14c496def185f104bd8d034c41ab10ccd318dda2154a845df3ed35867031b798", "")],
    [("Location: ", ""), ("app/routes/contributions.js:32-34", "cyan")],
    [("Recommendation: Replace `eval()` with `parseInt(value, 10)` (or `Number()`), reject `NaN`, negative,", "")],
    [("and out-of-range values, and validate the body with a schema before use.", "")],
]


def fonts():
    regular = ImageFont.truetype(MENLO, FONT_SIZE, index=0)
    bold = ImageFont.truetype(MENLO, FONT_SIZE, index=1)
    symbols = ImageFont.truetype(SYMBOLS, FONT_SIZE)
    return regular, bold, symbols


class Term:
    def __init__(self) -> None:
        self.regular, self.bold, self.symbols = fonts()
        self.cw = round(self.regular.getlength("M"))
        self.w = COLS * self.cw + 2 * PAD
        self.h = TITLE_H + ROWS * LINE_H + 2 * PAD
        self.lines: list[Line] = []
        self.frames: list[Image.Image] = []
        self.durations: list[int] = []

    def frame(self, duration: int, cursor: bool = True) -> None:
        img = Image.new("RGB", (self.w, self.h), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, self.w, TITLE_H], fill=(30, 35, 44))
        for i, color in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            d.ellipse([14 + i * 22, 11, 28 + i * 22, 25], fill=color)
        title = "secfoo — OWASP/NodeGoat — real run, 4 min 12 s, $3.73 (Claude Code, --depth quick)"
        d.text(((self.w - self.regular.getlength(title)) / 2, 9), title, font=self.regular, fill=(150, 160, 175))
        visible = self.lines[-ROWS:]
        y = TITLE_H + PAD
        for line in visible:
            x = PAD
            for text, style in line:
                color, is_bold = STYLES[style]
                for ch in text:
                    font = self.symbols if ch in SPINNER else (self.bold if is_bold else self.regular)
                    d.text((x, y), ch, font=font, fill=color)
                    x += self.cw
            y += LINE_H
        if cursor and visible:
            last = visible[-1]
            x = PAD + sum(len(t) for t, _ in last) * self.cw
            d.rectangle([x, y - LINE_H + 3, x + self.cw - 1, y - 3], fill=(150, 160, 175))
        self.frames.append(img.quantize(colors=64, method=Image.Quantize.MEDIANCUT))
        self.durations.append(duration)

    def type_command(self, cmd: str, continuation: str | None = None) -> None:
        self.lines.append([("$ ", "prompt")])
        for i in range(0, len(cmd) + 1, 2):
            self.lines[-1] = [("$ ", "prompt"), (cmd[:i], "")]
            self.frame(30)
        self.lines[-1] = [("$ ", "prompt"), (cmd, "")]
        if continuation:
            self.lines.append([])
            for i in range(0, len(continuation) + 1, 3):
                self.lines[-1] = [(continuation[:i], "")]
                self.frame(30)
            self.lines[-1] = [(continuation, "")]
        self.frame(500)

    def spinner(self) -> None:
        sast = ("SAST — Static Code Analysis", "bold")
        secrets = ("Secret Scanning — Code, Confluence & Docs", "bold")
        base = len(self.lines)
        self.lines += [[], []]

        def running(skill: Span, tick: int) -> Line:
            return [(SPINNER[tick % len(SPINNER)] + " Running ", ""), skill, (" via claude...", "")]

        def done(skill: Span) -> Line:
            return [("  ", ""), ("success", "green"), (" — ", ""), (skill[0], "")]

        for tick in range(26):
            self.lines[base] = running(sast, tick)
            self.lines[base + 1] = running(secrets, tick)
            self.frame(80, cursor=False)
        for tick in range(26, 42):
            self.lines[base] = running(sast, tick)
            self.lines[base + 1] = done(secrets)
            self.frame(80, cursor=False)
        self.lines[base] = done(sast)
        self.frame(600, cursor=False)

    def output(self, lines: list[Line], hold: int) -> None:
        self.lines += lines
        self.frame(hold, cursor=False)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        first, rest = self.frames[0], self.frames[1:]
        first.save(path, save_all=True, append_images=rest, duration=self.durations, loop=0, optimize=True, disposal=1)


def main() -> int:
    t = Term()
    t.frame(700)
    t.type_command(CMD1, CMD1B)
    t.spinner()
    t.output(TABLE, 3500)
    t.type_command(CMD2)
    t.output(FINDING, 3500)
    t.type_command(CMD3)
    t.output([[("Wrote 18 finding(s) to nodegoat.sarif.", "")]], 400)
    t.lines.append([("$ ", "prompt")])
    t.frame(4500)
    t.save(OUT)
    size = OUT.stat().st_size
    print(f"{OUT} {len(t.frames)} frames {size/1024:.0f} KiB {t.w}x{t.h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
