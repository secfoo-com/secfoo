# Secfoo Design System

**Secfoo — security review orchestration.** This is the base design system
extended with the Secfoo brand layer: the logo, brand role tokens, three new
themes and three new button variants.

Open [`brand.html`](./brand.html) for the logo and brand guidance, and
[`demo.html`](./demo.html) for the full component style guide.

## What the brand layer adds

| File | Contents |
|---|---|
| `tokens.css` | `--brand-ink`, `--brand-ink-deep`, `--brand-signal`, `--brand-signal-soft`, logo geometry (`--logo-*`), terminal surface tokens |
| `components/logo.css` | `.logo` lockup + `.logo__mark` / `__bracket` / `__dot` / `__word`, sizes `xs–xl`, variants `mark-only` / `stacked` / `inverse` / `mono`, `.logo-tile` app icon |
| `components/themes.css` | `data-theme="petrol"`, `data-theme="terminal"`, `data-accent="amber"`, `.surface` / `.surface--brand` / `.surface--terminal` |
| `components/buttons.css` | `.btn--signal`, `.btn--terminal`, `.btn--inverse`, `.btn--squared`, `.btn--block`, `.btn-group` |

### The logo

Two brackets enclosing a signal dot — the reviewed target, scoped. Drawn in
CSS from borders and a circle (no SVG, no image asset), so it inherits
`currentColor` and scales from one custom property:

```html
<a class="logo logo--md" href="/">
  <span class="logo__mark" aria-hidden="true">
    <i class="logo__bracket logo__bracket--left"></i>
    <i class="logo__dot"></i>
    <i class="logo__bracket logo__bracket--right"></i>
  </span>
  <span class="logo__word">secfoo</span>
</a>
```

Rules: scale via `--logo-size` only; `.logo--inverse` on grounds darker than
`--color-primary-600`; clearspace ≥ ½ mark height; wordmark is Inter 600,
never another face; no tagline inside the lockup.

### Themes

```html
<html data-theme="dark">              <!-- neutral dark -->
<section data-theme="petrol">         <!-- brand-saturated dark, hero -->
<section data-theme="terminal">       <!-- CLI surface, mono body -->
<div data-accent="amber">             <!-- signal accent → amber -->
```

Themes only re-point `--color-*` / `--brand-*` role tokens — no component CSS
is duplicated per theme, so anything you build inherits them for free.

### Buttons

```html
<button class="btn btn--signal btn--lg">Run assessment</button>
<button class="btn btn--terminal btn--md">secfoo run --agent claude</button>
<button class="btn btn--inverse btn--md">View on GitHub</button>
<button class="btn btn--primary btn--squared btn--sm">Re-run</button>
```

One `--signal` button per view — it is the highest-emphasis action.
`--terminal` is for copy-the-command affordances; `--squared` for dense
product UI where pills eat horizontal space.

### Originality

The mark is original geometry drawn from scratch; no existing logo, icon set
or brand asset was traced or referenced. Trademark searches surfaced no
`Secfoo` registration (near-misses — Secoo, Secom, SECGUO — are different
words in unrelated classes). Inter and IBM Plex Mono are both SIL OFL and
free for commercial use. This is not a legal clearance opinion — run a
proper search with a trademark attorney before filing.

---

# Base design system

An original, framework-agnostic design system: design tokens (color, type,
spacing, radius, shadow, motion) plus a component library (buttons, forms,
cards, navigation, badges, alerts, tabs, tables, modal).

Open [`demo.html`](./demo.html) in a browser to see every token and
component rendered as a live style guide.

## Provenance

This system was built by studying the general visual language of a few
public B2B websites (color families, spacing rhythm, rounded "pill" button
shapes, soft shadows) as creative reference — the kind of research any
designer does by looking at sites they like. Nothing here is copied:

- All color values, spacing scale, type scale, and component CSS were
  written from scratch with original names and values.
- No third-party CSS, class names, markup, images, icons, or logos were
  reused.
- The reference sites used a commercially licensed font (Avenir LT Std);
  this system uses **Inter** (open-source, SIL license) instead — swap it
  for any font you're licensed to use.

General visual concepts like "a blue/teal palette" or "rounded buttons" are
not protectable by copyright, so this gives you a safe, original foundation.
If you want extra distance from any reference aesthetic, the easiest levers
are: change `--color-primary-*` hue, swap `--radius-pill` for a smaller
radius, and pick a different typeface.

## File structure

```
design-system/
├── tokens.css              Design tokens (colors, type, spacing, radius, shadow, motion)
├── base.css                Reset + base element styles wired to tokens
├── components/
│   ├── buttons.css
│   ├── forms.css
│   ├── cards.css
│   ├── navigation.css
│   ├── badges.css
│   ├── alerts.css
│   ├── tabs.css
│   ├── tables.css
│   └── modal.css
├── design-system.css       Single entry point that imports everything
├── demo.html                Live style guide
└── README.md
```

## Usage

Link the single entry point:

```html
<link rel="stylesheet" href="design-system/design-system.css" />
```

Or import only what you need (e.g. tokens + buttons):

```html
<link rel="stylesheet" href="design-system/tokens.css" />
<link rel="stylesheet" href="design-system/components/buttons.css" />
```

### Example: button

```html
<button class="btn btn--primary btn--lg">Get started</button>
<button class="btn btn--outline btn--md">Learn more</button>
```

### Example: card

```html
<div class="card card--interactive">
  <span class="card__eyebrow">Category</span>
  <h4 class="card__title">Title</h4>
  <p class="card__body">Description text.</p>
</div>
```

Dark mode: add `data-theme="dark"` to `<html>` or any container — the
`--color-*` role tokens (`--color-bg`, `--color-text`, etc.) repoint
automatically (see bottom of `tokens.css`).

## Porting to another format later

Since everything reads from CSS custom properties in `tokens.css`, porting
is mostly a find-and-map exercise:

- **Tailwind**: map each token into `theme.extend` in `tailwind.config.js`
  (e.g. `colors.primary[700] = '#124a60'`, `borderRadius.pill = '999px'`).
  Component classes (`.btn--primary`) become `@apply` recipes or React
  components using the mapped utility classes.
- **React/Vue component library**: turn each `components/*.css` file into a
  component + its scoped styles (CSS Modules, styled-components, vanilla-
  extract, etc.), importing `tokens.css` as the shared variable layer.
- **Figma variables / design tokens JSON**: the flat key-value shape of
  `tokens.css` maps directly to a Style Dictionary or Figma Tokens JSON
  file — one variable per custom property.
- **Native (iOS/Android)**: `tokens.css` is your naming reference; generate
  a `Colors.swift` / `colors.xml` etc. from the same hex values.

Ask me when you're ready to convert and I can generate the port directly
(Tailwind config, React components, or a tokens.json) instead of doing it
by hand.
