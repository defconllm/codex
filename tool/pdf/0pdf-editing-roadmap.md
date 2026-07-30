# 0pdf — Editing Roadmap: forms, documents, new pages, layout & data

A deep plan for evolving the tool from a *page-management + line-edit + form-fill + sanitize*
utility into a genuine PDF **authoring** tool — while keeping its security-first identity.

---

## 1. Guiding principles

1. **Additive content stays vector; only touching existing glyphs may rasterize.** Adding a text box,
   image, shape, table, or new page can be composited as real PDF vector content on top of the
   original — selectable, searchable, tiny. Rasterizing (today's bake) should be reserved for editing
   *existing* text or for redaction, not for adding content.
2. **One canonical coordinate space.** Everything the user manipulates lives in *page points, origin
   top-left* (the space the editor already thinks in). Convert to PDF bottom-left only at render time.
   Nail this down before building object manipulation.
3. **Security posture is preserved.** Added content carries no scripts/actions; redaction options stay;
   export sanitization still runs. A form the tool *builds* must be inert (no JS field actions).
4. **Everything the user adds must reach the LLM outputs.** Text boxes, tables, and field values flow
   into the Markdown/JSON reconstruction in reading order — "layout and data" that stays machine-readable.
5. **Reversibility and safety.** A real editor needs undo/redo across *all* edit types and non-
   destructive editing (the source page is never mutated; edits are a layer).

---

## 2. Where we are today (honest capability map)

| Area | Have | Missing |
|---|---|---|
| Pages | rotate, delete, reorder, merge, extract | **insert/blank/new pages**, resize, crop, duplicate, split |
| Text | edit existing line text; per-line bold/italic/size/font/align; per-char bold/italic | **add new text anywhere**, reflow, move text, edit rotated pages, per-run size/color |
| Images | — | **add/place/resize images**, signatures-as-image |
| Vector markup | — | **shapes, lines, arrows, highlights, checkmarks, freehand/ink, stamps** |
| Forms | **fill** fields, save-filled (incremental), flatten | **create/edit fields**, field properties, better fill UX |
| Tables/data | detect tables for extraction | **insert/edit tables**, CSV/data import |
| Export | vector (page ops), searchable-image bake (edits), secure/lockdown | vector composite for added content |
| Reconstruction | Markdown/JSON w/ headings, lists, tables, bold | must ingest added objects |
| Editor infra | page-level undo only | **object selection/drag/resize UI, undo-redo for edits, copy/paste, snapping** |

Today a page is `{id, docId, srcIndex, rotation, selected, edited?, el}` — a pointer into a source
document. There is no object layer. Editing existing text works by white-out + redraw baked into a
raster (`drawEditOverlay` → `_bakeEditedPage`).

---

## 3. Users and the jobs they need done

- **Form filler** — type into fields; **type where there is no field** (overlay text); check boxes,
  add a date, sign; save filled (editable) or flatten (locked).
- **Document editor** — fix wording/formatting; **add a bullet/paragraph**; remove a section;
  **add a page**; insert a table; add header/footer/page numbers.
- **Redactor** — *truly remove* text/areas (not just cover), strip pages & metadata. (Mostly covered.)
- **Assembler** — merge, reorder, extract, **insert a blank/cover page**, split. (Mostly covered.)
- **Reviewer/annotator** — highlight, comment, strike-through, draw, stamp, sign.
- **Form builder** — add text/checkbox/radio/dropdown/signature fields with properties.
- **Data/LLM user** — clean, structured Markdown/JSON including any added tables and field values.

The request centers on **forms + docs + new pages + layout + data** → filler, editor, form-builder,
and data user. The plan covers the full spectrum but weights those.

---

## 4. The core architectural move: the page **object layer**

Introduce a per-page overlay of user objects. This single change unlocks most of the roadmap.

```
Page {
  source: { docId, srcIndex } | null   // null ⇒ a NEW/blank page
  rotation, mediaBox                    // mediaBox chosen for new pages (Letter/A4/…)
  template?: 'blank'|'lined'|'grid'|'dotted'
  edits?: [...]                          // existing-glyph edits (migrates into objects, §7 P5)
  objects: Object[]                      // NEW layer, z-ordered
}

Object {
  id, type, x, y, w, h, rotation, z, locked
  // type-specific:
  //  textbox:   text, runs[], fontSize, fam, bold, italic, align, color, lineHeight, autosize
  //  image:     data (bytes), mime, opacity
  //  shape:     kind('rect'|'line'|'arrow'|'ellipse'|'polyline'|'ink'|'highlight'|'check'),
  //             points[], stroke, fill, lineWidth, opacity, dashed
  //  field:     fieldType('text'|'checkbox'|'radio'|'dropdown'|'listbox'|'signature'),
  //             name, value, options[], required, readOnly, fontSize, align
  //  table:     rows, cols, cells[][]{runs,align}, colWidths[], rowHeights[],
  //             headerRow, borders{...}
}
```

**Why this is the right spine:**
- Non-destructive: the source page is never modified; objects are a separate, serializable layer.
- Uniform manipulation: one selection/drag/resize/snap/z-order system serves *all* object types.
- Vector export: each object renders to real PDF content, so added content stays selectable/small.
- Reconstruction: one traversal turns objects into Markdown/JSON blocks.

---

## 5. Export model (vector-first composite)

Per page, at export:

1. **Base:**
   - `source != null` → the original page content (as today, honoring rotation, disabled layers, and
     the existing-text edit path when present).
   - `source == null` (new page) → the chosen MediaBox with the template drawn as vector.
2. **Object layer → appended vector content** on top of the base:
   - **textbox** → `BT … Tj` with a standard font (Helvetica/Times/Courier + bold/italic variants via
     WinAnsi). Real text = selectable + searchable + tiny. Word-wrap computed from box width.
   - **image** → image XObject (JPEG `DCTDecode`, or PNG→raw RGB `FlateDecode`, reusing the bake's
     lossless/JPEG chooser).
   - **shape** → vector path operators (`re`, `m/l`, Bézier `c`), stroke/fill/opacity (`gs` for alpha),
     dashes (`d`). Ink/freehand = polyline of captured points.
   - **highlight** → semi-transparent filled rect over the text (multiply-ish via low alpha).
   - **field** → AcroForm widget annotation + field dict (interactive) **or** flattened appearance.
   - **table** → cell text (as textboxes) + border lines (as shapes).
3. **Only rasterize a page when** it has *existing-glyph* edits (today's searchable-image path) or a
   redaction that must destroy pixels. Everything else stays vector.

Net: adding a paragraph, image, box, table, or whole page produces a clean vector PDF; the heavy raster
path is confined to editing original text / redaction.

---

## 6. Reconstruction / LLM integration (so "data" stays readable)

The Markdown/JSON pipeline (`getOrderedItems` → `reconMarkdown` / `cleanBlock`) must ingest objects:

- **textbox** → a block positioned by (x,y); size drives heading vs body (reuse the size+bold logic).
- **table** → a real Markdown table + JSON `{kind:'table', rows}` (already have `mdTableText`).
- **field** → JSON `{kind:'field', name, value}` and a `**name:** value` line in Markdown.
- **image** → `{kind:'image', alt?}` placeholder (+ optional alt text the user types).
- **Reading order:** merge object blocks with original-content blocks by (page, y, x); let objects
  carry an optional explicit order. New pages slot in by their page index.
- Emit structure tags so the JSON can drive RAG and the Markdown reads top-to-bottom coherently.

This closes the loop: what you lay out on the page is what an LLM sees.

---

## 7. Phased roadmap

Each phase: **feature → UX → export → data/LLM → risks**. Phases are shippable increments.

### P0 — Object-layer foundation & editor canvas *(infrastructure)*
- **Feature:** the `objects[]` model; a manipulation layer over the big-view page (select, marquee-
  select, move, resize handles, rotate handle, z-order, duplicate, delete, keyboard nudge).
- **UX:** an "Insert" toolbar (Text, Image, Shape ▾, Table, Field ▾) + a contextual **Inspector** panel
  (position/size numeric, style, lock). Snapping to margins/grid/other objects with alignment guides.
- **Export:** wire the object→vector compositor into `buildPdf` (new step after base content).
- **Data/LLM:** object→block traversal stub feeding the reconstruction.
- **Cross-cutting:** replace page-only `undoStack` with a **command/history stack** covering text,
  objects, and page ops. Add clipboard (copy/paste objects, across pages/docs).
- **Risks:** coordinate correctness (write it once, unit-test round-trips); touch-vs-mouse handles.

### P1 — Text boxes *(the single biggest unlock)*
- **Feature:** add editable text anywhere; multi-line with word-wrap; per-line and per-run bold/italic/
  size/font/align/color; auto-size or fixed box.
- **UX:** click-drag to create; type; reuse the formatting toolbar (already built) + color.
- **Export:** vector text with wrapping; standard fonts (Latin/WinAnsi); note the Unicode limit.
- **Data/LLM:** textboxes become paragraphs/headings in reading order.
- **Serves:** doc editing (add content), and **form filling on non-field areas** (type anywhere).
- **Risks:** font metrics for wrap (measure via canvas, matching the bake); Unicode beyond Latin-1
  (deferred to font embedding, P9).

### P2 — New / blank pages
- **Feature:** insert blank pages (Letter/A4/Legal/match-previous/custom) at any position; templates
  (blank/lined/grid/dotted); duplicate an existing page; page resize/crop for existing pages.
- **UX:** "＋ Page" in the grid with a size/template picker; drag to position (reuse reorder).
- **Export:** fresh MediaBox + vector template + object layer.
- **Data/LLM:** included by page index.
- **Risks:** mixed page sizes in one doc (fine for PDF); template must not fight added content.

### P3 — Images
- **Feature:** place images (drag-drop/import), move/resize/rotate/opacity/crop; use for logos, figures,
  scanned **signatures**.
- **Export:** image XObject (reuse lossless/JPEG chooser).
- **Data/LLM:** placeholder block + optional alt text.
- **Risks:** large images → size (downscale option); EXIF/orientation.

### P4 — Shapes & markup
- **Feature:** rect, line, arrow, ellipse, polyline, **freehand/ink**, **highlight**, **checkmark/X**,
  stamps (Approved/Confidential/Draft), and a **draw-your-signature** (ink) tool.
- **Export:** vector paths with stroke/fill/alpha/dash.
- **Serves:** reviewers, and **form filling** (checkmarks, signatures, circling).
- **Risks:** ink smoothing; highlight blending on colored backgrounds.

### P5 — Migrate existing line-edit into the object model *(unify + go vector)*
- **Feature:** represent an edit of existing text as *(white-out rect object + textbox object)* seeded
  from the extracted glyphs' text/size/font/weight/position. The page stays **vector** (no full-page
  raster) and edited text is selectable.
- **Redaction switch:** a per-edit/per-export flag that additionally *destroys* the covered pixels
  (raster that region) or strips the underlying text — so "cover" vs "truly remove" is explicit
  (resolving the current searchable-image trade-off cleanly).
- **Risks:** original glyphs linger under a white-out unless redaction chosen (must be surfaced);
  keep the current raster path available as the redaction-safe fallback.

### P6 — Form **builder** + better filler
- **Feature (build):** add text/checkbox/radio/dropdown/listbox/signature fields as objects with
  properties (name, default, required, read-only, max-len, format, font/size, tab order).
- **Feature (fill):** upgrade the existing `renderForms` UX — inline overlay editing on the page (not
  just a side panel), field navigation, validation, and the existing save-filled/flatten paths.
- **Export:** AcroForm widgets + field dicts (interactive) or flattened appearances; **inert only** —
  no JS actions (security).
- **Data/LLM:** fields → `{name, value}` in JSON; `**name:** value` in Markdown.
- **Risks:** AcroForm correctness (appearance streams, NeedAppearances); radio groups; tab order.

### P7 — Tables & data *(layout + data)*
- **Feature:** insert/edit tables (add/remove rows/cols, merge cells, per-cell text/align, header row,
  borders/shading); **import CSV/TSV** → formatted table; column auto-fit.
- **Export:** vector text + border lines.
- **Data/LLM:** real Markdown table + JSON rows (reuse `mdTableText`) — the standout "layout+data" combo.
- **Risks:** cell wrapping/row-height; wide tables vs page width (scale/repeat header).

### P8 — Document furniture
- **Feature:** headers/footers, **page numbers**, Bates numbering (legal), date stamps, watermarks
  (add, complementing the existing *remove*), running titles.
- **Export:** applied per-page as textbox/shape objects with page-index tokens.
- **Risks:** odd/even, first-page-different, numbering ranges.

### P9 — Fonts & Unicode
- **Feature:** embed/subset a font so non-Latin (accents beyond Latin-1, CJK, RTL) text boxes render;
  a small curated font set + "use document's font" where feasible.
- **Risks:** subsetting complexity and size; RTL/shaping are hard — scope carefully.

---

## 8. Cross-cutting systems (needed early, used everywhere)

- **History (undo/redo):** a command stack of reversible ops (add/modify/delete object, edit text, page
  ops). Replaces the page-only `undoStack`. Ctrl+Z/Y; coalesce rapid edits.
- **Selection & manipulation:** single/multi select, drag-move, 8-handle resize, rotate, z-order,
  duplicate (Ctrl+D), delete, arrow-key nudge, snapping (grid/margins/objects) + alignment guides,
  align/distribute for multi-select.
- **Inspector panel:** numeric x/y/w/h/rotation; style (font, size, color, weight, border, fill,
  opacity); field/table props; lock/hide.
- **Clipboard:** copy/cut/paste objects within/across pages and documents.
- **Coordinate & measurement:** one top-left point space; helpers for pt↔PDF and rotation; rulers/grid.
- **Fonts:** standard-14 first (metrics table for wrap), embedding later (P9).

---

## 9. Security & integrity

- Added content is inherently script-free; **created form fields carry no JS/actions**; export
  sanitization/lockdown still applies to the whole document.
- **Redaction honesty:** "cover" (vector white-out, original text remains extractable) vs "remove"
  (raster/strip) must be a clear, labeled choice — never silent (this is the lesson already applied to
  the searchable-image mode).
- Non-destructive layer + full undo protects against accidental data loss.
- Keep every JS edit's CSP script-hash workflow intact; verify the delivered file renders each time
  (diff each block's hash against the CSP, then re-verify from disk).

---

## 10. Recommended sequencing & the first concrete slice

**Order:** P0 → P1 (text boxes) → P2 (pages) → P3 (images) → P4 (markup) → P6 (forms) → P7 (tables) →
P5 (migrate line-edit) → P8 (furniture) → P9 (fonts). Rationale: build the spine, then ship the highest-
value *additive* wins (which are vector and low-risk), tackle forms/tables (the request's core), and
only then take on the riskier migration of existing-text editing and font embedding.

**First slice to build if you say go — "P0 + P1 lite":**
1. Add `objects[]` to the page model + the object→vector compositor in `buildPdf` (start with textbox
   only), with round-trip-tested coordinates.
2. A minimal canvas: click-drag to create a **text box**, type into it, move/resize with handles, wire
   the existing formatting toolbar + a color control.
3. Vector text export with word-wrap (standard fonts), and feed text boxes into the Markdown/JSON
   reconstruction.
4. Introduce the command-stack undo/redo (even if only text boxes use it at first).

That single slice makes the tool able to **add text and content to any page (and, next, to brand-new
pages)** as clean vector — the foundation everything else snaps onto.

---

### Open questions to decide before P0
- Interactive **AcroForm** output vs flatten-only? (Interactive is more useful but more surface area.)
- Font embedding appetite (drives Unicode support and file size).
- Default for editing existing text: vector white-out (selectable, original lingers) vs raster
  (redaction-safe) — which is the default, which is the opt-in?
- How much "design canvas" polish (snapping/guides/align) for v1 vs later.
