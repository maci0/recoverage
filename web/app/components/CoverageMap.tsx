import type { JSX } from "preact";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "preact/compat";

import type { Section } from "@/api";
import {
  DEFAULT_GRID_COLUMNS,
  MAX_GRID_COLUMNS,
  hitTest,
  layoutSection,
  packSection,
  type Geometry,
  type Packed,
} from "@/grid/pack";
import { count, foldCellName, hex, isolate } from "@/lib/format";
import { MARK_CLASS, PALETTE_VARS, STATE_LABEL, dimSummary, isDimmed, type Mark } from "@/states";

/** The roving tab stop's next cell for a key, or null when the key is not a
 * navigation key. Home and End are the lattice's own ends. */
function stepFor(key: string, index: number, cols: number, last: number): number | null {
  switch (key) {
    case "ArrowRight": {
      return index + 1;
    }
    case "ArrowLeft": {
      return index - 1;
    }
    case "ArrowDown": {
      return index + cols;
    }
    case "ArrowUp": {
      return index - cols;
    }
    case "Home": {
      return 0;
    }
    case "End": {
      return last;
    }
    default: {
      return null;
    }
  }
}

/** A colour token as the canvas can use it. The tokens are `light-dark()`
 * pairs, and the build may rewrite those into variables that only resolve on
 * a property, so the raw custom property is not a colour a 2D context parses.
 * Set on the probe's `color`, the browser resolves it for the current theme
 * and hands back `rgb()`. */
function resolveColour(probe: HTMLElement, token: string): string {
  probe.style.color = `var(${token})`;
  return getComputedStyle(probe).color;
}

/** Device pixels per CSS pixel the canvas is drawn at, capped so a 3x screen
 * does not triple the backing store of a 39k-cell map. */
const MAX_CANVAS_SCALE = 2;

function canvasScale(): number {
  return Math.min(MAX_CANVAS_SCALE, window.devicePixelRatio || 1);
}

/** The mark tile, in CSS px: the `mark-*` utilities in index.css draw the
 * same 1px ink on the same tile. */
const MARK_TILE_PX = 4;
const MARK_DOT_RADIUS_PX = 0.75;

/** A verdict mark as a repeating canvas pattern in `ink`, or null for a slot
 * with no mark. The tile is drawn at the canvas scale and mapped back, so the
 * 1px lines stay sharp on a 2x screen. */
function markPattern(ctx: CanvasRenderingContext2D, mark: Mark, ink: string): CanvasPattern | null {
  if (mark === "") {
    return null;
  }
  const scale = canvasScale();
  const tile = document.createElement("canvas");
  tile.width = Math.round(MARK_TILE_PX * scale);
  tile.height = tile.width;
  const pen = tile.getContext("2d");
  if (pen === null) {
    return null;
  }
  pen.scale(scale, scale);
  pen.fillStyle = ink;
  pen.strokeStyle = ink;
  pen.lineWidth = 1;
  if (mark === "mark-dots") {
    pen.beginPath();
    pen.arc(MARK_TILE_PX / 2, MARK_TILE_PX / 2, MARK_DOT_RADIUS_PX, 0, Math.PI * 2);
    pen.fill();
  } else if (mark === "mark-rule") {
    pen.fillRect(0, 0, MARK_TILE_PX, 1);
  } else {
    pen.beginPath();
    for (const offset of [-MARK_TILE_PX, 0, MARK_TILE_PX]) {
      pen.moveTo(offset, MARK_TILE_PX);
      pen.lineTo(offset + MARK_TILE_PX, 0);
    }
    pen.stroke();
  }
  const pattern = ctx.createPattern(tile, "repeat");
  pattern?.setTransform(new DOMMatrix().scale(1 / scale));
  return pattern;
}

/** One section's coverage map.
 *
 * A canvas, not one element per cell: 39k cells is a page that cannot be
 * scrolled. The port keeps the VanJS code's shape — packed columns, a layout
 * memo keyed on the packed cells and the wrapper's width, one path per state
 * per alpha pass, and a hit test against the canvas — because every part of it
 * was measured against a real target. What React changes is where the state
 * lives: the roving focus, the selection and the filters arrive as props, and
 * the geometry lives in a ref because nothing renders from it. */

export type CoverageMapProps = {
  section: Section;
  filters: ReadonlySet<string>;
  /** The function names and VA spellings a live search matched, or null when
   * no search is active. */
  matchedFns: ReadonlySet<string | number> | null;
  selectedIndex: number | null;
  /** The selected cell's function, outlined on the map. */
  activeFn: string | number | null;
  theme: "dark" | "light";
  onSelect: (index: number) => void;
  /** Replaced by the component: jumps the roving tab stop and scrolls to a
   * cell (search Enter, an asm link, an arrow-key walk). */
  onGridReady?: (focusCell: (index: number) => void) => void;
};

type GridState = {
  pack: Packed;
  geometry: Geometry | null;
  layWidth: number;
  layCols: number;
  palette: Array<string>;
  marks: Array<CanvasPattern | null>;
  accent: string;
  ink: string;
  focus: number;
};

export function CoverageMap({
  section,
  filters,
  matchedFns,
  selectedIndex,
  activeFn,
  theme,
  onSelect,
  onGridReady,
}: CoverageMapProps) {
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const stateRef = useRef<GridState | null>(null);
  const probeRef = useRef<HTMLSpanElement | null>(null);
  const hintId = `grid-hint-${section.name.replaceAll(".", "")}`;
  // What the roving cursor is on, as text. A canvas has no accessible
  // children, so this is the only thing a screen reader can read about the
  // cell the arrow keys walked to (WCAG 4.1.2, 1.1.1).
  const [cursor, setCursor] = useState<string>("");
  // Whether the lattice is wider than its card. A section never draws fewer
  // columns than it declares, so on a phone most of the map sits past the
  // right edge of a card that shows no scrollbar until it is touched, and a
  // reader took the visible third for the whole section.
  const [overflows, setOverflows] = useState(false);

  // The pack is keyed on the section object, exactly like the VanJS memo: a
  // rebuild hands a fresh section object, and lazy cell loads replace it, so
  // identity is "the cells changed" and a stale hit map cannot survive it.
  const pack = useMemo(() => packSection(section), [section]);

  // The packed names, folded into the form `matchedFns` holds, so the paint
  // loop's membership test is one form compared one way. Built here rather
  // than in `isDim`: a cell's `functions[0]` is the RAW document spelling, the
  // match set is the FOLDED one the search produced, and the two spellings of
  // one name are different strings (an NFD symbol against an NFC row, or two
  // rows of one build that disagree). Folding per cell per frame would put
  // `normalize` on the hot path of every repaint; folding once per pack costs
  // one pass when the cells or the search change and nothing between.
  const isMatched = useMemo(() => {
    if (matchedFns === null) {
      return null;
    }
    const hit = new Uint8Array(pack.n);
    for (let i = 0; i < pack.n; i += 1) {
      const name = pack.fns[i];
      if (matchedFns.has(foldCellName(name))) {
        hit[i] = 1;
      }
    }
    return hit;
  }, [matchedFns, pack]);

  /** How many blocks the lattice is still showing at full strength.
   *
   * A filter or a search that leaves nothing lit painted an empty map that read as
   * "this section is empty", and the only way back was finding the "All states"
   * pill or the search box's Clear by eye. Counting here rather than in the
   * caller is what makes the figure honest: it walks the same columns the paint
   * walks, through the same `isDimmed`, so the number and the picture cannot
   * disagree. */
  // One byte per cell, built when the filter or the search changes. `paint`
  // walks every placement twice per palette slot, and calling `isDimmed` there
  // re-asked the same question 640k times on a 40k-cell section (p50 0.87 ms
  // against 0.12 ms for the byte read, bun, 21 runs). The caption counts the
  // same column, so the sentence and the lattice still cannot disagree.
  const dimmed = useMemo(() => {
    const column = new Uint8Array(pack.n);
    const searching = isMatched !== null;
    for (let i = 0; i < pack.n; i += 1) {
      if (isDimmed(pack.states[i] ?? 0, pack.ground[i] ?? 0, isMatched?.[i] === 1, filters, searching)) {
        column[i] = 1;
      }
    }
    return column;
  }, [filters, isMatched, pack]);

  // `ground` counts the lit blocks that are undocumented, so the caption can
  // say which of them a status filter left lit without matching it.
  const visible = useMemo(() => {
    let lit = 0;
    let ground = 0;
    for (const [index, byte] of dimmed.entries()) {
      if (byte === 0) {
        lit += 1;
        ground += pack.ground[index] ?? 0;
      }
    }
    return { lit, ground, total: dimmed.length };
  }, [dimmed, pack]);

  // The caption under the lattice, or null when nothing is dimming it. Derived
  // from the same count, so the sentence and the paint are one thing.
  const summary = useMemo(
    () => dimSummary(visible.lit, visible.total, visible.ground, filters, matchedFns !== null),
    [filters, matchedFns, visible],
  );
  const describe = useCallback(
    (index: number): string => {
      if (index < 0 || index >= pack.n) {
        return "";
      }
      const base = section.va ?? 0;
      const name = pack.fns[index];
      return [
        `Block ${count(index)}`,
        `${hex(base + (pack.starts[index] ?? 0), 8)} to ${hex(base + (pack.ends[index] ?? 0), 8)}`,
        STATE_LABEL[pack.states[index] ?? 0],
        name === "" ? "no function" : isolate(String(name)),
      ].join(", ");
    },
    [pack, section.va],
  );

  // The same upper bound Potato Mode applies (potato._MAX_GRID_COLUMNS), for
  // the same reason: `columns` reaches the reader as a plain int with no ceiling
  // (rebrew.coverage_toml._section), and `layoutSection` sizes a
  // `new Int32Array(rows * cols)` from it, so a document declaring 1e9 columns
  // asks the renderer for gigabytes and leaves the map blank. Potato rendered
  // the same document fine, so the two surfaces disagreed.
  const declaredColumns = Math.min(
    section.columns === 0 ? DEFAULT_GRID_COLUMNS : (section.columns ?? DEFAULT_GRID_COLUMNS),
    MAX_GRID_COLUMNS,
  );

  const geometry = useCallback(
    (force: boolean): Geometry | null => {
      const wrap = wrapRef.current;
      const state = stateRef.current;
      if (wrap === null || state === null) {
        return null;
      }
      const width = wrap.clientWidth;
      if (!force && state.geometry !== null && state.pack === pack && state.layWidth === width) {
        return state.geometry;
      }
      const next = layoutSection(pack, width, declaredColumns, window.innerWidth);
      state.geometry = next;
      state.pack = pack;
      state.layWidth = width;
      state.layCols = declaredColumns;
      const canvas = canvasRef.current;
      if (canvas !== null) {
        canvas.style.width = `${next.width}px`;
        canvas.style.height = `${next.height}px`;
        const dpr = canvasScale();
        canvas.width = Math.max(1, Math.round(next.width * dpr));
        canvas.height = Math.max(1, Math.round(next.height * dpr));
        canvas.getContext("2d")?.setTransform(dpr, 0, 0, dpr, 0, 0);
      }
      return next;
    },
    [declaredColumns, pack],
  );

  /** One paint: opaque cells first, dimmed ones in a second alpha pass, then
   * the selection and focus strokes. */
  const paint = useCallback(() => {
    const wrap = wrapRef.current;
    const canvas = canvasRef.current;
    const state = stateRef.current;
    if (wrap === null || canvas === null || state === null) {
      return;
    }
    const geo = geometry(false);
    if (geo === null) {
      return;
    }
    const ctx = canvas.getContext("2d");
    if (ctx === null) {
      return;
    }
    if (state.palette.length === 0) {
      const probe = probeRef.current;
      if (probe === null) {
        return;
      }
      state.palette = PALETTE_VARS.map((name) => resolveColour(probe, name));
      state.accent = resolveColour(probe, "--color-accent");
      state.ink = resolveColour(probe, "--color-text");
      // Padding is filler, so its rule is drawn in the muted ink, which still
      // clears 3:1 on the hairline fill; the verdict marks take the full ink.
      const muted = resolveColour(probe, "--color-text-muted");
      const { ink } = state;
      state.marks = MARK_CLASS.map((mark) => markPattern(ctx, mark, mark === "mark-rule" ? muted : ink));
    }
    const { cell } = geo;
    const { states, fns, n } = pack;
    const { pCell, pX, pY, pW, parts } = geo;
    // `dimmed` is the one answer `isDimmed` gave for this filter and search.
    // Reading it here keeps the paint and the caption on that one pass.
    ctx.clearRect(0, 0, geo.width, geo.height);
    for (let pass = 0; pass < 2; pass += 1) {
      ctx.globalAlpha = pass === 0 ? 1 : 0.15;
      for (let slot = 0; slot < state.palette.length; slot += 1) {
        ctx.fillStyle = state.palette[slot] || state.palette[0] || "";
        ctx.beginPath();
        let rects = 0;
        for (let k = 0; k < parts; k += 1) {
          const index = pCell[k] ?? -1;
          if (states[index] !== slot || (pass === 0) === (dimmed[index] === 1)) {
            continue;
          }
          rects += 1;
          ctx.rect(pX[k] ?? 0, pY[k] ?? 0, pW[k] ?? 0, cell);
        }
        if (rects === 0) {
          continue;
        }
        ctx.fill();
        const mark = state.marks[slot] ?? null;
        if (mark !== null) {
          ctx.fillStyle = mark;
          ctx.fill();
        }
      }
    }
    ctx.globalAlpha = 1;
    // The selection is drawn in ink, the roving focus in the accent: the
    // accent is the focus colour everywhere else on the page.
    const stroke = (index: number, dashed: boolean): void => {
      ctx.strokeStyle = dashed ? state.accent : state.ink;
      ctx.lineWidth = dashed ? 1 : 2;
      ctx.setLineDash(dashed ? [2, 2] : []);
      for (let k = geo.cellFirst[index] ?? -1; k >= 0 && k < parts && pCell[k] === index; k += 1) {
        ctx.strokeRect((pX[k] ?? 0) + 0.5, (pY[k] ?? 0) + 0.5, (pW[k] ?? 0) - 1, cell - 1);
      }
      ctx.setLineDash([]);
    };
    if (selectedIndex !== null && selectedIndex >= 0 && selectedIndex < n) {
      stroke(selectedIndex, false);
    } else if (activeFn !== null) {
      for (let i = 0; i < n; i += 1) {
        if (fns[i] === activeFn) {
          stroke(i, false);
          break;
        }
      }
    }
    if (
      document.activeElement === wrap &&
      state.focus >= 0 &&
      state.focus < n &&
      state.focus !== selectedIndex
    ) {
      stroke(state.focus, true);
    }
  }, [activeFn, dimmed, geometry, pack, selectedIndex]);

  // Rebuild the state on section change, then paint on every input change.
  //
  // The deps are `geometry` and `pack` alone, and both are section tokens
  // (`geometry` is keyed on exactly those two). `paint` is NOT one of them: it
  // is a function of the selection, the filters and the match set, so listing
  // it re-ran this teardown on every click and every search keystroke, and the
  // state it rebuilt starts at `focus: 0`. The roving cursor therefore jumped
  // back to the first block on the render the click that moved it caused, and
  // the arrow keys walked from there. Repainting on those changes is the
  // effect below's job, and it does not need the state rebuilt to do it.
  useLayoutEffect(() => {
    stateRef.current = {
      pack,
      geometry: null,
      layWidth: -1,
      layCols: declaredColumns,
      palette: [],
      marks: [],
      accent: "",
      ink: "",
      focus: 0,
    };
    geometry(true);
    paint();
    // `paint` is called for its side effect on the section that was just
    // rebuilt, and the effect below repaints on every change of its own.
  }, [declaredColumns, geometry, pack]);

  // A theme switch changes the tokens, not the geometry. `paint` is also a
  // function of the filters, the match set and the selection, so this is the
  // one effect that repaints on every change of those too.
  useEffect(() => {
    if (stateRef.current !== null) {
      stateRef.current.palette = [];
    }
    paint();
  }, [paint, theme]);

  const scrollCell = useCallback((index: number) => {
    const wrap = wrapRef.current;
    const state = stateRef.current;
    if (wrap === null || state?.geometry == null) {
      return;
    }
    // Every cursor move scrolls the page, so the animation is motion the user
    // did not ask for and cannot switch off per move: `prefers-reduced-motion`
    // is the one place that answers it (WCAG 2.3.3).
    const smooth = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches !== true;
    const geo = state.geometry;
    const y = geo.pad + (geo.cellRow[index] ?? 0) * (geo.cell + geo.gap);
    const top = wrap.getBoundingClientRect().top + window.scrollY + y;
    window.scrollTo({
      top: Math.max(0, top - window.innerHeight / 3),
      behavior: smooth ? "smooth" : "auto",
    });
    // Vertically the lattice is as tall as the page, so the window is the
    // scrollport; horizontally it is the wrapper, which on a narrow viewport is
    // narrower than the lattice.
    const x = geo.cellX[index] ?? 0;
    const right = x + (geo.cellW[index] ?? 0);
    if (x < wrap.scrollLeft || right > wrap.scrollLeft + wrap.clientWidth) {
      wrap.scrollTo({
        left: Math.max(0, x - wrap.clientWidth / 3),
        behavior: smooth ? "smooth" : "auto",
      });
    }
  }, []);

  useEffect(() => {
    onGridReady?.((index) => {
      const state = stateRef.current;
      if (state === null) {
        return;
      }
      state.focus = index;
      const wrap = wrapRef.current;
      if (wrap !== null && wrap.contains(document.activeElement)) {
        wrap.focus();
      }
      setCursor(describe(index));
      paint();
      scrollCell(index);
    });
  }, [describe, onGridReady, paint, scrollCell]);

  useEffect(() => {
    const wrap = wrapRef.current;
    if (wrap === null) {
      return;
    }
    const observer = new ResizeObserver(() => {
      geometry(true);
      paint();
      setOverflows(wrap.scrollWidth > wrap.clientWidth);
    });
    observer.observe(wrap);
    return () => observer.disconnect();
  }, [geometry, paint]);

  const onPointer = (clientX: number, clientY: number, select: boolean): void => {
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    const state = stateRef.current;
    if (canvas === null || wrap === null || state === null) {
      return;
    }
    const rect = canvas.getBoundingClientRect();
    // The dim caption lives inside this same region so it travels with the map
    // it describes, which makes a click on it a click on the region. Its box is
    // outside the canvas' own, so hit-testing it as canvas coordinates is what
    // would select whatever block happened to sit under the text; the same test
    // covers the horizontal scroll the wrapper allows.
    if (
      clientY < rect.top ||
      clientY > rect.bottom ||
      clientX < rect.left ||
      clientX > rect.right
    ) {
      wrap.title = "";
      wrap.style.cursor = "default";
      return;
    }
    const index = hitTest(state.geometry, clientX - rect.left, clientY - rect.top);
    if (index < 0) {
      wrap.title = "";
      wrap.style.cursor = "default";
      return;
    }
    if (!select) {
      wrap.style.cursor = "pointer";
      wrap.title = describe(index);
      return;
    }
    state.focus = index;
    onSelect(index);
    wrap.focus();
    setCursor(`${describe(index)}, selected`);
    paint();
  };

  const onKeyDown = (event: JSX.TargetedKeyboardEvent<HTMLDivElement>): void => {
    if (event.ctrlKey || event.metaKey || event.altKey) {
      return;
    }
    const state = stateRef.current;
    if (state === null) {
      return;
    }
    const last = pack.n - 1;
    if (last < 0) {
      return;
    }
    const cols = state.geometry?.cols ?? state.layCols;
    const index = state.focus;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(index);
      setCursor(`${describe(index)}, selected`);
      paint();
      return;
    }
    if (event.key === "Escape") {
      // The way out of everything else on this page: the search box clears on
      // it, and so does a block that is open. Escape did nothing here, so the
      // detail panel could only be left by switching section or target.
      if (selectedIndex === null) {
        return;
      }
      event.preventDefault();
      // `onSelect` is the toggle the click path uses, so this closes the block
      // that is open rather than selecting the cursor's, which an arrow-key
      // walk may have moved off. The status names the block that closed, not
      // the one the cursor is resting on, which is not that block.
      onSelect(selectedIndex);
      setCursor(`${describe(selectedIndex)}, selection cleared`);
      paint();
      return;
    }
    const target = stepFor(event.key, index, cols, last);
    if (target === null) {
      return;
    }
    event.preventDefault();
    state.focus = Math.max(0, Math.min(last, target));
    wrapRef.current?.focus();
    setCursor(describe(state.focus));
    paint();
    scrollCell(state.focus);
  };

  return (
    <>
      <div
        ref={wrapRef}
        // The `.grid` hook and `data-cols` are what the map and the browser
        // specs query; `id` is what a jump to an address scrolls.
        // The map and the detail panel beside it are both cards, so they share
        // the card corner and the hairline; two boxes in one row with different
        // corners read as two layouts.
        className="grid max-w-full overflow-x-auto rounded-card border border-border bg-surface"
        id={`grid-${section.name.replaceAll(".", "")}`}
        data-cols={declaredColumns}
        // A canvas carries no accessible children, so this is an application
        // region with a roving cursor rather than the listbox it used to claim:
        // a listbox with no options announces an empty widget and nothing about
        // the cell the arrow keys are on. The status paragraph below is the
        // value, the hint paragraph is how to move it.
        role="application"
        aria-label={`${isolate(section.name)} coverage map`}
        aria-describedby={hintId}
        tabIndex={0}
        onPointerMove={(event) => onPointer(event.clientX, event.clientY, false)}
        onPointerLeave={() => {
          const wrap = wrapRef.current;
          if (wrap !== null) {
            wrap.title = "";
            wrap.style.cursor = "default";
          }
        }}
        onClick={(event) => onPointer(event.clientX, event.clientY, true)}
        onKeyDown={onKeyDown}
      >
        <span ref={probeRef} className="hidden" aria-hidden="true" />
        <canvas ref={canvasRef} className="grid-canvas block" aria-hidden="true" />
        {/* Shown only while something is dimming the lattice, so the ordinary
            read of a full map is unchanged. A filter or a search naming states
            this section does not hold leaves nothing lit, and the map then reads
            as "this section is empty" rather than as "your filter excludes
            everything here"; this line says which rule did it, what it left and
            what undoes it. */}
        {summary !== null && (
          <p className="border-t border-border px-3 py-2 text-micro text-text-muted">{summary}</p>
        )}
        <p id={hintId} className="sr-only">
          Arrow keys move between blocks, Home and End jump to the first and last, Enter or Space
          selects the block under the cursor, Escape closes the block that is open.
        </p>
        <p className="sr-only" role="status" aria-live="polite">
          {cursor}
        </p>
      </div>
      {overflows && (
        <p className="m-0 mt-2 text-micro text-text-muted">
          The map is wider than the screen; swipe it sideways for the rest of the section.
        </p>
      )}
    </>
  );
}
