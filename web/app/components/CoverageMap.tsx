import type { JSX } from "preact";
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "preact/compat";

import type { Section } from "@/api";
import {
  DEFAULT_GRID_COLUMNS,
  MAX_GRID_COLUMNS,
  PALETTE_VARS,
  STATE_LABEL,
  hitTest,
  layoutSection,
  packSection,
  survivesFilter,
  type Geometry,
  type Packed,
} from "@/grid/pack";
import { hex, isolate } from "@/lib/format";

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
  accent: string;
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
  const hintId = `grid-hint-${section.name.replaceAll(".", "")}`;
  // What the roving cursor is on, as text. A canvas has no accessible
  // children, so this is the only thing a screen reader can read about the
  // cell the arrow keys walked to (WCAG 4.1.2, 1.1.1).
  const [cursor, setCursor] = useState<string>("");

  // The pack is keyed on the section object, exactly like the VanJS memo: a
  // rebuild hands a fresh section object, and lazy cell loads replace it, so
  // identity is "the cells changed" and a stale hit map cannot survive it.
  const pack = useMemo(() => packSection(section), [section]);

  const describe = useCallback(
    (index: number): string => {
      if (index < 0 || index >= pack.n) {
        return "";
      }
      const base = section.va ?? 0;
      const name = pack.fns[index];
      return [
        `Block ${index}`,
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
        const dpr = Math.min(2, window.devicePixelRatio || 1);
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
      // One getComputedStyle for all eight variables: each call returns a live
      // declaration, and reading a property off a fresh one re-flushes style.
      const computed = getComputedStyle(wrap);
      state.palette = PALETTE_VARS.map((name) => computed.getPropertyValue(name).trim());
      state.accent = computed.getPropertyValue("--c").trim();
    }
    const { cell } = geo;
    const { states, ground, fns, n } = pack;
    const { pCell, pX, pY, pW, parts } = geo;
    const filtering = filters.size > 0;
    const isDim = (index: number): boolean =>
      (filtering && !survivesFilter(states[index] ?? 0, ground[index] ?? 0, filters)) ||
      (matchedFns !== null && !matchedFns.has(fns[index] ?? ""));
    ctx.clearRect(0, 0, geo.width, geo.height);
    for (let pass = 0; pass < 2; pass += 1) {
      ctx.globalAlpha = pass === 0 ? 1 : 0.15;
      for (let slot = 0; slot < state.palette.length; slot += 1) {
        ctx.fillStyle = state.palette[slot] || state.palette[0] || "";
        ctx.beginPath();
        for (let k = 0; k < parts; k += 1) {
          const index = pCell[k] ?? -1;
          if (states[index] !== slot || (pass === 0) === isDim(index)) {
            continue;
          }
          ctx.rect(pX[k] ?? 0, pY[k] ?? 0, pW[k] ?? 0, cell);
        }
        ctx.fill();
      }
    }
    ctx.globalAlpha = 1;
    const stroke = (index: number, dashed: boolean): void => {
      ctx.strokeStyle = state.accent;
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
  }, [activeFn, filters, geometry, matchedFns, pack, selectedIndex]);

  // Rebuild the state on section change, then paint on every input change.
  useLayoutEffect(() => {
    stateRef.current = {
      pack,
      geometry: null,
      layWidth: -1,
      layCols: declaredColumns,
      palette: [],
      accent: "",
      focus: 0,
    };
    geometry(true);
    paint();
  }, [declaredColumns, geometry, pack, paint, section]);

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
    <div
      ref={wrapRef}
      // The `.grid` hook and `data-cols` are what the map and the browser
      // specs query; `id` is what a jump to an address scrolls.
      className="grid max-w-full overflow-x-auto rounded-hair border border-line bg-grid"
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
      <canvas ref={canvasRef} className="grid-canvas block" aria-hidden="true" />
      <p id={hintId} className="sr-only">
        Arrow keys move between blocks, Home and End jump to the first and last, Enter or Space
        selects the block under the cursor.
      </p>
      <p className="sr-only" role="status" aria-live="polite">
        {cursor}
      </p>
    </div>
  );
}
