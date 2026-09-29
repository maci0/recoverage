import type { ComponentChildren } from "preact";

/** The two-column metadata grid the detail panel and the data inspector draw. */
export const META_GRID = "meta-grid grid grid-cols-2 gap-x-4 gap-y-2 text-micro";

/** One label/value row inside a `META_GRID` list.
 *
 * The label is a word, so it is set in the sans; the value is data (an
 * address, a symbol, a size), so it is set in the mono.
 *
 * The value cell is `dir="auto"` because most of what lands in it is a value
 * out of a coverage document: a symbol, a module, a Ghidra name, an analyst's
 * blocker's prose. Those are ASCII for most targets and anything else for the
 * rest, and a base direction of the page's own reorders an Arabic or Hebrew
 * value against the cell edge. `auto` reads the value's own first strong
 * character, so an ASCII value is laid out exactly as it was. */
export function MetaItem({
  label,
  children,
  fullWidth,
}: {
  label: string;
  children: ComponentChildren;
  fullWidth?: boolean;
}): ComponentChildren {
  return (
    <div
      className={
        fullWidth === true ? "meta-item col-span-2 flex flex-col gap-0.5" : "meta-item flex min-w-0 flex-col gap-0.5"
      }
    >
      <dt className="meta-label text-text-muted">{label}</dt>
      <dd className="meta-value m-0 min-w-0 font-mono text-text wrap-anywhere" dir="auto">
        {children}
      </dd>
    </div>
  );
}
