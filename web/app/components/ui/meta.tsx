import type { ComponentChildren } from "preact";

/** The two-column metadata grid the detail panel and the data inspector draw. */
export const META_GRID =
  "meta-grid grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-label";

/** One label/value row inside a `META_GRID` list.
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
    <div className={fullWidth === true ? "meta-item col-span-2 flex gap-2" : "meta-item flex gap-2"}>
      <dt className="meta-label text-muted">{label}</dt>
      <dd className="meta-value wrap-anywhere" dir="auto">
        {children}
      </dd>
    </div>
  );
}
