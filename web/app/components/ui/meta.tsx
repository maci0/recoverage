import type { ComponentChildren } from "preact";

/** The two-column metadata grid the detail panel and the data inspector draw. */
export const META_GRID =
  "meta-grid grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-label";

/** One label/value row inside a `META_GRID` list. */
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
      <dd className="meta-value wrap-anywhere">{children}</dd>
    </div>
  );
}
