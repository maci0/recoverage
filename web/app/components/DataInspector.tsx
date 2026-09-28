import type { InspectorItem } from "@/lib/bytes";

import type { ComponentChildren } from "preact";import { MSG } from "@/lib/format";

/** The little-endian readings of a .data or .bss block's first bytes, which is
 * what a data section has instead of disassembly. */
export function DataInspector({ items }: { items: Array<InspectorItem> | null }): ComponentChildren {
  if (items === null || items.length === 0) {
    return <div className="code rounded-hair border border-line bg-code p-3 text-muted">{MSG.BYTES_BSS}</div>;
  }
  return (
    <dl className="meta-grid inspector-grid grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-xs">
      {items.map((item) => (
        <div
          key={item.label}
          className={item.fullWidth === true ? "meta-item col-span-2 flex gap-2" : "meta-item flex gap-2"}
        >
          <dt className="meta-label text-muted">{item.label}</dt>
          <dd className={item.fullWidth === true ? "meta-value wrap-anywhere" : "meta-value"}>
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
