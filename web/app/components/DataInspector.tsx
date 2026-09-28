import type { ComponentChildren } from "preact";

import type { InspectorItem } from "@/lib/bytes";
import { MSG } from "@/lib/format";
import { META_GRID, MetaItem } from "@/components/ui/meta";

/** The readings as the text every other pane hands to Copy and Open. One
 * spelling, so what a reader pastes is what the pane shows. */
export function inspectorText(items: Array<InspectorItem> | null): string {
  return (items ?? []).map((item) => `${item.label}: ${item.value}`).join("\n");
}

/** The little-endian readings of a .data or .bss block's first bytes, which is
 * what a data section has instead of disassembly. */
export function DataInspector({ items }: { items: Array<InspectorItem> | null }): ComponentChildren {
  if (items === null || items.length === 0) {
    return <div className="code rounded-hair border border-line bg-code p-3 text-muted">{MSG.BYTES_BSS}</div>;
  }
  return (
    <dl className={META_GRID}>
      {items.map((item) => (
        <MetaItem
          key={item.label}
          label={item.label}
          {...(item.fullWidth === true ? { fullWidth: true } : {})}
        >
          {item.value}
        </MetaItem>
      ))}
    </dl>
  );
}
