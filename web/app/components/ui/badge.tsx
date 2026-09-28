import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "preact";

import { cn } from "@/lib/cn";

/** A status chip.
 *
 * The four tones are the badge tokens the VanJS stylesheet carried; each text
 * token clears 4.5:1 on its own tinted fill. `tone="none"` is the neutral chip
 * (counts, labels) and reads `--meta-item-*`. */
const badgeVariants = cva(
  "inline-flex items-center rounded-pill border px-1.5 py-0.5 font-mono text-[11px] leading-tight",
  {
    variants: {
      tone: {
        none: "border-meta-border bg-meta text-muted",
        exact: "border-badge-exact-border bg-badge-exact-bg text-badge-exact-text",
        reloc: "border-badge-reloc-border bg-badge-reloc-bg text-badge-reloc-text",
        near: "border-badge-near-border bg-badge-near-bg text-badge-near-text",
        stub: "border-badge-stub-border bg-badge-stub-bg text-badge-stub-text",
      },
    },
    defaultVariants: { tone: "none" },
  },
);

export type BadgeProps = ComponentProps<"span"> & VariantProps<typeof badgeVariants>;

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
