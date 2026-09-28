import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "preact";

import { cn } from "@/lib/cn";

/** The one control recipe.
 *
 * A control reads the token layer, never a literal: the ground is `--btn-bg`,
 * the border `--border`, and the active state is the accent pair the old
 * `.tab-btn.active` rule carried. `data-active` is what the browser specs and
 * the stylesheet both query, so the state is on the element rather than in a
 * class list. */
export const controlVariants = cva(
  [
    "inline-flex items-center gap-2 rounded-hair border border-line",
    "px-2.5 py-1 font-mono text-xs",
    "cursor-pointer select-none whitespace-nowrap",
    "transition-colors",
    "disabled:cursor-not-allowed disabled:opacity-50",
  ],
  {
    variants: {
      variant: {
        default: "bg-btn text-text hover:bg-btn-hover focus-visible:bg-btn-hover",
        active:
          "bg-btn-active border-btn-active-border text-btn-active-text shadow-glow-active",
        ghost: "border-transparent bg-transparent text-muted hover:bg-btn hover:text-text",
        link: "border-transparent bg-transparent px-0 text-link hover:text-link-hover",
      },
      size: {
        sm: "px-2 py-0.5 text-[11px]",
        md: "px-2.5 py-1 text-xs",
      },
    },
    defaultVariants: { variant: "default", size: "md" },
  },
);

export type ButtonProps = ComponentProps<"button"> &
  VariantProps<typeof controlVariants> & {
    /** Rendered as the pressed control instead of a fresh one. */
    active?: boolean;
  };

export function Button({ className, variant, size, active, ...props }: ButtonProps) {
  return (
    <button
      type="button"
      data-active={active === true ? "" : undefined}
      className={cn(
        controlVariants({ variant: active === true ? "active" : variant, size }),
        className,
      )}
      {...props}
    />
  );
}
