import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "preact";
import { forwardRef } from "preact/compat";

import { cn } from "@/lib/cn";

/** The one control recipe, after shadcn/ui's Button, read through the relumea
 * tokens.
 *
 * `secondary` is the bordered default; `primary` is the filled action (at most
 * one per view); `ghost` is a toolbar control with no edge until hovered.
 * `active` marks the pressed control in a group and is carried on the element
 * as `data-active`, which the forced-colors rule and the browser specs query. */
export const controlVariants = cva(
  [
    "inline-flex shrink-0 cursor-pointer select-none items-center justify-center gap-1.5",
    "whitespace-nowrap rounded-control border font-sans font-medium",
    "transition-colors",
    "disabled:cursor-not-allowed disabled:opacity-50",
    "aria-disabled:cursor-progress",
  ],
  {
    variants: {
      variant: {
        secondary:
          "border-control-line bg-surface text-text hover:border-control-line-hover hover:bg-surface-2",
        primary: "border-transparent bg-text text-surface hover:bg-ink-hover",
        ghost: "border-transparent bg-transparent text-text-muted hover:bg-surface-2 hover:text-text",
        active: "border-control-line-hover bg-surface-3 text-text",
      },
      size: {
        // sm and icon are 24px tall (h-6/size-6): the WCAG 2.5.8 AA floor.
        // The previous h-7/size-8 were 28/32px, which is also above the
        // floor, but sm is the size the filter pills and copy/open controls
        // use, and its spacing and the section-tab row ("28px tab") were
        // written against h-7's height; h-6 keeps that row at one height
        // while every sm control stays at or above the floor.
        sm: "h-6 px-2 text-micro",
        md: "h-8 px-3 text-data",
        icon: "size-6 text-data",
      },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export type ButtonProps = ComponentProps<"button"> &
  Omit<VariantProps<typeof controlVariants>, "variant"> & {
    variant?: "secondary" | "primary" | "ghost";
    /** Rendered as the pressed control of its group. */
    active?: boolean;
  };

/** The ref reaches the `<button>` itself: a ref on a plain function component
 * is handed the component instance, which has no `focus()`, so the code
 * modal's move of focus to its Close button threw and focus stayed behind
 * the now-inert page. */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, active, variant, size, ...props }, ref) => (
    <button
      ref={ref}
      type="button"
      data-active={active === true ? "" : undefined}
      className={cn(
        controlVariants({ variant: active === true ? "active" : variant, size }),
        className,
      )}
      {...props}
    />
  ),
);
