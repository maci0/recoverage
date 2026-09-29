import { clsx, type ClassValue } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

/** `twMerge`, told the relumea scale names.
 *
 * `system/tokens.css` names its scales (`text-chip`, `rounded-control`,
 * `leading-title`, ...), and `twMerge` knows only Tailwind's defaults. An
 * unknown `text-*` reads as a TEXT COLOUR, so a recipe's size lost to a colour
 * it never conflicted with; an unknown `rounded-*` joins no group, so an
 * override kept both classes and the stylesheet order picked the winner
 * (`rounded-chip` on a tab rendered at the Button recipe's `rounded-control`).
 * Every name below is a token, and tests/test_server.py fails when one is
 * missing. */
const twMerge = extendTailwindMerge({
  extend: {
    theme: {
      text: ["chip", "micro", "data", "body", "intro", "lede", "figure", "title", "headline", "display"],
      radius: ["hair", "cell", "chip", "control", "action", "card", "panel"],
      shadow: ["lift"],
      leading: ["display", "title", "snug", "body", "prose", "code"],
      tracking: ["display", "title", "figure", "tight", "logo", "label", "chip"],
    },
  },
});

/** Join class names, letting a later Tailwind utility win over an earlier one. */
export function cn(...inputs: Array<ClassValue>): string {
  return twMerge(clsx(inputs));
}
