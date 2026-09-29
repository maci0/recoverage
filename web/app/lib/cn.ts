import { clsx, type ClassValue } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

/** `twMerge`, told what the relumea type scale is.
 *
 * `system/tokens.css` names its font sizes (`text-chip` … `text-display`), and
 * `twMerge` reads an unknown `text-*` class as a TEXT COLOUR. A recipe carrying
 * both a size and a colour (every control here) would then lose the size to a
 * conflict that does not exist: `text-data` dropped for `text-text`. Declaring
 * the names as the font-size group keeps the two apart. */
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      "font-size": [
        {
          text: [
            "chip",
            "micro",
            "data",
            "body",
            "intro",
            "lede",
            "figure",
            "title",
            "headline",
            "display",
          ],
        },
      ],
    },
  },
});

/** Join class names, letting a later Tailwind utility win over an earlier one. */
export function cn(...inputs: Array<ClassValue>): string {
  return twMerge(clsx(inputs));
}
