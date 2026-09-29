import { clsx, type ClassValue } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

/** `twMerge`, told what this app's type scale is.
 *
 * `index.css` names five font sizes (`text-micro` … `text-mark`) that Tailwind
 * does not ship, and `twMerge` reads an unknown `text-*` class as a TEXT
 * COLOUR. So a recipe carrying both a size and a colour — every control in the
 * dashboard — lost the size to a conflict that never existed: `text-label` lost
 * to `text-text`, and the workhorse control label rendered at the browser's
 * default 16px instead of the 12px the token names. Declaring the names as the
 * font-size group is what keeps the two apart. `extend` appends the group to
 * `twMerge`'s own, so the stock sizes keep merging as before. */
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      "font-size": [{ text: ["micro", "label", "title", "wordmark", "mark"] }],
    },
  },
});

/** Join class names, letting a later Tailwind utility win over an earlier one. */
export function cn(...inputs: Array<ClassValue>): string {
  return twMerge(clsx(inputs));
}
