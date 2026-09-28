import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Join class names, letting a later Tailwind utility win over an earlier one. */
export function cn(...inputs: Array<ClassValue>): string {
  return twMerge(clsx(inputs));
}
