import { useMemo } from "preact/compat";

import type { ComponentChildren } from "preact";

import { cn } from "@/lib/cn";
import { highlightCode, type HighlightLanguage } from "@/lib/highlight";

/** A pane's code block, highlighted.
 *
 * The HTML comes from highlight.js rather than from React children: the
 * highlighter returns markup, and escaping it would print the markup instead of
 * colouring the text. Addresses the disassembly pass turned into `<a>` elements
 * are routed back to the dashboard through one delegated click handler. */

export type HighlightedCodeProps = {
  text: string;
  language: HighlightLanguage;
  className?: string;
  /** Names the pane for assistive technology, and is required: the pane is a
   * scroll container, so it is focusable and reads as its own region. */
  label: string;
  /** Called with the numeric address of a clicked `.asm-link`. */
  onAddressClick?: (address: string) => void;
};

export function HighlightedCode({
  text,
  language,
  className,
  label,
  onAddressClick,
}: HighlightedCodeProps): ComponentChildren {
  const html = useMemo(() => highlightCode(text, language), [language, text]);
  return (
    <pre
      className={cn("code overflow-auto rounded-hair border border-line bg-code p-3", className)}
      // A scroll container that is not focusable cannot be scrolled from the
      // keyboard, which strands a long disassembly or byte dump off to the
      // right for anyone not using a mouse (WCAG 2.1.1).
      tabIndex={0}
      role="region"
      aria-label={label}
    >
      <code
        className="hljs block font-mono text-label leading-[1.45] whitespace-pre"
        onClick={(event) => {
          const { target } = event;
          if (!(target instanceof HTMLElement) || onAddressClick === undefined) {
            return;
          }
          const { dataset } = target.closest<HTMLElement>(".asm-link") ?? {};
          const address = dataset?.addr;
          if (address !== undefined) {
            event.preventDefault();
            onAddressClick(address);
          }
        }}
        // The highlighter's own output, not user HTML: highlight.js escapes the
        // text it is given, and the only markup added afterwards is the address
        // anchor above.
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </pre>
  );
}
