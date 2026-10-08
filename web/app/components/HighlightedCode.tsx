import { useEffect, useMemo, useState } from "preact/compat";

import type { ComponentChildren } from "preact";

import { cn } from "@/lib/cn";
import { MSG } from "@/lib/format";
import { highlightCode, loadHighlighter, type HighlightLanguage } from "@/lib/highlight";

/** A pane's code block, highlighted.
 *
 * The HTML comes from highlight.js rather than from React children: the
 * highlighter returns markup, and escaping it would print the markup instead of
 * colouring the text. Addresses the disassembly pass turned into `<a>` elements
 * are routed back to the dashboard through one delegated click handler.
 *
 * The highlighter itself is loaded on demand (`loadHighlighter`), because it is
 * a tenth of the SPA shell and only a SELECTION renders a pane. So the text is
 * shown escaped and unhighlighted on the first paint and repainted in colour
 * once the module lands — the pane is never blank and never waits on it. A
 * failed import says so on the pane instead of leaving the reader with
 * permanently plain text they cannot tell from a finished render. */

export type HighlightedCodeProps = {
  text: string;
  language: HighlightLanguage;
  className?: string;
  /** Names the pane for assistive technology, and is required: the pane is a
   * scroll container, so it is focusable and reads as its own region. */
  label: string;
  /** False when an ancestor already is the scroll container and the focusable
   * region for this text, which is what `CodeModal`'s body is. Two focusable
   * regions under one name over one scroll area is a tab stop that scrolls
   * nothing and an announcement that says the same thing twice (WCAG 2.4.3). */
  region?: boolean;
  /** Called with the numeric address of a clicked `.asm-link`. */
  onAddressClick?: (address: string) => void;
  /** True when *text* is a pane message ("(no disassembly for this block)",
   * an `Error:` line) rather than code: it is shown as it is, the
   * highlighter is not fetched for it, and a highlighter that failed to load
   * is not reported under a line that was never going to be coloured. */
  plain?: boolean;
};

type Highlighter = Awaited<ReturnType<typeof loadHighlighter>>;

export function HighlightedCode({
  text,
  language,
  className,
  label,
  region = true,
  onAddressClick,
  plain = false,
}: HighlightedCodeProps): ComponentChildren {
  const [highlighter, setHighlighter] = useState<Highlighter | null>(null);
  const [failed, setFailed] = useState(false);

  // Only a pane with text asks for the highlighter, and only the first pane
  // does any work: `loadHighlighter` memoises the in-flight load, so opening a
  // second cell costs a resolved promise rather than a second request.
  useEffect(() => {
    if (text === "" || plain) {
      return;
    }
    let live = true;
    void (async () => {
      try {
        const hljs = await loadHighlighter();
        if (live) {
          setHighlighter(hljs);
        }
        // The rejection becomes a RENDERED state, not a silence: the pane keeps
        // showing the text unhighlighted and says so underneath it, which is
        // what a reader can act on. Re-throwing here would take the whole cell
        // panel down over a missing syntax highlighter.
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- (perf, first-paint) the fallback is `setFailed`, which the pane renders as a status line; the rule's "return a typed error" is a state, and this one is on screen
      } catch (error: unknown) {
        if (live) {
          setFailed(true);
          // The console line is the diagnostic: the pane's own status names the
          // condition for the reader, and the detail — which of the two
          // failures, and which URL — is what a maintainer needs and a reader
          // does not.
          // oxlint-disable-next-line eslint/no-console -- the SPA has no logger, and a pane that can never highlight is worth one line here
          console.error("recoverage: syntax highlighting unavailable", error);
        }
      }
    })();
    return () => {
      live = false;
    };
  }, [plain, text]);

  // An empty pane has nothing to colour and nothing to show, so it does not
  // render a border around a blank box and does not fetch the highlighter.
  if (text === "") {
    return null;
  }

  // A search keystroke re-renders the shell, and the panel is a child of it.
  // `highlight` on a 4,000-line pane is 34.8 ms p50 (highlight.js 11, bun, 11
  // runs), so re-running it for text that did not change drops frames the
  // keystroke is painting. The memo key is the text and the highlighter.
  const html = useMemo(
    () =>
      highlighter === null || plain
        ? escapeHtml(text)
        : highlightCode(highlighter, text, language),
    [highlighter, language, plain, text],
  );

  return (
    <pre
      className={cn("code m-0 rounded-control border border-border bg-code p-3", className, {
        "max-h-80 overflow-auto": region,
      })}
      // A scroll container that is not focusable cannot be scrolled from the
      // keyboard, which strands a long disassembly or byte dump off to the
      // right for anyone not using a mouse (WCAG 2.1.1).
      tabIndex={region ? 0 : undefined}
      role={region ? "region" : undefined}
      aria-label={region ? label : undefined}
    >
      <code
        className="hljs block font-mono text-micro leading-code whitespace-pre"
        // The highlighter's own output once it is loaded, escaped text before
        // that: the same pane either way, and never unescaped document text.
        dangerouslySetInnerHTML={{ __html: html }}
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
      />
      {/* The status line is inside the labelled region, so a screen reader
       * reaching the pane is told the same thing the line shows. `role=status`
       * announces it without taking focus. */}
      {failed && !plain && (
        <span role="status" className="mt-2 block font-mono text-micro text-text-muted">
          {MSG.HIGHLIGHT_FAILED}
        </span>
      )}
    </pre>
  );
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
