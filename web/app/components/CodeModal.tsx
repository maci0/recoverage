import { createPortal, useCallback, useEffect, useRef, useState } from "preact/compat";

import type { ComponentChildren } from "preact";

import { HighlightedCode } from "@/components/HighlightedCode";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy-button";
import type { HighlightLanguage } from "@/lib/highlight";

/** The expanded code viewer.
 *
 * Rendered into `document.body` rather than into the panel, because the modal
 * makes the page behind it `inert` and a dialog inside an inert region could
 * not be focused. `inert` is what actually contains focus — it removes the
 * background from the tab order and the accessibility tree, which a hand-rolled
 * Tab handler can only approximate. */

export type CodeModalProps = {
  open: boolean;
  title: string;
  text: string;
  language: HighlightLanguage;
  onClose: () => void;
};

/** One id per dialog instance: the header text is the dialog's name, so the
 * visible title and the announced one cannot drift apart. */
let dialogSeq = 0;

export function CodeModal({
  open,
  title,
  text,
  language,
  onClose,
}: CodeModalProps): ComponentChildren {
  const closeRef = useRef<HTMLButtonElement | null>(null);
  const [titleId] = useState(() => {
    dialogSeq += 1;
    return `code-modal-title-${dialogSeq}`;
  });
  const lastFocused = useRef<HTMLElement | null>(null);
  // Escape is one listener for the life of the component, not one per open:
  // `addEventListener` and `removeEventListener` match on the function
  // identity, so a handler rebuilt on each open left the previous one attached
  // and every reopen stacked another.
  const latestClose = useRef(onClose);
  latestClose.current = onClose;
  const onEscape = useCallback((event: KeyboardEvent): void => {
    if (event.key === "Escape") {
      latestClose.current();
    }
  }, []);

  useEffect(() => {
    const regions = document.querySelectorAll(".skip-link, .topbar, .layout");
    if (!open) {
      for (const region of regions) {
        // SAFETY: the selector above names page regions this dashboard renders,
        // and every one of them is an HTMLElement.
        (region as HTMLElement).inert = false;
      }
      lastFocused.current?.focus();
      lastFocused.current = null;
      return;
    }
    lastFocused.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    for (const region of regions) {
      // SAFETY: as above: the page regions this dashboard renders are elements.
      (region as HTMLElement).inert = true;
    }
    closeRef.current?.focus();
    document.addEventListener("keydown", onEscape);
    return () => document.removeEventListener("keydown", onEscape);
  }, [onEscape, open]);

  if (!open) {
    return null;
  }

  return createPortal(
    <div
      className="modal show fixed inset-0 z-40 flex items-center justify-center bg-black/80 p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="modal-content flex max-h-[85vh] w-[min(1200px,95vw)] flex-col overflow-hidden rounded-control border border-line bg-panel">
        <div className="modal-header flex items-center gap-2 border-b border-line bg-modal-header px-3 py-2">
          <span id={titleId} className="modal-title font-mono text-title font-bold">
            {title === "" ? "Code viewer" : title}
          </span>
          <div className="modal-actions ms-auto flex gap-2">
            <CopyButton label="Copy" value={text} ariaLabel="Copy Modal Content" />
            <Button ref={closeRef} className="modal-close" aria-label="Close Modal" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
        {/* The body is the scroll container no other control reaches, so it is
            focusable and names itself: the long disassembly it holds cannot be
            scrolled from the keyboard otherwise (WCAG 2.1.1). The pane inside
            hands the region over to it rather than declaring a second,
            identically named one over the same content. */}
        <div
          className="modal-body min-h-0 overflow-auto p-3"
          tabIndex={0}
          role="region"
          aria-label={title === "" ? "Code viewer" : `${title} pane`}
        >
          <HighlightedCode
            text={text}
            language={language}
            label={title === "" ? "Code viewer" : `${title} pane`}
            region={false}
          />
        </div>
      </div>
    </div>,
    document.body,
  );
}
