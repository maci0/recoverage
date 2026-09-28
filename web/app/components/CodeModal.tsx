import { createPortal, useEffect, useRef, useState } from "preact/compat";

import type { ComponentChildren } from "preact";

import { HighlightedCode } from "@/components/HighlightedCode";
import { Button } from "@/components/ui/button";
import type { HighlightLanguage } from "@/lib/highlight";

/** The expanded code viewer.
 *
 * Rendered into `document.body` rather than into the panel, because the modal
 * makes the page behind it `inert` and a dialog inside an inert region could
 * not be focused. `inert` is what actually contains focus — it removes the
 * background from the tab order and the accessibility tree, which a hand-rolled
 * Tab handler can only approximate. */

/** Escape closes the dialog. One function, so the listener added and the one
 * removed are the same reference. */
function closeOnEscape(onClose: () => void): (event: KeyboardEvent) => void {
  return (event) => {
    if (event.key === "Escape") {
      onClose();
    }
  };
}

export type CodeModalProps = {
  open: boolean;
  title: string;
  text: string;
  language: HighlightLanguage;
  onClose: () => void;
};

/** How long the copied label holds before the button returns to "Copy". */
const COPIED_FLASH_MS = 1000;

export function CodeModal({
  open,
  title,
  text,
  language,
  onClose,
}: CodeModalProps): ComponentChildren {
  const closeRef = useRef<HTMLButtonElement | null>(null);
  const lastFocused = useRef<HTMLElement | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // The component stays mounted between opens, so a label left flashing on the
  // previous view would greet the next one.
  useEffect(() => {
    if (open) {
      setCopied(null);
    }
  }, [open]);

  // The same outcome label every Copy button in the panel shows: a copy with
  // no confirmation is the one action the reader cannot tell succeeded.
  const copy = (): void => {
    void (async () => {
      try {
        await navigator.clipboard.writeText(text);
        setCopied("Copied!");
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- a refused clipboard is reported on the button itself ("Failed")
      } catch {
        setCopied("Failed");
      } finally {
        window.setTimeout(() => setCopied(null), COPIED_FLASH_MS);
      }
    })();
  };

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
    document.addEventListener("keydown", closeOnEscape(onClose));
    return () => document.removeEventListener("keydown", closeOnEscape(onClose));
  }, [onClose, open]);

  if (!open) {
    return null;
  }

  return createPortal(
    <div
      className="modal show fixed inset-0 z-40 flex items-center justify-center bg-black/80 p-6"
      role="dialog"
      aria-modal="true"
      aria-label={title === "" ? "Code viewer" : title}
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="modal-content flex max-h-[85vh] w-[min(1200px,95vw)] flex-col overflow-hidden rounded-control border border-line bg-panel">
        <div className="modal-header flex items-center gap-2 border-b border-line bg-modal-header px-3 py-2">
          <span className="modal-title font-mono text-sm font-bold">{title}</span>
          <div className="modal-actions ml-auto flex gap-2">
            <Button className="copy-btn" aria-label="Copy Modal Content" onClick={copy}>
              {copied ?? "Copy"}
            </Button>
            <Button ref={closeRef} className="modal-close" aria-label="Close Modal" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
        <div className="modal-body min-h-0 overflow-auto p-3">
          <HighlightedCode text={text} language={language} />
        </div>
      </div>
    </div>,
    document.body,
  );
}
