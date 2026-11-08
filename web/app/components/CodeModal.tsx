import { createPortal, useCallback, useEffect, useRef, useState } from "preact/compat";

import type { ComponentChildren } from "preact";

import { HighlightedCode } from "@/components/HighlightedCode";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy-button";
import { Icon } from "@/system/icons/Icon";
import type { HighlightLanguage } from "@/lib/highlight";

/** The expanded code viewer.
 *
 * Rendered into `document.body` rather than into the panel, because the modal
 * makes the page behind it `inert` and a dialog inside an inert region could
 * not be focused. `inert` is what actually contains focus — it removes the
 * background from the tab order and the accessibility tree, which a hand-rolled
 * Tab handler can only approximate. The trap below is the wrap that `inert`
 * alone does not do: the browser cycles the dialog's own controls and, with
 * no native dialog, never re-enters the first one by itself. */

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
  const dialogRef = useRef<HTMLDivElement | null>(null);
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
  // The modal is the one focus container while it is open: the page behind it
  // is `inert`, so Tab cannot leave the page, but without this handler it
  // cycles through the dialog's own controls and then wraps back to the
  // first one with no way out except Escape. The trap is the keydown that
  // keeps Tab on the last focusable in the dialog — it wraps to the first
  // (or, with Shift, to the last) instead of escaping the dialog (WCAG 2.1.2).
  const onTrapTab = useCallback((event: KeyboardEvent): void => {
    if (event.key !== "Tab") {
      return;
    }
    const dialog = dialogRef.current;
    if (dialog === null) {
      return;
    }
    const focusable = [
      ...dialog.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    ].filter((element) => element.offsetParent !== null || element === document.activeElement);
    if (focusable.length === 0) {
      event.preventDefault();
      return;
    }
    const [first] = focusable;
    const last = focusable.at(-1);
    if (first === undefined || last === undefined) {
      return;
    }
    const active = document.activeElement;
    if (event.shiftKey && (active === first || active === dialog)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  }, []);
  const onEscape = useCallback((event: KeyboardEvent): void => {
    if (event.key === "Escape") {
      // Escape closes the dialog, and the page behind it is inert, so the
      // event must not also reach the map or the search field behind it:
      // the map's Escape clears the selected block and the search's clears
      // the query, so a dialog Escape that bubbled through would take
      // those down as well (WCAG 2.1.2).
      event.preventDefault();
      event.stopPropagation();
      latestClose.current();
    }
  }, []);

  useEffect(() => {
    const regions = document.querySelectorAll(".skip-link, .topbar, #main-content");
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
    document.addEventListener("keydown", onTrapTab);
    return () => {
      document.removeEventListener("keydown", onEscape);
      document.removeEventListener("keydown", onTrapTab);
      // Unmounting while open (the panel is unmounted when the target or the
      // section changes under a dialog) used to leave the page regions inert,
      // and an inert page is a page no keyboard user can reach at all.
      for (const region of regions) {
        // SAFETY: as above: the page regions this dashboard renders are elements.
        (region as HTMLElement).inert = false;
      }
    };
  }, [onEscape, onTrapTab, open]);

  if (!open) {
    return null;
  }

  return createPortal(
    <div
      ref={dialogRef}
      className="modal fixed inset-0 z-40 flex items-center justify-center bg-scrim p-4 sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="modal-content flex max-h-full w-full max-w-shell flex-col overflow-hidden rounded-action border border-border bg-surface shadow-lift">
        <div className="modal-header flex items-center gap-3 border-b border-border bg-raised px-4 py-3">
          <span id={titleId} className="modal-title min-w-0 font-mono text-data font-semibold wrap-anywhere">
            {title === "" ? "Code viewer" : title}
          </span>
          <div className="modal-actions ms-auto flex gap-2">
            <CopyButton label="Copy" value={text} ariaLabel="Copy the code" />
            <Button ref={closeRef} className="modal-close" size="sm" onClick={onClose}>
              <Icon name="x" />
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
          className="modal-body min-h-0 overflow-auto p-4"
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
