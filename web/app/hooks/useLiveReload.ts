import { useCallback, useEffect, useRef, useState } from "preact/compat";

import { postRegen, newRegenKey } from "@/api";
import { MSG } from "@/lib/format";

/** Live reload and the Reload button.
 *
 * The stream is `/api/events`: a `db-updated` event (the coverage documents
 * rewritten by `rebrew build-db`) refreshes the map, and EventSource reconnects
 * on its own, so a dropped stream self-heals. Reload regenerates first, which
 * is rate-limited server-side and cooldown-limited here so a double click is
 * not reported as a failure. */

const REGEN_COOLDOWN_MS = 5000;
const EVENTS_DEBOUNCE_MS = 300;

export type LiveReload = {
  /** Regenerate, then refresh; cooldown-limited. */
  reload: () => void;
  /** True while a regen is in flight, which disables the button. */
  busy: boolean;
};

export function useLiveReload({
  enabled,
  onDbUpdated,
  onNotice,
  onDone,
}: {
  enabled: boolean;
  onDbUpdated: () => void;
  /** A message that stays until something replaces it: an in-flight line and a
   * failure both have to outlive the read that raised them. */
  onNotice: (text: string | null) => void;
  /** A transient confirmation, which the shell clears on its own. */
  onDone: (text: string) => void;
}): LiveReload {
  const [busy, setBusy] = useState(false);
  // null, not 0: performance.now() counts from page load, so a first Reload
  // clicked within the cooldown of loading the page would read as inside the
  // window and silently skip the regen.
  const lastRegen = useRef<number | null>(null);

  useEffect(() => {
    if (!enabled) {
      return;
    }
    const events = new EventSource("/api/events");
    let timer: number | null = null;
    events.addEventListener("db-updated", () => {
      // Coalesce bursts: a build may rewrite the documents in stages.
      if (timer !== null) {
        window.clearTimeout(timer);
      }
      timer = window.setTimeout(onDbUpdated, EVENTS_DEBOUNCE_MS);
    });
    return () => {
      if (timer !== null) {
        window.clearTimeout(timer);
      }
      events.close();
    };
  }, [enabled, onDbUpdated]);

  const reload = useCallback((): void => {
    const now = performance.now();
    const since = lastRegen.current === null ? Number.POSITIVE_INFINITY : now - lastRegen.current;
    if (since < REGEN_COOLDOWN_MS) {
      onNotice(MSG.REGEN_USING_CACHE(Math.ceil((REGEN_COOLDOWN_MS - since) / 1000)));
      onDbUpdated();
      return;
    }
    lastRegen.current = now;
    setBusy(true);
    onNotice(MSG.REGEN_IN_PROGRESS);
    // One key per action, minted here and not inside postRegen: the key is what
    // tells the server a re-send is the same regenerate rather than a second
    // one, so it has to outlive the request it is attached to.
    const key = newRegenKey();
    void (async () => {
      try {
        const { ok, inProgress } = await postRegen(key);
        // A regen runs for minutes behind a button that says "Regenerating...".
        // Saying nothing when it ends leaves the reader to tell a finished
        // rebuild from a failed one out of the map's own repaint, so the
        // success is stated; the failure still holds the line until it is
        // replaced, which is what the two callbacks are for.
        if (ok) {
          onDone(MSG.REGEN_DONE);
        } else if (inProgress) {
          // The re-send reached a run already under way.  It is not a failure
          // and the pipeline is not this reader's to start again: the line
          // stays, and the documents land when that run writes them.
          onNotice(MSG.REGEN_IN_PROGRESS);
        } else {
          onNotice(MSG.REGEN_UNAVAILABLE);
        }
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- a failed regen is reported to the reader as REGEN_UNAVAILABLE, and the refresh still runs
      } catch {
        onNotice(MSG.REGEN_UNAVAILABLE);
      } finally {
        setBusy(false);
        onDbUpdated();
      }
    })();
  }, [onDbUpdated, onDone, onNotice]);

  return { reload, busy };
}
