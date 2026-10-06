import { useCallback, useEffect, useRef, useState } from "preact/compat";

import { postRegen, newRegenKey } from "@/api";
import { MSG } from "@/lib/format";

/** Live reload and the Reload button.
 *
 * The stream is `/api/events`: a `db-updated` event (the coverage documents
 * rewritten by `rebrew coverage build`) refreshes the map, and EventSource reconnects
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
    // Whether the notice line is currently carrying the "live reload is off"
    // message, so a reconnect clears it and a repeat error does not re-set it
    // against a notice some OTHER surface owns (a regen in progress, a failed
    // lookup). Without this the error handler would clobber those on every
    // reconnect attempt.
    let reloadNotice = false;
    events.addEventListener("db-updated", () => {
      // Coalesce bursts: a build may rewrite the documents in stages.
      if (timer !== null) {
        window.clearTimeout(timer);
      }
      timer = window.setTimeout(onDbUpdated, EVENTS_DEBOUNCE_MS);
    });
    // An EventSource that cannot connect (the server is down, /api/events is
    // refused at its client cap with 503, the network dropped) auto-reconnects
    // and reports NOTHING while it fails: the reader kept a map that stops
    // updating when the next build lands and had no way to know. The SPA never
    // polls /api/health, so this is the only place the disconnect is visible.
    // onerror also fires for a transient blip, so it is a sticky notice the
    // next onopen takes back, not a modal.
    events.addEventListener("error", () => {
      if (reloadNotice) {
        return;
      }
      reloadNotice = true;
      onNotice(MSG.LIVE_RELOAD_OFF);
    });
    events.addEventListener("open", () => {
      if (reloadNotice) {
        reloadNotice = false;
        onNotice(null);
      }
    });
    return () => {
      if (timer !== null) {
        window.clearTimeout(timer);
      }
      events.close();
    };
  }, [enabled, onDbUpdated, onNotice]);

  const reload = useCallback((): void => {
    if (busy) {
      return;
    }
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
        const { ok, inProgress, reason } = await postRegen(key);
        // A regen runs for minutes behind a button that says "Regenerating…".
        // Saying nothing when it ends leaves the reader to tell a finished
        // rebuild from a failed one out of the map's own repaint, so the
        // success is stated; the failure still holds the line until it is
        // replaced, which is what the two callbacks are for. A re-send that
        // reached a run already under way is neither: the line stays as it is
        // and the documents land when that run writes them.
        if (ok) {
          onDone(MSG.REGEN_DONE);
        } else if (inProgress) {
          // The run this key named is still going: a re-send that reached the
          // run its own first send started. Neither a success nor a refusal,
          // and the line left as it stood said neither: "Regenerating…"
          // beside a button already back to "Regenerate" is a run nothing
          // owns, so the reader clicks again and asks for a second pipeline.
          // The documents land on their own and `db-updated` refreshes the
          // map, so the line says that instead of holding a claim nothing
          // will ever complete.
          onNotice(MSG.REGEN_ALREADY_RUNNING);
        } else {
          // A refusal carries the server's own words and the request id, so
          // the reader is left with something an operator can look up rather
          // than one line covering every way this can fail.
          onNotice(reason ?? MSG.REGEN_UNAVAILABLE);
        }
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- a failed regen is reported to the reader as REGEN_UNAVAILABLE, and the refresh still runs
      } catch {
        onNotice(MSG.REGEN_UNAVAILABLE);
      } finally {
        setBusy(false);
        onDbUpdated();
      }
    })();
  }, [busy, onDbUpdated, onDone, onNotice]);

  return { reload, busy };
}
