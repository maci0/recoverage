import { useCallback, useEffect, useRef, useState } from "preact/compat";

import { postRegen } from "@/api";
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
}: {
  enabled: boolean;
  onDbUpdated: () => void;
  onNotice: (text: string | null) => void;
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
    void (async () => {
      try {
        const { ok } = await postRegen();
        onNotice(ok ? null : MSG.REGEN_UNAVAILABLE);
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- a failed regen is reported to the reader as REGEN_UNAVAILABLE, and the refresh still runs
      } catch {
        onNotice(MSG.REGEN_UNAVAILABLE);
      } finally {
        setBusy(false);
        onDbUpdated();
      }
    })();
  }, [onDbUpdated, onNotice]);

  return { reload, busy };
}
