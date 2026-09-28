import { useEffect, useMemo, useRef, useState } from "preact/compat";

import { fetchArrayBufferSafe } from "@/api";
import { encodePathSegments, sameOriginPath } from "@/lib/format";

/** The target binary, downloaded once per (target, build), on first use.
 *
 * The byte panes slice it at a file offset, so every selection needs it; a
 * multi-megabyte fetch per selection is not an option. It is also the largest
 * response this page ever asks for, and only a selection reads it, so
 * *enabled* is the selection, not the resolved target: a visit that reads the
 * map and leaves never transfers it. After the first download the guard below
 * keeps the buffer, so deselecting and selecting again costs nothing.
 *
 * The buffer is stored against the path AND the build it came from: a target
 * switch while the download is in flight would otherwise install the previous
 * target's bytes, and every later slice would read the wrong binary at the
 * current target's offsets. The build is half the key because a rebuild can
 * rewrite the binary under the same path — `rebrew build-db` after a recompile
 * moves the bytes and the `db-updated` frame that announces it moves neither
 * the path nor the target id. Keyed on the path alone, the hook kept serving
 * the pre-rebuild binary until the reader switched targets and back, so the
 * byte panes read one build while `/asm` and `/bytes` (whose server-side memos
 * the rebuild broadcast does clear) served the next. */

export type OriginalBinary = {
  /** The default path for a target when the document names none. */
  path: string;
  buffer: ArrayBuffer | null;
  loading: boolean;
  failed: boolean;
};

/** The fallback for a document that names no `paths.originalDll`.
 *
 * The target id is used verbatim, not lowercased: rebrew creates
 * `src/<target>` and `original/<target>.dll` with the target's own spelling,
 * and a case-insensitive filesystem (macOS, Windows) hides a lowercased
 * request that only resolves there.
 *
 * A document-supplied path is percent-encoded before the fetch and the fallback
 * already is, because the guard accepts the value raw and this string goes
 * straight into `fetch`: a `paths.originalDll` of `/original/a#b.dll` asked for
 * `/original/a` and the byte panes fell back to a decode error on a file that
 * is sitting on disk. The branch is identity rather than equality because
 * `sameOriginPath` hands back the very string it was given when it accepts one,
 * and a fallback built here is never that string. */
export function originalDllPath(documentPath: string | undefined, target: string): string {
  const accepted = sameOriginPath(
    documentPath ?? "",
    `/original/${encodeURIComponent(target)}.dll`,
  );
  return accepted === documentPath ? encodePathSegments(accepted) : accepted;
}

export function useOriginalBinary(
  path: string,
  enabled: boolean,
  reloadToken: number,
): OriginalBinary {
  const [buffer, setBuffer] = useState<ArrayBuffer | null>(null);
  const [failed, setFailed] = useState(false);
  const [loading, setLoading] = useState(false);
  const loaded = useRef<{ path: string; token: number } | null>(null);

  useEffect(() => {
    if (
      !enabled ||
      path === "" ||
      (loaded.current?.path === path && loaded.current.token === reloadToken)
    ) {
      return;
    }
    // The buffer belongs to the (path, build) it was fetched for, so a target
    // switch or a rebuild puts the hook back in the waiting state. The
    // controller only stops the previous download from landing: it does not
    // retract bytes that already landed, and a consumer that reads
    // `buffer !== null` as "the bytes for the current path are here" would
    // slice the previous binary at this target's offsets for as long as the
    // download takes.
    const control = new AbortController();
    setBuffer(null);
    setFailed(false);
    setLoading(true);
    void fetchArrayBufferSafe(path, control.signal).then((result) => {
      if (control.signal.aborted) {
        return;
      }
      setLoading(false);
      if (result === null) {
        setFailed(true);
        return;
      }
      loaded.current = { path, token: reloadToken };
      setFailed(false);
      setBuffer(result);
    });
    // Aborting, not just ignoring the answer: this is the largest response the
    // page asks for (a built PE of several megabytes), and without the abort
    // every deselect, target switch and rebuild left the previous download
    // running to completion — the socket, the transfer and the browser's
    // buffering of a body nobody will read, one per change, on a path the
    // reader reaches by arrowing through cells.
    return () => {
      control.abort();
      // Settle the wait here, because the aborted `.then` above returns before
      // it and the effect that replaces this one may not start a download at
      // all: a deselect (`enabled` false) or an empty `path` returns at the
      // guard, so nothing would ever clear `loading` and the pane it feeds
      // waited on a fetch that had just been cancelled. A successor that DOES
      // start a download sets `loading` back in the same commit this cleanup
      // belongs to, so the two cannot be observed apart.
      setLoading(false);
    };
  }, [enabled, path, reloadToken]);

  // Memoized on the values: a fresh object every render would re-run every
  // effect that takes it as a dependency, which cancelled the selection's
  // fetches before they could land.
  return useMemo(() => ({ path, buffer, loading, failed }), [buffer, failed, loading, path]);
}
