import { useEffect, useMemo, useRef, useState } from "preact/compat";

import { fetchArrayBufferSafe } from "@/api";
import { sameOriginPath } from "@/lib/format";

/** The target binary, downloaded once per (target, build).
 *
 * The byte panes slice it at a file offset, so every selection needs it; a
 * multi-megabyte fetch per selection is not an option. The buffer is stored
 * against the path AND the build it came from: a target switch while the
 * download is in flight would otherwise install the previous target's bytes,
 * and every later slice would read the wrong binary at the current target's
 * offsets. The build is half the key because a rebuild can rewrite the binary
 * under the same path — `rebrew build-db` after a recompile moves the bytes
 * and the `db-updated` frame that announces it moves neither the path nor the
 * target id. Keyed on the path alone, the hook kept serving the pre-rebuild
 * binary until the reader switched targets and back, so the byte panes read
 * one build while `/asm` and `/bytes` (whose server-side memos the rebuild
 * broadcast does clear) served the next. */

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
 * request that only resolves there. */
export function originalDllPath(documentPath: string | undefined, target: string): string {
  return sameOriginPath(documentPath ?? "", `/original/${encodeURIComponent(target)}.dll`);
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
    let cancelled = false;
    // The buffer belongs to the (path, build) it was fetched for, so a target
    // switch or a rebuild puts the hook back in the waiting state. The
    // `cancelled` flag only stops the previous download from landing: it does
    // not retract bytes that already landed, and a consumer that reads
    // `buffer !== null` as "the bytes for the current path are here" would
    // slice the previous binary at this target's offsets for as long as the
    // download takes.
    setBuffer(null);
    setFailed(false);
    setLoading(true);
    void fetchArrayBufferSafe(path).then((result) => {
      if (cancelled) {
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
    return () => {
      cancelled = true;
    };
  }, [enabled, path, reloadToken]);

  // Memoized on the values: a fresh object every render would re-run every
  // effect that takes it as a dependency, which cancelled the selection's
  // fetches before they could land.
  return useMemo(() => ({ path, buffer, loading, failed }), [buffer, failed, loading, path]);
}
