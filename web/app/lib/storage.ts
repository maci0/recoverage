/** The dashboard's two remembered preferences.
 *
 * `localStorage` throws where the browser blocks storage (private mode, a
 * disabled store, a full quota), and that is a supported state: the dashboard
 * has a default for both values.  The failure is reported once per key rather
 * than swallowed, because a preference that silently stops sticking is a bug
 * report that names the wrong cause.
 */

const REPORTED = new Set<string>();

function report(action: string, key: string, failure: Error): void {
  const mark = `${action}:${key}`;
  if (REPORTED.has(mark)) {
    return;
  }
  REPORTED.add(mark);
  // oxlint-disable-next-line no-console -- the SPA has no logger, and a dropped preference is worth one line in the console
  console.warn(`recoverage: cannot ${action} "${key}" in localStorage`, failure);
}

export function readStored(key: string): string | null {
  try {
    return localStorage.getItem(key);
    // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- a blocked storage is a supported state: the default is the answer and the failure is reported on the console
  } catch (error) {
    report("read", key, error instanceof Error ? error : new Error(String(error)));
    return null;
  }
}

export function writeStored(key: string, preference: string): void {
  try {
    localStorage.setItem(key, preference);
    // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- same policy as the read: storage may be blocked, and the failure is reported on the console
  } catch (error) {
    report("write", key, error instanceof Error ? error : new Error(String(error)));
  }
}
