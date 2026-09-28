import { useState } from "preact/compat";

import type { ComponentChildren } from "preact";

import { Button } from "@/components/ui/button";

/** How long the outcome label holds before the button returns to its own. */
const COPIED_FLASH_MS = 1000;

/** A button that flashes the outcome of a copy, then restores its label. The
 * same outcome label every copy control in the dashboard shows: a copy with no
 * confirmation is the one action the reader cannot tell succeeded. */
export function CopyButton({
  label,
  value,
  ariaLabel,
  title,
  disabled,
}: {
  label: string;
  value: string;
  ariaLabel: string;
  title?: string;
  disabled?: boolean;
}): ComponentChildren {
  const [flashed, setFlashed] = useState<string | null>(null);
  const copy = (): void => {
    if (value === "") {
      setFlashed("Nothing");
      window.setTimeout(() => setFlashed(null), COPIED_FLASH_MS);
      return;
    }
    void (async () => {
      try {
        await navigator.clipboard.writeText(value);
        setFlashed("Copied!");
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- a refused clipboard is reported on the button itself ("Failed")
      } catch {
        setFlashed("Failed");
      } finally {
        window.setTimeout(() => setFlashed(null), COPIED_FLASH_MS);
      }
    })();
  };
  return (
    <Button
      className="copy-btn"
      aria-label={ariaLabel}
      title={title}
      disabled={disabled === true}
      onClick={copy}
    >
      {flashed ?? label}
    </Button>
  );
}
