import { render } from "preact";

import { App } from "@/App";
// oxlint-disable-next-line import/no-unassigned-import -- a CSS import is a side effect by definition; the bundle emits it as style.css and the Python shell inlines it
import "@/index.css";

/** The bundle's entry. The shell inlines one script, so this is the only mount
 * point and the document is the server's. */
const host = document.querySelector("#root");
if (host === null) {
  throw new Error("recoverage: the shell has no #root");
}

// oxlint-disable-next-line vitest/require-hook -- not a test: this is the application entry, where mounting at import time is the point
render(<App />, host);
