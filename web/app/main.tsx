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

// The shell ships its first-paint line inside #root so the page is not blank
// while this bundle is still being parsed and the data is still in flight.
// `render` mounts beside whatever the host already holds, so that line is
// removed here, before the app's first node exists; leaving it would sit a
// "Loading coverage..." above a live dashboard.
host.replaceChildren();

render(<App />, host);
