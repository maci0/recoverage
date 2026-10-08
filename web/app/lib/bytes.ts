/** The byte panes: the hex dump and the data inspector.
 *
 * `formatBytes` and the `DataInspector` readings both read the original
 * binary, which arrives as an `ArrayBuffer` sliced per selection, so nothing
 * here touches the network or the DOM. The integer readings go through
 * `format.count`, because a `uint32` is ten digits wide and `String` spells
 * those the same for every reader. */

import { count, hex, reading } from "@/lib/format";

export type InspectorItem = { label: string; value: string; fullWidth?: boolean };

/** The ASCII the dump's gutter and the string prefix print as themselves, and
 * what stands in for everything else. Both panes read the same range, so it is
 * named once here rather than spelled twice. */
const PRINTABLE_LOW = 0x20;
const PRINTABLE_HIGH = 0x7E;
const UNPRINTABLE = ".";

function asciiChar(byte: number): string {
  return byte >= PRINTABLE_LOW && byte <= PRINTABLE_HIGH
    ? String.fromCodePoint(byte)
    : UNPRINTABLE;
}

/** A classic 16-byte-per-row dump: offset, two hex columns, ASCII gutter, in
 * the lowercase `server._format_hex_dump` prints for Potato Mode and `/bytes`. */
export function formatBytes(buffer: ArrayBuffer, baseOffset = 0): string {
  const bytes = new Uint8Array(buffer);
  let out = "";
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.subarray(i, i + 16);
    // `hex`, not the open-coded `toString(16)` this used to spell: the row
    // offset is a document-derived address (`section.va + cell.start`), and
    // `(-4096).toString(16)` is `"-1000"`, which `padStart` pads on the left
    // of the MINUS into `"000-1000"`. One spelling per address, so the gutter
    // cannot go on rendering an address the debugger will not accept.
    const offset = hex(baseOffset + i, 8).slice(2);
    const parts = Array.from({ length: 16 }, (_, j) =>
      j < slice.length ? (slice[j] ?? 0).toString(16).padStart(2, "0") : "  ",
    );
    const ascii = Array.from(slice, asciiChar).join("");
    out += `${offset}  ${parts.slice(0, 8).join(" ")}  ${parts.slice(8, 16).join(" ")}  |${ascii}|\n`;
  }
  return out.trimEnd();
}

/** The little-endian readings of the first bytes, plus the printable prefix. */
export function inspectBytes(buffer: ArrayBuffer): Array<InspectorItem> {
  const view = new DataView(buffer);
  const length = buffer.byteLength;
  const read = (size: number, reader: () => string): string =>
    length >= size ? reader() : "N/A";
  const items: Array<InspectorItem> = [
    { label: "int8", value: read(1, () => count(view.getInt8(0))) },
    { label: "uint8", value: read(1, () => count(view.getUint8(0))) },
    { label: "int16", value: read(2, () => count(view.getInt16(0, true))) },
    { label: "uint16", value: read(2, () => count(view.getUint16(0, true))) },
    { label: "int32", value: read(4, () => count(view.getInt32(0, true))) },
    {
      label: "uint32",
      value: read(4, () => {
        const value = view.getUint32(0, true);
        return `${count(value)} (${hex(value, 8)})`;
      }),
    },
    {
      label: "float32",
      value: read(4, () => {
        const value = view.getFloat32(0, true);
        return Number.isFinite(value) ? reading(value) : String(value);
      }),
    },
    {
      label: "float64",
      value: read(8, () => {
        const value = view.getFloat64(0, true);
        return Number.isFinite(value) ? reading(value) : String(value);
      }),
    },
  ];
  let text = "";
  for (let i = 0; i < Math.min(length, 64); i += 1) {
    const code = view.getUint8(i);
    if (code === 0) {
      break;
    }
    text += asciiChar(code);
  }
  items.push({ label: "string (ascii)", value: `"${text}"`, fullWidth: true });
  return items;
}
