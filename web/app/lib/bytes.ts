/** The byte panes: the hex dump and the data inspector.
 *
 * `formatBytes` and the `DataInspector` readings both read the original
 * binary, which arrives as an `ArrayBuffer` sliced per selection, so nothing
 * here touches the network or the DOM. */

import { hex } from "@/lib/format";

export type InspectorItem = { label: string; value: string; fullWidth?: boolean };

/** A classic 16-byte-per-row dump: offset, two hex columns, ASCII gutter. */
export function formatBytes(buffer: ArrayBuffer, baseOffset = 0): string {
  const bytes = new Uint8Array(buffer);
  let out = "";
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.subarray(i, i + 16);
    const offset = (baseOffset + i).toString(16).toUpperCase().padStart(8, "0");
    const parts = Array.from({ length: 16 }, (_, j) =>
      j < slice.length ? (slice[j] ?? 0).toString(16).toUpperCase().padStart(2, "0") : "  ",
    );
    const ascii = Array.from(slice, (byte) =>
      byte >= 32 && byte <= 126 ? String.fromCodePoint(byte) : ".",
    ).join("");
    out += `${offset}  ${parts.slice(0, 8).join(" ")}  ${parts.slice(8, 16).join(" ")}  |${ascii}|\n`;
  }
  return out.trimEnd();
}

/** The little-endian readings of the first bytes, plus the printable prefix. */
export function inspectBytes(buffer: ArrayBuffer): Array<InspectorItem> {
  const view = new DataView(buffer);
  const length = buffer.byteLength;
  const read = <T>(size: number, reader: () => T | string): T | string | "N/A" =>
    length >= size ? reader() : "N/A";
  const items: Array<InspectorItem> = [
    { label: "int8", value: String(read(1, () => view.getInt8(0))) },
    { label: "uint8", value: String(read(1, () => view.getUint8(0))) },
    { label: "int16", value: String(read(2, () => view.getInt16(0, true))) },
    { label: "uint16", value: String(read(2, () => view.getUint16(0, true))) },
    { label: "int32", value: String(read(4, () => view.getInt32(0, true))) },
    {
      label: "uint32",
      value: String(
        read(4, () => {
          const value = view.getUint32(0, true);
          return `${value} (${hex(value, 8)})`;
        }),
      ),
    },
    {
      label: "float32",
      value: String(
        read(4, () => {
          const value = view.getFloat32(0, true);
          return Number.isFinite(value) ? value.toPrecision(7) : value;
        }),
      ),
    },
    {
      label: "float64",
      value: String(
        read(8, () => {
          const value = view.getFloat64(0, true);
          return Number.isFinite(value) ? value.toPrecision(15) : value;
        }),
      ),
    },
  ];
  let text = "";
  for (let i = 0; i < Math.min(length, 64); i += 1) {
    const code = view.getUint8(i);
    if (code === 0) {
      break;
    }
    text += code >= 32 && code <= 126 ? String.fromCodePoint(code) : ".";
  }
  items.push({ label: "string (ascii)", value: `"${text}"`, fullWidth: true });
  return items;
}
