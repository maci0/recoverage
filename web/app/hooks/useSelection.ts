/* oxlint-disable @rikalabs/no-placeholder-implementation -- every
   `MSG.*PLACEHOLDER` below is a user-facing pane message from the shared MSG
   vocabulary ("(no disassembly for this block)"), not an unimplemented stub. */

import { useEffect, useState } from "preact/compat";

import { fetchAsm, fetchFunction, fetchTextSafe, type FunctionDetail, type Section } from "@/api";
import type { OriginalBinary } from "@/hooks/useOriginalBinary";
import { formatBytes, inspectBytes, type InspectorItem } from "@/lib/bytes";
import { MSG, extractDocs, hex, toVa } from "@/lib/format";

/** The selected block's detail panes.
 *
 * One effect owns the whole flow: resolve the cell, fetch the function, fetch
 * its C source and its disassembly, and slice the original binary. Every fetch
 * shares one AbortController, because a newer selection supersedes an older one
 * and a superseded request that still writes would land the previous
 * function's panes on top of the current one. */

export type Panes = {
  fn: FunctionDetail | null;
  /** The selected cell's function name (or VA spelling), for the map outline. */
  fnKey: string | number | null;
  source: string;
  docs: string | null;
  asm: string;
  bytes: string;
  inspector: Array<InspectorItem> | null;
};

const IDLE: Panes = {
  fn: null,
  fnKey: null,
  source: MSG.SELECT_FUNCTION,
  docs: null,
  asm: MSG.ASM_PLACEHOLDER,
  bytes: MSG.SELECT_FUNCTION,
  inspector: null,
};

export type SelectionInput = {
  target: string;
  section: string;
  sections: Record<string, Section>;
  sourceRoot: string;
  cellIndex: number | null;
  dll: OriginalBinary;
};

/** The cell covering *va* in *section*, or -1. */
export function cellIndexForVa(section: Section | undefined, va: number): number {
  const cells = section?.cells;
  const base = section?.va ?? 0;
  if (cells === undefined) {
    return -1;
  }
  const relative = va - base;
  return cells.findIndex((cell) => relative >= cell.start && relative <= cell.end);
}

function bytesMissMessage(dll: OriginalBinary): string {
  if (dll.buffer !== null) {
    return MSG.BYTES_FAILED;
  }
  return dll.loading ? MSG.LOADING : MSG.BYTES_LOAD_FAILED;
}

/** The panes for a selection of *cellIndex* in *section*, fetched and sliced. */
export function useSelection({
  target,
  section,
  sections,
  sourceRoot,
  cellIndex,
  dll,
}: SelectionInput): Panes {
  const [panes, setPanes] = useState<Panes>(IDLE);
  const row = sections[section];
  const cells = row?.cells;

  useEffect(() => {
    if (cellIndex === null || row === undefined || cells === undefined) {
      setPanes(IDLE);
      return;
    }
    const { [cellIndex]: cell } = cells;
    if (cell === undefined) {
      setPanes(IDLE);
      return;
    }
    const control = new AbortController();
    const { signal } = control;
    const firstFn = cell.functions?.[0] ?? null;
    const sectionBase = row.va ?? 0;
    const sectionOffset = row.fileOffset;

    /** A slice of the original binary, or null when the offset is not file
     * backed or the range falls outside it. `fileOffset` and `size` are
     * nullable, and `null < 0` is false, so an unchecked null would slice from
     * byte 0 and label the start of the binary with this block's address. */
    const sliceAt = (start: number | null | undefined, size: number | null | undefined): ArrayBuffer | null => {
      const { buffer } = dll;
      if (buffer === null || start === null || start === undefined || size === null || size === undefined) {
        return null;
      }
      if (!Number.isInteger(start) || !Number.isInteger(size) || size <= 0) {
        return null;
      }
      if (start < 0 || start + size > buffer.byteLength) {
        return null;
      }
      return buffer.slice(start, start + size);
    };

    const bytesPane = (buffer: ArrayBuffer | null, base: number): Pick<Panes, "bytes" | "inspector"> => {
      if (buffer === null) {
        return { bytes: bytesMissMessage(dll), inspector: null };
      }
      return { bytes: formatBytes(buffer, base), inspector: inspectBytes(buffer) };
    };

    void (async () => {
      if (firstFn === null) {
        // An undocumented block: nothing to fetch, but its bytes and, in .text,
        // its disassembly are still worth showing.
        const base = sectionBase + cell.start;
        const size = cell.end - cell.start;
        const bytes =
          section === ".bss"
            ? { bytes: MSG.BYTES_BSS, inspector: null }
            : bytesPane(
                section === ".text"
                  ? sliceAt(sectionOffset, size)
                  : sliceAt((sectionOffset ?? 0) + cell.start, 16),
                base,
              );
        setPanes({
          fn: null,
          fnKey: null,
          source: MSG.NO_C_FOR_BLOCK,
          docs: MSG.UNDOCUMENTED_BLOCK,
          asm: section === ".text" ? MSG.ASM_LOADING : MSG.DATA_SECTION_NO_ASM,
          ...bytes,
        });
        if (section !== ".text") {
          return;
        }
        try {
          // oxlint-disable-next-line @rikalabs/no-placeholder-implementation -- MSG.ASM_PLACEHOLDER is the pane's own "no disassembly" message, not an unimplemented stub
          const asm = await fetchAsm(target, hex(base, 8), size, section, signal);
          if (!signal.aborted) {
            setPanes((current) => ({ ...current, asm }));
          }
          // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- the pane falls back to its placeholder and says so on the console
        } catch (error: unknown) {
          if (!signal.aborted) {
            // oxlint-disable-next-line eslint/no-console -- a pane that never resolves is worth a console trace
            console.warn("recoverage: assembly fetch failed", error);
            setPanes((current) => ({ ...current, asm: MSG.ASM_PLACEHOLDER }));
          }
        }
        return;
      }

      const global = section !== ".text";
      setPanes({
        fn: null,
        fnKey: firstFn,
        source: MSG.LOADING,
        docs: MSG.LOADING,
        asm: global ? MSG.DATA_SECTION_NO_ASM : MSG.ASM_LOADING,
        bytes: MSG.LOADING,
        inspector: null,
      });

      try {
        const detail = await fetchFunction(target, firstFn, signal);
        if (signal.aborted) {
          return;
        }
        if (global) {
          const address = toVa(detail.va);
          const start = (sectionOffset ?? 0) + (address - sectionBase);
          const bytes =
            section === ".bss"
              ? { bytes: MSG.BYTES_BSS, inspector: null }
              : bytesPane(sliceAt(sectionOffset === null ? null : start, 16), address);
          setPanes({
            fn: { ...detail, isGlobal: true },
            fnKey: firstFn,
            source: detail.decl ?? MSG.NO_DECL,
            docs: MSG.GLOBAL_VAR,
            asm: MSG.DATA_SECTION_NO_ASM,
            ...bytes,
          });
          return;
        }

        const file = detail.files?.at(0);
        const sourceUrl =
          file === undefined
            ? null
            : `${sourceRoot}/${file.split("/").map((segment) => encodeURIComponent(segment)).join("/")}`;
        const address = detail.vaStart ?? detail.va;
        const size = detail.size ?? 0;

        // The C source and the disassembly load in parallel: neither is needed
        // to start the other, and the panes show whichever lands first.
        const asm = fetchAsm(target, address, size, section, signal).catch(
          (): string => MSG.ASM_PLACEHOLDER,
        );
        const source = await fetchTextSafe(sourceUrl, signal);
        if (signal.aborted) {
          return;
        }
        const bytes = bytesPane(sliceAt(detail.fileOffset, size), toVa(address));
        setPanes({
          fn: detail,
          fnKey: firstFn,
          source,
          docs: extractDocs(source) ?? MSG.NO_DOCS,
          asm: MSG.ASM_LOADING,
          ...bytes,
        });
        const text = await asm;
        if (!signal.aborted) {
          setPanes((current) => ({ ...current, asm: text }));
        }
        // oxlint-disable-next-line @rikalabs/no-silent-catch-fallback -- a failed selection renders as the error text the panes show, not a swallow
      } catch (error: unknown) {
        if (signal.aborted) {
          return;
        }
        setPanes({
          fn: null,
          fnKey: firstFn,
          source: MSG.ERROR_PREFIX + (error instanceof Error ? error.message : String(error)),
          docs: MSG.NO_DOCS,
          asm: global ? MSG.DATA_SECTION_NO_ASM : MSG.ASM_PLACEHOLDER,
          bytes: bytesMissMessage(dll),
          inspector: null,
        });
      }
    })();

    return () => control.abort();
    // `dll` participates: the bytes pane waits for the download, so a late
    // arrival has to re-run the selection that asked for it.
  }, [cellIndex, dll, row, section, sourceRoot, target]);

  return panes;
}
