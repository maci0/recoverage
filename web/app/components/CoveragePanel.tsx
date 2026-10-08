import { useState } from "preact/compat";

import type { ComponentChildren } from "preact";

import type { Cell, FunctionDetail, Section } from "@/api";
import { CodeModal } from "@/components/CodeModal";
import { DataInspector, inspectorText } from "@/components/DataInspector";
import { HighlightedCode } from "@/components/HighlightedCode";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy-button";
import { META_GRID, MetaItem } from "@/components/ui/meta";
import type { Panes } from "@/hooks/useSelection";
import type { HighlightLanguage } from "@/lib/highlight";
import { cn } from "@/lib/cn";
import {
  MSG,
  byteCount,
  count,
  dateTime,
  hex,
  isolate,
  similarityPct,
  sourceFileUrl,
  toVa,
} from "@/lib/format";
import { STATE_LABEL, stateSlot } from "@/states";
import { Icon } from "@/system/icons/Icon";
import type { IconName } from "@/system/icons/paths";

/** The selected block's detail.
 *
 * The panel head names the selection and carries the metadata grid; the body is
 * three code panes — C source, disassembly (or the data inspector for a
 * non-code section) and the original bytes — each with its own Copy and Open.
 * The class names (`panel`, `panel-head`, `panel-body`, `section`) are the hooks
 * the browser specs query. */

export type CoveragePanelProps = {
  section: Section | null;
  cellIndex: number | null;
  panes: Panes;
  sourceRoot: string;
  /** The address a parent-function NAME resolves to, or null when the search
   * index does not carry it. `Cell.parent_function` is a name, so the Parent
   * link is a lookup rather than an address it already holds. */
  parentVaFor: (name: string) => number | null;
  onJumpToAddress: (address: number) => void;
  /** Take the panel out of the flow below `lg`, where it stacks under the
   * map. Beside the map (`lg` and up) it stays, since nothing above it moves. */
  hiddenWhenStacked: boolean;
};

/** Pane text that stands for "nothing to", which turns Copy and Open off:
 * copying "(select a function)" is never what the reader wants. */
function isEmptyMessage(text: string): boolean {
  return (
    text === MSG.SELECT_FUNCTION ||
    text === MSG.ASM_PLACEHOLDER ||
    text === MSG.NO_C_SOURCE ||
    text === MSG.NO_C_FOR_BLOCK ||
    text === MSG.UNDOCUMENTED_BLOCK ||
    text === MSG.DATA_SECTION_NO_ASM ||
    text === MSG.BYTES_FAILED ||
    text === MSG.BYTES_BSS ||
    text === MSG.BYTES_LOAD_FAILED ||
    text === MSG.GLOBAL_VAR ||
    text === MSG.NO_DECL ||
    text === MSG.NA ||
    text === MSG.LOADING ||
    text === MSG.ASM_LOADING ||
    text === MSG.DETAIL_UNAVAILABLE ||
    text.startsWith(MSG.ERROR_PREFIX) ||
    text.startsWith("(failed to load:")
  );
}

/** The verdict word's ink (`st-*`), keyed by the status rebrew wrote. A status
 * this table does not name reads in the muted ink rather than a verdict colour
 * it has not earned. */
const STATUS_INK = new Map<string, string>([
  ["EXACT", "text-st-exact"],
  ["VERIFIED", "text-st-exact"],
  ["RELOC", "text-st-reloc"],
  ["PROVEN", "text-st-proven"],
  ["NEAR", "text-st-near"],
  ["NEAR_MATCH", "text-st-near"],
  ["MATCHING", "text-st-near"],
  ["SIZE_MISMATCH", "text-st-near"],
  ["STUB", "text-st-stub"],
  ["COMPILE_ERROR", "text-st-fail"],
  ["EXTRACT_ERROR", "text-st-fail"],
]);

/** A document column as a value, or null when the document left it empty.
 * rebrew writes an unset text column as `""` rather than omitting it, so
 * `updated_by = ""` beside `updated_at = ""` rendered the row as ` ()`. */
function filled(column: string | null | undefined): string | null {
  return column == null || column === "" ? null : column;
}

function statusInk(status: string): string {
  return STATUS_INK.get(status.toUpperCase()) ?? "text-text-muted";
}

/** A pane heading: the pane's icon beside its name. The icon is decorative;
 * the heading carries the name. */
function PaneTitle({ icon, heading }: { icon: IconName; heading: string }): ComponentChildren {
  return (
    <div className="flex min-w-0 items-center gap-2 text-text-muted">
      <Icon name={icon} />
      <h3 className="section-title-text m-0 text-data font-semibold text-text">{heading}</h3>
    </div>
  );
}

function CodeSection({
  icon,
  heading,
  language,
  text,
  onOpen,
  onAddressClick,
}: {
  icon: IconName;
  heading: string;
  language: HighlightLanguage;
  text: string;
  onOpen: (heading: string, text: string, language: HighlightLanguage) => void;
  onAddressClick?: (address: string) => void;
}): ComponentChildren {
  const empty = isEmptyMessage(text);
  return (
    <section className="section mt-5">
      <div className="section-title mb-2 flex items-center gap-2">
        <PaneTitle icon={icon} heading={heading} />
        <div className="section-actions ms-auto flex gap-2">
          <CopyButton
            label="Copy"
            value={text}
            ariaLabel={`Copy ${heading}`}
            title={empty ? "This pane holds no code to copy" : ""}
            disabled={empty}
          />
          <Button
            size="sm"
            aria-label={`Open ${heading} in a larger view`}
            title={empty ? "This pane holds no code to open" : ""}
            disabled={empty}
            onClick={() => onOpen(heading, text, language)}
          >
            Open
          </Button>
        </div>
      </div>
      <HighlightedCode
        text={text}
        language={language}
        label={`${heading} pane`}
        plain={empty}
        {...(onAddressClick === undefined ? {} : { onAddressClick })}
      />
    </section>
  );
}

function FunctionMeta({
  fn,
  sourceRoot,
  docs,
  onJumpToAddress,
}: {
  fn: FunctionDetail;
  sourceRoot: string;
  docs: string | null;
  onJumpToAddress: (address: number) => void;
}): ComponentChildren {
  const sourceItem =
    fn.files !== undefined && fn.files.length > 0 ? (
      <MetaItem label="Source">
        {fn.files.map((file, index) => (
          <span key={file}>
            {index > 0 ? ", " : ""}
            <a
              className="source-link"
              href={sourceFileUrl(sourceRoot, file)}
              target="_blank"
              rel="noopener noreferrer"
            >
              {file}
            </a>
          </span>
        ))}
      </MetaItem>
    ) : null;

  if (fn.isGlobal === true) {
    let storageLabel = "Global variable";
    switch (fn.storage_kind) {
      case "import": {
        storageLabel = "Import pointer";
        break;
      }
      case "span": {
        storageLabel = "Layout span";
        break;
      }
      case "literal": {
        storageLabel = "Compiler literal";
        break;
      }
      case "alias": {
        storageLabel = "Storage view";
        break;
      }
      default: {
        break;
      }
    }
    let ownerLabel = "Unknown";
    if (fn.storage_kind === "span") {
      ownerLabel = "Layout span";
    } else if (fn.backing) {
      ownerLabel = `View of ${fn.backing}`;
    }
    return (
      <dl className={META_GRID}>
        <MetaItem label="VA">
          <a
            className="meta-value asm-link"
            href="#"
            title={`Jump the map to ${hex(toVa(fn.va), 8)}`}
            onClick={(event) => {
              event.preventDefault();
              onJumpToAddress(toVa(fn.va));
            }}
          >
            {hex(toVa(fn.va), 8)}
          </a>
        </MetaItem>
        <MetaItem label="Type">
          {storageLabel}
        </MetaItem>
        <MetaItem label="Owner">{fn.owners?.join(", ") || ownerLabel}</MetaItem>
        <MetaItem label="Users">{fn.referenced_in?.join(", ") || MSG.NA}</MetaItem>
        <MetaItem label="Declarations">
          {fn.declared_in?.join(", ") || fn.files?.join(", ") || MSG.NA}
        </MetaItem>
      </dl>
    );
  }

  const address = fn.vaStart ?? fn.va;
  // `/functions/<va>` carries the address as a bare number, which is the
  // spelling for the wire, not for the page: every other address on this panel
  // is hex, and a reader matching this one against a map range, a search term
  // or a disassembly line has to convert it by hand.
  const addressHex = hex(toVa(address), 8);
  const status = filled(fn.status) ?? MSG.NA;
  // Both similarity columns are 0-1 fractions off the wire; `similarityPct`
  // scales, floors, and refuses a value the document spelled as something else.
  const fnSimilarity = similarityPct(fn.similarity);
  const lastVerifySimilarity = similarityPct(fn.last_verify?.similarity);
  const updatedBy = filled(fn.updated_by);
  const symbol = filled(fn.symbol);
  const ghidraName = filled(fn.ghidra_name);
  const listName = filled(fn.list_name);
  const sizeReason = filled(fn.size_reason);
  const sha256 = filled(fn.sha256);
  const updatedAt = filled(fn.updated_at);
  // The Blocker row already prints the blocker, so its `// BLOCKER:` line
  // is left out of the annotations rather than repeated under it.
  const blocker = filled(fn.blocker);
  const annotations =
    docs === null || docs === MSG.SELECT_FUNCTION || docs === MSG.NO_DOCS
      ? null
      : withoutRepeatedBlocker(docs, blocker);
  return (
    <dl className={META_GRID}>
      <MetaItem label="VA">
        <a
          className="meta-value asm-link"
          href="#"
          title={`Jump the map to ${addressHex}`}
          onClick={(event) => {
            event.preventDefault();
            onJumpToAddress(toVa(address));
          }}
        >
          {addressHex}
        </a>
      </MetaItem>
      <MetaItem label="Size">{byteCount(fn.size ?? 0)}</MetaItem>
      <MetaItem label="Offset">{hex(fn.fileOffset ?? 0, 1)}</MetaItem>
      <MetaItem label="Symbol">{symbol ?? MSG.NA}</MetaItem>
      <MetaItem label="Status">
        <span
          className={cn(
            "meta-value inline-flex rounded-chip bg-surface-2 px-1.5 py-0.5 font-mono text-chip font-semibold tracking-chip",
            statusInk(status),
          )}
        >
          {status}
        </span>
      </MetaItem>
      <MetaItem label="Module">{filled(fn.module) ?? MSG.NA}</MetaItem>
      <MetaItem label="Compiler">{filled(fn.cflags) ?? MSG.NA}</MetaItem>
      <MetaItem label="Marker">{filled(fn.markerType) ?? MSG.NA}</MetaItem>
      {blocker === null ? null : (
        <MetaItem label="Blocker" fullWidth>
          <span className="meta-value">{blocker}</span>
        </MetaItem>
      )}
      {fn.blockerDelta == null ? null : (
        <MetaItem label="Delta">
          <span className="meta-value">{byteCount(fn.blockerDelta)}</span>
        </MetaItem>
      )}
      {ghidraName !== null && ghidraName !== fn.name ? (
        <MetaItem label="Ghidra">{ghidraName}</MetaItem>
      ) : null}
      {listName !== null && listName !== fn.name ? (
        <MetaItem label="Function list">{listName}</MetaItem>
      ) : null}
      {sizeReason === null ? null : <MetaItem label="Size source">{sizeReason}</MetaItem>}
      {fn.last_verify == null ? null : (
        <MetaItem label="Verified">
          {`${fn.last_verify.verified_at == null ? "" : dateTime(fn.last_verify.verified_at)}${
            fn.last_verify.byte_delta == null ? "" : ` (${isolate(`Δ${count(fn.last_verify.byte_delta)} B`)})`
          }`}
        </MetaItem>
      )}
      {lastVerifySimilarity === null ? null : (
        <MetaItem label="Code similarity">{lastVerifySimilarity}</MetaItem>
      )}
      {fn.last_verify?.diff_lines == null ? null : (
        <MetaItem label="Diff lines">{count(fn.last_verify.diff_lines)}</MetaItem>
      )}
      {fn.last_verify?.reg_delta == null ? null : (
        <MetaItem label="Register delta">{count(fn.last_verify.reg_delta)}</MetaItem>
      )}
      {fn.last_verify?.effective_match === true ? (
        <MetaItem label="Effective">register-only delta, a candidate for a proof</MetaItem>
      ) : null}
      {updatedBy === null ? null : (
        <MetaItem label="Updated by">
          {`${updatedBy}${updatedAt === null ? "" : ` (${dateTime(updatedAt)})`}`}
        </MetaItem>
      )}
      {fnSimilarity === null ? null : <MetaItem label="Similarity">{fnSimilarity}</MetaItem>}
      {fn.is_thunk === true ? <MetaItem label="Type">IAT thunk (not reversible)</MetaItem> : null}
      {fn.is_export === true ? <MetaItem label="Type">Exported function</MetaItem> : null}
      {sha256 === null ? null : (
        // The row shows enough of the digest to recognise it beside another
        // report, and the rest is one hover away: a digest truncated with no
        // way to read or take the whole of it is a value the reader cannot
        // use, and the panel head's Copy button is how the rest of this panel
        // hands over a value verbatim.
        <MetaItem label="SHA256">
          <span title={sha256}>{`${sha256.slice(0, 16)}…`}</span>
        </MetaItem>
      )}
      {sourceItem}
      {annotations === null ? null : (
        <MetaItem label="Annotations" fullWidth>
          <pre className="m-0 whitespace-pre-wrap text-micro">{annotations}</pre>
        </MetaItem>
      )}
    </dl>
  );
}

const BLOCKER_PREFIX = "// BLOCKER:";

/** *docs* without the `// BLOCKER:` line that says what the Blocker row
 * already does, or null when nothing else is left. */
function withoutRepeatedBlocker(docs: string, blocker: string | null): string | null {
  const kept = docs
    .split("\n")
    .filter(
      (line) =>
        blocker === null ||
        !line.startsWith(BLOCKER_PREFIX) ||
        line.slice(BLOCKER_PREFIX.length).trim() !== blocker.trim(),
    );
  return kept.length > 0 ? kept.join("\n") : null;
}

/** The metadata under the title: a selected function's grid, a block's three
 * facts, or nothing when no block is selected. */
function PanelMeta({
  fn,
  cell,
  section,
  sourceRoot,
  docs,
  parentVaFor,
  onJumpToAddress,
}: {
  fn: FunctionDetail | null;
  cell: Cell | undefined;
  section: Section | null;
  sourceRoot: string;
  docs: string | null;
  parentVaFor: (name: string) => number | null;
  onJumpToAddress: (address: number) => void;
}): ComponentChildren {
  if (fn !== null) {
    return (
      <FunctionMeta
        fn={fn}
        sourceRoot={sourceRoot}
        docs={docs}
        onJumpToAddress={onJumpToAddress}
      />
    );
  }
  if (cell === undefined) {
    return null;
  }
  const parent = cell.parent_function;
  const parentVa = parent === undefined ? null : parentVaFor(parent);
  return (
    <dl className={META_GRID}>
      <MetaItem label="State">{STATE_LABEL[stateSlot(cell.state)]}</MetaItem>
      <MetaItem label="Range">
        {hex((section?.va ?? 0) + cell.start, 8)}..{hex((section?.va ?? 0) + cell.end, 8)}
      </MetaItem>
      {/* `span` is the cell's width in lattice units, not its length: the
          bytes are `end - start`, the range the row above prints and the
          Original Bytes pane dumps (Potato's block panel reads the same). */}
      <MetaItem label="Size">{byteCount(cell.end - cell.start)}</MetaItem>
      {/* A data or thunk cell carries no function of its own: `parent_function`
       * is the link to the function that owns it, and `label` the name rebrew
       * gave it. Both are on the cell the server sends and on the Potato panel
       * beside this one; a block without a function is exactly the case they
       * exist for, so the branch that has no function panel is the branch that
       * needs them. The parent is spelled as the NAME rebrew stored (the Potato
       * panel beside this one prints the same string), and it is a link only
       * when the search index resolves it to an address: a link to nowhere
       * answers a click with a block that covers no such function. */}
      {cell.label === undefined ? null : <MetaItem label="Label">{cell.label}</MetaItem>}
      {parent === undefined ? null : (
        <MetaItem label="Parent">
          {parentVa === null ? (
            <span className="meta-value">{parent}</span>
          ) : (
            <a
              className="meta-value asm-link"
              href="#"
              onClick={(event) => {
                event.preventDefault();
                onJumpToAddress(parentVa);
              }}
            >
              {parent}
            </a>
          )}
        </MetaItem>
      )}
    </dl>
  );
}

export function CoveragePanel({
  section,
  cellIndex,
  panes,
  sourceRoot,
  parentVaFor,
  onJumpToAddress,
  hiddenWhenStacked,
}: CoveragePanelProps): ComponentChildren {
  const [modal, setModal] = useState<{
    title: string;
    text: string;
    language: HighlightLanguage;
  } | null>(null);

  const { cells } = section ?? {};
  const cell = cellIndex === null || cells === undefined ? undefined : cells.at(cellIndex);
  const { fn } = panes;
  const selected = fn !== null || cellIndex !== null;
  const subject = cellIndex === null ? (section?.name ?? "") : `Block ${count(cellIndex)}`;
  const title = isolate(fn?.name ?? subject);
  const openModal = (heading: string, text: string, language: HighlightLanguage): void => {
    setModal({ title: `${heading}: ${title}`, text, language });
  };
  let copyVA: string | null = null;
  if (fn !== null) {
    // The hex the VA row above shows, so the button hands over the address the
    // reader can see rather than a second spelling of it.
    copyVA = hex(toVa(fn.vaStart ?? fn.va), 8);
  } else if (cell !== undefined) {
    const base = section?.va ?? 0;
    copyVA = `${hex(base + cell.start, 8)}..${hex(base + cell.end, 8)}`;
  }
  // The whole digest behind the abbreviated SHA256 row, or null when the
  // function carries none. Shown beside the other two copy controls because a
  // digest the panel abbreviates is otherwise a value no reader can take
  // anywhere: it is the one row whose full text is longer than the row.
  const copySha = filled(fn?.sha256);
  const copySymbol = filled(fn?.symbol);
  // The Data Inspector's readings as text, for the Copy and Open its pane
  // carries. Empty when the section is `.text` (no inspector) and when the
  // block has no file-backed bytes, which is the same empty message the pane
  // itself draws.
  const inspector = inspectorText(panes.inspector);
  const inspectorEmpty = inspector === "";

  return (
    <aside
      // From `xl` the panel is wide enough for one row of the Original Bytes
      // dump (offset, 16 bytes, the ASCII gutter: 78 mono columns). At 30rem
      // the gutter was cut off at its second character on a 1440px screen, and
      // the long disassembly lines with it; the map still keeps the larger
      // share of the row.
      className={cn(
        "panel w-full shrink-0 self-start overflow-hidden rounded-card border border-border bg-surface lg:w-form xl:w-prose-wide",
        hiddenWhenStacked && "max-lg:hidden",
      )}
      id="panel"
      // With nothing selected there is no title to name the panel by, and an
      // `aria-labelledby` naming a missing id names nothing.
      aria-labelledby={selected ? "panel-title" : undefined}
      aria-label={selected ? undefined : "Block detail"}
    >
      {/* The head names a selection and hands over its values. Before one
          exists it would be a title naming the section the tabs already
          name, over copy buttons with nothing to copy. */}
      {selected && (
        <div className="panel-head border-b border-border bg-raised p-4">
          <div className="flex flex-wrap items-start gap-2">
            {/* A decompiled C identifier is as long as the analyst's patience, and
                in the terminal face it has no break opportunity, so it pushes the
                copy buttons out of the panel unless the title may break and the
                buttons are the part that stays whole. The title keeps at least
                10rem; past that the buttons wrap to their own row, or a phone
                stacks the title one letter per line. */}
            <h2
              className="panel-title m-0 min-w-0 flex-1 basis-40 font-mono text-intro font-semibold leading-snug wrap-anywhere"
              id="panel-title"
              dir="auto"
            >
              {title}
            </h2>
            {/* Under `sm` the buttons always take a row of their own, so they
                start at the title's edge rather than hanging off the right. */}
            <div className="panel-actions flex shrink-0 flex-wrap gap-2 sm:ms-auto sm:justify-end">
              <CopyButton
                label="Copy VA"
                value={copyVA ?? ""}
                ariaLabel="Copy VA"
                title="Copy this block's address range"
                disabled={copyVA === null}
              />
              {/* Offered when there is a symbol to take, like Copy SHA: a
                  block with no function would otherwise carry a button that
                  can never do anything. */}
              {copySymbol === null ? null : (
                <CopyButton
                  label="Copy Symbol"
                  value={copySymbol}
                  ariaLabel="Copy Symbol"
                  title="Copy the function's symbol"
                />
              )}
              {copySha === null ? null : (
                <CopyButton
                  label="Copy SHA"
                  value={copySha}
                  ariaLabel="Copy SHA256"
                  title="Copy the function's full SHA256 digest"
                />
              )}
            </div>
          </div>
          <div className="mt-3">
            <PanelMeta
              fn={fn}
              cell={cell}
              section={section}
              sourceRoot={sourceRoot}
              docs={panes.docs}
              parentVaFor={parentVaFor}
              onJumpToAddress={onJumpToAddress}
            />
          </div>
        </div>
      )}
      <div className="px-4 pb-4">
        {selected ? (
          <>
            <CodeSection
              icon="braces"
              heading="C Source"
              language="c"
              text={panes.source}
              onOpen={openModal}
            />
            {section?.name === ".text" ? (
              <CodeSection
                icon="cpu"
                heading="Assembly"
                language="x86asm"
                text={panes.asm}
                onOpen={openModal}
                onAddressClick={(address) => {
                  onJumpToAddress(Number.parseInt(address, 16));
                }}
              />
            ) : (
              <section className="section mt-5">
                {/* The same head and the same two controls the three text panes
                    carry: a reader who copies a block's disassembly can copy
                    its interpreted values the same way, and a data block's
                    readings are the ones most often wanted as text (into a
                    note, a diff, a review). A pane the pattern skipped is a
                    pane a reader has to read off the screen. A block with no
                    file-backed bytes leaves nothing to take, so both controls
                    go off with them, as they do on a text pane that holds only
                    a message. */}
                <div className="section-title mb-2 flex items-center gap-2">
                  <PaneTitle icon="list" heading="Data Inspector" />
                  <div className="section-actions ms-auto flex gap-2">
                    <CopyButton
                      label="Copy"
                      value={inspector}
                      ariaLabel="Copy Data Inspector"
                      title={inspectorEmpty ? "This block has no file-backed bytes to copy" : ""}
                      disabled={inspectorEmpty}
                    />
                    <Button
                      size="sm"
                      aria-label="Open Data Inspector in a larger view"
                      title={inspectorEmpty ? "This block has no file-backed bytes to open" : ""}
                      disabled={inspectorEmpty}
                      onClick={() => openModal("Data Inspector", inspector, "hex")}
                    >
                      Open
                    </Button>
                  </div>
                </div>
                <DataInspector items={panes.inspector} />
              </section>
            )}
            <CodeSection
              icon="file-binary"
              heading="Original Bytes"
              language="hex"
              text={panes.bytes}
              onOpen={openModal}
            />
          </>
        ) : (
          <p className="hint m-0 pt-4 text-data text-text-muted">
            Select a block on the map, or search for a function, to see its C source, disassembly
            and original bytes here.
          </p>
        )}
      </div>
      <CodeModal
        open={modal !== null}
        title={modal?.title ?? ""}
        text={modal?.text ?? ""}
        language={modal?.language ?? "c"}
        onClose={() => setModal(null)}
      />
    </aside>
  );
}
