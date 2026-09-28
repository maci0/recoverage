import { useState } from "preact/compat";

import type { ComponentChildren } from "preact";

import type { Cell, FunctionDetail, Section } from "@/api";
import { CodeModal } from "@/components/CodeModal";
import { DataInspector } from "@/components/DataInspector";
import { HighlightedCode } from "@/components/HighlightedCode";
import { Button } from "@/components/ui/button";
import { STATE_LABEL, stateSlot } from "@/grid/pack";
import type { Panes } from "@/hooks/useSelection";
import type { HighlightLanguage } from "@/lib/highlight";
import { MSG, hex, toVa } from "@/lib/format";

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
  onJumpToAddress: (address: number) => void;
};

/** Pane text that stands for "nothing to show", which turns Copy and Open off:
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

/** A button that flashes the outcome of a copy, then restores its label. */
function CopyButton({
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
      window.setTimeout(() => setFlashed(null), 1000);
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
        window.setTimeout(() => setFlashed(null), 1000);
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

/** The hexagon badge each code pane is titled with. */
function HexLogo({
  label,
  color,
  heading,
}: {
  label: string;
  color: string;
  heading: string;
}): ComponentChildren {
  return (
    <div className="section-title-left flex items-center gap-2">
      <span className="hex-logo" aria-hidden="true" style={{ color }}>
        <svg viewBox="0 0 100 100" width="22" height="22">
          <polygon
            points="50,5 90,27.5 90,72.5 50,95 10,72.5 10,27.5"
            fill="currentColor"
            fillOpacity="0.15"
            stroke="currentColor"
            strokeWidth="6"
            strokeLinejoin="round"
          />
          <text
            x="50"
            y="54"
            dominantBaseline="middle"
            textAnchor="middle"
            fill="currentColor"
            fontWeight="800"
            fontSize={label.length > 2 ? "26" : "42"}
          >
            {label}
          </text>
        </svg>
      </span>
      <h3 className="section-title-text font-mono text-xs font-bold">{heading}</h3>
    </div>
  );
}

function CodeSection({
  logo,
  color,
  heading,
  language,
  text,
  onOpen,
  onAddressClick,
}: {
  logo: string;
  color: string;
  heading: string;
  language: HighlightLanguage;
  text: string;
  onOpen: (heading: string, text: string, language: HighlightLanguage) => void;
  onAddressClick?: (address: string) => void;
}): ComponentChildren {
  const empty = isEmptyMessage(text);
  return (
    <section className="section mt-3">
      <div className="section-title flex items-center gap-2 border-b border-line pb-1">
        <HexLogo label={logo} color={color} heading={heading} />
        <div className="section-actions ml-auto flex gap-2">
          <CopyButton
            label="Copy"
            value={text}
            ariaLabel={`Copy ${heading}`}
            title={empty ? "Select a block first" : ""}
            disabled={empty}
          />
          <Button
            className="copy-btn"
            aria-label={`Open ${heading} in a larger view`}
            title={empty ? "Select a block first" : ""}
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
        {...(onAddressClick === undefined ? {} : { onAddressClick })}
      />
    </section>
  );
}

function MetaItem({
  label,
  children,
  fullWidth,
}: {
  label: string;
  children: ComponentChildren;
  fullWidth?: boolean;
}): ComponentChildren {
  return (
    <div className={fullWidth === true ? "meta-item col-span-2 flex gap-2" : "meta-item flex gap-2"}>
      <dt className="meta-label text-muted">{label}</dt>
      <dd className="meta-value wrap-anywhere">{children}</dd>
    </div>
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
              href={`${sourceRoot}/${file.split("/").map((segment) => encodeURIComponent(segment)).join("/")}`}
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
    return (
      <dl className="meta-grid grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-xs">
        <MetaItem label="VA">
          <a
            className="meta-value asm-link"
            href="#"
            onClick={(event) => {
              event.preventDefault();
              onJumpToAddress(toVa(fn.va));
            }}
          >
            {hex(toVa(fn.va), 1)}
          </a>
        </MetaItem>
        <MetaItem label="Type">Global Variable</MetaItem>
        {sourceItem}
      </dl>
    );
  }

  const address = fn.vaStart ?? fn.va;
  const status = fn.status ?? "?";
  return (
    <dl className="meta-grid grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-xs">
      <MetaItem label="VA">
        <a
          className="meta-value asm-link"
          href="#"
          onClick={(event) => {
            event.preventDefault();
            onJumpToAddress(toVa(address));
          }}
        >
          {String(address)}
        </a>
      </MetaItem>
      <MetaItem label="Size">{`${fn.size ?? 0} bytes`}</MetaItem>
      <MetaItem label="Offset">{hex(fn.fileOffset ?? 0, 1)}</MetaItem>
      <MetaItem label="Symbol">{fn.symbol ?? MSG.NA}</MetaItem>
      <MetaItem label="Status">
        <span className={`meta-value status-badge status-${status.toLowerCase().replace("_", "-")}`}>
          {status}
        </span>
      </MetaItem>
      <MetaItem label="Module">{fn.module ?? "?"}</MetaItem>
      <MetaItem label="Compiler">{fn.cflags ?? MSG.NA}</MetaItem>
      <MetaItem label="Marker">{fn.markerType ?? "?"}</MetaItem>
      {fn.blocker == null ? null : (
        <MetaItem label="Blocker" fullWidth>
          <span className="meta-value blocker-value">{fn.blocker}</span>
        </MetaItem>
      )}
      {fn.blockerDelta == null ? null : (
        <MetaItem label="Delta">
          <span className="meta-value delta-value">{`${fn.blockerDelta} bytes`}</span>
        </MetaItem>
      )}
      {fn.ghidra_name != null && fn.ghidra_name !== fn.name ? (
        <MetaItem label="Ghidra">{fn.ghidra_name}</MetaItem>
      ) : null}
      {fn.list_name != null && fn.list_name !== fn.name ? (
        <MetaItem label="Func List">{fn.list_name}</MetaItem>
      ) : null}
      {fn.size_reason == null ? null : <MetaItem label="Size Source">{fn.size_reason}</MetaItem>}
      {fn.last_verify == null ? null : (
        <MetaItem label="Verified">
          {`${fn.last_verify.verified_at ?? ""}${
            fn.last_verify.byte_delta == null ? "" : ` (Δ${fn.last_verify.byte_delta}B)`
          }`}
        </MetaItem>
      )}
      {fn.last_verify?.similarity == null ? null : (
        <MetaItem label="Code Sim">{`${(fn.last_verify.similarity * 100).toFixed(1)}%`}</MetaItem>
      )}
      {fn.last_verify?.reg_delta == null ? null : (
        <MetaItem label="Reg Delta">{String(fn.last_verify.reg_delta)}</MetaItem>
      )}
      {fn.last_verify?.effective_match === true ? (
        <MetaItem label="Effective">register-only delta — prove candidate</MetaItem>
      ) : null}
      {fn.updated_by == null ? null : (
        <MetaItem label="Updated By">
          {`${fn.updated_by}${fn.updated_at == null ? "" : ` (${fn.updated_at})`}`}
        </MetaItem>
      )}
      {fn.similarity == null ? null : (
        <MetaItem label="Similarity">{`${(fn.similarity * 100).toFixed(1)}%`}</MetaItem>
      )}
      {fn.is_thunk === true ? <MetaItem label="Type">IAT thunk (not reversible)</MetaItem> : null}
      {fn.is_export === true ? <MetaItem label="Type">Exported function</MetaItem> : null}
      {fn.sha256 == null ? null : (
        <MetaItem label="SHA256">{`${fn.sha256.slice(0, 16)}...`}</MetaItem>
      )}
      {sourceItem}
      {docs === null || docs === MSG.SELECT_FUNCTION || docs === MSG.NO_DOCS ? null : (
        <MetaItem label="Annotations" fullWidth>
          <pre className="meta-docs whitespace-pre-wrap">{docs}</pre>
        </MetaItem>
      )}
    </dl>
  );
}

/** The metadata under the title: a selected function's grid, a block's three
 * facts, or nothing when no block is selected. */
function PanelMeta({
  fn,
  cell,
  section,
  sourceRoot,
  docs,
  onJumpToAddress,
}: {
  fn: FunctionDetail | null;
  cell: Cell | undefined;
  section: Section | null;
  sourceRoot: string;
  docs: string | null;
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
  return (
    <dl className="meta-grid grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-xs">
      <MetaItem label="State">{STATE_LABEL[stateSlot(cell.state)]}</MetaItem>
      <MetaItem label="Range">
        {hex((section?.va ?? 0) + cell.start, 8)}..{hex((section?.va ?? 0) + cell.end, 8)}
      </MetaItem>
      <MetaItem label="Size">{`${cell.span} bytes`}</MetaItem>
    </dl>
  );
}

export function CoveragePanel({
  section,
  cellIndex,
  panes,
  sourceRoot,
  onJumpToAddress,
}: CoveragePanelProps): ComponentChildren {
  const [modal, setModal] = useState<{
    title: string;
    text: string;
    language: HighlightLanguage;
  } | null>(null);

  const { cells } = section ?? {};
  const cell = cellIndex === null || cells === undefined ? undefined : cells.at(cellIndex);
  const { fn } = panes;
  const subject = cellIndex === null ? (section?.name ?? "") : `Block ${cellIndex}`;
  const title = fn?.name ?? subject;
  const openModal = (heading: string, text: string, language: HighlightLanguage): void => {
    setModal({ title: `${heading}: ${fn?.name ?? subject}`, text, language });
  };
  let copyVA: string | null = null;
  if (fn !== null && fn !== undefined) {
    copyVA = String(fn.vaStart ?? fn.va);
  } else if (cell !== undefined) {
    const base = section?.va ?? 0;
    copyVA = `${hex(base + cell.start, 8)}..${hex(base + cell.end, 8)}`;
  }

  return (
    <aside
      className="panel w-[460px] max-w-[45vw] shrink-0 self-start rounded-control border border-line bg-panel p-3"
      id="panel"
    >
      <div className="panel-head border-b border-line pb-2">
        <div className="flex items-center gap-2">
          <h2 className="panel-title font-mono text-sm font-bold">{title}</h2>
          <div className="panel-actions ml-auto flex gap-2">
            <CopyButton
              label="Copy VA"
              value={copyVA ?? ""}
              ariaLabel="Copy VA"
              title="Copy this block's address range"
              disabled={copyVA === null}
            />
            <CopyButton
              label="Copy Symbol"
              value={fn?.symbol ?? ""}
              ariaLabel="Copy Symbol"
              title="Copy the function's symbol"
              disabled={fn?.symbol == null}
            />
          </div>
        </div>
        <div className="panel-meta mt-2">
          <PanelMeta
            fn={fn}
            cell={cell}
            section={section}
            sourceRoot={sourceRoot}
            docs={panes.docs}
            onJumpToAddress={onJumpToAddress}
          />
        </div>
      </div>
      <div className="panel-body pt-2">
        {fn === null && cellIndex === null ? (
          <p className="hint text-muted">{MSG.SELECT_FUNCTION}</p>
        ) : (
          <>
            <CodeSection
              logo="C"
              color="var(--accent-c-source)"
              heading="C Source"
              language="c"
              text={panes.source}
              onOpen={openModal}
            />
            {section?.name === ".text" ? (
              <CodeSection
                logo="ASM"
                color="var(--accent-asm)"
                heading="Assembly"
                language="x86asm"
                text={panes.asm}
                onOpen={openModal}
                onAddressClick={(address) => {
                  onJumpToAddress(Number.parseInt(address, 16));
                }}
              />
            ) : (
              <section className="section mt-3">
                <div className="section-title border-b border-line pb-1">
                  <HexLogo label="{}" color="var(--accent-data)" heading="Data Inspector" />
                </div>
                <DataInspector items={panes.inspector} />
              </section>
            )}
            <CodeSection
              logo="01"
              color="var(--accent-bytes)"
              heading="Original Bytes"
              language="hex"
              text={panes.bytes}
              onOpen={openModal}
            />
          </>
        )}
      </div>
      <CodeModal
        open={modal !== null}
        title={modal?.title ?? ""}
        text={modal?.text ?? ""}
        language={modal?.language ?? "c"}
        onClose={() => setModal(null)}
        onCopy={() => {
          void navigator.clipboard.writeText(modal?.text ?? "");
        }}
      />
    </aside>
  );
}
