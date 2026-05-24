import { Component, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import type { CVEDetailEnvelope, DecisionRecord } from "../types";
import VerdictBadge from "../components/VerdictBadge";

// ---------------------------------------------------------------------------
// Defensive helpers — the backend returns the raw per-CVE result which has
// many nested objects (component, severity, fix, confidence ...).  React
// throws "Objects are not valid as a React child" if we let any of those
// reach JSX directly, so every text-rendered value is funnelled through
// safeText() and a top-level ErrorBoundary catches anything else.
// ---------------------------------------------------------------------------

function safeText(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  // Common nested shapes: Severity{label,cvss}, Component{name,version}
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (typeof o.label === "string") return o.label;
    if (typeof o.name === "string") return o.name;
    if (typeof o.text === "string") return o.text;
    if (typeof o.value === "string") return o.value;
    try {
      return JSON.stringify(v);
    } catch {
      return String(v);
    }
  }
  return String(v);
}

class ErrorBoundary extends Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error, info: unknown) {
    // eslint-disable-next-line no-console
    console.error("CVEDetail render crash", error, info);
  }
  render() {
    if (this.state.error) {
      return (
        <div className="error">
          Failed to render this CVE detail: {this.state.error.message}.
          Click <em>Show raw JSON</em> in the toolbar to inspect the payload.
        </div>
      );
    }
    return this.props.children;
  }
}

export default function CVEDetail() {
  const { runId, cveId } = useParams();
  const [data, setData] = useState<CVEDetailEnvelope | null>(null);
  const [decision, setDecision] = useState<DecisionRecord | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!runId || !cveId) return;
    api.getCVE(runId, cveId).then(setData).catch((e) => setError(String(e)));
    api.getDecision(runId, cveId).then(setDecision).catch(() => {});
  }, [runId, cveId]);

  const fields = extractFields(data);

  async function submitDecision(payload: Record<string, unknown>) {
    if (!runId || !cveId) return;
    try {
      const rec = await api.postDecision(runId, cveId, payload);
      setDecision(rec);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <ErrorBoundary>
    <div>
      <div className="toolbar">
        <div>
          <Link to={`/runs/${runId}`}>← Back to run</Link>
          <h2 style={{ margin: "8px 0" }}>
            <code>{safeText(cveId)}</code>
          </h2>
          <div className="row">
            <VerdictBadge verdict={safeText(data?.verdict || fields.verdict)} />
            {fields.severity && (
              <span className="badge unknown">{safeText(fields.severity)}</span>
            )}
            {fields.component && (
              <span className="muted">in {safeText(fields.component)}</span>
            )}
          </div>
        </div>
        <div className="row">
          <button onClick={() => setShowRaw((v) => !v)}>
            {showRaw ? "Hide" : "Show"} raw JSON
          </button>
        </div>
      </div>

      {error && <div className="error">{error}</div>}
      {!data && <div className="empty">Loading…</div>}

      {data && (
        <>
          <Summary fields={fields} />
          <FixPatchPanel runId={runId!} cveId={cveId!} data={data} />
          <HITLPanel
            decision={decision}
            onSubmit={submitDecision}
            currentVerdict={fields.verdict}
          />
          {showRaw && (
            <div className="card">
              <h3>Raw JSON</h3>
              <pre>{JSON.stringify(data, null, 2)}</pre>
            </div>
          )}
        </>
      )}
    </div>
    </ErrorBoundary>
  );
}

// ---------------------------------------------------------------------------
// Human-friendly summary
// ---------------------------------------------------------------------------

interface Fields {
  verdict?: string;
  severity?: string;
  component?: string;
  current_version?: string;
  affected_version?: string;
  fixed_version?: string;
  description?: string;
  impact?: string;
  reachability_reason?: string;
  exploitability_reason?: string;
  suggested_remediation?: string;
  ubuntu_security?: any;
  confidence?: any;
  cwe?: string;
  cvss?: number | string;
  references?: string[];
}

function get(obj: any, ...paths: string[]): any {
  for (const p of paths) {
    let cur = obj;
    for (const k of p.split(".")) {
      if (cur == null) {
        cur = undefined;
        break;
      }
      cur = cur[k];
    }
    if (cur !== undefined && cur !== null && cur !== "") return cur;
  }
  return undefined;
}

function extractFields(d: any): Fields {
  if (!d) return {};
  // Common paths across artifact shapes. The CVEAnalysis schema strips
  // the original CVEEvent, so we also probe the evidence_bundle.cve_event
  // and the start-sidecar synthesised `event` field.
  const f: Fields = {
    verdict: get(d, "verdict", "routing.final_verdict", "verifier.verdict"),
    severity: get(
      d,
      "event.severity.label",
      "evidence_bundle.cve_event.severity.label",
      "event.severity",
      "severity",
    ),
    component: get(
      d,
      "component.name",
      "event.component.name",
      "evidence_bundle.cve_event.component.name",
      "component",
    ),
    current_version: get(
      d,
      "component.current_version",
      "event.component.current_version",
      "evidence_bundle.cve_event.component.current_version",
    ),
    affected_version: get(
      d,
      "affected_version",
      "event.affected_version",
      "payload.installed_version",
    ),
    fixed_version: get(
      d,
      "fix.fixed_version",
      "component.fixed_version",
      "evidence_bundle.fixed_version",
      "evidence_bundle.ubuntu_security.fixed_version",
      "event.component.fixed_version",
    ),
    description: get(
      d,
      "event.description",
      "evidence_bundle.cve_event.description",
      "description",
      "evidence_bundle.ubuntu_security.description",
    ),
    impact: get(
      d,
      "triage.rationale",
      "verifier.rationale",
      "routing.reason",
      "rationale",
      "impact",
    ),
    reachability_reason: get(
      d,
      "evidence_bundle.reachability",
      "triage.reachability_reason",
      "verifier.reachability_reason",
    ),
    exploitability_reason: get(
      d,
      "exploitability_reason",
      "triage.exploitability_reason",
      "verifier.exploitability_reason",
    ),
    suggested_remediation: get(
      d,
      "fix.suggested_remediation",
      "evidence_bundle.ubuntu_security.remediation",
      "routing.suggested_remediation",
    ),
    ubuntu_security: get(d, "evidence_bundle.ubuntu_security", "ubuntu_security"),
    confidence: get(d, "confidence", "verifier.confidence", "routing.confidence"),
    cwe: get(d, "cwe", "event.cwe", "evidence_bundle.cve_event.cwe"),
    cvss: get(
      d,
      "event.severity.cvss",
      "evidence_bundle.cve_event.severity.cvss",
      "cvss",
    ),
    references: get(
      d,
      "event.external_links",
      "evidence_bundle.cve_event.external_links",
      "references",
    ),
  };
  // Collapse any leftover nested shapes to plain strings.
  if (f.verdict !== undefined) f.verdict = safeText(f.verdict);
  if (f.severity !== undefined) f.severity = safeText(f.severity);
  if (f.component !== undefined) f.component = safeText(f.component);
  if (f.current_version !== undefined)
    f.current_version = safeText(f.current_version);
  if (f.affected_version !== undefined)
    f.affected_version = safeText(f.affected_version);
  if (f.fixed_version !== undefined) f.fixed_version = safeText(f.fixed_version);
  if (f.cwe !== undefined) f.cwe = safeText(f.cwe);
  if (f.cvss !== undefined && typeof f.cvss === "object")
    f.cvss = safeText(f.cvss);
  if (Array.isArray(f.references)) {
    f.references = f.references.map((r) => safeText(r)).filter(Boolean);
  } else if (f.references !== undefined) {
    f.references = undefined;
  }
  return f;
}

function Summary({ fields }: { fields: Fields }) {
  return (
    <div className="card">
      <h3>Summary</h3>
      <dl className="kv">
        {fields.description && (
          <>
            <dt>Description</dt>
            <dd>{safeText(fields.description)}</dd>
          </>
        )}
        {fields.impact && (
          <>
            <dt>Impact</dt>
            <dd>{safeText(fields.impact)}</dd>
          </>
        )}
        {fields.cwe && (
          <>
            <dt>CWE</dt>
            <dd>{safeText(fields.cwe)}</dd>
          </>
        )}
        {fields.cvss !== undefined && (
          <>
            <dt>CVSS</dt>
            <dd>{safeText(fields.cvss)}</dd>
          </>
        )}
        {fields.affected_version && (
          <>
            <dt>Affected version</dt>
            <dd>
              <code>{safeText(fields.affected_version)}</code>
            </dd>
          </>
        )}
        {fields.current_version && (
          <>
            <dt>Current version (in use)</dt>
            <dd>
              <code>{safeText(fields.current_version)}</code>
            </dd>
          </>
        )}
        {fields.fixed_version && (
          <>
            <dt>Fixed version</dt>
            <dd>
              <code>{safeText(fields.fixed_version)}</code>
            </dd>
          </>
        )}
        {fields.reachability_reason && (
          <>
            <dt>Reachability</dt>
            <dd>{safeText(fields.reachability_reason)}</dd>
          </>
        )}
        {fields.exploitability_reason && (
          <>
            <dt>Exploitability</dt>
            <dd>{safeText(fields.exploitability_reason)}</dd>
          </>
        )}
        {fields.suggested_remediation && (
          <>
            <dt>Suggested remediation</dt>
            <dd>{safeText(fields.suggested_remediation)}</dd>
          </>
        )}
        {fields.ubuntu_security && (
          <>
            <dt>Ubuntu security</dt>
            <dd>
              <UbuntuSecurity data={fields.ubuntu_security} />
            </dd>
          </>
        )}
        {fields.confidence !== undefined && (
          <>
            <dt>Confidence</dt>
            <dd>
              {typeof fields.confidence === "object" ? (
                <pre style={{ margin: 0 }}>
                  {JSON.stringify(fields.confidence, null, 2)}
                </pre>
              ) : (
                String(fields.confidence)
              )}
            </dd>
          </>
        )}
        {fields.references && fields.references.length > 0 && (
          <>
            <dt>References</dt>
            <dd>
              <ul style={{ paddingLeft: 20, margin: 0 }}>
                {fields.references.slice(0, 12).map((r) => (
                  <li key={r}>
                    <a href={r} target="_blank" rel="noreferrer">
                      {r}
                    </a>
                  </li>
                ))}
              </ul>
            </dd>
          </>
        )}
      </dl>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Ubuntu security panel
// ---------------------------------------------------------------------------

function UbuntuSecurity({ data }: { data: any }) {
  if (!data || typeof data !== "object") {
    return <span className="muted">no data</span>;
  }
  const pkgs: any[] = Array.isArray(data.package_statuses)
    ? data.package_statuses
    : [];
  const jammy = pkgs.find(
    (p) => safeText(p?.release).toLowerCase() === "jammy",
  );
  return (
    <div>
      <dl className="kv" style={{ margin: 0 }}>
        {data.status && (
          <>
            <dt>Status</dt>
            <dd>{safeText(data.status)}</dd>
          </>
        )}
        {data.priority && (
          <>
            <dt>Priority</dt>
            <dd>{safeText(data.priority)}</dd>
          </>
        )}
        {data.fixed_version && (
          <>
            <dt>Fixed version (upstream)</dt>
            <dd>
              <code>{safeText(data.fixed_version)}</code>
            </dd>
          </>
        )}
        {jammy && (
          <>
            <dt>Jammy (22.04) fix</dt>
            <dd>
              <span
                className={`badge ${
                  /released/i.test(safeText(jammy.status))
                    ? "not_applicable"
                    : /needed|pending/i.test(safeText(jammy.status))
                    ? "needs_human"
                    : "unknown"
                }`}
              >
                {safeText(jammy.status) || "unknown"}
              </span>
              {jammy.fixed_version && (
                <>
                  {" "}
                  · <code>{safeText(jammy.fixed_version)}</code>
                </>
              )}
            </dd>
          </>
        )}
        {Array.isArray(data.usn_ids) && data.usn_ids.length > 0 && (
          <>
            <dt>USNs</dt>
            <dd>
              {data.usn_ids.map((u: any) => safeText(u)).filter(Boolean).join(", ")}
            </dd>
          </>
        )}
        {data.remediation && (
          <>
            <dt>Remediation</dt>
            <dd>{safeText(data.remediation)}</dd>
          </>
        )}
      </dl>
      {pkgs.length > 0 && (
        <details style={{ marginTop: 8 }}>
          <summary className="muted">
            All releases ({pkgs.length})
          </summary>
          <table style={{ marginTop: 6 }}>
            <thead>
              <tr>
                <th>Release</th>
                <th>Status</th>
                <th>Fixed version</th>
              </tr>
            </thead>
            <tbody>
              {pkgs.map((p, i) => (
                <tr key={i}>
                  <td>{safeText(p?.release)}</td>
                  <td>{safeText(p?.status)}</td>
                  <td>
                    {p?.fixed_version ? (
                      <code>{safeText(p.fixed_version)}</code>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
      {data.raw_url && (
        <div style={{ marginTop: 6 }}>
          <a href={safeText(data.raw_url)} target="_blank" rel="noreferrer">
            View on Ubuntu Security Tracker ↗
          </a>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// HITL panel
// ---------------------------------------------------------------------------

const REASSIGN_OPTIONS = [
  "package_upgrade",
  "not_applicable",
  "code_change",
  "needs_human",
];

function HITLPanel({
  decision,
  onSubmit,
  currentVerdict,
}: {
  decision: DecisionRecord | null;
  onSubmit: (p: Record<string, unknown>) => void | Promise<void>;
  currentVerdict?: string;
}) {
  const [note, setNote] = useState("");
  const [actor, setActor] = useState("");
  const [reassignTo, setReassignTo] = useState(
    currentVerdict === "package_upgrade" ? "not_applicable" : "package_upgrade",
  );

  function send(action: string, extra: Record<string, unknown> = {}) {
    onSubmit({ action, note: note.trim() || undefined, actor: actor || undefined, ...extra });
    setNote("");
  }

  return (
    <div className="card">
      <h3>Human-in-the-loop review</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        Approve, reject, reassign the verdict, or attach a note. Decisions are
        appended to an audit ledger and emitted as bus events.
      </p>

      <div className="grid-2">
        <div>
          <label>Reviewer (optional)</label>
          <input
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            placeholder="e.g. alice"
            style={{ width: "100%" }}
          />
        </div>
        <div>
          <label>Reassign to verdict</label>
          <select
            value={reassignTo}
            onChange={(e) => setReassignTo(e.target.value)}
            style={{ width: "100%" }}
          >
            {REASSIGN_OPTIONS.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div style={{ marginTop: 10 }}>
        <label>Note</label>
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Optional review note…"
          rows={3}
          style={{ width: "100%" }}
        />
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <button className="success" onClick={() => send("approve")}>
          ✓ Approve
        </button>
        <button className="danger" onClick={() => send("reject")}>
          ✗ Reject
        </button>
        <button
          onClick={() => send("reassign", { new_verdict: reassignTo })}
        >
          ↻ Reassign → {reassignTo}
        </button>
        <button
          onClick={() => send("note")}
          disabled={!note.trim()}
          title="Add a note without changing the verdict"
        >
          📝 Add note
        </button>
      </div>

      {decision && decision.history.length > 0 && (
        <>
          <h4 style={{ marginTop: 16 }}>History</h4>
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Reviewer</th>
                <th>Action</th>
                <th>New verdict</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {decision.history.slice().reverse().map((h, i) => (
                <tr key={i}>
                  <td>{new Date(h.ts * 1000).toLocaleString()}</td>
                  <td>{h.actor}</td>
                  <td>
                    <strong>{h.action}</strong>
                  </td>
                  <td>{h.new_verdict || "—"}</td>
                  <td>{h.note || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Fix patch panel — renders the authored unified diff and lets a reviewer
// either preview (`git apply --check`) or apply it (`git apply`) against the
// indexed repo_root. We embed the diff directly so developers do not need to
// drop to the shell to inspect what would change.
// ---------------------------------------------------------------------------

function FixPatchPanel({
  runId,
  cveId,
  data,
}: {
  runId: string;
  cveId: string;
  data: any;
}) {
  const fix = data?.fix as
    | undefined
    | {
        patch_unified_diff?: string;
        files_touched?: string[];
        lines_added?: number;
        lines_removed?: number;
        rationale?: string;
        fix_confidence?: number;
        verdict_override?: string | null;
      };
  const diff = (fix?.patch_unified_diff || "").trim();
  const [busy, setBusy] = useState<null | "check" | "apply">(null);
  const [result, setResult] = useState<
    null | import("../types").ApplyPatchResult
  >(null);
  const [err, setErr] = useState<string | null>(null);

  if (!fix || !diff) {
    return (
      <div className="card">
        <h3>Proposed fix</h3>
        <div className="muted">
          No code patch was authored for this CVE. (Only CVEs triaged as{" "}
          <code>code_change</code> get a patch; <code>upgrade_only</code> and{" "}
          <code>not_applicable</code> verdicts produce a recommendation only.)
        </div>
      </div>
    );
  }

  async function run(checkOnly: boolean) {
    setBusy(checkOnly ? "check" : "apply");
    setErr(null);
    setResult(null);
    try {
      const r = await api.applyPatch(runId, cveId, checkOnly);
      setResult(r);
    } catch (e: any) {
      setErr(String(e?.message || e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="card">
      <h3>Proposed fix</h3>
      <dl className="kv">
        <dt>Files touched</dt>
        <dd>
          {(fix.files_touched || []).length === 0 ? (
            <span className="muted">none</span>
          ) : (
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              {(fix.files_touched || []).map((f) => (
                <li key={f}>
                  <code>{f}</code>
                </li>
              ))}
            </ul>
          )}
        </dd>
        <dt>Lines</dt>
        <dd>
          <span style={{ color: "#1a7f37" }}>+{fix.lines_added ?? 0}</span>{" "}
          <span style={{ color: "#cf222e" }}>-{fix.lines_removed ?? 0}</span>
        </dd>
        {typeof fix.fix_confidence === "number" && (
          <>
            <dt>Confidence</dt>
            <dd>{(fix.fix_confidence * 100).toFixed(0)}%</dd>
          </>
        )}
        {fix.rationale && (
          <>
            <dt>Rationale</dt>
            <dd>{safeText(fix.rationale)}</dd>
          </>
        )}
      </dl>

      <div className="row" style={{ gap: 8, margin: "8px 0" }}>
        <button disabled={busy !== null} onClick={() => run(true)}>
          {busy === "check" ? "Checking…" : "Preview (git apply --check)"}
        </button>
        <button
          disabled={busy !== null}
          onClick={() => {
            if (
              confirm(
                "Apply this patch to the indexed repo working tree? " +
                  "You can undo with `git restore` / `git checkout -- .` " +
                  "in the repo.",
              )
            ) {
              run(false);
            }
          }}
        >
          {busy === "apply" ? "Applying…" : "Apply to repo"}
        </button>
      </div>

      {err && <div className="error">{err}</div>}
      {result && (
        <div
          className={result.ok ? "" : "error"}
          style={{ margin: "8px 0" }}
        >
          <strong>
            {result.check_only
              ? result.ok
                ? "Patch applies cleanly."
                : "Patch would NOT apply cleanly."
              : result.ok
              ? `Applied to ${result.repo_root}`
              : `Apply failed (rc=${result.returncode})`}
          </strong>
          {result.stderr && (
            <pre style={{ margin: "4px 0", whiteSpace: "pre-wrap" }}>
              {result.stderr}
            </pre>
          )}
          {result.stdout && (
            <pre style={{ margin: "4px 0", whiteSpace: "pre-wrap" }}>
              {result.stdout}
            </pre>
          )}
        </div>
      )}

      <details open>
        <summary className="muted">Unified diff</summary>
        <pre
          style={{
            background: "#0d1117",
            color: "#c9d1d9",
            padding: 12,
            borderRadius: 6,
            overflowX: "auto",
            fontSize: 12,
            lineHeight: 1.45,
          }}
        >
          {diff.split("\n").map((line, i) => {
            let color = "#c9d1d9";
            if (line.startsWith("+++") || line.startsWith("---"))
              color = "#8b949e";
            else if (line.startsWith("@@")) color = "#79c0ff";
            else if (line.startsWith("+")) color = "#3fb950";
            else if (line.startsWith("-")) color = "#f85149";
            return (
              <div key={i} style={{ color, whiteSpace: "pre" }}>
                {line || " "}
              </div>
            );
          })}
        </pre>
      </details>
    </div>
  );
}
