import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import type { CVERow, Verdict } from "../types";
import VerdictBadge, { VERDICT_LABELS } from "../components/VerdictBadge";
import ProgressBar from "../components/ProgressBar";
import EventTimeline from "../components/EventTimeline";
import { useEventStream } from "../hooks/useEventStream";

interface RunEnvelope {
  run_id: string;
  status: { state?: string; started_at?: number; ended_at?: number } | null;
  artifact: any;
}

type CVELive = {
  cve_id: string;
  verdict?: string;
  component?: string;
  severity?: string;
  state?: "queued" | "running" | "completed" | "failed";
};

const TAB_ORDER: Verdict[] = [
  "package_upgrade",
  "code_change",
  "needs_human",
  "not_applicable",
];

function isCancellable(
  run: RunEnvelope | null,
  events: Array<{ event: string }>,
): boolean {
  // A run is cancellable while it is still running (i.e. we haven't
  // observed a terminal event and the registry hasn't transitioned to
  // a non-running state).
  const state = run?.status?.state;
  if (state && state !== "running") return false;
  const terminal = events.some(
    (e) => e.event === "run.completed" || e.event === "run.failed",
  );
  return !terminal;
}

export default function RunDetail() {
  const { runId } = useParams();
  const [run, setRun] = useState<RunEnvelope | null>(null);
  const [rest, setRest] = useState<CVERow[]>([]);
  const [activeTab, setActiveTab] = useState<Verdict | "all">("all");
  const [cancelState, setCancelState] = useState<
    "idle" | "pending" | "requested" | "failed"
  >("idle");
  const [cancelError, setCancelError] = useState<string | null>(null);
  const { events, connected, error } = useEventStream(runId);

  // Poll the run summary
  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    function load() {
      api.getRun(runId!).then(
        (r) => !cancelled && setRun(r),
        () => {},
      );
      api.getRunCVEs(runId!).then(
        (rs) => !cancelled && setRest(rs),
        () => {},
      );
    }
    load();
    const id = setInterval(load, 4000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [runId]);

  // Derive a live CVE table from events + REST snapshot
  const cves = useMemo(() => {
    const map = new Map<string, CVELive>();
    for (const c of rest) {
      map.set(c.cve_id, {
        cve_id: c.cve_id,
        verdict: c.verdict,
        component: c.component,
        severity: c.severity,
        state: c.state as CVELive["state"],
      });
    }
    for (const ev of events) {
      const d = ev.data || {};
      const cve = (d as any).cve_id;
      if (!cve) continue;
      const cur: CVELive = map.get(cve) || { cve_id: cve, verdict: "unknown" };
      if (ev.event === "cve.queued") cur.state = "queued";
      if (ev.event === "cve.started") cur.state = "running";
      if (ev.event === "cve.completed") {
        cur.state = "completed";
        // Orchestrator emits `final_verdict`; older builds used `verdict`.
        const v = (d as any).final_verdict ?? (d as any).verdict;
        if (v) cur.verdict = v;
      }
      if (ev.event === "cve.failed") cur.state = "failed";
      if ((d as any).component && !cur.component)
        cur.component = (d as any).component;
      if ((d as any).severity && !cur.severity)
        cur.severity = (d as any).severity;
      map.set(cve, cur);
    }
    return Array.from(map.values()).sort((a, b) =>
      a.cve_id.localeCompare(b.cve_id),
    );
  }, [rest, events]);

  // Determine total CVEs even when no run.total event has fired yet.
  // We pick the max of: queued count, run payload limit, current cve set size.
  const queued = cves.filter((c) => !!c.state).length;
  const total = useMemo(() => {
    // Prefer an explicit RUN_STARTED total
    const startEv = events.find((e) => e.event === "run.started");
    const fromStart = startEv && (startEv.data as any)?.total;
    if (typeof fromStart === "number" && fromStart > 0) return fromStart;
    // Otherwise: number of cve.queued events we've ever seen
    const queuedSet = new Set<string>();
    for (const ev of events) {
      if (ev.event === "cve.queued") {
        const c = (ev.data as any).cve_id;
        if (c) queuedSet.add(c);
      }
    }
    if (queuedSet.size) return queuedSet.size;
    return cves.length;
  }, [events, cves.length, queued]);

  const done = cves.filter(
    (c) => c.state === "completed" || c.state === "failed",
  ).length;

  // Group by verdict for tabs
  const grouped: Record<string, CVELive[]> = {
    package_upgrade: [],
    code_change: [],
    needs_human: [],
    not_applicable: [],
    unknown: [],
  };
  for (const c of cves) {
    const v = (c.verdict || "unknown").toLowerCase();
    (grouped[v] ?? grouped.unknown).push(c);
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <Link to="/">← Runs</Link>
          <h2 style={{ margin: "8px 0" }}>
            <code>{runId}</code>
          </h2>
          <div className="row muted">
            <span>
              Status:{" "}
              <strong style={{ color: "var(--fg)" }}>
                {run?.status?.state ?? (run?.artifact ? "archived" : "—")}
              </strong>
            </span>
            <span>·</span>
            <span>WS: {connected ? "🟢 connected" : "⚪ idle"}</span>
            {error && <span className="error" style={{ padding: "2px 8px" }}>{error}</span>}
          </div>
        </div>
        <div className="row">
          <button
            className="danger"
            disabled={
              cancelState === "pending" ||
              cancelState === "requested" ||
              !runId ||
              !isCancellable(run, events)
            }
            title={
              isCancellable(run, events)
                ? "Stop / terminate this run"
                : "Run is no longer active"
            }
            onClick={async () => {
              if (!runId) return;
              setCancelState("pending");
              setCancelError(null);
              try {
                await api.cancelRun(runId);
                setCancelState("requested");
              } catch (e) {
                setCancelError(String(e));
                setCancelState("failed");
              }
            }}
          >
            {cancelState === "requested"
              ? "Stop requested…"
              : cancelState === "pending"
              ? "Stopping…"
              : "⏹ Stop run"}
          </button>
          <a
            href={api.reportXlsxUrl(runId!)}
            target="_blank"
            rel="noreferrer"
          >
            <button>⬇ Download Excel report</button>
          </a>
        </div>
      </div>
      {cancelError && <div className="error">{cancelError}</div>}

      <div className="card">
        <ProgressBar
          done={done}
          total={total}
          label={`Analyzing CVEs (${done} done of ${total})`}
        />
        <div className="row" style={{ marginTop: 12 }}>
          {TAB_ORDER.map((v) => (
            <span key={v} className={`badge ${v}`}>
              {VERDICT_LABELS[v]}: {grouped[v]?.length ?? 0}
            </span>
          ))}
          {grouped.unknown.length > 0 && (
            <span className="badge unknown">
              Pending: {grouped.unknown.length}
            </span>
          )}
        </div>
      </div>

      <div className="tabs">
        <button
          className={`tab ${activeTab === "all" ? "active" : ""}`}
          onClick={() => setActiveTab("all")}
        >
          All <span className="count">{cves.length}</span>
        </button>
        {TAB_ORDER.map((v) => (
          <button
            key={v}
            className={`tab ${activeTab === v ? "active" : ""}`}
            onClick={() => setActiveTab(v)}
          >
            {VERDICT_LABELS[v]}{" "}
            <span className="count">{grouped[v]?.length ?? 0}</span>
          </button>
        ))}
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <CVETable
          rows={
            activeTab === "all" ? cves : (grouped[activeTab] || []).slice()
          }
          runId={runId!}
        />
      </div>

      <div className="card">
        <h3>Event timeline</h3>
        <EventTimeline events={events} />
      </div>
    </div>
  );
}

function CVETable({ rows, runId }: { rows: CVELive[]; runId: string }) {
  if (!rows.length) return <div className="empty">No CVEs in this group.</div>;
  return (
    <table>
      <thead>
        <tr>
          <th>CVE</th>
          <th>Component</th>
          <th>Severity</th>
          <th>State</th>
          <th>Verdict</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((c) => (
          <tr
            key={c.cve_id}
            style={{ cursor: "pointer" }}
            onClick={(e) => {
              // ignore clicks on the link itself
              if ((e.target as HTMLElement).tagName === "A") return;
              window.location.href = `/runs/${runId}/cves/${c.cve_id}`;
            }}
          >
            <td>
              <Link to={`/runs/${runId}/cves/${c.cve_id}`}>
                <code>{c.cve_id}</code>
              </Link>
            </td>
            <td>{c.component || "—"}</td>
            <td>{c.severity || "—"}</td>
            <td>
              <span className="muted">{c.state || "—"}</span>
            </td>
            <td>
              <VerdictBadge verdict={c.verdict} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
