import { useState } from "react";
import { api } from "../api";

export default function JenkinsPage() {
  const [sbomPath, setSbomPath] = useState("");
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function trigger() {
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.jenkinsTrigger({ sbom_path: sbomPath || undefined });
      setResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <h2>Jenkins</h2>
      <div className="card">
        <p className="muted" style={{ marginTop: 0 }}>
          Submit an SBOM (BOM) file to a Jenkins job. The actual trigger
          integration will be added later — for now this records the request
          and returns a ticket id.
        </p>
        <label>SBOM file path (optional)</label>
        <input
          value={sbomPath}
          onChange={(e) => setSbomPath(e.target.value)}
          placeholder="/path/to/bom.yaml"
          style={{ width: "100%" }}
        />
        <div className="row" style={{ marginTop: 12 }}>
          <button
            className="primary"
            onClick={trigger}
            disabled={submitting}
          >
            {submitting ? "Submitting…" : "🛠 Trigger Jenkins job"}
          </button>
        </div>
        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
        {result && (
          <div className="success-banner" style={{ marginTop: 12 }}>
            Queued ticket <code>{result.ticket}</code> · state {result.state}
          </div>
        )}
      </div>
    </div>
  );
}
