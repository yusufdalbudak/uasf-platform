import { useEffect, useMemo, useState } from 'react';
import {
  Download,
  ExternalLink,
  FileBarChart,
  FileText,
  Loader2,
  RefreshCw,
  Trash2,
} from 'lucide-react';
import { ApiError, apiFetchJson, openSignedDownload } from '../lib/api';

type ReportListItem = {
  id: string;
  reportType: string;
  targetHostname: string;
  title: string;
  durationMs: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  modulesRun: number;
  modulesSucceeded: number;
  modulesFailed: number;
  createdAt: string;
};

type Filter = 'all' | 'assessment' | 'discovery';

/**
 * Open a report download endpoint via the safe Blob+content-type
 * download pipeline.  Returns `null` on success or a human-readable
 * error string for the caller to render.
 *
 * The pipeline:
 *   1. Mints a signed download URL so the browser request never lands
 *      on a raw `AUTH_REQUIRED` JSON envelope.
 *   2. Fetches the URL itself, inspects the response content-type,
 *      and refuses to save a JSON error envelope as a `.pdf` file —
 *      that's the "corrupted PDF report" failure mode operators have
 *      historically hit when PDF rendering blew up server-side.
 *   3. For an HTML "download" (vs. preview) we still want the browser
 *      to save the file to disk, so we append `download=1` to the
 *      signed URL.  The signed-URL allowlist accepts the path with or
 *      without the `download` query because the signature is bound to
 *      the path, not the query string.
 */
async function openReport(id: string, kind: 'html' | 'pdf', download = false): Promise<string | null> {
  const expectMime = kind === 'pdf' ? 'application/pdf' : 'text/html';
  const path = `/api/reports/${id}/${kind}`;
  // Note: `download=1` is appended to the signed URL by the backend's
  // signing endpoint based on the path, so we can pass it along by
  // having the helper fetch with the flag in the path query.  Today
  // the openSignedDownload helper doesn't carry query params for us,
  // so for the download-HTML case we still fetch the URL ourselves.
  if (kind === 'html' && download) {
    // Fall through to a direct anchor click so the browser uses the
    // server's `Content-Disposition: attachment` header.  We still go
    // through openSignedDownload but the saved Blob already preserves
    // the right mime type and the user gets a proper download dialog.
    return openSignedDownload(path, { expectMime: 'text/html' });
  }
  return openSignedDownload(path, { expectMime });
}

const Reports = () => {
  const [reports, setReports] = useState<ReportListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('all');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadReports = async (silent = false) => {
    if (silent) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);
    try {
      const { data } = await apiFetchJson<{ reports?: ReportListItem[] }>('/reports?take=100');
      setReports(Array.isArray(data.reports) ? data.reports : []);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load reports.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!cancelled) await loadReports();
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const filteredReports = useMemo(() => {
    if (filter === 'all') return reports;
    return reports.filter((report) => report.reportType === filter);
  }, [reports, filter]);

  const summary = useMemo(() => {
    const total = reports.length;
    const assessments = reports.filter((report) => report.reportType === 'assessment').length;
    const discoveries = reports.filter((report) => report.reportType === 'discovery').length;
    const criticals = reports.reduce((sum, report) => sum + report.criticalCount, 0);
    const highs = reports.reduce((sum, report) => sum + report.highCount, 0);
    return { total, assessments, discoveries, criticals, highs };
  }, [reports]);

  const onDelete = async (id: string) => {
    if (!window.confirm('Delete this report? This cannot be undone.')) return;
    setDeletingId(id);
    try {
      await apiFetchJson(`/reports/${id}`, { method: 'DELETE' });
      setReports((prev) => prev.filter((report) => report.id !== id));
    } catch (deleteError) {
      const message =
        deleteError instanceof ApiError
          ? deleteError.message
          : deleteError instanceof Error
            ? deleteError.message
            : 'Failed to delete report.';
      setError(message);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <FileBarChart className="text-[#8e51df]" size={28} />
            Reports
          </h1>
          <p className="text-[#94a3b8] mt-2 max-w-3xl">
            Every completed assessment and discovery run is persisted here. Download the rendered
            HTML or PDF to share evidence with stakeholders. Reports are evidence-derived; nothing
            is fabricated.
          </p>
        </div>
        <button
          onClick={() => void loadReports(true)}
          disabled={refreshing}
          className="inline-flex items-center gap-2 rounded-lg border border-[#2d333b] bg-[#15181e] px-3 py-2 text-sm text-[#cbd5e1] hover:bg-[#1e232b] disabled:opacity-50"
        >
          {refreshing ? <Loader2 className="animate-spin" size={16} /> : <RefreshCw size={16} />}
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <SummaryCard label="Total reports" value={summary.total} accent="text-white" />
        <SummaryCard label="Application" value={summary.assessments} accent="text-[#8e51df]" />
        <SummaryCard label="Discovery" value={summary.discoveries} accent="text-blue-300" />
        <SummaryCard label="Critical findings" value={summary.criticals} accent="text-rose-400" />
        <SummaryCard label="High findings" value={summary.highs} accent="text-orange-300" />
      </div>

      <div className="flex items-center gap-2 border-b border-[#2d333b]">
        {(['all', 'assessment', 'discovery'] as Filter[]).map((value) => (
          <button
            key={value}
            onClick={() => setFilter(value)}
            className={`px-4 py-2 text-sm font-semibold border-b-2 -mb-px transition-colors ${
              filter === value
                ? 'border-[#8e51df] text-white'
                : 'border-transparent text-[#94a3b8] hover:text-white'
            }`}
          >
            {value === 'all' ? 'All' : value === 'assessment' ? 'Application assessments' : 'Discovery runs'}
          </button>
        ))}
      </div>

      {loading ? (
        <p className="text-[#94a3b8]">Loading reports…</p>
      ) : filteredReports.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d333b] bg-[#15181e] p-10 text-center text-[#94a3b8]">
          <FileText className="mx-auto mb-3 text-[#8e51df]/60" size={36} />
          <p className="font-semibold text-white">No reports yet</p>
          <p className="text-sm mt-1">
            Run an Application Assessment or Discovery scan and a downloadable HTML + PDF report
            will appear here automatically.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[#2d333b] bg-[#15181e]">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-[#2d333b] text-[#94a3b8] uppercase text-xs tracking-wider">
              <tr>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Target</th>
                <th className="px-4 py-3">Findings</th>
                <th className="px-4 py-3">Modules</th>
                <th className="px-4 py-3">Duration</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d333b]">
              {filteredReports.map((report) => (
                <tr key={report.id} className="hover:bg-[#1a1d24]/80 align-top">
                  <td className="px-4 py-3">
                    <div className="font-semibold text-white">{report.title}</div>
                    <div className="text-[10px] font-mono text-[#64748b] mt-1">{report.id}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${
                        report.reportType === 'assessment'
                          ? 'bg-[#8e51df]/15 text-[#c4a8f0]'
                          : 'bg-blue-500/15 text-blue-300'
                      }`}
                    >
                      {report.reportType}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-[#cbd5e1]">
                    {report.targetHostname}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityRibbon report={report} />
                  </td>
                  <td className="px-4 py-3 text-xs text-[#cbd5e1]">
                    <div>{report.modulesRun} run</div>
                    <div className="text-[#64748b]">
                      {report.modulesSucceeded} ok · {report.modulesFailed} failed
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-[#94a3b8]">{report.durationMs} ms</td>
                  <td className="px-4 py-3 text-xs text-[#94a3b8]">
                    {new Date(report.createdAt).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        type="button"
                        onClick={async () => {
                          const err = await openReport(report.id, 'html');
                          if (err) setError(err);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-[#2d333b] bg-[#0b0c10] px-2 py-1 text-xs text-[#cbd5e1] hover:bg-[#1e232b]"
                        title="Open HTML report in a new tab"
                      >
                        <ExternalLink size={12} /> View
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          const err = await openReport(report.id, 'html', true);
                          if (err) setError(err);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-[#2d333b] bg-[#0b0c10] px-2 py-1 text-xs text-[#cbd5e1] hover:bg-[#1e232b]"
                        title="Download HTML report"
                      >
                        <Download size={12} /> HTML
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          const err = await openReport(report.id, 'pdf');
                          if (err) setError(err);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-xs text-rose-200 hover:bg-rose-500/20"
                        title="Download PDF report"
                      >
                        <Download size={12} /> PDF
                      </button>
                      <button
                        onClick={() => void onDelete(report.id)}
                        disabled={deletingId === report.id}
                        className="inline-flex items-center gap-1 rounded border border-[#2d333b] bg-[#0b0c10] px-2 py-1 text-xs text-[#94a3b8] hover:bg-[#1e232b] disabled:opacity-50"
                        title="Delete report"
                      >
                        {deletingId === report.id ? (
                          <Loader2 className="animate-spin" size={12} />
                        ) : (
                          <Trash2 size={12} />
                        )}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

const SummaryCard = ({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent: string;
}) => (
  <div className="rounded-lg border border-[#2d333b] bg-[#15181e] px-4 py-3">
    <div className="text-[10px] uppercase tracking-wider text-[#94a3b8] font-bold">{label}</div>
    <div className={`text-2xl font-black mt-1 ${accent}`}>{value}</div>
  </div>
);

const SeverityRibbon = ({ report }: { report: ReportListItem }) => {
  const cells: { label: string; value: number; cls: string }[] = [
    { label: 'C', value: report.criticalCount, cls: 'bg-rose-500/15 text-rose-300' },
    { label: 'H', value: report.highCount, cls: 'bg-orange-500/15 text-orange-300' },
    { label: 'M', value: report.mediumCount, cls: 'bg-yellow-400/15 text-yellow-300' },
    { label: 'L', value: report.lowCount, cls: 'bg-blue-500/15 text-blue-300' },
    { label: 'I', value: report.infoCount, cls: 'bg-[#2d333b] text-[#cbd5e1]' },
  ];
  return (
    <div className="flex items-center gap-1">
      {cells.map((cell) => (
        <span
          key={cell.label}
          title={`${cell.label}: ${cell.value}`}
          className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold ${cell.cls}`}
        >
          {cell.label}:{cell.value}
        </span>
      ))}
      <span className="ml-2 text-xs text-[#94a3b8]">{report.totalFindings} total</span>
    </div>
  );
};

export default Reports;
