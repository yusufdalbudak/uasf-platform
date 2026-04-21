/**
 * UASF — External Attack Surface Management Dashboard
 *
 * Cover page for the platform that consolidates the same data the
 * Executive Summary report (HTML / PDF) is built from.  Single shared
 * view-model means the dashboard tile and the PDF cover can never
 * disagree.
 */

import { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Boxes,
  Bug,
  ChevronRight,
  Download,
  ExternalLink,
  FileText,
  Globe,
  Loader2,
  RefreshCw,
  Server,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { apiFetchJson, openSignedDownload } from '../lib/api';

type SeverityLabel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

interface SeverityCount {
  label: SeverityLabel;
  count: number;
}

interface MetricTile {
  label: string;
  value: number;
  delta: number | null;
  subline: string;
}

interface ScoreSummary {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  weights: Record<SeverityLabel, number>;
  summary: string;
}

interface TopAssetRow {
  hostname: string;
  assetType: string;
  rating: 'A' | 'B' | 'C' | 'D' | 'F';
  ratingScore: number;
  issues: number;
  technologies: number;
}

interface TopIssueRow {
  title: string;
  severity: SeverityLabel;
  category: string;
  assetCount: number;
}

interface TopTechnologyRow {
  productKey: string;
  productName: string;
  category: string;
  vendor: string | null;
  version: string | null;
  versionFamily: string | null;
  assetCount: number;
  vulnerabilityCount: number;
}

interface TimelineBucket {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface EasmOverview {
  generatedAt: string;
  window: { from: string; to: string };
  tiles: {
    assets: MetricTile;
    technologies: MetricTile;
    issues: MetricTile;
    vulnerabilities: MetricTile;
  };
  score: ScoreSummary;
  timeline: TimelineBucket[];
  assets: {
    total: number;
    domains: number;
    subdomains: number;
    ipAddresses: number;
    byType: Array<{ type: string; count: number }>;
    top: TopAssetRow[];
  };
  issues: {
    total: number;
    bySeverity: SeverityCount[];
    byCategory: Array<{ category: string; count: number }>;
    mostCritical: TopIssueRow[];
    mostSeen: TopIssueRow[];
  };
  technologies: {
    total: number;
    byCategory: Array<{ category: string; count: number }>;
    mostUsed: TopTechnologyRow[];
    mostVulnerable: TopTechnologyRow[];
  };
  vulnerabilities: {
    total: number;
    bySeverity: SeverityCount[];
  };
}

const SEV_COLOR: Record<SeverityLabel, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6',
  Info: '#6b7280',
};

const GRADE_COLOR: Record<'A' | 'B' | 'C' | 'D' | 'F', string> = {
  A: '#10b981',
  B: '#22c55e',
  C: '#eab308',
  D: '#f97316',
  F: '#dc2626',
};

const TILE_ICONS: Record<string, JSX.Element> = {
  assets: <Server size={18} />,
  technologies: <Boxes size={18} />,
  issues: <AlertTriangle size={18} />,
  vulnerabilities: <Bug size={18} />,
};

export default function EasmDashboard(): JSX.Element {
  const [overview, setOverview] = useState<EasmOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async (mode: 'first' | 'refresh' = 'first') => {
    if (mode === 'refresh') setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const { data } = await apiFetchJson<EasmOverview>('/easm/overview');
      setOverview(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load EASM overview');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void load('first');
  }, []);

  const downloadReport = async (kind: 'html' | 'pdf') => {
    const path = kind === 'pdf' ? '/api/easm/report.pdf' : '/api/easm/report.html';
    const err = await openSignedDownload(path, {
      expectMime: kind === 'pdf' ? 'application/pdf' : 'text/html',
      filename: `uasf-easm-executive-summary.${kind}`,
    });
    if (err) setError(err);
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-[#94a3b8]">
        <Loader2 size={28} className="animate-spin mb-3" />
        <p className="text-sm">Building executive overview…</p>
      </div>
    );
  }

  if (!overview) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-[#94a3b8]">
        <AlertTriangle size={32} className="mb-3 opacity-40" />
        <p className="text-sm">{error ?? 'No data available.'}</p>
        <button
          type="button"
          onClick={() => void load('first')}
          className="mt-4 px-4 py-1.5 rounded bg-[#6a2bba] hover:bg-[#7a31d0] text-white text-sm transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-3">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 rounded-md bg-gradient-to-br from-[#8e51df] to-[#4d1c8c] flex items-center justify-center">
              <Globe size={18} className="text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">
              External Attack Surface Management
            </h1>
          </div>
          <p className="text-sm text-[#94a3b8]">
            Aggregated executive view of every approved asset — assets, technologies, issues, and
            vulnerabilities. Generated{' '}
            <span className="text-[#cbd5e1]">{new Date(overview.generatedAt).toLocaleString()}</span>
            .
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void load('refresh')}
            disabled={refreshing}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-md bg-[#1a1d24] border border-[#2d333b] hover:bg-[#222730] text-sm text-[#dbe4f0] transition-colors disabled:opacity-50"
          >
            <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} /> Refresh
          </button>
          <button
            type="button"
            onClick={() => void downloadReport('html')}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-md bg-[#1a1d24] border border-[#2d333b] hover:bg-[#222730] text-sm text-[#dbe4f0] transition-colors"
          >
            <ExternalLink size={14} /> Open HTML
          </button>
          <button
            type="button"
            onClick={() => void downloadReport('pdf')}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-md bg-[#6a2bba] hover:bg-[#7a31d0] text-sm text-white transition-colors"
          >
            <Download size={14} /> Executive PDF
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-red-700/50 bg-red-950/40 px-3 py-2 text-sm text-red-200">
          {error}
        </div>
      )}

      {/* Top row — score + 4 tiles */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <ScoreCard score={overview.score} className="lg:col-span-4" />
        <div className="lg:col-span-8 grid grid-cols-2 gap-3">
          <Tile icon={TILE_ICONS.assets} tile={overview.tiles.assets} accent="#22c55e" />
          <Tile icon={TILE_ICONS.technologies} tile={overview.tiles.technologies} accent="#3b82f6" />
          <Tile icon={TILE_ICONS.issues} tile={overview.tiles.issues} accent="#f97316" />
          <Tile
            icon={TILE_ICONS.vulnerabilities}
            tile={overview.tiles.vulnerabilities}
            accent="#ef4444"
          />
        </div>
      </div>

      {/* Timeline */}
      <Card
        title="Issue volume — last 14 days"
        subtitle="Daily critical / high / medium / low rollup from your reports"
      >
        <div className="h-[180px] -mx-2">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={overview.timeline}
              margin={{ top: 6, right: 12, left: 0, bottom: 6 }}
            >
              <CartesianGrid stroke="#2d333b" vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fill: '#94a3b8', fontSize: 10 }}
                tickFormatter={(d: string) => d.slice(5)}
                axisLine={{ stroke: '#2d333b' }}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#94a3b8', fontSize: 10 }}
                axisLine={{ stroke: '#2d333b' }}
                tickLine={false}
                allowDecimals={false}
                width={28}
              />
              <RechartsTooltip
                contentStyle={{
                  background: '#15181e',
                  border: '1px solid #2d333b',
                  fontSize: 12,
                  borderRadius: 8,
                }}
                labelStyle={{ color: '#cbd5e1' }}
              />
              <Bar dataKey="low" stackId="s" fill={SEV_COLOR.Low} radius={[0, 0, 0, 0]} />
              <Bar dataKey="medium" stackId="s" fill={SEV_COLOR.Medium} />
              <Bar dataKey="high" stackId="s" fill={SEV_COLOR.High} />
              <Bar dataKey="critical" stackId="s" fill={SEV_COLOR.Critical} radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      {/* Assets section */}
      <SectionTitle icon={<Server size={16} />} title="Assets" total={overview.assets.total} />
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <Card title="Asset surface" className="lg:col-span-4">
          <div className="grid grid-cols-2 gap-3">
            <MiniStat label="Domains" value={overview.assets.domains} />
            <MiniStat label="Subdomains" value={overview.assets.subdomains} />
            <MiniStat label="IP addresses" value={overview.assets.ipAddresses} />
            <MiniStat label="Approved total" value={overview.assets.total} />
          </div>
          <div className="mt-3">
            <div className="text-[10px] uppercase tracking-wider text-[#94a3b8] mb-1.5">
              Asset types
            </div>
            <ChipRow
              items={overview.assets.byType.map((b) => ({ label: b.type, count: b.count }))}
            />
          </div>
        </Card>
        <Card title="Top assets by risk" className="lg:col-span-8">
          {overview.assets.top.length === 0 ? (
            <Empty label="No approved assets registered yet." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wider text-[#94a3b8] border-b border-[#2d333b]">
                  <th className="py-2 pr-2">Hostname</th>
                  <th className="py-2 pr-2">Type</th>
                  <th className="py-2 pr-2 text-right">Issues</th>
                  <th className="py-2 pr-2 text-right">Tech</th>
                  <th className="py-2 pr-2 text-right">Score</th>
                  <th className="py-2 pr-2 text-right">Rating</th>
                </tr>
              </thead>
              <tbody>
                {overview.assets.top.map((a) => (
                  <tr
                    key={a.hostname}
                    className="border-b border-[#2d333b]/60 last:border-0 hover:bg-[#222730]/40"
                  >
                    <td className="py-2 pr-2 font-mono text-xs text-[#dbe4f0]">{a.hostname}</td>
                    <td className="py-2 pr-2 text-[#94a3b8]">{a.assetType}</td>
                    <td className="py-2 pr-2 text-right text-[#dbe4f0]">{a.issues}</td>
                    <td className="py-2 pr-2 text-right text-[#dbe4f0]">{a.technologies}</td>
                    <td className="py-2 pr-2 text-right text-[#dbe4f0]">{a.ratingScore}</td>
                    <td className="py-2 pr-2 text-right">
                      <GradeBadge grade={a.rating} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {/* Issues section */}
      <SectionTitle
        icon={<AlertTriangle size={16} />}
        title="Issues"
        total={overview.issues.total}
      />
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <Card title="Severity distribution" className="lg:col-span-4">
          <SeverityBar rows={overview.issues.bySeverity} total={overview.issues.total} />
          <div className="mt-3">
            <div className="text-[10px] uppercase tracking-wider text-[#94a3b8] mb-1.5">
              By category
            </div>
            <ChipRow
              items={overview.issues.byCategory.map((b) => ({
                label: b.category,
                count: b.count,
              }))}
            />
          </div>
        </Card>
        <Card title="Most critical issues" className="lg:col-span-8">
          <IssueTable rows={overview.issues.mostCritical} />
        </Card>
        <Card title="Most seen issues" className="lg:col-span-12">
          <IssueTable rows={overview.issues.mostSeen} />
        </Card>
      </div>

      {/* Technologies section */}
      <SectionTitle
        icon={<Boxes size={16} />}
        title="Technologies"
        total={overview.technologies.total}
      />
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <Card title="By category" className="lg:col-span-4">
          <ChipRow
            items={overview.technologies.byCategory.map((b) => ({
              label: prettyCategory(b.category),
              count: b.count,
            }))}
          />
        </Card>
        <Card title="Most identified" className="lg:col-span-8">
          <TechTable rows={overview.technologies.mostUsed} />
        </Card>
        <Card title="Most vulnerable" className="lg:col-span-12">
          <TechTable rows={overview.technologies.mostVulnerable} />
        </Card>
      </div>

      {/* Vulnerabilities section */}
      <SectionTitle
        icon={<Bug size={16} />}
        title="Vulnerabilities"
        total={overview.vulnerabilities.total}
      />
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <Card title="Severity distribution" className="lg:col-span-12">
          <SeverityBar
            rows={overview.vulnerabilities.bySeverity}
            total={overview.vulnerabilities.total}
          />
          <p className="mt-3 text-xs text-[#94a3b8] leading-relaxed">
            Vulnerability counts combine CVE/advisory correlations from detected technologies (mycve
            + OSV.dev) with cached dependency advisories (NVD). Where the local feed could not
            assert version applicability the correlation is reported with hedged certainty rather
            than dropped.
          </p>
        </Card>
      </div>

      <Card title="Generate executive deliverables" className="bg-gradient-to-br from-[#1a1d24] to-[#181e30]">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <Deliverable
            icon={<FileText size={18} />}
            title="Open HTML report"
            description="Inline preview of the full Executive Summary in a new tab."
            cta="Open"
            onClick={() => void downloadReport('html')}
          />
          <Deliverable
            icon={<Download size={18} />}
            title="Download PDF report"
            description="7-page executive summary, formatted for board-level distribution."
            cta="Download"
            onClick={() => void downloadReport('pdf')}
          />
          <Deliverable
            icon={<Sparkles size={18} />}
            title="Refresh aggregations"
            description="Re-run the executive aggregator without re-scanning any asset."
            cta="Refresh"
            onClick={() => void load('refresh')}
          />
        </div>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reusable building blocks
// ---------------------------------------------------------------------------

function Tile({
  icon,
  tile,
  accent,
}: {
  icon?: JSX.Element;
  tile: MetricTile;
  accent: string;
}): JSX.Element {
  return (
    <div className="rounded-xl border border-[#2d333b] bg-[#15181e] p-4 flex flex-col">
      <div className="flex items-center justify-between mb-1">
        <div
          className="w-7 h-7 rounded flex items-center justify-center"
          style={{ background: `${accent}22`, color: accent }}
        >
          {icon}
        </div>
        <span className="text-[10px] uppercase tracking-wider text-[#94a3b8]">{tile.label}</span>
      </div>
      <div className="text-3xl font-bold text-white leading-tight">
        {tile.value.toLocaleString('en-US')}
      </div>
      <div className="mt-1 flex items-center gap-2">
        {tile.delta !== null && tile.delta > 0 && (
          <span
            className="text-[10px] px-1.5 py-0.5 rounded-full"
            style={{ background: `${accent}22`, color: accent }}
          >
            +{tile.delta}
          </span>
        )}
        <span className="text-[11px] text-[#94a3b8]">{tile.subline}</span>
      </div>
    </div>
  );
}

function ScoreCard({
  score,
  className,
}: {
  score: ScoreSummary;
  className?: string;
}): JSX.Element {
  const color = GRADE_COLOR[score.grade];
  return (
    <div
      className={`rounded-xl border border-[#2d333b] bg-gradient-to-br from-[#1a1d24] to-[#181e30] p-5 flex flex-col items-center text-center ${className ?? ''}`}
    >
      <div className="text-[10px] uppercase tracking-wider text-[#94a3b8] mb-3">
        Security score
      </div>
      <div className="relative">
        <div
          className="w-28 h-28 rounded-full flex items-center justify-center text-5xl font-extrabold text-white shadow-lg"
          style={{ background: color }}
        >
          {score.grade}
        </div>
        <div
          className="absolute -bottom-2 left-1/2 -translate-x-1/2 px-3 py-0.5 rounded-full text-xs font-bold"
          style={{ background: '#0f1115', border: `1px solid ${color}`, color }}
        >
          {score.score}
        </div>
      </div>
      <p className="mt-5 text-xs text-[#dbe4f0] leading-relaxed max-w-[280px]">{score.summary}</p>
      <div className="mt-3 text-[10px] text-[#94a3b8] uppercase tracking-wider">
        Scale: 0 — 1000 (higher is better)
      </div>
    </div>
  );
}

function Card({
  title,
  subtitle,
  children,
  className,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  className?: string;
}): JSX.Element {
  return (
    <section
      className={`rounded-xl border border-[#2d333b] bg-[#15181e] p-4 ${className ?? ''}`}
    >
      <header className="mb-3 flex items-baseline justify-between gap-3">
        <h3 className="text-sm font-semibold text-white">{title}</h3>
        {subtitle && <span className="text-[11px] text-[#94a3b8]">{subtitle}</span>}
      </header>
      {children}
    </section>
  );
}

function SectionTitle({
  icon,
  title,
  total,
}: {
  icon: JSX.Element;
  title: string;
  total: number;
}): JSX.Element {
  return (
    <div className="flex items-center gap-2 pt-2">
      <span className="text-[#8e51df]">{icon}</span>
      <h2 className="text-base font-semibold text-white">{title}</h2>
      <span className="text-xs text-[#94a3b8]">({total.toLocaleString('en-US')})</span>
      <ChevronRight size={14} className="text-[#475569]" />
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: number }): JSX.Element {
  return (
    <div className="rounded-md border border-[#2d333b] bg-[#11141a] px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-[#94a3b8]">{label}</div>
      <div className="text-lg font-bold text-white">{value.toLocaleString('en-US')}</div>
    </div>
  );
}

function ChipRow({ items }: { items: Array<{ label: string; count: number }> }): JSX.Element {
  if (items.length === 0)
    return <div className="text-xs text-[#94a3b8] italic">No data.</div>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((it) => (
        <span
          key={`${it.label}-${it.count}`}
          className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-[#6a2bba]/15 text-[#c4b5fd] text-[11px]"
        >
          <span>{prettyCategory(it.label)}</span>
          <span className="bg-[#6a2bba]/40 text-white rounded-full px-1.5 text-[10px]">
            {it.count}
          </span>
        </span>
      ))}
    </div>
  );
}

function SeverityBar({
  rows,
  total,
}: {
  rows: SeverityCount[];
  total: number;
}): JSX.Element {
  if (total === 0) {
    return <Empty label="No findings recorded." />;
  }
  return (
    <div>
      <div className="flex h-3 rounded-full overflow-hidden bg-[#0b0c10]">
        {rows.map((r) =>
          r.count === 0 ? null : (
            <div
              key={r.label}
              style={{ flex: r.count, background: SEV_COLOR[r.label] }}
              title={`${r.label}: ${r.count}`}
            />
          ),
        )}
      </div>
      <div className="mt-3 flex flex-wrap gap-3 text-xs">
        {rows.map((r) => (
          <div key={r.label} className="inline-flex items-center gap-1.5 text-[#cbd5e1]">
            <span
              className="inline-block w-2.5 h-2.5 rounded-sm"
              style={{ background: SEV_COLOR[r.label] }}
            />
            <span className="text-[#dbe4f0] font-medium">{r.label}</span>
            <span className="text-[#94a3b8]">{r.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function GradeBadge({ grade }: { grade: 'A' | 'B' | 'C' | 'D' | 'F' }): JSX.Element {
  return (
    <span
      className="inline-block min-w-[24px] px-2 py-0.5 rounded font-bold text-white text-xs"
      style={{ background: GRADE_COLOR[grade] }}
    >
      {grade}
    </span>
  );
}

function IssueTable({ rows }: { rows: TopIssueRow[] }): JSX.Element {
  if (rows.length === 0) return <Empty label="No issues observed yet." />;
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-[10px] uppercase tracking-wider text-[#94a3b8] border-b border-[#2d333b]">
          <th className="py-2 pr-2">Issue</th>
          <th className="py-2 pr-2">Category</th>
          <th className="py-2 pr-2 text-right">Assets</th>
          <th className="py-2 pr-2">Severity</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((i) => (
          <tr
            key={i.title}
            className="border-b border-[#2d333b]/60 last:border-0 hover:bg-[#222730]/40"
          >
            <td className="py-2 pr-2 text-[#dbe4f0]">{i.title}</td>
            <td className="py-2 pr-2 text-[#94a3b8]">{i.category}</td>
            <td className="py-2 pr-2 text-right text-[#dbe4f0]">{i.assetCount}</td>
            <td className="py-2 pr-2">
              <SeverityChip severity={i.severity} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TechTable({ rows }: { rows: TopTechnologyRow[] }): JSX.Element {
  if (rows.length === 0) return <Empty label="No technologies fingerprinted yet." />;
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-[10px] uppercase tracking-wider text-[#94a3b8] border-b border-[#2d333b]">
          <th className="py-2 pr-2">Technology</th>
          <th className="py-2 pr-2">Category</th>
          <th className="py-2 pr-2">Version</th>
          <th className="py-2 pr-2 text-right">Assets</th>
          <th className="py-2 pr-2 text-right">Vulns</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((t) => (
          <tr
            key={t.productKey}
            className="border-b border-[#2d333b]/60 last:border-0 hover:bg-[#222730]/40"
          >
            <td className="py-2 pr-2">
              <div className="text-[#dbe4f0] font-medium">{t.productName}</div>
              {t.vendor && <div className="text-[10px] text-[#94a3b8]">{t.vendor}</div>}
            </td>
            <td className="py-2 pr-2 text-[#94a3b8]">{prettyCategory(t.category)}</td>
            <td className="py-2 pr-2 font-mono text-xs text-[#dbe4f0]">
              {t.version ?? t.versionFamily ?? '—'}
            </td>
            <td className="py-2 pr-2 text-right text-[#dbe4f0]">{t.assetCount}</td>
            <td className="py-2 pr-2 text-right">
              <span
                className={`px-1.5 py-0.5 rounded text-xs ${
                  t.vulnerabilityCount > 0
                    ? 'bg-red-500/15 text-red-300'
                    : 'text-[#94a3b8]'
                }`}
              >
                {t.vulnerabilityCount}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SeverityChip({ severity }: { severity: SeverityLabel }): JSX.Element {
  const color = SEV_COLOR[severity];
  return (
    <span
      className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider"
      style={{ background: `${color}22`, color }}
    >
      {severity}
    </span>
  );
}

function Empty({ label }: { label: string }): JSX.Element {
  return (
    <div className="flex items-center gap-2 text-xs text-[#94a3b8] italic py-1.5">
      <ShieldCheck size={14} className="opacity-50" />
      {label}
    </div>
  );
}

function Deliverable({
  icon,
  title,
  description,
  cta,
  onClick,
}: {
  icon: JSX.Element;
  title: string;
  description: string;
  cta: string;
  onClick: () => void;
}): JSX.Element {
  return (
    <button
      type="button"
      onClick={onClick}
      className="text-left rounded-md border border-[#2d333b] bg-[#11141a] px-3 py-3 hover:bg-[#181c24] transition-colors"
    >
      <div className="flex items-center gap-2 mb-1.5">
        <span className="text-[#8e51df]">{icon}</span>
        <span className="text-sm font-semibold text-white">{title}</span>
      </div>
      <p className="text-xs text-[#94a3b8] leading-relaxed">{description}</p>
      <span className="mt-2 inline-flex items-center gap-1 text-xs text-[#c4b5fd]">
        {cta} <Activity size={12} />
      </span>
    </button>
  );
}

function prettyCategory(c: string): string {
  return c.replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());
}
