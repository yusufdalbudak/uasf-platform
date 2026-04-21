import { AppDataSource } from '../db/connection';
import { CodeFinding } from '../db/models/CodeFinding';

/**
 * Code Security (SAST) ingest pipeline.
 *
 * Operators upload a SARIF v2 document produced by their existing scanner
 * (Semgrep, CodeQL, Bandit, ...). UASF parses the document, normalizes each
 * result into a {@link CodeFinding} row, and exposes those rows to the
 * Code Security console.
 *
 * SARIF is the OASIS standard format for static-analysis results; using it as
 * the input contract keeps UASF integration-friendly without binding to any
 * particular vendor.
 */

interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: { uri?: string };
    region?: { startLine?: number; endLine?: number; snippet?: { text?: string } };
    contextRegion?: { snippet?: { text?: string } };
  };
}

interface SarifResult {
  ruleId?: string;
  level?: string;
  message?: { text?: string };
  locations?: SarifLocation[];
  properties?: Record<string, unknown>;
}

interface SarifRule {
  id?: string;
  name?: string;
  shortDescription?: { text?: string };
  fullDescription?: { text?: string };
  help?: { text?: string };
  defaultConfiguration?: { level?: string };
  properties?: { tags?: string[]; cwe?: string[]; security_severity?: string };
}

interface SarifRun {
  tool?: { driver?: { name?: string; rules?: SarifRule[] } };
  results?: SarifResult[];
}

interface SarifDocument {
  version?: string;
  runs?: SarifRun[];
}

function levelToSeverity(level: string | undefined): string {
  switch ((level ?? '').toLowerCase()) {
    case 'error':
      return 'high';
    case 'warning':
      return 'medium';
    case 'note':
      return 'low';
    case 'none':
      return 'info';
    default:
      return 'medium';
  }
}

function normalizeCwe(value: string | string[] | undefined): string | null {
  if (!value) return null;
  const candidate = Array.isArray(value) ? value[0] : value;
  if (!candidate) return null;
  const m = /CWE[-:]?(\d+)/i.exec(candidate);
  return m ? `CWE-${m[1]}` : null;
}

function pickRule(rules: SarifRule[] | undefined, ruleId: string | undefined): SarifRule | null {
  if (!Array.isArray(rules) || !ruleId) return null;
  return rules.find((rule) => rule?.id === ruleId) ?? null;
}

function pickLocation(result: SarifResult): {
  filePath: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  snippet: { before?: string; matched?: string; after?: string } | null;
} {
  const location = Array.isArray(result.locations) ? result.locations[0] : undefined;
  const physical = location?.physicalLocation;
  const filePath = physical?.artifactLocation?.uri ?? null;
  const lineStart = physical?.region?.startLine ?? null;
  const lineEnd = physical?.region?.endLine ?? lineStart;
  const matched = physical?.region?.snippet?.text;
  const context = physical?.contextRegion?.snippet?.text;
  if (matched || context) {
    const snippet: { matched?: string; before?: string } = {};
    if (matched) snippet.matched = matched;
    if (context) snippet.before = context;
    return { filePath, lineStart, lineEnd, snippet };
  }
  return { filePath, lineStart, lineEnd, snippet: null };
}

export interface SarifIngestSummary {
  repository: string;
  ref: string | null;
  tool: string;
  parsed: number;
  inserted: number;
  failures: Array<{ ruleId: string | null; error: string }>;
}

/**
 * Ingest a SARIF document and persist its results as CodeFinding rows.
 * The repository name is required so findings can be scoped per project.
 */
export async function ingestSarifDocument(input: {
  repository: string;
  ref?: string | null;
  document: SarifDocument;
}): Promise<SarifIngestSummary> {
  const repo = AppDataSource.getRepository(CodeFinding);
  const repository = (input.repository ?? '').trim();
  if (!repository) {
    throw new Error('Repository identifier is required to ingest a SARIF document.');
  }

  const failures: SarifIngestSummary['failures'] = [];
  let inserted = 0;
  let parsed = 0;
  let toolName = 'sarif';

  const runs = Array.isArray(input.document?.runs) ? input.document.runs : [];
  for (const run of runs) {
    toolName = (run?.tool?.driver?.name || toolName).toLowerCase();
    const rules = run?.tool?.driver?.rules;
    const results = Array.isArray(run?.results) ? run.results : [];
    for (const result of results) {
      parsed += 1;
      try {
        const ruleEntry = pickRule(rules, result.ruleId);
        const ruleId = result.ruleId ?? ruleEntry?.id ?? 'unknown-rule';
        const severityFromProps =
          ruleEntry?.properties?.security_severity ??
          (result.properties?.['security-severity'] as string | undefined);
        const severity = severityFromProps
          ? mapNumericSeverity(severityFromProps)
          : levelToSeverity(result.level ?? ruleEntry?.defaultConfiguration?.level);
        const title =
          result.message?.text ??
          ruleEntry?.shortDescription?.text ??
          ruleEntry?.name ??
          ruleId;
        const description =
          ruleEntry?.fullDescription?.text ?? ruleEntry?.help?.text ?? null;
        const cwe = normalizeCwe(
          ruleEntry?.properties?.cwe ?? (result.properties?.cwe as string | string[] | undefined),
        );
        const remediation = ruleEntry?.help?.text ?? null;
        const { filePath, lineStart, lineEnd, snippet } = pickLocation(result);

        await repo.save(
          repo.create({
            repository,
            ref: input.ref ?? null,
            tool: toolName,
            ruleId,
            severity,
            title: title.slice(0, 510),
            description,
            filePath,
            lineStart,
            lineEnd,
            cwe,
            remediation,
            rawSnippet: snippet,
          }),
        );
        inserted += 1;
      } catch (error) {
        failures.push({ ruleId: result.ruleId ?? null, error: (error as Error).message });
      }
    }
  }

  return {
    repository,
    ref: input.ref ?? null,
    tool: toolName,
    parsed,
    inserted,
    failures,
  };
}

function mapNumericSeverity(raw: string): string {
  const score = Number.parseFloat(String(raw));
  if (Number.isFinite(score)) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    if (score > 0) return 'low';
  }
  return levelToSeverity(raw);
}
