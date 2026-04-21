/**
 * UASF — External Attack Surface Management API
 *
 *   GET  /api/easm/overview        Aggregated executive view-model for the
 *                                  EASM dashboard and reports.  Cheap to
 *                                  re-fetch (~50ms with warm pools).
 *
 *   GET  /api/easm/report.html     Executive Summary HTML report.
 *   GET  /api/easm/report.pdf      Executive Summary PDF report.
 *
 * Inline rendering by default; pass ?download=1 to force the browser to
 * save the file instead of previewing it.  All three routes go through
 * the global authPlugin (token or signed-download token).
 */

import type { FastifyInstance } from 'fastify';
import { buildEasmOverview } from '../services/easm/easmOverviewService';
import {
  renderEasmExecutiveSummaryHtml,
  renderEasmExecutiveSummaryPdf,
} from '../services/easm/easmReport';

export async function setupEasmRoutes(server: FastifyInstance): Promise<void> {
  server.get('/api/easm/overview', async (_request, reply) => {
    try {
      const overview = await buildEasmOverview();
      return overview;
    } catch (err) {
      server.log.error({ err }, 'EASM overview failed');
      return reply.code(500).send({
        error: 'Failed to build EASM overview',
        code: 'EASM_OVERVIEW_FAILED',
      });
    }
  });

  server.get('/api/easm/report.html', async (request, reply) => {
    const query = request.query as { download?: string };
    try {
      const overview = await buildEasmOverview();
      const html = renderEasmExecutiveSummaryHtml(overview);
      const disposition = query.download === '1' ? 'attachment' : 'inline';
      reply
        .header('Content-Type', 'text/html; charset=utf-8')
        .header(
          'Content-Disposition',
          `${disposition}; filename="uasf-easm-executive-summary.html"`,
        );
      return html;
    } catch (err) {
      request.log.error({ err }, 'EASM HTML report failed');
      return reply.code(500).send({
        error: 'Failed to render EASM HTML report',
        code: 'EASM_REPORT_HTML_FAILED',
      });
    }
  });

  server.get('/api/easm/report.pdf', async (request, reply) => {
    const query = request.query as { download?: string };
    try {
      const overview = await buildEasmOverview();
      const pdf = await renderEasmExecutiveSummaryPdf(overview);
      const disposition = query.download === '1' ? 'attachment' : 'inline';
      reply
        .header('Content-Type', 'application/pdf')
        .header(
          'Content-Disposition',
          `${disposition}; filename="uasf-easm-executive-summary.pdf"`,
        );
      return reply.send(pdf);
    } catch (err) {
      request.log.error({ err }, 'EASM PDF report failed');
      return reply.code(500).send({
        error: 'Failed to render EASM PDF report',
        code: 'EASM_REPORT_PDF_FAILED',
      });
    }
  });
}
