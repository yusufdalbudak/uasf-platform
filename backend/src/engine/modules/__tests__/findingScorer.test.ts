import { describe, it, expect } from 'vitest';
import { scoreFinding, sortFindingsByScoring } from '../findingScorer';
import { ScanFinding } from '../../scanTypes';

describe('findingScorer', () => {
  it('should appropriately boost confidence based on source evidence', () => {
    const defaultFinding: ScanFinding = {
      id: 'test-1',
      category: 'Info',
      title: 'Test',
      severity: 'Low',
      description: 'Test finding',
      evidence: 'Authoritative mapping found from valid dns.'
    };
    const scored = scoreFinding(defaultFinding);
    expect(scored.confidence).toBeGreaterThan(50);
  });

  it('should correctly sort findings prioritizing Critical severity', () => {
    const list: ScanFinding[] = [
      { id: '1', category: 'Info', title: 'Low', severity: 'Low', description: 't', confidence: 50 },
      { id: '2', category: 'Info', title: 'Crit', severity: 'Critical', description: 't', confidence: 50 },
      { id: '3', category: 'Info', title: 'Med', severity: 'Medium', description: 't', confidence: 50 }
    ];
    const sorted = sortFindingsByScoring(list);
    expect(sorted[0].severity).toBe('Critical');
    expect(sorted[1].severity).toBe('Medium');
    expect(sorted[2].severity).toBe('Low');
  });

  it('should fallback to confidence sorting when severities tie', () => {
    const list: ScanFinding[] = [
      { id: '1', category: 'Info', title: 'Low conf', severity: 'High', description: 't', confidence: 30 },
      { id: '2', category: 'Info', title: 'High conf', severity: 'High', description: 't', confidence: 99 }
    ];
    const sorted = sortFindingsByScoring(list);
    expect(sorted[0].confidence).toBe(99);
    expect(sorted[1].confidence).toBe(30);
  });
});
