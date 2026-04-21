import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDedupeKey,
  buildTags,
  buildTakeaways,
  canonicalizeUrl,
  classifyArticleType,
  cleanSummary,
  cleanTitle,
  estimateReadingMinutes,
  extractActors,
  extractCves,
  normalizeItem,
} from '../normalize';

test('canonicalizeUrl: lowercases host, strips utm and trailing slash', () => {
  assert.equal(
    canonicalizeUrl('HTTPS://Example.COM/Path/?utm_source=feed&utm_medium=rss&id=42'),
    'https://example.com/Path?id=42',
  );
  assert.equal(
    canonicalizeUrl('https://example.com/path/'),
    'https://example.com/path',
  );
  assert.equal(canonicalizeUrl('not-a-url'), null);
});

test('cleanTitle: strips publisher suffixes', () => {
  assert.equal(
    cleanTitle('CISA warns of new exploit | The Hacker News'),
    'CISA warns of new exploit',
  );
  assert.equal(
    cleanTitle('Microsoft fixes 0-day - BleepingComputer'),
    'Microsoft fixes 0-day',
  );
});

test('buildDedupeKey: stable across stop-words and casing differences', () => {
  const a = buildDedupeKey('Microsoft fixes a zero-day vulnerability in Windows');
  const b = buildDedupeKey('MICROSOFT FIXES THE ZERO-DAY VULNERABILITY IN WINDOWS!');
  assert.equal(a, b);
  // Different stories must hash differently.
  const c = buildDedupeKey('Apple ships emergency patch for iOS 18');
  assert.notEqual(a, c);
});

test('classifyArticleType: prioritises CVE/zero-day over fallback', () => {
  assert.equal(
    classifyArticleType('A flaw tracked as CVE-2026-1234 was disclosed', null, 'news'),
    'vulnerability',
  );
  assert.equal(
    classifyArticleType('Hospital reports massive data breach', null, 'news'),
    'breach',
  );
  assert.equal(
    classifyArticleType('Random vendor newsletter', null, 'news'),
    'news',
  );
  assert.equal(
    classifyArticleType('Project Zero blog post on browser sandbox', null, 'vendor-research'),
    'vendor-research',
  );
});

test('buildTags: dedupes upstream + keyword matches', () => {
  const tags = buildTags(
    'Ransomware crew exploits zero-day in cloud workloads',
    'Patch your AWS S3 buckets immediately.',
    ['Cybercrime', 'Ransomware'],
    ['vendor-research'],
  );
  assert.ok(tags.includes('ransomware'));
  assert.ok(tags.includes('zero-day'));
  assert.ok(tags.includes('cloud'));
  assert.ok(tags.includes('cybercrime'));
});

test('extractCves: dedupes and uppercases', () => {
  const cves = extractCves(
    'CVE-2026-1111 and cve-2026-1111 also CVE-2026-2222 fixed',
    null,
  );
  assert.deepEqual(cves.sort(), ['CVE-2026-1111', 'CVE-2026-2222']);
});

test('extractActors: catches APT/ransomware family names', () => {
  const actors = extractActors(
    'APT29 deploys new loader; Lockbit affiliates target manufacturing',
    null,
  );
  assert.ok(actors.includes('apt29'));
  assert.ok(actors.includes('lockbit'));
});

test('cleanSummary: clamps to bound', () => {
  const long = 'a '.repeat(2000);
  const out = cleanSummary(long);
  assert.ok(out && out.length <= 1200);
});

test('buildTakeaways: returns null when too few sentences', () => {
  assert.equal(buildTakeaways('One short line.'), null);
  const good =
    'Microsoft shipped an out-of-band patch on Tuesday. Researchers say active exploitation predates disclosure. ' +
    'Admins should apply the fix immediately. The vendor recommends rotating affected service-account credentials.';
  const out = buildTakeaways(good);
  assert.ok(out);
  assert.ok(out!.length >= 2);
});

test('estimateReadingMinutes: never below 1', () => {
  assert.equal(estimateReadingMinutes(null), 1);
  assert.equal(estimateReadingMinutes('hi'), 1);
  // 660 words ≈ 3 min
  const long = Array(660).fill('word').join(' ');
  assert.equal(estimateReadingMinutes(long), 3);
});

test('normalizeItem: returns null for unusable input', () => {
  const source = {
    slug: 'x',
    name: 'X',
    description: '',
    category: 'news' as const,
    reputation: 'A' as const,
    feedUrl: 'https://x/',
    homepageUrl: 'https://x/',
    defaultArticleType: 'news' as const,
  };
  assert.equal(
    normalizeItem(source, {
      title: '',
      link: 'https://x/article',
      rawSummary: null,
      publishedAt: null,
      author: null,
      categories: [],
      imageUrl: null,
    }),
    null,
  );
  assert.equal(
    normalizeItem(source, {
      title: 'Real title',
      link: 'not-a-url',
      rawSummary: null,
      publishedAt: null,
      author: null,
      categories: [],
      imageUrl: null,
    }),
    null,
  );
});

test('normalizeItem: produces a complete article shape', () => {
  const source = {
    slug: 'thn',
    name: 'The Hacker News',
    description: '',
    category: 'news' as const,
    reputation: 'A' as const,
    feedUrl: 'https://thehackernews.com/feed',
    homepageUrl: 'https://thehackernews.com/',
    defaultArticleType: 'news' as const,
  };
  const out = normalizeItem(source, {
    title: 'CISA warns of CVE-2026-9999 actively exploited | The Hacker News',
    link: 'https://thehackernews.com/2026/04/cve-2026-9999.html?utm_source=rss',
    rawSummary:
      'CISA added CVE-2026-9999 to the KEV catalog after observing in-the-wild exploitation. Affected vendor X recommends patching immediately. Federal agencies have 21 days to comply with BOD 22-01.',
    publishedAt: new Date('2026-04-15T09:00:00Z'),
    author: 'Ravie Lakshmanan',
    categories: ['Security', 'Vulnerability'],
    imageUrl: null,
  });
  assert.ok(out);
  assert.equal(out!.canonicalUrl, 'https://thehackernews.com/2026/04/cve-2026-9999.html');
  assert.equal(out!.articleType, 'vulnerability');
  assert.ok(out!.cveIds.includes('CVE-2026-9999'));
  assert.ok(out!.tags.includes('zero-day') || out!.tags.includes('vulnerability'));
  assert.equal(out!.title, 'CISA warns of CVE-2026-9999 actively exploited');
});
