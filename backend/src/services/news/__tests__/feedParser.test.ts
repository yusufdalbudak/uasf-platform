import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeEntities,
  firstTag,
  parseFeed,
  splitItems,
  stripHtml,
} from '../feedParser';

test('decodeEntities: handles named, decimal, and hex references', () => {
  assert.equal(decodeEntities('&amp;'), '&');
  assert.equal(decodeEntities('&lt;tag&gt;'), '<tag>');
  assert.equal(decodeEntities('&#39;'), "'");
  assert.equal(decodeEntities('&#x2014;'), '\u2014');
  // Unknown entity is left untouched.
  assert.equal(decodeEntities('&doesnotexist;'), '&doesnotexist;');
  // Control byte is dropped.
  assert.equal(decodeEntities('a&#1;b'), 'ab');
});

test('stripHtml: removes script/style and decodes entities', () => {
  const input = `
    <p>Microsoft <script>bad()</script> patches a
    <strong>zero-day</strong> exploited in the wild &mdash; &amp; more.</p>
  `;
  const out = stripHtml(input);
  assert.equal(
    out,
    'Microsoft patches a zero-day exploited in the wild \u2014 & more.',
  );
});

test('firstTag: matches namespaced and attributed tags', () => {
  const xml = '<entry><dc:date>2026-01-02</dc:date></entry>';
  assert.equal(firstTag(xml, 'date'), '2026-01-02');
  const attr = '<title type="text">Hello</title>';
  assert.equal(firstTag(attr, 'title'), 'Hello');
});

test('splitItems: detects RSS items', () => {
  const xml = `
    <rss><channel>
      <title>Test</title>
      <item><title>One</title></item>
      <item><title>Two</title></item>
    </channel></rss>`;
  const items = splitItems(xml);
  assert.equal(items.length, 2);
  assert.match(items[0], /<title>One<\/title>/);
});

test('splitItems: detects Atom entries', () => {
  const xml = `
    <feed>
      <title>Test</title>
      <entry><title>A</title></entry>
      <entry><title>B</title></entry>
      <entry><title>C</title></entry>
    </feed>`;
  const items = splitItems(xml);
  assert.equal(items.length, 3);
});

test('parseFeed: parses an RSS 2.0 sample', () => {
  const xml = `<?xml version="1.0"?>
    <rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
      <channel>
        <title>BleepingComputer</title>
        <item>
          <title>Microsoft fixes 0-day exploited in the wild</title>
          <link>https://www.bleepingcomputer.com/news/security/microsoft-fixes-zero-day/</link>
          <pubDate>Mon, 14 Apr 2026 10:05:00 +0000</pubDate>
          <description><![CDATA[<p>Microsoft has shipped an out-of-band fix for an actively exploited <strong>zero-day</strong> CVE-2026-12345.</p>]]></description>
          <dc:creator>Lawrence Abrams</dc:creator>
          <category>Security</category>
        </item>
      </channel>
    </rss>`;
  const feed = parseFeed(xml);
  assert.equal(feed.channelTitle, 'BleepingComputer');
  assert.equal(feed.items.length, 1);
  const item = feed.items[0];
  assert.equal(item.title, 'Microsoft fixes 0-day exploited in the wild');
  assert.equal(
    item.link,
    'https://www.bleepingcomputer.com/news/security/microsoft-fixes-zero-day/',
  );
  assert.ok(item.publishedAt, 'publishedAt parsed');
  assert.equal(item.author, 'Lawrence Abrams');
  assert.deepEqual(item.categories, ['Security']);
  assert.match(item.rawSummary ?? '', /CVE-2026-12345/);
});

test('parseFeed: parses an Atom sample with author + category attrs', () => {
  const xml = `<?xml version="1.0" encoding="utf-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title>Schneier on Security</title>
      <entry>
        <title>On Surveillance Capitalism</title>
        <link rel="alternate" href="https://www.schneier.com/blog/posts/2026/04/sc.html"/>
        <id>https://www.schneier.com/?p=12345</id>
        <updated>2026-04-15T12:00:00Z</updated>
        <author><name>Bruce Schneier</name></author>
        <category term="surveillance" />
        <summary type="html">&lt;p&gt;Short essay on data harvesting.&lt;/p&gt;</summary>
      </entry>
    </feed>`;
  const feed = parseFeed(xml);
  assert.equal(feed.items.length, 1);
  const item = feed.items[0];
  assert.equal(item.link, 'https://www.schneier.com/blog/posts/2026/04/sc.html');
  assert.equal(item.author, 'Bruce Schneier');
  assert.deepEqual(item.categories, ['surveillance']);
});
