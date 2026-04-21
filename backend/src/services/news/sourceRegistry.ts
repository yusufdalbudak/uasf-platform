/**
 * Curated registry of public cybersecurity news / advisory sources that
 * the platform pulls into its News & Intelligence feed.
 *
 * Selection rules:
 *   - Public RSS / Atom feeds only — no scraping, no API keys, no paywalls.
 *   - Reputable, internationally recognized publishers in three buckets:
 *       1. Mainstream cybersecurity press
 *       2. CERT / CSIRT / government advisory publishers
 *       3. Vendor product-security / threat-research blogs
 *   - Each entry carries a `defaultArticleType` and optional `defaultTags`
 *     so the feed is well-classified even when an upstream story is light
 *     on metadata.
 *
 * Adding a source: add an entry below; on next startup the bootstrap path
 * upserts it into `news_sources`. Removing one is a soft-disable: set
 * `enabled: false` so historical articles stay queryable.
 */

import type { ArticleType } from './types';

export interface NewsSourceDefinition {
  slug: string;
  name: string;
  description: string;
  category: 'news' | 'vendor' | 'cert' | 'research';
  reputation: 'S' | 'A' | 'B';
  feedUrl: string;
  homepageUrl: string;
  defaultArticleType: ArticleType;
  defaultTags?: string[];
  enabled?: boolean;
}

export const NEWS_SOURCE_REGISTRY: NewsSourceDefinition[] = [
  // ---------------------------------------------------------------------
  // 1. Mainstream cybersecurity press
  // ---------------------------------------------------------------------
  {
    slug: 'thehackernews',
    name: 'The Hacker News',
    description:
      'High-volume cybersecurity newsroom covering breaches, malware, APT activity, and product vulnerabilities.',
    category: 'news',
    reputation: 'A',
    feedUrl: 'https://feeds.feedburner.com/TheHackersNews',
    homepageUrl: 'https://thehackernews.com/',
    defaultArticleType: 'news',
  },
  {
    slug: 'bleepingcomputer',
    name: 'BleepingComputer',
    description:
      'Operationally focused security news with strong coverage of ransomware, data breaches, and Windows/Linux ecosystem advisories.',
    category: 'news',
    reputation: 'A',
    feedUrl: 'https://www.bleepingcomputer.com/feed/',
    homepageUrl: 'https://www.bleepingcomputer.com/',
    defaultArticleType: 'news',
  },
  {
    slug: 'krebsonsecurity',
    name: 'Krebs on Security',
    description:
      'Long-form investigative reporting by Brian Krebs on cybercrime, fraud rings, and identity-related security incidents.',
    category: 'news',
    reputation: 'S',
    feedUrl: 'https://krebsonsecurity.com/feed/',
    homepageUrl: 'https://krebsonsecurity.com/',
    defaultArticleType: 'news',
  },
  {
    slug: 'darkreading',
    name: 'Dark Reading',
    description:
      'Enterprise-security news desk with coverage of threats, defensive operations, and CISO-level analysis.',
    category: 'news',
    reputation: 'A',
    feedUrl: 'https://www.darkreading.com/rss.xml',
    homepageUrl: 'https://www.darkreading.com/',
    defaultArticleType: 'news',
  },
  {
    slug: 'securityweek',
    name: 'SecurityWeek',
    description:
      'Industry-news publication covering vendor disclosures, vulnerabilities, and enterprise security operations.',
    category: 'news',
    reputation: 'A',
    feedUrl: 'https://www.securityweek.com/feed/',
    homepageUrl: 'https://www.securityweek.com/',
    defaultArticleType: 'news',
  },
  {
    slug: 'therecord',
    name: 'The Record',
    description:
      'Threat-intelligence news desk operated by Recorded Future, focused on nation-state activity and ransomware ecosystems.',
    category: 'news',
    reputation: 'A',
    feedUrl: 'https://therecord.media/feed',
    homepageUrl: 'https://therecord.media/',
    defaultArticleType: 'news',
  },
  {
    slug: 'helpnetsecurity',
    name: 'Help Net Security',
    description:
      'Daily cybersecurity news, product releases, and research summaries for security operations teams.',
    category: 'news',
    reputation: 'B',
    feedUrl: 'https://www.helpnetsecurity.com/feed/',
    homepageUrl: 'https://www.helpnetsecurity.com/',
    defaultArticleType: 'news',
  },
  {
    slug: 'schneier',
    name: 'Schneier on Security',
    description:
      'Security commentary and essays by Bruce Schneier on cryptography, surveillance, and security policy.',
    category: 'research',
    reputation: 'S',
    feedUrl: 'https://www.schneier.com/feed/atom/',
    homepageUrl: 'https://www.schneier.com/',
    defaultArticleType: 'news',
  },

  // ---------------------------------------------------------------------
  // 2. CERT / CSIRT / advisory publishers
  // ---------------------------------------------------------------------
  {
    slug: 'cisa-advisories',
    name: 'CISA Cybersecurity Advisories',
    description:
      'United States CISA cybersecurity advisories — official guidance on actively exploited vulnerabilities and incident response.',
    category: 'cert',
    reputation: 'S',
    feedUrl: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    homepageUrl: 'https://www.cisa.gov/news-events/cybersecurity-advisories',
    defaultArticleType: 'advisory',
    defaultTags: ['cisa', 'advisory'],
  },
  {
    slug: 'ncsc-uk',
    name: 'NCSC UK',
    description:
      'United Kingdom National Cyber Security Centre — guidance, advisories, and threat reports from the UK government.',
    category: 'cert',
    reputation: 'S',
    feedUrl: 'https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml',
    homepageUrl: 'https://www.ncsc.gov.uk/',
    defaultArticleType: 'advisory',
    defaultTags: ['ncsc', 'advisory'],
  },
  {
    slug: 'sans-isc',
    name: 'SANS Internet Storm Center',
    description:
      'SANS Internet Storm Center daily diary entries covering active threat patterns, fresh CVEs, and incident handler observations.',
    category: 'cert',
    reputation: 'A',
    feedUrl: 'https://isc.sans.edu/rssfeed.xml',
    homepageUrl: 'https://isc.sans.edu/',
    defaultArticleType: 'advisory',
    defaultTags: ['sans', 'isc'],
  },

  // ---------------------------------------------------------------------
  // 3. Vendor / product-security / threat-research blogs
  // ---------------------------------------------------------------------
  {
    slug: 'msrc',
    name: 'Microsoft Security Response Center',
    description:
      'Official Microsoft Security Response Center disclosures, advisories, and security update commentary.',
    category: 'vendor',
    reputation: 'S',
    feedUrl: 'https://msrc.microsoft.com/blog/feed',
    homepageUrl: 'https://msrc.microsoft.com/blog/',
    defaultArticleType: 'vendor-research',
    defaultTags: ['microsoft'],
  },
  {
    slug: 'project-zero',
    name: 'Google Project Zero',
    description:
      'Google Project Zero — deep, technical vulnerability research disclosures from one of the most influential offensive-research teams.',
    category: 'research',
    reputation: 'S',
    feedUrl: 'https://googleprojectzero.blogspot.com/feeds/posts/default',
    homepageUrl: 'https://googleprojectzero.blogspot.com/',
    defaultArticleType: 'vendor-research',
    defaultTags: ['google', 'project-zero', 'research'],
  },
  {
    slug: 'talos',
    name: 'Cisco Talos Intelligence',
    description:
      'Threat-research and incident-response publications by Cisco Talos, including malware reverse-engineering and campaign attribution.',
    category: 'vendor',
    reputation: 'S',
    feedUrl: 'https://blog.talosintelligence.com/rss/',
    homepageUrl: 'https://blog.talosintelligence.com/',
    defaultArticleType: 'vendor-research',
    defaultTags: ['talos', 'cisco', 'research'],
  },
  {
    slug: 'unit42',
    name: 'Palo Alto Unit 42',
    description:
      'Threat-intelligence research from Palo Alto Networks Unit 42 — campaign analyses, malware deep-dives, and adversary tradecraft writeups.',
    category: 'vendor',
    reputation: 'S',
    feedUrl: 'https://feeds.feedburner.com/Unit42',
    homepageUrl: 'https://unit42.paloaltonetworks.com/',
    defaultArticleType: 'vendor-research',
    defaultTags: ['unit42', 'palo-alto', 'research'],
  },
  {
    slug: 'mandiant',
    name: 'Mandiant',
    description:
      'Mandiant front-line incident-response intelligence and threat-actor research published by Google Cloud / Mandiant.',
    category: 'vendor',
    reputation: 'S',
    feedUrl: 'https://www.mandiant.com/resources/blog/rss.xml',
    homepageUrl: 'https://www.mandiant.com/resources/blog',
    defaultArticleType: 'vendor-research',
    defaultTags: ['mandiant', 'research'],
  },
  {
    slug: 'crowdstrike',
    name: 'CrowdStrike',
    description:
      'CrowdStrike adversary-tradecraft and threat-intelligence research, including OverWatch and Falcon telemetry analyses.',
    category: 'vendor',
    reputation: 'A',
    feedUrl: 'https://www.crowdstrike.com/en-us/blog/feed/',
    homepageUrl: 'https://www.crowdstrike.com/en-us/blog/',
    defaultArticleType: 'vendor-research',
    defaultTags: ['crowdstrike', 'research'],
  },
];
