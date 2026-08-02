import { defineConfig, type HeadConfig } from 'vitepress'

const REPO = 'https://github.com/oumarbarry/better-auth-py'
const PYPI = 'https://pypi.org/project/better-auth-server/'

const DESCRIPTION =
  'Authentication for Python, ported from better-auth. Full parity with the ' +
  'TypeScript v1.6.25 wire and storage format: 35 social providers, 26 plugins, ' +
  'FastAPI integration, your database.'

// Absolute URLs (og:url, sitemap) need a real hostname. Vercel exposes one; a
// self-hosted build can pass SITE_URL. Never guessed — omitted when unknown.
const vercelHost = process.env.VERCEL_PROJECT_PRODUCTION_URL
const SITE_URL = process.env.SITE_URL ?? (vercelHost ? `https://${vercelHost}` : undefined)

// Inline SVG favicon: an orbit ring over a near-black field with one bright
// body on the track. No external asset, no extra request.
const FAVICON =
  'data:image/svg+xml,' +
  encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">` +
      `<rect width="32" height="32" rx="7" fill="#070c18"/>` +
      `<ellipse cx="16" cy="16" rx="11" ry="5.5" fill="none" stroke="#51deec" ` +
      `stroke-width="1.6" opacity=".85" transform="rotate(-28 16 16)"/>` +
      `<circle cx="16" cy="16" r="4.2" fill="#7c83f7"/>` +
      `<circle cx="25.3" cy="11.6" r="2.1" fill="#b77ff2"/>` +
    `</svg>`,
  )

const head: HeadConfig[] = [
  ['link', { rel: 'icon', href: FAVICON }],
  ['meta', { name: 'theme-color', content: '#070c18' }],
  ['meta', { name: 'color-scheme', content: 'dark light' }],
  ['meta', { property: 'og:type', content: 'website' }],
  ['meta', { property: 'og:site_name', content: 'better-auth-server' }],
  ['meta', { property: 'og:title', content: 'better-auth-server — auth for Python' }],
  ['meta', { property: 'og:description', content: DESCRIPTION }],
  ['meta', { name: 'twitter:card', content: 'summary' }],
  ['meta', { name: 'twitter:title', content: 'better-auth-server — auth for Python' }],
  ['meta', { name: 'twitter:description', content: DESCRIPTION }],
]
if (SITE_URL) head.push(['meta', { property: 'og:url', content: SITE_URL }])

export default defineConfig({
  title: 'better-auth-server',
  description: DESCRIPTION,
  lang: 'en-US',
  cleanUrls: true,
  appearance: 'dark',
  lastUpdated: false,
  head,
  sitemap: SITE_URL ? { hostname: SITE_URL } : undefined,

  markdown: {
    theme: { light: 'github-light', dark: 'aurora-x' },
  },

  themeConfig: {
    siteTitle: 'better-auth-server',

    nav: [
      { text: 'Guide', link: '/guide/getting-started', activeMatch: '/guide/' },
      { text: 'Plugins', link: '/plugins/', activeMatch: '/plugins/' },
      { text: 'Providers', link: '/providers/', activeMatch: '/providers/' },
      { text: 'Migrate', link: '/migrate/from-node', activeMatch: '/migrate/' },
      { text: 'Deploy', link: '/deploy/production', activeMatch: '/deploy/' },
      { text: 'PyPI', link: PYPI },
    ],

    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Core Concepts', link: '/guide/concepts' },
          { text: 'Configuration', link: '/guide/configuration' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Plugins', link: '/plugins/' },
          { text: 'Social providers', link: '/providers/' },
          { text: 'Migrate from Node', link: '/migrate/from-node' },
          { text: 'Production deploy', link: '/deploy/production' },
        ],
      },
    ],

    socialLinks: [{ icon: 'github', link: REPO }],

    search: { provider: 'local' },

    outline: { level: [2, 3], label: 'On this page' },

    editLink: {
      pattern: `${REPO}/edit/main/docs-site/:path`,
      text: 'Edit this page on GitHub',
    },

    docFooter: { prev: 'Previous', next: 'Next' },

    footer: {
      message: `MIT licensed · API-compatible with <a href="https://better-auth.com">better-auth</a>`,
      copyright: 'Server-side parity, in your own database.',
    },
  },
})
