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
      {
        text: 'Plugins',
        collapsed: true,
        items: [
          { text: 'username', link: '/plugins/username' },
          { text: 'magic-link', link: '/plugins/magic-link' },
          { text: 'email-otp', link: '/plugins/email-otp' },
          { text: 'phone-number', link: '/plugins/phone-number' },
          { text: 'passkey', link: '/plugins/passkey' },
          { text: 'anonymous', link: '/plugins/anonymous' },
          { text: 'siwe', link: '/plugins/siwe' },
          { text: 'one-tap', link: '/plugins/one-tap' },
          { text: 'two-factor', link: '/plugins/two-factor' },
          { text: 'admin', link: '/plugins/admin' },
          { text: 'organization', link: '/plugins/organization' },
          { text: 'api-key', link: '/plugins/api-key' },
          { text: 'jwt', link: '/plugins/jwt' },
          { text: 'bearer', link: '/plugins/bearer' },
          { text: 'one-time-token', link: '/plugins/one-time-token' },
          { text: 'oauth-provider', link: '/plugins/oauth-provider' },
          { text: 'device-authorization', link: '/plugins/device-authorization' },
          { text: 'sso', link: '/plugins/sso' },
          { text: 'generic-oauth', link: '/plugins/generic-oauth' },
          { text: 'oauth-proxy', link: '/plugins/oauth-proxy' },
          { text: 'oauth-popup', link: '/plugins/oauth-popup' },
          { text: 'multi-session', link: '/plugins/multi-session' },
          { text: 'custom-session', link: '/plugins/custom-session' },
          { text: 'last-login-method', link: '/plugins/last-login-method' },
          { text: 'captcha', link: '/plugins/captcha' },
          { text: 'have-i-been-pwned', link: '/plugins/have-i-been-pwned' },
        ],
      },
      {
        text: 'Social providers',
        collapsed: true,
        items: [
          { text: 'Apple', link: '/providers/apple' },
          { text: 'Atlassian', link: '/providers/atlassian' },
          { text: 'Amazon Cognito', link: '/providers/cognito' },
          { text: 'Discord', link: '/providers/discord' },
          { text: 'Dropbox', link: '/providers/dropbox' },
          { text: 'Facebook', link: '/providers/facebook' },
          { text: 'Figma', link: '/providers/figma' },
          { text: 'GitHub', link: '/providers/github' },
          { text: 'GitLab', link: '/providers/gitlab' },
          { text: 'Google', link: '/providers/google' },
          { text: 'Hugging Face', link: '/providers/huggingface' },
          { text: 'Kakao', link: '/providers/kakao' },
          { text: 'Kick', link: '/providers/kick' },
          { text: 'LINE', link: '/providers/line' },
          { text: 'Linear', link: '/providers/linear' },
          { text: 'LinkedIn', link: '/providers/linkedin' },
          { text: 'Microsoft Entra ID', link: '/providers/microsoft' },
          { text: 'Naver', link: '/providers/naver' },
          { text: 'Notion', link: '/providers/notion' },
          { text: 'Paybin', link: '/providers/paybin' },
          { text: 'PayPal', link: '/providers/paypal' },
          { text: 'Polar', link: '/providers/polar' },
          { text: 'Railway', link: '/providers/railway' },
          { text: 'Reddit', link: '/providers/reddit' },
          { text: 'Roblox', link: '/providers/roblox' },
          { text: 'Salesforce', link: '/providers/salesforce' },
          { text: 'Slack', link: '/providers/slack' },
          { text: 'Spotify', link: '/providers/spotify' },
          { text: 'TikTok', link: '/providers/tiktok' },
          { text: 'Twitch', link: '/providers/twitch' },
          { text: 'Twitter (X)', link: '/providers/twitter' },
          { text: 'Vercel', link: '/providers/vercel' },
          { text: 'VK', link: '/providers/vk' },
          { text: 'WeChat', link: '/providers/wechat' },
          { text: 'Zoom', link: '/providers/zoom' },
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
