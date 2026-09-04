// Generates /llms.txt (llmstxt.org index) and /llms-full.txt (all pages,
// concatenated) into .vitepress/dist. Page order and titles come from the
// sidebar in config.mts, so the two stay in sync with the site for free.
// Run after `vitepress build`.
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const DIST = '.vitepress/dist'
if (!existsSync(DIST)) {
  console.error(`build-llms: ${DIST} not found — run vitepress build first`)
  process.exit(1)
}

// Same base-URL resolution as config.mts. Without either env var the links
// stay root-relative, which is still valid for a crawler that knows the host.
const vercelHost = process.env.VERCEL_PROJECT_PRODUCTION_URL
const SITE_URL = process.env.SITE_URL ?? (vercelHost ? `https://${vercelHost}` : '')

// --- page order: '/' first, then every internal sidebar link, deduped -------
const config = readFileSync('.vitepress/config.mts', 'utf8')
const sidebarSrc = config.slice(config.indexOf('sidebar:'), config.indexOf('socialLinks'))
const sidebar = [...sidebarSrc.matchAll(/text:\s*'([^']+)',\s*link:\s*'(\/[^']*)'/g)].map(
  (m) => ({ text: m[1], link: m[2] }),
)
if (sidebar.length < 60) {
  console.error(`build-llms: only ${sidebar.length} sidebar links parsed from config.mts`)
  process.exit(1)
}

const byGroup = { Guide: [], Plugins: [], Providers: [], Migrate: [], Deploy: [] }
const groupOf = (link) =>
  link.startsWith('/guide/') ? 'Guide'
  : link.startsWith('/plugins') ? 'Plugins'
  : link.startsWith('/providers') ? 'Providers'
  : link.startsWith('/migrate') ? 'Migrate'
  : 'Deploy'
const seen = new Set()
for (const item of sidebar) {
  if (seen.has(item.link)) continue
  seen.add(item.link)
  byGroup[groupOf(item.link)].push(item)
}

const routeToFile = (link) => (link.endsWith('/') ? `${link}index.md` : `${link}.md`).slice(1)
const pages = [
  { text: 'Home', link: '/', file: 'index.md' },
  ...['Guide', 'Plugins', 'Providers', 'Migrate', 'Deploy'].flatMap((g) =>
    byGroup[g].map((p) => ({ ...p, group: g, file: routeToFile(p.link) })),
  ),
]

// Every sidebar page must exist on disk, and every source page must be listed.
const onDisk = ['index.md']
for (const dir of ['guide', 'plugins', 'providers', 'migrate', 'deploy'])
  for (const f of readdirSync(dir))
    if (f.endsWith('.md') && statSync(join(dir, f)).isFile()) onDisk.push(join(dir, f))
const listed = new Set(pages.map((p) => p.file))
let bad = 0
for (const p of pages)
  if (!existsSync(p.file)) (console.error(`MISSING FILE  ${p.file} (sidebar: ${p.link})`), bad++)
for (const f of onDisk)
  if (!listed.has(f)) (console.error(`NOT IN SIDEBAR  ${f}`), bad++)
if (bad) process.exit(1)

// --- per-page title + one-line description ---------------------------------
const stripFrontmatter = (src) => src.replace(/^---\n[\s\S]*?\n---\n/, '')
const title = (src, fallback) =>
  src.match(/^---\n[\s\S]*?^title:\s*(.+?)\s*$[\s\S]*?\n---\n/m)?.[1] ??
  stripFrontmatter(src).match(/^#\s+(.+)$/m)?.[1] ??
  fallback

const firstSentence = (src) => {
  const body = stripFrontmatter(src)
  const tagline = body === src ? null : src.match(/^\s*tagline:\s*(.+)$/m)?.[1] // home page
  const para = tagline
    ? [tagline]
    : body
        .replace(/```[\s\S]*?```/g, '')
        .split(/\n{2,}/)
        .map((b) => b.trim())
        .find((b) => b && /^[A-Za-z0-9`[]/.test(b) && !/^(#|:::|\||- |> )/.test(b))
  if (!para) return ''
  const text = String(para)
    .replace(/\n/g, ' ')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/\*\*/g, '')
  return text.match(/^.*?[.!?](?=\s|$)/)?.[0] ?? text
}

// --- llms.txt ---------------------------------------------------------------
const url = (link) => `${SITE_URL}${link}`
const sources = new Map(pages.map((p) => [p.file, readFileSync(p.file, 'utf8')]))

let index = `# Better Auth for Python\n\n`
index +=
  `> \`better-auth-server\` is a server-side Python port of Better Auth, at wire and ` +
  `storage parity with the TypeScript library v1.6.25 — same routes, JSON shapes, error ` +
  `codes and database schema. 35 social providers, 26 plugins, FastAPI, Litestar, Flask ` +
  `and Django integrations, plus \`better-auth-client\`, a Python HTTP client for any ` +
  `Better Auth server.\n`
for (const group of ['Guide', 'Plugins', 'Providers', 'Migrate', 'Deploy']) {
  const items = pages.filter((p) => p.group === group || (group === 'Guide' && p.link === '/'))
  index += `\n## ${group}\n\n`
  for (const p of items) {
    const src = sources.get(p.file)
    const desc = firstSentence(src)
    index += `- [${title(src, p.text)}](${url(p.link)})${desc ? `: ${desc}` : ''}\n`
  }
}
writeFileSync(join(DIST, 'llms.txt'), index)

// --- llms-full.txt ----------------------------------------------------------
let full = ''
for (const p of pages) full += `\n\n---\nurl: ${url(p.link)}\n---\n\n${stripFrontmatter(sources.get(p.file)).trim()}`
writeFileSync(join(DIST, 'llms-full.txt'), full.trimStart() + '\n')

console.log(`llms.txt: ${pages.length} pages indexed; llms-full.txt: ${full.length} chars`)
