// VitePress fails the build on dead page links but not on dead #fragments,
// and headings that contain inline HTML get a doubled slug. This catches both.
// Run after `npm run docs:build`.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const DIST = '.vitepress/dist'
const files = []
;(function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry)
    statSync(p).isDirectory() ? walk(p) : p.endsWith('.html') && files.push(p)
  }
})(DIST)

const route = (f) =>
  ('/' + relative(DIST, f).replace(/index\.html$/, '').replace(/\.html$/, '')).replace(/\/$/, '') || '/'

const ids = new Map()
const bodies = new Map()
for (const f of files) {
  const body = readFileSync(f, 'utf8')
  bodies.set(f, body)
  ids.set(route(f), new Set([...body.matchAll(/id="([^"]+)"/g)].map((m) => m[1])))
}

let bad = 0
for (const [f, body] of bodies) {
  const here = route(f)
  for (const m of body.matchAll(/href="(\/[^"#]*)?#([^"]+)"/g)) {
    const anchor = decodeURIComponent(m[2])
    if (!anchor || anchor.startsWith('VP')) continue
    const target = (m[1] ?? here).replace(/\/$/, '') || '/'
    if (!ids.has(target)) {
      console.error(`MISSING PAGE  ${here} -> ${target}`)
      bad++
    } else if (!ids.get(target).has(anchor)) {
      console.error(`DEAD ANCHOR   ${here} -> ${target}#${anchor}`)
      bad++
    }
  }
}

console.log(bad ? `\n${bad} dead anchor(s)` : `anchors OK across ${files.length} pages`)
process.exit(bad ? 1 : 0)
