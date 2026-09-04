---
name: anti-ai-slop
description:
  Use when writing or editing prose in this repo (README, docs-site pages,
  skill files, error or log messages, release notes), when asked to remove
  AI-sounding text ("ai-slop", "de-slop", "humanize"), or before committing
  new user-facing docs.
---

# anti-ai-slop

De-slopping changes how something is said, never what is said. Two chains of
custody are absolute in this repo: docs quote the source byte-for-byte, and
the source matches the TypeScript reference (`../better-auth`) byte-for-byte
wherever a TS anchor comment says so. Style bends around those two, never
through them.

## What counts as slop

| Tell | Fix |
|---|---|
| Em/en dash in prose | Period, comma, colon, or parentheses; ranges become "3.10 to 3.14" |
| Rule-of-three rhetoric ("intuitive, powerful, and flexible") | State the one concrete fact, or cut |
| "Not just X, it's Y" | Keep the plain claim |
| Tacked-on "-ing" analysis ("..., ensuring robust security") | Concrete fact or nothing |
| Promo adjectives: seamless, robust, comprehensive, powerful, effortless, vibrant | Neutral wording |
| Editorializing around facts ("impressive coverage") | Keep the fact, cut the applause |
| Arrow shorthand in prose ("name → class") | Spell it out |
| Punchy negation pairs as drama ("no config, no guessing") | An ordinary clause |

## What is NOT slop (leave it)

- Terse factual capability notes ("Pure OAuth2. No PKCE, no id token."):
  reference register is the correct human voice here.
- Any string near a TS anchor comment (`# TS file.ts:line`): byte-locked to
  upstream, wire parity wins over style.
- Quoted program output in code fences: it follows the source, not style.
- Comments and docstrings under `src/` and `tests/`: internal prose full of
  load-bearing TS anchors. Out of scope, always.
- Numbers, version pins, counts: see the volatile-claims step below.

## The decision walk (per flagged span)

1. **Inside a code fence or inline code?** If it quotes a source string or
   program output, byte-check it against the source file. TS-anchored source
   string: leave both sides. Port-authored (no anchor): fix the source string
   first, then re-sync the quote. Snippet comments: leave.
2. **Frontmatter?** Fields that render (title, description, tagline, hero
   text) are prose and get the full treatment. Machine keys are not.
3. **A heading?** Renaming changes the anchor slug. An explicit `{#id}` pins
   it; otherwise sweep referrers and rerun the docs build, which validates
   anchors.
4. **A volatile claim** (test count, parity version, plugin/provider/endpoint
   count)? Keep the number, cut only the editorializing around it, and list
   the file:line in your report for the release-chore inventory. Those values
   are refreshed in one sweep at release time so published numbers match the
   published package.
5. **Anything else:** rewrite the style, keep the claim. The sentence's
   information survives; only the wrapper changes. Deleting a sentence is
   only correct when it carries zero information.

## Hard edges

- A claim that looks wrong (stale, contradicting the code) is verified
  against the source or a build before it changes, and the fix names its
  evidence in the report or commit. Never silently replace copy with
  invented copy.
- No drive-by edits. Reformatting or restructuring beyond the tells needs a
  documented repo standard, cited by location. No citation, no edit.

## Tools and gates

- Runtime code strings:
  `uv run python .agents/skills/anti-ai-slop/scripts/slop_scan.py src packages/better-auth-client/src`
  AST-based; skips docstrings and comments by design. A hit is a candidate,
  not a verdict: the TS-anchor check decides.
- Prose: `rg "—|–" <paths>`, then walk each hit through the decision list.
- Docs touched: `cd docs-site && npm run docs:build` must stay green.

## Common mistakes (all observed in baseline runs)

| Mistake | Correct move |
|---|---|
| Deleting the sentence because its metric looks stale | Cut the applause, keep the number, inventory it |
| "Frontmatter is protected" | Rendered fields are prose |
| Replacing a vague description with invented copy | Style-only rewrite; flag the content problem separately |
| Reformatting code blocks "per project standards" | Cite the written standard or leave it alone |
| De-slopping a TS-anchored error string | Anchored strings are byte-locked; the docs quote follows |
