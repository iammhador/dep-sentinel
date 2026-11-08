# Code checks scanners can't do

Dependency scanners only know about published advisories. These quick checks find the in-house bugs that make a vulnerable (or unfixable) package dangerous. They're stack-agnostic, so adapt the search patterns to the language.

Use them when:
- the project renders user/CMS/admin content
- a finding is being mitigated instead of upgraded
- the user asks for a broader security review

Report each hit with `file:line` and why it matters. Fix the clear ones and ask about the rest.

## 1. Untrusted HTML reaching the page (XSS)

**Find the sinks:**
- `dangerouslySetInnerHTML`
- `innerHTML =`
- `v-html`
- `{@html`
- `[innerHTML]`
- `bypassSecurityTrust`
- `|safe` / `{% autoescape false %}`
- `html_safe` / `raw()`
- `Markup(`
- `template.HTML(`

**For each one, trace where the value comes from.** It is safe only if it is cleaned by a real sanitizer (DOMPurify, sanitize-html, bleach, Loofah, …) **on the path to rendering**: when reading or rendering, not only when saving.

Cleaning only on save leaves a hole. Anything written another way (imports, seeds, scripts, direct database edits, an older code path) renders raw. Rich-text editors (Quill, TipTap, CKEditor) have had XSS advisories without fixed versions, so render-side sanitization is what actually protects users.

**Verify.** On a local or staging database, put a payload such as `<img src=x onerror=alert(1)>` into each rich text field, load every public page, and confirm nothing executes.

## 2. Injection

- **SQL built with string concatenation or interpolation:**
  - `"... WHERE id = " + id`
  - `` `...${x}` `` passed to `query`
  - `f"SELECT ... {x}"`
  - `fmt.Sprintf` into `db.Query`
  - Use parameters or the query builder instead.
- **Shell commands built from input:**
  - `exec(` / `child_process.exec`
  - `subprocess(..., shell=True)`
  - `system(`
  - backticks
  - Use argument arrays with no shell.
- **Path traversal:** user input joined into file paths without normalizing it and checking the result stays inside an allowed folder.
- **SSRF:** server-side fetches of user-supplied URLs (webhooks, "import from URL", image proxies) without an allowlist.

## 3. Authorization order

Every server action, API route or controller that writes data should check the session or permission **before** reading the input and writing to the database.

Search mutation handlers (`"use server"`, `POST`/`PUT`/`DELETE` routes, form actions) for writes that run before the auth call, or with no auth call at all. In frameworks that expose server functions as public endpoints (Next.js server actions, Remix actions), anyone can call them directly. Hiding a button is not access control.

## 4. Secrets and client exposure

- **Variables bundled into browser code**, so their values are public:
  - `NEXT_PUBLIC_*`
  - `VITE_*`
  - `REACT_APP_*`
  - `PUBLIC_*` (Astro/SvelteKit)
  - `EXPO_PUBLIC_*`

  Make sure no token, secret, password or private API key uses these prefixes.
- **Server-only modules** (database, mailer, SDK clients that hold keys) must not be importable from client components. Use `server-only` or the framework's equivalent.
- **Committed config files:** `.env`, `*.pem`, `id_rsa`, `credentials.json`, cloud config files. `scan.sh` flags tracked `.env` files.
- **Logs** that print request bodies, tokens or connection strings.

## 5. Unsafe parsing of uploads

Spreadsheet, archive, image, XML and YAML parsers are frequent advisory targets (ReDoS, prototype pollution, XXE, zip-slip, decompression bombs).

For each upload handler:
- check that file size and type are limited **before** parsing
- confirm the parser version is fixed
- prefer `yaml.safe_load` / `SAFE_SCHEMA`
- disable XML external entities
- limit decompressed size

## 6. Lockfile and install hygiene

- **One package manager, one lockfile.** Stale extra lockfiles make scanners check the wrong versions and make installs non-reproducible.
- **CI and deploy use frozen installs** (`npm ci`, `--frozen-lockfile`, `--locked`), so what was tested is what ships.
- **Install scripts:** consider disabling lifecycle scripts for untrusted packages (`--ignore-scripts`, `trustedDependencies` in Bun, `onlyBuiltDependencies` in pnpm).
