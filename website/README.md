# Documentation site

The `k8s-kms-plugin` documentation site: [Hugo](https://gohugo.io/) with the
[Hextra](https://github.com/imfing/hextra) theme, published to GitHub Pages by
[`.github/workflows/docs.yml`](../.github/workflows/docs.yml).

`baseURL` in [`hugo.toml`](./hugo.toml) is only the **local-dev default**. The workflow overrides it
with the URL `actions/configure-pages` reports for whichever repository is running the build, so the
same config publishes correctly from a fork and from `eclipse-keysealer` upstream with nothing to
remember. Override it locally the same way:

```sh
cd website && hugo --baseURL https://example.github.io/k8s-kms-plugin/
```

Hextra's "Edit this page" link is **disabled**: it derives the file path from a Hugo internal that
assumes content lives at `<project>/content/`, and with content mounted from `../docs` it splices an
absolute filesystem path into the URL. `hugo.toml` explains it in full.

**The content is not here.** Pages live in [`../docs/`](../docs/README.md) and are *mounted* into
this site by [`hugo.toml`](./hugo.toml), so `docs/` stays the single source of truth and keeps
rendering when browsing the repository on GitHub. To change a page, edit it under `docs/`.

## Build

```sh
make site-serve   # http://localhost:1313/k8s-kms-plugin/ with live reload
make site         # production build -> website/public/
make site-clean   # remove public/ and the Hugo caches
```

Hugo does **not** need to be the *extended* build: Hextra v0.12.x ships its Tailwind CSS
precompiled, so there is no SCSS to transpile.

```sh
go install github.com/gohugoio/hugo@v0.164.0
```

## Why this directory exists

Hugo Modules are Go modules. A Hugo project at the repository root would add the theme to the
plugin's own `go.mod`, where it would surface in `go mod tidy`, `NOTICES.md` and `govulncheck` —
none of which should know about a documentation theme. Keeping the site here gives it a separate
[`go.mod`](./go.mod), which pins the theme version with a checksum in `go.sum` and leaves the
plugin's module graph untouched.

## Adding a page

Create the Markdown file under `docs/` and give it front matter:

```yaml
---
title: "Short sidebar label"
weight: 45
---
```

- `title` supplies the page heading — **do not also write an `# H1`** in the body, or the title
  renders twice.
- `weight` orders the sidebar. Current spacing: concepts 10, installation 20, usage 30, crypto 40,
  HSM guides 51–55, Kubernetes guides 61–62, development 70, supply chain 80, CLI reference 90+.
- A `README.md` is *not* a section index to Hugo. It is excluded from the content mount and
  re-mounted as `_index.md`; adding a new directory with a `README.md` means adding a mount for it
  in `hugo.toml`.

Run `make check-doc-links` after moving or renaming anything.

## Mermaid and search

Both Mermaid and FlexSearch are fetched **at build time** and re-served from this site with a
Subresource Integrity hash, so published pages never call a CDN at runtime. The versions are pinned
in `hugo.toml`: Hextra's default Mermaid base is `mermaid@latest`, which would otherwise let an
upstream release change what the site ships without a commit here.

For a build with no network access at all, drop the two files into `website/assets/js/`
(git-ignored) and switch the config from `base` to `js`:

```sh
mkdir -p website/assets/js
curl -sSLo website/assets/js/mermaid.min.js \
  https://cdn.jsdelivr.net/npm/mermaid@11.16.1/dist/mermaid.min.js
curl -sSLo website/assets/js/flexsearch.bundle.min.js \
  https://cdn.jsdelivr.net/npm/flexsearch@0.8.143/dist/flexsearch.bundle.min.js
```

```sh
HUGO_PARAMS_MERMAID_BASE="" \
HUGO_PARAMS_MERMAID_JS="js/mermaid.min.js" \
HUGO_PARAMS_SEARCH_FLEXSEARCH_JS="js/flexsearch.bundle.min.js" \
  make site
```

## Upgrading the theme

```sh
cd website && hugo mod get -u github.com/imfing/hextra && hugo mod tidy
```

Then rebuild and check the pages still render — in particular that raw HTML still works
(`markup.goldmark.renderer.unsafe`), since the documentation relies on `<details>` blocks.
