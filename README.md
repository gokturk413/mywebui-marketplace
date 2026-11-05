# mywebui marketplace

The community registry of custom controls, npm widgets and themes for
[mywebui](https://github.com/gokturk413/ioBroker.mywebui). The designer shows these packages in
**Gallery → Marketplace**.

The registry publishes `index.json` and the package previews on GitHub Pages:
`https://gokturk413.github.io/mywebui-marketplace/index.json`. The packages themselves are
release assets in their authors' own repositories.

## Adding a package

1. Build and sign the package (`<name>-<version>.mwpkg`) with the mywebui VS Code extension, or
   by hand as [the format](https://github.com/gokturk413/ioBroker.mywebui/blob/main/docs/marketplace.md)
   describes.
2. Attach the `.mwpkg` to a release of your own GitHub repository.
3. Open a pull request here that adds these files:

   | File | Content |
   |---|---|
   | `packages/<owner>/<name>.json` | the entry (below) |
   | `previews/<owner>/<name>.svg` | the gallery preview: SVG, at most 200 KB, with no script, foreignObject, event attributes or external links |
   | `keys/<owner>.pub` | first package only: your public key, `ed25519:<base64 of the 32 raw bytes>` |

   `<owner>` is your GitHub login in lower case.
4. The pull request check downloads your package and checks it the way mywebui does:
   - SHA-256 and your signature;
   - the manifest is the entry, and every file is listed with its hash;
   - the controls (control fields only, known property types);
   - the scripts (no `debugger;`, `eval` or `new Function`; network use and state writes only
     when `uses` declares them).
5. A maintainer reviews and merges. The index is rebuilt and published.

An update means a new release and a pull request that changes `version`, `download`, `sha256`
and `sig`.

## The entry

```json
{
  "id": "ahmadov/pump-isa",
  "name": "Pump symbol ISA",
  "version": "1.2.0",
  "kind": "control",
  "license": { "type": "free", "spdx": "MIT" },
  "author": { "name": "Ahmadov Automation", "github": "ahmadov" },
  "description": { "en": "ISA pump symbol with running / stopped / fault", "az": "ISA nasos simvolu" },
  "tags": ["pump", "isa"],
  "uses": { "writes": false, "sendTo": [], "network": false },
  "download": "https://github.com/ahmadov/pump-isa/releases/download/v1.2.0/pump-isa-1.2.0.mwpkg",
  "sha256": "<sha256 of the .mwpkg>",
  "sig": "<base64 Ed25519 signature of the 32 raw bytes of that sha256>",
  "updated": "2026-11-04"
}
```

`kind` is `control`, `npm-widget` or `theme`. An npm widget may carry its `npm pack` .tgz in the
package (`manifest.npm.tarball`), so it needs no npm account. A theme package holds
`themes/<name>.css`, one plain `html[data-webui-theme="<name>"]{…}` rule each.
`license.type` is `free` or `private`; commercial packages come later.

## Checking locally

```
node scripts/build-index.mjs            # the entries and previews
node scripts/build-index.mjs --verify   # also every package
```
