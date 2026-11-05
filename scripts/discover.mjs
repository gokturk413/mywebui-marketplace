#!/usr/bin/env node
// Finds packages on GitHub by themselves (Kamran 2026-11-05: a control published on GitHub must
// show in the marketplace without asking anyone). Run by the registry CI before build-index:
//
//   a repository with the topic "mywebui-package" whose newest release has the assets
//     entry.json          the index entry (VS Code: Package for Marketplace writes it)
//     <name>-<ver>.mwpkg  the package entry.download points at (an asset of the SAME release)
//   and, unless the registry already holds keys/<owner>.pub, the file mywebui-key.pub in the
//   repository's default branch ("ed25519:<base64 of the 32-byte key>"): the GitHub account that
//   owns the repository vouches for its key, and the key signs the package.
//
// It writes packages/<owner>/<name>.json, previews/<owner>/<name>.(svg|png) (taken from the
// package) and keys/<owner>.pub into the CI checkout only (never committed); an entry committed
// to the registry wins over a discovered one. build-index --verify then checks every package as
// before: SHA-256, signature, manifest, controls, the security scan.
//
// Usage: GITHUB_TOKEN=... node scripts/discover.mjs
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const TOPIC = 'mywebui-package';
const API = 'https://api.github.com';
const TOKEN = process.env.GITHUB_TOKEN || '';
const ID_RE = /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9._-]{0,63}$/;
const KEY_RE = /^ed25519:[A-Za-z0-9+/]{43}=$/;
const MAX_REPOS = 500;

const headers = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'mywebui-marketplace-registry', ...(TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {}) };
const log = (...a) => console.log('[discover]', ...a);

async function api(url) {
    const r = await fetch(url.startsWith('http') ? url : API + url, { headers });
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
    return r.json();
}
async function download(url, max = 11 * 1048576) {
    const r = await fetch(url, { headers: { 'User-Agent': headers['User-Agent'], Accept: 'application/octet-stream' }, redirect: 'follow' });
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > max) throw new Error(`${url}: too large`);
    return buf;
}

// the preview file named by the package's manifest (a minimal zip reader, like build-index's)
function previewOf(buf) {
    let eocd = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error('not a zip file');
    const files = new Map();
    let p = buf.readUInt32LE(eocd + 16);
    for (let i = 0, n = buf.readUInt16LE(eocd + 10); i < n; i++) {
        const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20);
        const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32), local = buf.readUInt32LE(p + 42);
        const name = buf.toString('utf8', p + 46, p + 46 + nlen);
        p += 46 + nlen + xlen + clen;
        const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
        const data = buf.subarray(start, start + csize);
        // only the manifest and the previews, each with a cap (no zip bomb)
        const cap = name === 'manifest.json' ? 1048576 : 200 * 1024;
        if (name === 'manifest.json' || /\.(svg|png)$/.test(name)) {
            if (buf.readUInt32LE(p - (46 + nlen + xlen + clen) + 24) > cap) continue;
            files.set(name, method === 8 ? zlib.inflateRawSync(data, { maxOutputLength: cap }) : Buffer.from(data.subarray(0, cap)));
        }
    }
    const m = JSON.parse(files.get('manifest.json')?.toString('utf8') ?? 'null');
    const pv = m && typeof m.preview === 'string' ? files.get(m.preview) : null;
    if (!pv) throw new Error('no preview in the package (or it is larger than 200 KB)');
    return { ext: m.preview.endsWith('.png') ? 'png' : 'svg', data: pv };
}

const repos = [];
for (let page = 1; repos.length < MAX_REPOS && page <= 5; page++) {
    const r = await api(`/search/repositories?q=${encodeURIComponent('topic:' + TOPIC)}&per_page=100&page=${page}`);
    repos.push(...(r.items ?? []));
    if (!r.items || r.items.length < 100) break;
}
log(`${repos.length} repositories with the topic ${TOPIC}`);

let added = 0;
for (const repo of repos) {
    const owner = String(repo.owner?.login || '').toLowerCase();
    const where = repo.full_name;
    try {
        if (repo.private || repo.archived || repo.disabled) continue;
        const releases = await api(`/repos/${repo.full_name}/releases?per_page=5`);
        const rel = releases.find(x => !x.draft && !x.prerelease && x.assets?.some(a => a.name === 'entry.json'));
        if (!rel) { log(`${where}: no release with entry.json`); continue; }
        const entryAsset = rel.assets.find(a => a.name === 'entry.json');
        const e = JSON.parse((await download(entryAsset.browser_download_url, 200 * 1024)).toString('utf8'));
        if (!ID_RE.test(String(e.id)) || e.id.split('/')[0] !== owner) { log(`${where}: entry id "${e.id}" must be ${owner}/<name>`); continue; }
        if (e.listed === false) { log(`${where}: unlisted`); continue; }
        const pkgAsset = rel.assets.find(a => a.browser_download_url === e.download);
        if (!pkgAsset || !pkgAsset.name.endsWith('.mwpkg')) { log(`${where}: entry.download is not a .mwpkg of the same release`); continue; }
        const name = e.id.split('/')[1];
        const entryFile = path.join(ROOT, 'packages', owner, name + '.json');
        if (fs.existsSync(entryFile)) { log(`${where}: the registry has its own entry for ${e.id}`); continue; }
        // the owner's key: the registry's own, else the one in the owner's repository
        const keyFile = path.join(ROOT, 'keys', owner + '.pub');
        if (!fs.existsSync(keyFile)) {
            let key = '';
            try { key = (await download(`https://raw.githubusercontent.com/${repo.full_name}/${repo.default_branch}/mywebui-key.pub`, 1024)).toString('utf8').trim(); } catch { }
            if (!KEY_RE.test(key)) { log(`${where}: no keys/${owner}.pub in the registry and no mywebui-key.pub in the repository`); continue; }
            fs.mkdirSync(path.dirname(keyFile), { recursive: true });
            fs.writeFileSync(keyFile, key + '\n');
        }
        const pv = previewOf(await download(pkgAsset.browser_download_url));
        fs.mkdirSync(path.join(ROOT, 'previews', owner), { recursive: true });
        for (const ext of ['svg', 'png']) fs.rmSync(path.join(ROOT, 'previews', owner, name + '.' + ext), { force: true });
        fs.writeFileSync(path.join(ROOT, 'previews', owner, name + '.' + pv.ext), pv.data);
        delete e.scan; delete e.scanAccepted;     // the registry's to set, never the author's
        e.source = { repo: repo.html_url, release: rel.html_url };
        fs.mkdirSync(path.dirname(entryFile), { recursive: true });
        fs.writeFileSync(entryFile, JSON.stringify(e, null, 1));
        added++;
        log(`${where}: ${e.id} ${e.version}`);
    } catch (x) { log(`${where}: ${x.message}`); }
}
log(`${added} package(s) found on GitHub`);
