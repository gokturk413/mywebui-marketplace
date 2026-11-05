// Builds the registry: checks every package entry and writes _site/index.json + _site/previews/.
//   node scripts/build-index.mjs            check the entries, write _site/
//   node scripts/build-index.mjs --verify   also download every package and check it the way
//                                           mywebui does: SHA-256, the owner's Ed25519 signature,
//                                           the manifest (every file listed with its hash)
// No dependencies; Node 20+.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VERIFY = process.argv.includes('--verify');
const OUT = path.join(ROOT, '_site');
const ID_RE = /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9._-]{0,63}$/;
const VERSION_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/;
const PATH_RE = /^(?!\/)(?!.*(^|\/)\.\.?(\/|$))[A-Za-z0-9._/-]{1,200}$/;
const KINDS = ['control', 'npm-widget', 'theme'];
const TYPES = ['string', 'boolean', 'number', 'color', 'date', 'signal', 'screen', 'object', 'enum'];
const RELEASE_HOSTS = ['github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com'];
const errors = [];
const err = (where, msg) => errors.push(`${where}: ${msg}`);

const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const list = (dir) => fs.existsSync(path.join(ROOT, dir)) ? fs.readdirSync(path.join(ROOT, dir)) : [];

// keys/<owner>.pub: "ed25519:<base64 of the 32 raw bytes>"
const keys = {};
for (const f of list('keys').filter(f => f.endsWith('.pub'))) {
    const owner = f.slice(0, -4), k = read('keys/' + f).trim();
    if (!/^[a-z0-9][a-z0-9-]{0,38}$/.test(owner)) err('keys/' + f, 'the owner is a GitHub login in lower case');
    else if (!/^ed25519:[A-Za-z0-9+/]{43}=$/.test(k)) err('keys/' + f, 'not "ed25519:<base64 of 32 bytes>"');
    else keys[owner] = k;
}

const packages = [];
for (const owner of list('packages').filter(d => fs.statSync(path.join(ROOT, 'packages', d)).isDirectory())) {
    for (const f of list('packages/' + owner).filter(f => f.endsWith('.json'))) {
        const where = `packages/${owner}/${f}`;
        let e;
        try { e = JSON.parse(read(where)); } catch (x) { err(where, 'not JSON: ' + x.message); continue; }
        const id = owner + '/' + f.slice(0, -5);
        if (e.id !== id) err(where, `id must be "${id}" (the file's place)`);
        if (!ID_RE.test(String(e.id))) err(where, 'bad id');
        if (!keys[owner]) err(where, `no keys/${owner}.pub: every owner signs with a key`);
        if (typeof e.name !== 'string' || !e.name || e.name.length > 80) err(where, 'name: 1–80 characters');
        if (!VERSION_RE.test(String(e.version))) err(where, 'version: semver');
        if (!KINDS.includes(e.kind)) err(where, 'kind: ' + KINDS.join(' or '));
        if (!e.license || !['free', 'private', 'commercial'].includes(e.license.type)) err(where, 'license.type');
        if (e.license?.type === 'free' && !e.license.spdx) err(where, 'a free package names its SPDX licence');
        if (!e.author?.github) err(where, 'author.github');
        if (!e.description?.en) err(where, 'description.en');
        if (!e.uses || typeof e.uses.writes !== 'boolean' || typeof e.uses.network !== 'boolean' || !Array.isArray(e.uses.sendTo)) err(where, 'uses {writes, sendTo, network}');
        if (!/^[0-9a-f]{64}$/.test(String(e.sha256))) err(where, 'sha256');
        if (!/^[A-Za-z0-9+/]{86}==$/.test(String(e.sig))) err(where, 'sig: base64 Ed25519 signature');
        let host = '';
        try { const u = new URL(e.download); host = u.hostname; if (u.protocol !== 'https:') err(where, 'download: https'); } catch { err(where, 'download: a URL'); }
        if (host && !RELEASE_HOSTS.includes(host)) err(where, 'download: a GitHub release asset');
        const preview = `previews/${owner}/${f.slice(0, -5)}.svg`;
        if (!fs.existsSync(path.join(ROOT, preview))) err(where, 'no ' + preview);
        else {
            const svg = read(preview);
            if (Buffer.byteLength(svg) > 200 * 1024) err(preview, 'more than 200 KB');
            if (!/^\s*(<\?xml[^>]*>\s*)?(<!--[\s\S]*?-->\s*)*<svg[\s>]/i.test(svg)) err(preview, 'not an SVG');
            if (/<script|<foreignObject|\bon[a-z]+\s*=|(href|src)\s*=\s*["']\s*(https?:|\/\/|javascript:)/i.test(svg)) err(preview, 'no script, foreignObject, event attributes or external links');
        }
        packages.push({ ...e, preview });
    }
}

// ── --verify: the package itself ──
function readZip(buf) {
    let eocd = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error('not a zip file');
    const count = buf.readUInt16LE(eocd + 10);
    let p = buf.readUInt32LE(eocd + 16);
    const files = new Map();
    for (let i = 0; i < count; i++) {
        const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24);
        const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32), local = buf.readUInt32LE(p + 42);
        const name = buf.toString('utf8', p + 46, p + 46 + nlen);
        p += 46 + nlen + xlen + clen;
        if (name.endsWith('/')) continue;
        if (!PATH_RE.test(name)) throw new Error('a file name a package may not have: ' + name);
        const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
        const data = buf.subarray(start, start + csize);
        const out = method === 0 ? Buffer.from(data) : method === 8 ? zlib.inflateRawSync(data) : null;
        if (!out || out.length !== usize) throw new Error(name + ': unknown compression or wrong size');
        files.set(name, out);
    }
    return files;
}
const sha = (b) => crypto.createHash('sha256').update(b).digest();
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');

async function verify(e) {
    const where = e.id + '@' + e.version;
    const res = await fetch(e.download, { redirect: 'follow' });
    if (!res.ok) return err(where, `download: HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > 10 * 1048576) return err(where, 'more than 10 MB');
    const digest = sha(buf);
    if (digest.toString('hex') !== e.sha256) return err(where, 'sha256 differs from the download');
    const owner = e.id.split('/')[0];
    const pub = crypto.createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(keys[owner].slice(8), 'base64')]), format: 'der', type: 'spki' });
    if (!crypto.verify(null, digest, pub, Buffer.from(e.sig, 'base64'))) return err(where, `the signature is not ${owner}'s`);
    let files, m;
    try { files = readZip(buf); m = JSON.parse(files.get('manifest.json')?.toString('utf8') ?? 'null'); } catch (x) { return err(where, x.message); }
    if (!m || m.id !== e.id || m.version !== e.version || m.kind !== e.kind || m.license?.type !== e.license.type) return err(where, 'the manifest is not this entry');
    const listed = new Set();
    for (const f of m.files ?? []) {
        const b = files.get(f.path);
        if (!b || sha(b).toString('hex') !== f.sha256) err(where, 'missing or changed: ' + f.path);
        listed.add(f.path);
    }
    for (const n of files.keys()) if (n !== 'manifest.json' && !listed.has(n)) err(where, 'not in the manifest: ' + n);
    for (const n of listed) {
        if (!n.endsWith('.control')) continue;
        if (!n.startsWith('controls/')) { err(where, 'controls belong under controls/: ' + n); continue; }
        let c;
        try { c = JSON.parse(files.get(n).toString('utf8')); } catch { err(where, n + ' is not JSON'); continue; }
        for (const k of Object.keys(c)) if (!['html', 'style', 'script', 'properties', 'settings', 'translations'].includes(k)) err(where, `${n}: "${k}" is not part of a control`);
        for (const [pn, d] of Object.entries(c.properties ?? {})) if (!TYPES.includes(d?.type)) err(where, `${n}: property "${pn}" type`);
        const script = String(c.script ?? '');
        if (/\bdebugger\s*;/.test(script)) err(where, n + ': debugger;');
        if (/\beval\s*\(|new\s+Function\s*\(/.test(script)) err(where, n + ': eval / new Function');
        if (!e.uses.network && /\b(fetch|XMLHttpRequest|WebSocket|EventSource)\b/.test(script)) err(where, n + ': network use, but uses.network is false');
        if (!e.uses.writes && /\bsetState\s*\(/.test(script)) err(where, n + ': writes states, but uses.writes is false');
    }
}

if (VERIFY) for (const e of packages) await verify(e);

if (errors.length) {
    console.error(errors.map(x => '✕ ' + x).join('\n'));
    console.error(`\n${errors.length} problem(s); nothing written`);
    process.exit(1);
}
fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(path.join(OUT, 'previews'), { recursive: true });
for (const e of packages) {
    fs.mkdirSync(path.join(OUT, path.dirname(e.preview)), { recursive: true });
    fs.copyFileSync(path.join(ROOT, e.preview), path.join(OUT, e.preview));
}
const index = { schema: 1, name: 'mywebui community', keys, packages: packages.sort((a, b) => a.id.localeCompare(b.id)) };
fs.writeFileSync(path.join(OUT, 'index.json'), JSON.stringify(index, null, 1));
fs.writeFileSync(path.join(OUT, '.nojekyll'), '');
console.log(`index: ${packages.length} package(s), ${Object.keys(keys).length} key(s)${VERIFY ? ', every package verified' : ''}`);
