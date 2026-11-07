// Security scan of a marketplace package (Kamran 2026-11-05: "bizdən lazım olan həmin kodun
// təhlükəsizlik baxımından scan edilməsi"). The authors sign their packages and licences; the
// platform reads the code and says what it found. Used by mywebui.0 before a package from a FILE is
// installed and by the registry's CI. THIS FILE IS A COPY of mywebui's src-original/backend/packageScan.js: change it there.
//
// It is a static scan, not a proof: it finds the usual ways code reaches out, runs strings as code
// or hides itself, and compares them with what the package says it touches (`uses`). A finding is
// a reason to look, not a verdict; "no findings" does not make a package safe.
import zlib from 'node:zlib';

const MAX_TEXT = 4 * 1048576;       // per file scanned
const MAX_FINDINGS = 200;

// rule: { id, level: 'high' | 'warn' | 'info', re, what, unless?: (uses) => bool }
const RULES = [
    { id: 'eval', level: 'high', re: /\beval\s*\(/, what: 'eval() runs a string as code' },
    { id: 'function-ctor', level: 'high', re: /\bnew\s+Function\s*\(|(?<![.\w$])Function\s*\(\s*['"`]/, what: 'new Function() runs a string as code' },
    { id: 'timer-string', level: 'high', re: /\bset(?:Timeout|Interval)\s*\(\s*['"`]/, what: 'a timer with a string runs it as code' },
    { id: 'document-write', level: 'warn', re: /\bdocument\.write(?:ln)?\s*\(/, what: 'document.write()' },
    { id: 'cookie', level: 'high', re: /\bdocument\.cookie\b/, what: 'reads or writes the page cookies (the login token lives there)' },
    { id: 'storage', level: 'warn', re: /\b(?:localStorage|sessionStorage|indexedDB)\b/, what: 'uses the browser storage' },
    { id: 'network', level: 'high', re: /\bfetch\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\(|\bnavigator\.sendBeacon\b|\bnew\s+EventSource\s*\(/, what: 'talks to the network', unless: (u) => u.network },
    { id: 'remote-import', level: 'high', re: /\bimport\s*\(\s*['"`]\s*(?:https?:)?\/\//, what: 'loads code from another address' },
    { id: 'remote-url', level: 'warn', re: /(?:src|href|action)\s*=\s*["']\s*(?:https?:)?\/\/|url\(\s*["']?\s*(?:https?:)?\/\//i, what: 'refers to another address', unless: (u) => u.network },
    { id: 'writes', level: 'warn', re: /\b(?:IOB|iobrokerHandler|connection)\s*\.\s*(?:setState|setStateAsync|secWriteState|protectedWrite)\s*\(/, what: 'writes ioBroker states', unless: (u) => u.writes },
    // the same in markup: the text may be raw, JSON-escaped (\") or HTML-escaped (&quot;)
    { id: 'writes', level: 'warn', re: /\bbind-[a-z]+:[^\s=<>"'\\&]+\s*=\s*(?:\\*["']|&quot;|&apos;|&#0*3[49];|&#x0*2[27];)?\s*=(?!=)/i, what: 'writes ioBroker states (a two-way binding)', unless: (u) => u.writes },
    { id: 'writes', level: 'warn', re: /\btwoWay(?:\\*["']|&quot;|&apos;|&#0*3[49];|&#x0*2[27];)?\s*:\s*true\b/, what: 'writes ioBroker states (a two-way binding)', unless: (u) => u.writes },
    { id: 'writes', level: 'warn', re: /\b(?:SetSignalValue|ToggleSignalValue|ToggleSignalValueThroughList|IncrementSignalValue|DecrementSignalValue|SetBitInSignal|ClearBitInSignal|ToggleBitInSignal|CalculateSignalValue|WriteSignalsInGroup|CopySignalValuesFromFolder|ImportSignalValuesFromJson)\b/, what: 'writes ioBroker states (a Simple Script command)', unless: (u) => u.writes },
    { id: 'sendto', level: 'warn', re: /\bsendTo\s*\(/, what: 'calls sendTo', unless: (u) => u.sendTo.length > 0 },
    { id: 'obfuscated', level: 'warn', re: /\b_0x[0-9a-f]{4,}\b/, what: 'looks obfuscated (_0x… names)' },
    { id: 'base64-blob', level: 'warn', re: /\batob\s*\(\s*['"`][A-Za-z0-9+/=]{200,}/, what: 'decodes a long base64 string' },
    { id: 'script-tag', level: 'warn', re: /<script\b/i, what: 'a <script> tag in the markup' },
    { id: 'debugger', level: 'warn', re: /\bdebugger\s*;/, what: 'a debugger statement (it pauses the page)' },
    { id: 'process', level: 'high', re: /\brequire\s*\(\s*['"](?:node:)?(?:child_process|fs|net|http|https|worker_threads)['"]\s*\)|\bprocess\.env\b/, what: 'Node.js APIs (child_process, fs, net, process.env)' },
];

const RANK = { info: 0, warn: 1, high: 2 };

/** Scan one text: findings [{ file, line, rule, level, what, text }]. */
export function scanText(file, text, uses = {}) {
    const u = { network: uses.network === true, writes: uses.writes === true, sendTo: Array.isArray(uses.sendTo) ? uses.sendTo : [] };
    const out = [];
    const src = String(text ?? '').slice(0, MAX_TEXT);
    const lines = src.split(/\r?\n/);
    for (let i = 0; i < lines.length && out.length < MAX_FINDINGS; i++) {
        const line = lines[i];
        for (const r of RULES) {
            if (r.unless && r.unless(u)) continue;
            const m = r.re.exec(line);
            if (!m) continue;
            const at = Math.max(0, m.index - 40);
            out.push({ file, line: i + 1, rule: r.id, level: r.level, what: r.what, text: line.slice(at, at + 120).trim() });
        }
    }
    return out;
}

/** The files of an `npm pack` tarball (gzip + tar): Map path → Buffer (package/ prefix removed). */
export function readTarball(buf, { maxFiles = 2000, maxBytes = 40 * 1048576 } = {}) {
    const tar = zlib.gunzipSync(buf, { maxOutputLength: maxBytes });
    const files = new Map();
    let off = 0, longName = null;
    while (off + 512 <= tar.length && files.size < maxFiles) {
        const h = tar.subarray(off, off + 512);
        if (h.every(b => b === 0)) break;
        const str = (a, b) => h.subarray(a, b).toString('utf8').replace(/\0.*$/s, '');
        let name = str(0, 100);
        const prefix = str(345, 500);
        if (prefix) name = prefix + '/' + name;
        const size = parseInt(str(124, 136).trim() || '0', 8) || 0;
        const type = String.fromCharCode(h[156] || 48);
        const body = tar.subarray(off + 512, off + 512 + size);
        off += 512 + Math.ceil(size / 512) * 512;
        if (type === 'L') { longName = body.toString('utf8').replace(/\0.*$/s, ''); continue; }
        if (longName) { name = longName; longName = null; }
        if (type !== '0' && type !== '\0') continue;          // files only (no links, no dirs)
        const rel = name.replace(/^package\//, '');
        if (!rel || rel.includes('..')) continue;
        files.set(rel, Buffer.from(body));
    }
    return files;
}

const SCANNED = /\.(m?js|cjs|ts|html?|css|svg|control|json)$/i;

/**
 * Scan a checked package: its controls (html/style/script), themes, and the JS / markup inside
 * an npm tarball. `files` = the .mwpkg's files (Map path → Buffer), `manifest` its manifest.
 * Returns { level: 'ok'|'info'|'warn'|'high', findings, scanned, at }.
 */
export function scanPackage(files, manifest) {
    const uses = manifest?.uses ?? {};
    const findings = [];
    let scanned = 0;
    const add = (list) => { for (const f of list) if (findings.length < MAX_FINDINGS) findings.push(f); };
    for (const [path, buf] of files) {
        if (path === 'manifest.json') continue;
        if (path.endsWith('.control')) {
            let c = null;
            try { c = JSON.parse(buf.toString('utf8')); } catch { continue; }
            for (const k of ['html', 'style', 'script']) if (typeof c?.[k] === 'string') { add(scanText(path + '#' + k, c[k], uses)); scanned++; }
        }
        else if (path.endsWith('.tgz')) {
            let tf;
            try { tf = readTarball(buf); }
            catch (e) { findings.push({ file: path, line: 0, rule: 'tarball', level: 'high', what: 'the npm tarball cannot be read: ' + e.message, text: '' }); continue; }
            for (const [p, b] of tf) {
                if (!SCANNED.test(p) || p.endsWith('package.json')) continue;
                if (/(^|\/)node_modules\//.test(p)) { findings.push({ file: path + ':' + p, line: 0, rule: 'bundled-deps', level: 'info', what: 'brings node_modules inside its tarball', text: '' }); continue; }
                add(scanText(path + ':' + p, b.toString('utf8'), uses));
                scanned++;
            }
            // install scripts never run (npm --ignore-scripts), but they say something about the package
            try {
                const pj = JSON.parse(tf.get('package.json')?.toString('utf8') ?? '{}');
                for (const s of ['preinstall', 'install', 'postinstall', 'prepare']) if (pj.scripts?.[s]) findings.push({ file: path + ':package.json', line: 0, rule: 'install-script', level: 'warn', what: `has an "${s}" script (mywebui never runs it)`, text: String(pj.scripts[s]).slice(0, 120) });
            } catch { }
        }
        else if (SCANNED.test(path) && !path.endsWith('.json')) { add(scanText(path, buf.toString('utf8'), uses)); scanned++; }
    }
    const level = findings.reduce((l, f) => RANK[f.level] > RANK[l] ? f.level : l, 'info');
    return { level: findings.length ? level : 'ok', findings, scanned, at: new Date().toISOString() };
}
