// SPDX-FileCopyrightText: 2026 Beweird SAS
// SPDX-License-Identifier: Apache-2.0
/**
 * The offline web verifier's page: the same checks as `azoth-verify` (SPEC.md),
 * on files the reader chooses, entirely in this page — the page's own policy forbids any
 * network access (connect-src 'none'), and nothing here asks for one. Bundled into one HTML file
 * by scripts/build-web.mjs, with crypto-web.mjs as its cryptography.
 */
import { verifyDossier } from '../src/verify.mjs';
import { verifyReceipt } from '../src/receipt.mjs';
import { readZip } from '../src/zip.mjs';
import { fromUtf8 } from '../src/bytes.mjs';

const TEXT = {
  en: {
    title: 'Azoth verifier — offline', lead: 'Checks an evidence dossier, a receipt and their timestamps entirely in this page: nothing is sent anywhere — the page forbids itself any network access. The same rules as the azoth-verify command line (SPEC.md).',
    dossier: 'Evidence dossier (.zip)', root: 'Root certificate of the time-stamping authority (PEM, optional) — to trust its timestamps',
    receipt: 'Receipt (the X-Azoth-Receipt header, optional)', keys: 'The workspace\'s published keys (keys.jwks.json, from /api/proof/keys/<workspace> — for a platform package, /api/proof/platform-keys) — required: a dossier verifies only under a key you chose, never one it ships',
    run: 'Verify', pass: 'PASS', warn: 'NOTE', fail: 'FAIL', ok: 'VERIFIED — everything is intact.', ko: 'FAILED — something does not verify.',
    nothing: 'Choose a dossier, or paste a receipt.', noKeys: 'A receipt is checked against the workspace\'s keys: give a dossier that holds them, or keys.jwks.json.',
    unreadable: 'Unreadable file: {e}', note: 'Each check\'s detail is in English, as in the specification.',
  },
  fr: {
    title: 'Vérificateur Azoth — hors ligne', lead: 'Vérifie un dossier de preuve, un reçu et leurs horodatages entièrement dans cette page : rien n’est envoyé nulle part — la page s’interdit tout accès réseau. Les mêmes règles que la commande azoth-verify (SPEC.md).',
    dossier: 'Dossier de preuve (.zip)', root: 'Certificat racine de l’autorité d’horodatage (PEM, facultatif) — pour faire confiance à ses horodatages',
    receipt: 'Reçu (l’en-tête X-Azoth-Receipt, facultatif)', keys: 'Les clés publiées du workspace (keys.jwks.json, à l’adresse /api/proof/keys/<workspace> — pour un dossier de la plateforme, /api/proof/platform-keys) — requises : un dossier ne se vérifie que sous une clé que vous avez choisie, jamais sous celle qu’il apporte',
    run: 'Vérifier', pass: 'OK', warn: 'À NOTER', fail: 'ÉCHEC', ok: 'VÉRIFIÉ — tout est intact.', ko: 'ÉCHEC — quelque chose ne se vérifie pas.',
    nothing: 'Choisissez un dossier, ou collez un reçu.', noKeys: 'Un reçu se vérifie avec les clés du workspace : donnez un dossier qui les contient, ou keys.jwks.json.',
    unreadable: 'Fichier illisible : {e}', note: 'Le détail de chaque contrôle est en anglais, comme dans la spécification.',
  },
};
const lang = String(globalThis.navigator?.language ?? 'en').toLowerCase().startsWith('fr') ? 'fr' : 'en';
const t = (k, v = {}) => TEXT[lang][k].replace(/\{(\w+)\}/g, (_, n) => String(v[n] ?? ''));
const $ = id => document.getElementById(id);

/** A chosen file's bytes (FileReader: every browser, and jsdom). */
const bytesOf = file => new Promise((resolve, reject) => {
  const r = new FileReader();
  r.onload = () => resolve(new Uint8Array(r.result));
  r.onerror = () => reject(r.error ?? new Error('read failed'));
  r.readAsArrayBuffer(file);
});

function show(checks, ok) {
  const list = $('checks');
  list.replaceChildren(...checks.map(c => {
    const li = document.createElement('li');
    const level = !c.ok ? 'fail' : c.level === 'warn' ? 'warn' : 'pass';
    li.className = level;
    const tag = document.createElement('strong');
    tag.textContent = t(level);
    const id = document.createElement('code');
    id.textContent = c.id;
    li.append(tag, ' ', id, ' ', c.detail);
    return li;
  }));
  const verdict = $('verdict');
  verdict.textContent = ok ? t('ok') : t('ko');
  verdict.className = ok ? 'pass' : 'fail';
}

function say(message) {
  $('checks').replaceChildren();
  const verdict = $('verdict');
  verdict.textContent = message;
  verdict.className = 'fail';
}

async function run() {
  const dossierFile = $('dossier').files?.[0];
  const rootFile = $('root').files?.[0];
  const keysFile = $('keys').files?.[0];
  const receipt = $('receipt').value.trim();
  if (!dossierFile && !receipt) { say(t('nothing')); return; }
  let files = null; let tsaRootPem; let jwks = null;
  try {
    if (dossierFile) files = readZip(await bytesOf(dossierFile));
    if (rootFile) tsaRootPem = fromUtf8(await bytesOf(rootFile));
    if (keysFile) jwks = JSON.parse(fromUtf8(await bytesOf(keysFile)));
    else if (files?.['keys.jwks.json']) jwks = JSON.parse(fromUtf8(files['keys.jwks.json']));
  } catch (err) { say(t('unreadable', { e: err?.message ?? String(err) })); return; }

  // Keys the reader chose are the ones pinned: the dossier's signature is checked against them too.
  const checks = files ? [...verifyDossier(files, { tsaRootPem, keys: keysFile ? jwks : null }).checks] : [];
  if (receipt) {
    if (!jwks) { say(t('noKeys')); return; }
    let pack = null;
    try { pack = files?.['evidence.json'] ? JSON.parse(fromUtf8(files['evidence.json'])) : null; } catch { pack = null; }
    checks.push(...verifyReceipt(receipt, jwks, { pack }));
  }
  show(checks, checks.every(c => c.ok));
}

document.documentElement.lang = lang;
document.title = t('title');
for (const el of document.querySelectorAll('[data-t]')) el.textContent = t(el.dataset.t);
$('run').addEventListener('click', () => {
  $('run').disabled = true;
  run().finally(() => { $('run').disabled = false; });
});
