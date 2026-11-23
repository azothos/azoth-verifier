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
import { verifyExport } from '../src/export.mjs';
import { readZip } from '../src/zip.mjs';
import { fromUtf8 } from '../src/bytes.mjs';
import { readPublishedRoots } from '../src/headroot.mjs';

const TEXT = {
  en: {
    title: 'Azoth verifier — offline', lead: 'Checks an evidence dossier, a signed evidence pack, a receipt and their timestamps entirely in this page: nothing is sent anywhere — the page forbids itself any network access. The same rules as the azoth-verify command line (SPEC.md).',
    dossier: 'Evidence dossier (.zip)', root: 'Root certificate of the time-stamping authority (PEM, optional) — to trust its timestamps',
    publishedRoots: 'The hourly roots the producer published (.json, saved from /api/proof/head-roots?from=<hour>&to=<hour> — optional, one file or more) — to check that the dossier\'s roots are the ones published then',
    receipt: 'Receipt (the X-Azoth-Receipt header, optional)',
    pack: 'Evidence pack (.json, from /api/v1/journal/export, saved exactly as received — optional)', packSignature: 'Its signature (the X-Azoth-Export-Signature header)',
    keys: 'The workspace\'s published keys (keys.jwks.json, from /api/proof/keys/<workspace> — for a platform package, /api/proof/platform-keys) — required: a dossier verifies only under a key you chose, never one it ships',
    run: 'Verify', pass: 'PASS', warn: 'NOTE', fail: 'FAIL', ok: 'VERIFIED — everything is intact.', ko: 'FAILED — something does not verify.',
    nothing: 'Choose a dossier or an evidence pack, or paste a receipt.', noKeys: 'A receipt is checked against the workspace\'s keys: give a dossier that holds them, or keys.jwks.json.',
    unreadable: 'Unreadable file: {e}', note: 'Each check\'s detail is in English, as in the specification.',
  },
  fr: {
    title: 'Vérificateur Azoth — hors ligne', lead: 'Vérifie un dossier de preuve, un pack de preuve signé, un reçu et leurs horodatages entièrement dans cette page : rien n’est envoyé nulle part — la page s’interdit tout accès réseau. Les mêmes règles que la commande azoth-verify (SPEC.md).',
    dossier: 'Dossier de preuve (.zip)', root: 'Certificat racine de l’autorité d’horodatage (PEM, facultatif) — pour faire confiance à ses horodatages',
    publishedRoots: 'Les racines horaires publiées par le producteur (.json, enregistré depuis /api/proof/head-roots?from=<heure>&to=<heure> — facultatif, un fichier ou plusieurs) — pour vérifier que les racines du dossier sont celles publiées alors',
    receipt: 'Reçu (l’en-tête X-Azoth-Receipt, facultatif)',
    pack: 'Pack de preuve (.json, de /api/v1/journal/export, enregistré tel que reçu — facultatif)', packSignature: 'Sa signature (l’en-tête X-Azoth-Export-Signature)',
    keys: 'Les clés publiées du workspace (keys.jwks.json, à l’adresse /api/proof/keys/<workspace> — pour un dossier de la plateforme, /api/proof/platform-keys) — requises : un dossier ne se vérifie que sous une clé que vous avez choisie, jamais sous celle qu’il apporte',
    run: 'Vérifier', pass: 'OK', warn: 'À NOTER', fail: 'ÉCHEC', ok: 'VÉRIFIÉ — tout est intact.', ko: 'ÉCHEC — quelque chose ne se vérifie pas.',
    nothing: 'Choisissez un dossier ou un pack de preuve, ou collez un reçu.', noKeys: 'Un reçu se vérifie avec les clés du workspace : donnez un dossier qui les contient, ou keys.jwks.json.',
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
  const packFile = $('pack').files?.[0];
  const publishedFiles = [...($('publishedRoots').files ?? [])];
  if (!dossierFile && !receipt && !packFile) { say(t('nothing')); return; }
  let files = null; let tsaRootPem; let jwks = null; let packBody = null; let publishedRoots = null;
  try {
    if (dossierFile) files = readZip(await bytesOf(dossierFile));
    if (packFile) packBody = await bytesOf(packFile);
    if (rootFile) tsaRootPem = fromUtf8(await bytesOf(rootFile));
    if (keysFile) jwks = JSON.parse(fromUtf8(await bytesOf(keysFile)));
    else if (files?.['keys.jwks.json']) jwks = JSON.parse(fromUtf8(files['keys.jwks.json']));
    // The roots the producer published (Check 18, step 6): files the reader saved — the page fetches nothing.
    for (const f of publishedFiles) {
      const read = readPublishedRoots(await bytesOf(f));
      if (read.error) throw new Error(`${f.name}: ${read.error}`);
      publishedRoots = [...(publishedRoots ?? []), ...read.roots];
    }
  } catch (err) { say(t('unreadable', { e: err?.message ?? String(err) })); return; }

  // Keys the reader chose are the ones pinned: the dossier's signature is checked against them too.
  const checks = files ? [...verifyDossier(files, { tsaRootPem, keys: keysFile ? jwks : null, publishedRoots }).checks] : [];
  if (receipt) {
    if (!jwks) { say(t('noKeys')); return; }
    let pack = null;
    try { pack = files?.['evidence.json'] ? JSON.parse(fromUtf8(files['evidence.json'])) : null; } catch { pack = null; }
    checks.push(...verifyReceipt(receipt, jwks, { pack }));
  }
  // A signed evidence pack (Check 17): only under the keys the reader chose — the pack ships none.
  if (packBody) checks.push(...verifyExport(packBody, $('packSignature').value, { keys: keysFile ? jwks : null }).checks);
  show(checks, checks.every(c => c.ok));
}

document.documentElement.lang = lang;
document.title = t('title');
for (const el of document.querySelectorAll('[data-t]')) el.textContent = t(el.dataset.t);
$('run').addEventListener('click', () => {
  $('run').disabled = true;
  run().finally(() => { $('run').disabled = false; });
});
