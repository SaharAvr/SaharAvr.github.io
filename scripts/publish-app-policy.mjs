#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const defaultSite = path.resolve(path.dirname(scriptPath), '..');
const argv = process.argv.slice(2);
const valueAfter = (flag) => {
  const index = argv.indexOf(flag);
  return index >= 0 ? argv[index + 1] : undefined;
};
const hasFlag = (flag) => argv.includes(flag);
const project = path.resolve(valueAfter('--project') || process.cwd());
const site = path.resolve(valueAfter('--site') || defaultSite);
const dryRun = hasFlag('--dry-run');
const deploymentTimeoutMs = Number(valueAfter('--deployment-timeout-ms') || 600_000);
const lockTimeoutMs = Number(valueAfter('--lock-timeout-ms') || 600_000);

const state = {
  siteCommit: null,
  pushed: false,
  deploymentVerified: false,
};

class PolicyPublishError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'PolicyPublishError';
    this.code = code;
    this.details = details;
  }
}

function fail(code, message, details) {
  throw new PolicyPublishError(code, message, details);
}

function readJson(absolute, label) {
  if (!fs.existsSync(absolute)) fail('MISSING_FILE', `${label} was not found`, { path: absolute });
  try {
    return JSON.parse(fs.readFileSync(absolute, 'utf8'));
  } catch (error) {
    fail('INVALID_JSON', `${label} is not valid JSON`, { path: absolute, message: error.message });
  }
}

function requiredText(value, label) {
  if (typeof value !== 'string' || value.trim() === '') fail('INVALID_APP_PROFILE', `${label} must be a non-empty string`);
  return value.trim();
}

function runGit(args, options = {}) {
  try {
    return execFileSync('git', args, {
      cwd: site,
      encoding: 'utf8',
      stdio: options.inherit ? 'inherit' : ['ignore', 'pipe', 'pipe'],
    }).trim();
  } catch (error) {
    const stderr = typeof error.stderr === 'string' ? error.stderr.trim() : '';
    fail('GIT_COMMAND_FAILED', `git ${args.join(' ')} failed`, { stderr, exitCode: error.status ?? null });
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function render(template, values, label) {
  const rendered = template.replace(/\{\{([A-Z0-9_]+)\}\}/g, (match, key) => {
    if (!(key in values)) fail('UNKNOWN_TEMPLATE_TOKEN', `${label} contains unknown token ${match}`);
    return values[key];
  });
  const remaining = rendered.match(/\{\{[A-Z0-9_]+\}\}/g);
  if (remaining) fail('UNRESOLVED_TEMPLATE_TOKEN', `${label} contains unresolved tokens`, { tokens: remaining });
  return `${rendered.trim()}\n`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function processExists(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

async function acquireLock() {
  const gitDirectoryRaw = runGit(['rev-parse', '--git-dir']);
  const gitDirectory = path.resolve(site, gitDirectoryRaw);
  const lockDirectory = path.join(gitDirectory, 'publish-app-policy.lock');
  const ownerPath = path.join(lockDirectory, 'owner.json');
  const deadline = Date.now() + lockTimeoutMs;
  while (true) {
    try {
      fs.mkdirSync(lockDirectory, { mode: 0o700 });
      fs.writeFileSync(ownerPath, `${JSON.stringify({ pid: process.pid, project, acquiredAt: new Date().toISOString() })}\n`, { mode: 0o600 });
      return () => fs.rmSync(lockDirectory, { recursive: true, force: true });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      let owner = null;
      try {
        owner = JSON.parse(fs.readFileSync(ownerPath, 'utf8'));
      } catch {}
      const lockAgeMs = Date.now() - fs.statSync(lockDirectory).mtimeMs;
      if (owner !== null && !processExists(owner.pid)) {
        fs.rmSync(lockDirectory, { recursive: true, force: true });
        continue;
      }
      if (owner === null && lockAgeMs >= 30_000) {
        fs.rmSync(lockDirectory, { recursive: true, force: true });
        continue;
      }
      if (Date.now() >= deadline) {
        fail('SITE_REPOSITORY_LOCK_TIMEOUT', 'Timed out waiting for another policy publisher to finish', { owner });
      }
      await sleep(500);
    }
  }
}

function atomicWrite(absolute, content) {
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, content, { mode: 0o644 });
  fs.renameSync(temporary, absolute);
}

function validateGeneratedHtml(html, label, app) {
  const required = [app.name, app.androidPackage, app.iosBundleId, app.developerName, app.contactEmail, app.fingerprint];
  for (const value of required) {
    if (!html.includes(escapeHtml(value)) && !html.includes(value)) {
      fail('GENERATED_POLICY_IDENTITY_MISSING', `${label} is missing required app identity`, { value });
    }
  }
  if (/\u2014/.test(html)) fail('GENERATED_POLICY_EM_DASH', `${label} contains an em dash`);
  if (/\b(?:19|20)\d{2}\b/.test(html)) fail('GENERATED_POLICY_YEAR', `${label} contains a year`);
  if (/\b(?:local|locally)\b/i.test(html)) fail('GENERATED_POLICY_LOCAL_WORDING', `${label} contains prohibited local terminology`);
}

async function verifyDeployment(urls, fingerprint, app) {
  const deadline = Date.now() + deploymentTimeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    for (const [kind, url] of Object.entries(urls)) {
      try {
        const parsed = new URL(url);
        parsed.searchParams.set('policy-fingerprint', fingerprint);
        parsed.searchParams.set('attempt', String(Date.now()));
        const response = await fetch(parsed, {
          redirect: 'follow',
          cache: 'no-store',
          signal: AbortSignal.timeout(15_000),
          headers: { 'cache-control': 'no-cache', pragma: 'no-cache' },
        });
        const body = await response.text();
        const identitiesPresent = [app.name, app.androidPackage, app.iosBundleId, app.developerName]
          .every((identity) => body.includes(escapeHtml(identity)) || body.includes(identity));
        const fingerprintPresent = body.includes(`name="policy-fingerprint" content="${fingerprint}"`);
        last = { kind, url, status: response.status, identitiesPresent, fingerprintPresent };
        if (!response.ok || !identitiesPresent || !fingerprintPresent) break;
        if (kind === 'dataDeletion' && !/(delete|deletion|remove)/i.test(body)) break;
        if (kind === 'dataDeletion') return;
      } catch (error) {
        last = { kind, url, message: error.message };
        break;
      }
    }
    await sleep(2_000);
  }
  fail('GITHUB_PAGES_DEPLOYMENT_TIMEOUT', 'The site push succeeded, but the exact generated policy fingerprint did not appear before the deployment timeout', { last });
}

async function main() {
  if (!Number.isFinite(deploymentTimeoutMs) || deploymentTimeoutMs < 10_000) fail('INVALID_ARGUMENT', '--deployment-timeout-ms must be at least 10000');
  if (!Number.isFinite(lockTimeoutMs) || lockTimeoutMs < 1_000) fail('INVALID_ARGUMENT', '--lock-timeout-ms must be at least 1000');

  const appJson = readJson(path.join(project, 'app.json'), 'app.json');
  const appProfile = readJson(path.join(project, 'release', 'app-profile.json'), 'release/app-profile.json');
  const publisher = readJson(path.join(site, 'policy-templates', 'publisher-profile.json'), 'publisher profile');
  const expo = appJson?.expo;
  const name = requiredText(expo?.name, 'expo.name');
  const slug = requiredText(expo?.slug, 'expo.slug');
  const androidPackage = requiredText(expo?.android?.package, 'expo.android.package');
  const iosBundleId = requiredText(expo?.ios?.bundleIdentifier, 'expo.ios.bundleIdentifier');
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) fail('INVALID_APP_PROFILE', 'expo.slug must use lowercase hyphen-case');
  if (!/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(androidPackage)) fail('INVALID_APP_PROFILE', 'expo.android.package is invalid');
  if (!/^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$/.test(iosBundleId)) fail('INVALID_APP_PROFILE', 'expo.ios.bundleIdentifier is invalid');
  const adsEnabled = appProfile?.ads?.enabled;
  if (typeof adsEnabled !== 'boolean') fail('INVALID_APP_PROFILE', 'release/app-profile.json must contain ads.enabled as a boolean');
  if (adsEnabled && appProfile?.ads?.provider !== 'admob') fail('UNSUPPORTED_ADS_PROVIDER', 'Only the AdMob ads profile is supported');
  const affiliateEnabled = appProfile?.affiliateLinks?.enabled === true;
  const affiliateProviders = Array.isArray(appProfile?.affiliateLinks?.providers) ? appProfile.affiliateLinks.providers : [];
  if (affiliateEnabled && (affiliateProviders.length !== 1 || affiliateProviders[0] !== 'aliexpress')) {
    fail('UNSUPPORTED_AFFILIATE_PROVIDER', 'Only the AliExpress affiliate profile is supported');
  }

  const developerName = requiredText(publisher.developerName, 'publisherProfile.developerName');
  const contactEmail = requiredText(publisher.contactEmail, 'publisherProfile.contactEmail');
  const websiteUrl = new URL(requiredText(publisher.websiteUrl, 'publisherProfile.websiteUrl')).toString().replace(/\/$/, '');
  const templates = {
    privacy: fs.readFileSync(path.join(site, 'policy-templates', 'privacy.html'), 'utf8'),
    deletion: fs.readFileSync(path.join(site, 'policy-templates', 'data-deletion.html'), 'utf8'),
    admob: fs.readFileSync(path.join(site, 'policy-templates', 'fragments', 'admob.html'), 'utf8'),
    noAds: fs.readFileSync(path.join(site, 'policy-templates', 'fragments', 'no-ads.html'), 'utf8'),
    aliexpress: fs.readFileSync(path.join(site, 'policy-templates', 'fragments', 'aliexpress.html'), 'utf8'),
  };
  const fingerprintSource = JSON.stringify({
    schemaVersion: 1,
    name,
    slug,
    androidPackage,
    iosBundleId,
    ads: adsEnabled ? 'admob' : 'none',
    affiliate: affiliateEnabled ? 'aliexpress' : 'none',
    developerName,
    contactEmail,
    websiteUrl,
    templates,
  });
  const fingerprint = crypto.createHash('sha256').update(fingerprintSource).digest('hex');
  const privacyPolicyUrl = `${websiteUrl}/privacy-policy/${slug}/`;
  const dataDeletionUrl = `${privacyPolicyUrl}data-deletion/`;
  const app = { name, slug, androidPackage, iosBundleId, developerName, contactEmail, fingerprint };
  const fragmentValues = { APP_NAME: escapeHtml(name) };
  const adsSection = render(adsEnabled ? templates.admob : templates.noAds, fragmentValues, 'advertising fragment').trim();
  const affiliateSection = affiliateEnabled ? render(templates.aliexpress, fragmentValues, 'affiliate fragment').trim() : '';
  const thirdPartyDeletion = adsEnabled || affiliateEnabled
    ? `<section>\n      <h2>Third-party information</h2>\n      <p>Information processed independently by ${adsEnabled ? 'Google and its advertising partners' : ''}${adsEnabled && affiliateEnabled ? ', or by ' : ''}${affiliateEnabled ? 'AliExpress and its service providers' : ''}, is governed by those providers' privacy and retention policies. Use the app's available privacy controls, your provider accounts, and your device settings to manage applicable choices.</p>\n    </section>`
    : '';
  const values = {
    APP_NAME: escapeHtml(name),
    ANDROID_PACKAGE: escapeHtml(androidPackage),
    IOS_BUNDLE_ID: escapeHtml(iosBundleId),
    DEVELOPER_NAME: escapeHtml(developerName),
    CONTACT_EMAIL: escapeHtml(contactEmail),
    CONTACT_EMAIL_URI: encodeURIComponent(contactEmail),
    WEBSITE_URL: escapeHtml(websiteUrl),
    POLICY_FINGERPRINT: fingerprint,
    PRIVACY_EMAIL_SUBJECT: encodeURIComponent(`${name} Privacy`),
    DELETION_EMAIL_SUBJECT: encodeURIComponent(`${name} Data Deletion Request`),
    ADS_SECTION: adsSection,
    AFFILIATE_SECTION: affiliateSection,
    THIRD_PARTY_DELETION_SECTION: thirdPartyDeletion,
  };
  const privacyHtml = render(templates.privacy, values, 'privacy template');
  const deletionHtml = render(templates.deletion, values, 'data deletion template');
  validateGeneratedHtml(privacyHtml, 'privacy policy', app);
  validateGeneratedHtml(deletionHtml, 'data deletion page', app);

  const result = {
    status: dryRun ? 'dry_run' : 'success',
    projectPath: project,
    app: { name, slug, androidPackage, iosBundleId },
    profile: { ads: adsEnabled ? 'admob' : 'none', affiliateLinks: affiliateEnabled ? 'aliexpress' : 'none' },
    fingerprint,
    urls: { privacyPolicy: privacyPolicyUrl, dataDeletion: dataDeletionUrl, website: websiteUrl },
    site: { repositoryPath: site, commit: null, changed: false, pushed: false, deploymentVerified: false },
  };
  if (dryRun) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const releaseLock = await acquireLock();
  try {
    if (runGit(['branch', '--show-current']) !== 'main') fail('SITE_REPOSITORY_WRONG_BRANCH', 'The GitHub Pages repository must be on main');
    const dirty = runGit(['status', '--porcelain=v1', '--untracked-files=all']);
    if (dirty !== '') fail('SITE_REPOSITORY_DIRTY', 'The GitHub Pages repository has changes unrelated to this publisher run', { status: dirty.split('\n') });
    runGit(['pull', '--rebase', 'origin', 'main']);

    const privacyRelative = path.posix.join('privacy-policy', slug, 'index.html');
    const deletionRelative = path.posix.join('privacy-policy', slug, 'data-deletion', 'index.html');
    atomicWrite(path.join(site, privacyRelative), privacyHtml);
    atomicWrite(path.join(site, deletionRelative), deletionHtml);
    runGit(['add', '--', privacyRelative, deletionRelative]);
    const staged = runGit(['diff', '--cached', '--name-only']);
    if (staged !== '') {
      const unexpected = staged.split('\n').filter((entry) => entry !== privacyRelative && entry !== deletionRelative);
      if (unexpected.length) fail('UNEXPECTED_STAGED_FILE', 'The publisher staged a file outside this app policy', { unexpected });
      runGit(['commit', '-m', `Update ${name} policy pages`]);
      result.site.changed = true;
    }
    runGit(['push', 'origin', 'main']);
    state.pushed = true;
    state.siteCommit = runGit(['rev-parse', 'HEAD']);
    result.site.commit = state.siteCommit;
    result.site.pushed = true;
  } finally {
    releaseLock();
  }

  await verifyDeployment({ privacyPolicy: privacyPolicyUrl, dataDeletion: dataDeletionUrl }, fingerprint, app);
  state.deploymentVerified = true;
  result.site.deploymentVerified = true;
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  const structured = {
    status: 'failed',
    code: error.code || 'POLICY_PUBLISH_FAILED',
    message: error.message,
    details: error.details || {},
    site: state,
  };
  console.log(JSON.stringify(structured, null, 2));
  process.exitCode = 1;
});
