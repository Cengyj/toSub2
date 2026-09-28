import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import vm from "node:vm";

// Exercise actual server functions with in-memory files and credentials only.
const source = await fs.readFile(new URL("../src/console-server.mjs", import.meta.url), "utf8");
const names = [
  "importAccount", "startJob", "updateJobCredentials", "accountImportChanges", "prepareImportedAction",
  "withEmailJobLock", "retryJob", "enqueueJob", "startTotpSetup", "startPasswordAdd",
  "finishTotpSetup", "finishPasswordAdd", "loadTotpSetupResult", "assertNoPendingTotpRecovery", "removePrivateFile",
  "normalizeLoginCredentials", "normalizeTotpSecret", "normalizeResetTotpOption", "normalizeLogoutAllDevicesOption",
  "newTotpResetState", "newLogoutAllDevicesState", "totpResetMetadata", "logoutAllDevicesMetadata",
  "readTotpResetState", "readLogoutAllDevicesState", "applyTotpResetResult", "applyTotpLogoutResult",
  "applyTotpResetCompletion", "applyTotpLogoutCheckpoint", "totpLogoutResultText", "finalizeRestoredTotpJob",
  "canRetryJob", "canForceRelogin", "canSetupTotp", "totpSetupUnavailableReason",
  "canResetTotp", "totpResetUnavailableReason", "canAddPassword", "publicJob",
  "getAutoRepairEligibility", "getQueuePosition", "accountSourceVersion", "isActive", "isTerminalStatus", "occupiesActiveSlot",
  "recordJobOperation", "beginAuthorizationAutomationAttempt", "touch", "setStage", "sanitizeLog", "generateStrongPassword",
  "supportsPersistentCredentialStorage", "rememberSessionLoginCredentials", "saveJobMetadata",
  "restoredAttemptCount", "restoredCredentialFlags", "restoredMissingCredentials", "restoredTotpSetupState", "syncCompletedOutputs",
];
const functions = names.map((name) => {
  const start = new RegExp(`^(?:async )?function ${name}[(]`, "m").exec(source);
  assert.ok(start, name);
  const end = source.indexOf("\n}", start.index);
  return source.slice(start.index, end + 2);
}).join("\n\n");
const key = "NB2W45DFOIZAQWER";

function harness(platform = "win32") {
  const files = new Map(); const directories = new Set(); const stored = new Map(); const events = [];
  const root = path.resolve("mock-import-output");
  const missingFile = () => Object.assign(new Error("missing"), { code: "ENOENT" });
  const ctx = vm.createContext({
    crypto, path, Buffer, Date, process: { platform },
    OUTPUT_ROOT: root, JOB_META_FILENAME: "job-meta.json", LOGIN_CHECKPOINT_FILENAME: "login-checkpoint.json",
    TOTP_SETUP_RESULT_FILENAME: "totp-setup-result.json", PASSWORD_ADD_RESULT_FILENAME: "password-add-result.json",
    jobs: new Map(), emailJobLocks: new Map(), sessionLoginCredentials: new Map(),
    outputSyncPromise: null, lastOutputSyncAt: 0, mailRequestConfig: { method: "GET", url: null },
    fs: {
      async mkdir(dir) { directories.add(dir); },
      async writeFile(file, value) { files.set(file, String(value)); },
      async readFile(file) { if (!files.has(file)) throw missingFile(); return files.get(file); },
      async rename(from, to) { if (!files.has(from)) throw missingFile(); files.set(to, files.get(from)); files.delete(from); },
      async unlink(file) { if (!files.has(file)) throw missingFile(); files.delete(file); },
      async stat(file) { if (!files.has(file)) throw missingFile(); return { mtime: new Date() }; },
      async readdir() { return [...directories].map((dir) => ({ name: path.basename(dir), isDirectory: () => true })); },
    },
    httpError(status, message) { return Object.assign(new Error(message), { status }); },
    validateMailApiUrl(value) { return typeof value === "string" && /^https?:\/\//.test(value); },
    normalizeProxyUrl(value) { return value ? String(value).trim() : null; },
    isEmail(value) { return typeof value === "string" && value.includes("@"); },
    findJobByEmail(email) { return [...ctx.jobs.values()].find((job) => job.email.toLowerCase() === email.toLowerCase()) || null; },
    newSmsState() { return {}; }, restoredSmsState() { return {}; },
    restoredProxyRiskState() { return {}; }, restoredAutoRepairState() { return {}; },
    async saveStoredLoginCredentials(email, credentials) {
      events.push("credential-save");
      if (platform !== "win32" && platform !== "darwin") return false;
      stored.set(email.toLowerCase(), { ...credentials }); return true;
    },
    async loadStoredLoginCredentials(email) { events.push("credential-read"); return stored.get(email.toLowerCase()) || { password: "", totpSecret: "", proxyUrl: null }; },
    async recoverAddedPasswordCredential({ credentials }) { return { credentials, recovered: false }; },
    async recoverActivatedTotpCredential({ credentials }) { return { credentials, recovered: false }; },
    async fileExists(file) { return files.has(file); },
    async reloadMissingJobCredentials() {},
    appendJobLog(job, text) { job.logs += text; },
    scheduleQueuedJobs() { events.push("schedule"); },
    stopMailPolling() {}, stopSmsPolling() {}, releaseSmsNumber() {}, resetProxyRiskState() {}, clearAutoRepairBlock() {},
    restartJobAfterConfigurationUpdate() { throw new Error("import must not restart a protocol"); },
    loadMailboxBaseline() { throw new Error("import must not request email"); },
    spawn() { throw new Error("import must not launch a protocol"); },
  });
  vm.runInContext(functions, ctx);
  return { ctx, files, stored, events, root };
}

async function importOne(h, email, credentials = {}, proxyUrl = null) {
  return (await h.ctx.importAccount({ email, ...credentials }, proxyUrl, Boolean(proxyUrl))).job;
}

{
  const h = harness();
  const job = await importOne(h, "import-only@example.test", { password: "imported-password", mailApiUrl: "https://mail.example.test/otp" });
  const view = h.ctx.publicJob(job);
  assert.equal(view.status, "imported"); assert.equal(view.attempt, 0);
  assert.equal(view.lastOperationType, "account_import"); assert.equal(view.canDownload, false);
  assert.equal(view.canRetry, true); assert.equal(view.canForceRelogin, true); assert.equal(view.canSetupTotp, true);
  assert.equal(view.autoRepairEligible, false); assert.equal(view.queuePosition, 0);
  assert.equal(job.authAutomationAttempt, null); assert.equal(job.child, null);
  assert.equal(h.ctx.occupiesActiveSlot(job), false); assert.equal(h.events.includes("schedule"), false);
  assert.equal(h.files.size, 1, "import writes only non-secret job metadata");
  const metadata = JSON.parse([...h.files.values()][0]);
  assert.equal(metadata.status, "imported"); assert.equal(metadata.attempt, 0);
  assert.equal(metadata.queued_mode, null); assert.equal(metadata.queued_at, null);
  assert.equal(JSON.stringify(metadata).includes("imported-password"), false);
  h.ctx.jobs.clear(); h.ctx.sessionLoginCredentials.clear(); h.stored.clear();
  await h.ctx.syncCompletedOutputs(true);
  const restored = h.ctx.jobs.get(job.id);
  assert.equal(restored.status, "imported"); assert.equal(restored.attempt, 0);
  assert.equal(restored.queuedMode, null); assert.equal(restored.hasPasswordCredential, true);
  assert.equal(restored.password, ""); assert.equal(h.events.includes("schedule"), false);
  const before = [...h.files.entries()]; const saves = h.events.filter((event) => event === "credential-save").length;
  await assert.rejects(h.ctx.retryJob(restored, { proxyUrl: "" }), { status: 409 });
  assert.equal(restored.status, "imported"); assert.equal(restored.attempt, 0);
  assert.deepEqual([...h.files.entries()], before, "missing credentials must not overwrite recovery files");
  assert.equal(h.events.filter((event) => event === "credential-save").length, saves);
}

{
  const h = harness();
  const job = await h.ctx.startJob("single-account@example.test");
  assert.equal(job.status, "queued"); assert.equal(job.attempt, 1);
  assert.equal(job.lastOperationType, "initial_authorization"); assert.equal(h.events.includes("schedule"), true);
}

for (const platform of ["linux", "win32"]) {
  const h = harness(platform);
  const entry = { password: "first-password", totpSecret: key };
  const job = await importOne(h, "repeat@example.test", entry);
  const initialAt = job.lastOperationAt;
  const repeated = await importOne(h, job.email.toUpperCase(), entry);
  assert.equal(repeated.id, job.id); assert.equal(job.lastOperationAt, initialAt);
  assert.equal(job.status, "imported"); assert.equal(job.attempt, 0);
  await importOne(h, job.email, { ...entry, password: "updated-password" });
  assert.equal(job.password, "updated-password"); assert.equal(job.status, "imported");
  assert.equal(job.attempt, 0); assert.equal(job.lastOperationType, "account_update");
  assert.equal(h.events.includes("schedule"), false);
  Object.assign(job, { status: "working", runMode: "totp_setup", totpCredentialAckRunId: "current" });
  await importOne(h, job.email, { preserveExistingCredentials: true });
  await assert.rejects(importOne(h, job.email, { password: "must-not-change", totpSecret: key }), { status: 409 });
  assert.equal(job.password, "updated-password"); assert.equal(job.status, "working");
  Object.assign(job, { status: "queued", runMode: null, totpCredentialAckRunId: null, password: "", loginMode: "password", hasPasswordCredential: true });
  await importOne(h, job.email, { preserveExistingCredentials: true });
  assert.equal(job.loginMode, "password", "no-op email import must not rewrite missing stored credential flags");
  await assert.rejects(importOne(h, job.email, { password: "must-not-start", totpSecret: key }), { status: 409 });
  assert.equal(h.events.includes("schedule"), false);
}

{
  const h = harness();
  const job = await importOne(h, "manual-authorization@example.test");
  await h.ctx.retryJob(job);
  assert.equal(job.status, "queued"); assert.equal(job.queuedMode, "full");
  assert.equal(job.attempt, 1); assert.equal(job.lastOperationType, "initial_authorization");
  assert.equal(h.events.filter((event) => event === "schedule").length, 1);
  job.status = "failed";
  await h.ctx.retryJob(job);
  assert.equal(job.attempt, 2); assert.equal(job.lastOperationType, "reauthorize");
}

for (const mode of ["totp_setup", "password_add"]) {
  const h = harness();
  const job = await importOne(h, `${mode}@example.test`);
  if (mode === "totp_setup") await h.ctx.startTotpSetup(job);
  else await h.ctx.startPasswordAdd(job);
  assert.equal(job.status, "queued"); assert.equal(job.queuedMode, mode);
  assert.equal(job.attempt, 0); assert.equal(job.securityActionReturnStatus, "imported");
  assert.equal(job.totpSetupResumesAuthorization, false); assert.equal(job.passwordAddResumesAuthorization, false);
  if (mode === "totp_setup") {
    h.files.set(job.totpResultPath, JSON.stringify({ version: 1, email: job.email, activation_succeeded: true, activation_mode: "automatic", secret: key, otpauth_uri: "otpauth://totp/test" }));
    await h.ctx.finishTotpSetup(job, 0, null);
  } else {
    h.files.set(job.passwordAddResultPath, JSON.stringify({ version: 1, email: job.email, password: job.pendingNewPassword }));
    await h.ctx.finishPasswordAdd(job, 0, null);
  }
  assert.equal(job.status, "imported"); assert.equal(job.attempt, 0);
  assert.equal(job.queuedMode, null); assert.equal(job.queuedAt, null);
  assert.equal(h.ctx.publicJob(job).canDownload, false);
  await h.ctx.retryJob(job);
  assert.equal(job.attempt, 1); assert.equal(job.lastOperationType, "initial_authorization");
}

for (const mode of ["totp_setup", "password_add"]) {
  const h = harness();
  const job = await importOne(h, `interrupted-${mode}@example.test`);
  if (mode === "totp_setup") await h.ctx.startTotpSetup(job); else await h.ctx.startPasswordAdd(job);
  await job.metadataWritePromise;
  h.ctx.jobs.clear();
  await h.ctx.syncCompletedOutputs(true);
  const restored = h.ctx.jobs.get(job.id);
  assert.equal(restored.status, "failed", "interrupted security selection must not become automatic authorization");
  assert.equal(restored.attempt, 0); assert.equal(restored.queuedMode, null);
  assert.equal(h.ctx.occupiesActiveSlot(restored), false);
  assert.equal(h.events.filter((event) => event === "schedule").length, 1, "only the original manual selection may schedule work");
}

{
  const h = harness("linux");
  const job = await importOne(h, "unsupported-first-setup@example.test");
  await h.ctx.startTotpSetup(job);
  h.files.set(job.totpResultPath, JSON.stringify({ version: 1, email: job.email, activation_succeeded: true, activation_mode: "automatic", secret: key, otpauth_uri: "otpauth://totp/test" }));
  await h.ctx.finishTotpSetup(job, 0, null);
  assert.equal(job.status, "imported"); assert.equal(job.totpRecoveryPending, true);
  assert.equal(job.totpCredentialCommitted, false); assert.equal(h.files.has(job.totpResultPath), true);
  await assert.rejects(h.ctx.retryJob(job), { status: 409 });
  await assert.rejects(h.ctx.startPasswordAdd(job), { status: 409 });
  await assert.rejects(importOne(h, job.email, { totpSecret: key }), { status: 409 });
  assert.equal(job.totpRecoveryPending, true); assert.equal(job.attempt, 0);
}

{
  const h = harness();
  const job = await importOne(h, "proxy-import@example.test", {}, "http://proxy.example:8080");
  await h.ctx.retryJob(job, { proxyUrl: "" });
  assert.equal(job.proxyUrl, "http://proxy.example:8080");
  const missing = await importOne(h, "missing-proxy@example.test", {}, "http://lost.example:8080");
  missing.proxyUrl = null; h.stored.delete(missing.email);
  await assert.rejects(h.ctx.retryJob(missing, { proxyUrl: "" }), { status: 409 });
  await assert.rejects(h.ctx.startTotpSetup(missing, { proxyUrl: "" }), { status: 409 });
  await assert.rejects(h.ctx.startPasswordAdd(missing, { proxyUrl: "" }), { status: 409 });
  assert.equal(missing.status, "imported"); assert.equal(missing.attempt, 0);
  await h.ctx.retryJob(missing, { proxyUrl: "http://replacement.example:8080" });
  assert.equal(missing.proxyUrl, "http://replacement.example:8080"); assert.equal(missing.attempt, 1);
}

console.log("Batch import-only lifecycle tests passed: no automatic work, safe updates, manual actions, and no security replay.");
