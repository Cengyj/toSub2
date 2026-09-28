import assert from "node:assert/strict";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs/promises";
import vm from "node:vm";

// Exercise the actual server lifecycle with deterministic files and credential I/O.
const source = await fs.readFile(new URL("../src/console-server.mjs", import.meta.url), "utf8");
const names = [
  "normalizeLogoutAllDevicesOption", "normalizeResetTotpOption", "newLogoutAllDevicesState",
  "newTotpResetState", "totpResetMetadata", "readTotpResetState", "applyTotpResetResult",
  "applyTotpResetCompletion", "acknowledgeTotpResetState", "logoutAllDevicesMetadata",
  "readLogoutAllDevicesState", "applyTotpLogoutResult", "totpLogoutResultText",
  "applyTotpLogoutCheckpoint", "sendTotpCredentialAck", "acknowledgeTotpCredential",
  "loadTotpSetupResult", "finishTotpSetup", "removePrivateFile", "assertNoPendingTotpRecovery",
  "recoverActivatedTotpCredential", "finalizeRestoredTotpJob", "restoredTotpSetupState",
  "stopTotpChild", "cancelJob", "canSetupTotp", "totpSetupUnavailableReason",
  "canResetTotp", "totpResetUnavailableReason", "isActive", "isTerminalStatus",
  "sanitizeLog", "normalizeTotpSecret", "saveStoredLoginCredentials", "loadStoredLoginCredentials",
  "updateJobCredentials", "getAutoRepairEligibility",
  "assertAccountSourceAvailable", "readAccountSource", "accountSourceRevision",
  "assertAccountSourceSnapshotCurrent", "accountSourceVersion", "exportSourceAccounts", "withEmailJobLock",
];
const functions = names.map((name) => {
  const start = new RegExp(`^(?:async )?function ${name}[(]`, "m").exec(source);
  assert.ok(start, name);
  const end = source.indexOf("\n}", start.index);
  return source.slice(start.index, end + 2);
}).join("\n\n");
const oldKey = "JBSWY3DPEHPK3PXP";
const newKey = "NB2W45DFOIZAQWER";
const now = "2026-09-29T00:00:00.000Z";

function harness() {
  const events = [];
  const files = new Map();
  const controls = { saveFails: false, readMismatch: false, metadataFails: false, readHook: null };
  let stored = { password: "test-password", totpSecret: oldKey, proxyUrl: "" };
  const ctx = vm.createContext({
    crypto, Buffer, setTimeout, clearTimeout, shuttingDown: false, jobs: new Map(), emailJobLocks: new Map(),
    fs: {
      async readFile(file) {
        if (!files.has(file)) throw Object.assign(new Error("missing"), { code: "ENOENT" });
        return JSON.stringify(files.get(file));
      },
      async unlink(file) { events.push("delete:" + file); files.delete(file); },
      async rename(from, to) { files.set(to, files.get(from)); files.delete(from); },
    },
    credentialStore: {
      async save(_email, data) { events.push("store-save"); if (controls.saveFails) throw new Error("store unavailable"); stored = { ...data }; },
      async load(email) { events.push("store-read"); await controls.readHook?.(email); return { ...stored, totpSecret: controls.readMismatch ? "" : stored.totpSecret }; },
    },
    async saveJobMetadata(job) {
      events.push("metadata");
      if (controls.metadataFails) throw new Error("metadata write failed");
      files.set("metadata", { ...ctx.logoutAllDevicesMetadata(job), ...ctx.totpResetMetadata(job), status: job.status });
    },
    httpError(status, message) { return Object.assign(new Error(message), { status }); },
    touch() {}, appendJobLog(job, value) { job.logs = (job.logs || "") + value; },
    setStage(job, status, prompt) { job.status = status; job.prompt = prompt; },
    stopMailPolling() {}, stopSmsPolling() {}, releaseSmsNumber() {}, scheduleQueuedJobs() {},
    normalizeProxyUrl(value) { return value || ""; },
    normalizeLoginCredentials(value) { return { loginMode: "password", password: value.password || "", totpSecret: value.totpSecret || "", mailApiUrl: value.mailApiUrl || null, mailRequestBody: value.mailRequestBody || "" }; },
    async reloadMissingJobCredentials() {},
    async fileExists(file) { return files.has(file); },
    async deleteStoredLoginCredentials() { stored = {}; },
    recordJobOperation() {}, restartJobAfterConfigurationUpdate() { throw new Error("unexpected restart"); },
    resolveSelectedJobs(ids) { return ids.map((id) => ctx.jobs.get(id)); },
    downloadTimestamp() { return "test"; },
  });
  vm.runInContext(functions, ctx);
  const child = new EventEmitter();
  child.connected = true; child.exitCode = null; child.signalCode = null;
  child.send = (message, callback) => { events.push({ ack: { ...message } }); callback?.(); };
  const job = {
    ...ctx.newLogoutAllDevicesState(true), ...ctx.newTotpResetState(true),
    id: "unit-job", email: "local-unit@example.com", password: "test-password", totpSecret: oldKey,
    hasTotpCredential: true, totpKnownEnabled: true, hasPasswordCredential: true,
    status: "working", runMode: "totp_setup", runId: "current", totpOperationId: "current",
    child, totpResultPath: "result", checkpointPath: "checkpoint", resultSaved: false,
    totpSetupResumesAuthorization: true, proxyUrl: "", logs: "",
  };
  ctx.jobs.set(job.id, job);
  files.set("checkpoint", { version: 1 });
  return { ctx, events, files, controls, child, job, stored: () => stored };
}

function resetResult(overrides = {}) {
  return { version: 1, email: "local-unit@example.com", operation_id: "current",
    reset_totp_requested: true, reset_totp_status: "disabling", reset_totp_phase: "disable_intent",
    reset_totp_attempted_at: now, old_factor_invalidated: true,
    logout_all_devices_requested: true, logout_all_devices_status: "pending", ...overrides };
}

function activatedResult(overrides = {}) {
  return resetResult({ secret: newKey, otpauth_uri: "otpauth://totp/test",
    activation_mode: "automatic", activation_succeeded: true, activation_verified: true,
    reset_totp_status: "activated", reset_totp_phase: "activated_verified", ...overrides });
}

{
  const { ctx } = harness();
  for (const value of ["false", 0, null, [], {}]) {
    assert.throws(() => ctx.normalizeLogoutAllDevicesOption({ logoutAllDevicesAfterTotp: value }), { status: 400 });
    assert.throws(() => ctx.normalizeResetTotpOption({ resetTotp: value }), { status: 400 });
  }
  assert.equal(ctx.normalizeLogoutAllDevicesOption({}), false);
  const completed = { status: "completed", resultSaved: true, totpSecret: oldKey };
  assert.equal(ctx.canSetupTotp(completed), false);
  assert.equal(ctx.canResetTotp(completed), true);
  assert.match(ctx.totpSetupUnavailableReason(completed), /首次启用/);
  assert.equal(ctx.canResetTotp({ ...completed, totpCredentialInvalidated: true }), false);
  assert.equal(ctx.readLogoutAllDevicesState({ logout_all_devices_requested: true, logout_all_devices_status: "pending" }, {}, true).logoutAllDevicesStatus, "skipped");
  assert.equal(ctx.readLogoutAllDevicesState({ logout_all_devices_requested: true, logout_all_devices_status: "pending", logout_all_devices_attempted_at: now }, {}, true).logoutAllDevicesStatus, "unknown");
}

{
  const h = harness(); h.files.set("result", resetResult());
  await h.ctx.acknowledgeTotpResetState(h.job, h.child, "stale");
  assert.equal(h.events.length, 0);
  await h.ctx.acknowledgeTotpResetState(h.job, h.child, "current");
  assert.equal(h.events.at(-1).ack.ok, true);
  assert.equal(h.events.at(-2), "metadata");
  assert.equal(h.job.totpCredentialInvalidated, true);
  assert.equal(h.job.totpSecret, "");
  assert.equal(h.stored().totpSecret, oldKey);
  assert.equal(h.ctx.getAutoRepairEligibility(h.job).eligible, false);
  h.files.set("result", activatedResult());
  await h.ctx.acknowledgeTotpCredential(h.job, h.child, "current");
  assert.equal(h.events.at(-1).ack.ok, true);
  assert.equal(h.events.at(-2), "metadata");
  assert.equal(h.stored().totpSecret, newKey);
  assert.equal(h.job.totpCredentialInvalidated, false);
  assert.equal(h.job.totpSecret, newKey);
  assert.equal(JSON.stringify(h.events).includes(newKey), false);
}

for (const failure of ["saveFails", "readMismatch", "metadataFails"]) {
  const h = harness(); h.controls[failure] = true; h.files.set("result", resetResult());
  await h.ctx.acknowledgeTotpResetState(h.job, h.child, "current");
  assert.equal(h.events.at(-1).ack.ok, false, failure);
  assert.equal(h.files.has("result"), true);
}

{
  const h = harness(); h.files.set("result", activatedResult({ activation_verified: false, reset_totp_status: "unknown", reset_totp_phase: "recovery_required" }));
  const recovery = await h.ctx.recoverActivatedTotpCredential({ email: h.job.email, resultPath: "result", credentials: { password: h.job.password, totpSecret: oldKey } });
  assert.equal(recovery.recovered, true);
  assert.equal(h.stored().totpSecret, newKey);
  assert.equal(h.files.has("result"), true);
  await h.ctx.finalizeRestoredTotpJob(h.job, recovery);
  assert.equal(h.job.status, "failed");
  assert.equal(h.job.totpCredentialInvalidated, true);
  assert.equal(h.job.totpSecret, "");
  assert.equal(h.files.has("result"), true);
  await assert.rejects(h.ctx.assertNoPendingTotpRecovery(h.job), { status: 409 });
}

{
  const h = harness(); h.files.set("result", activatedResult({ reset_totp_phase: "credential_persisted", logout_all_devices_status: "succeeded", logout_all_devices_attempted_at: now }));
  const recovery = await h.ctx.recoverActivatedTotpCredential({ email: h.job.email, resultPath: "result", credentials: { password: h.job.password } });
  await h.ctx.finalizeRestoredTotpJob(h.job, recovery);
  assert.equal(h.job.logoutAllDevicesStatus, "succeeded");
  assert.equal(h.job.status, "reauth_required");
  assert.equal(h.files.has("checkpoint"), false);
  assert.equal(h.files.has("result"), false);
  assert.ok(h.events.lastIndexOf("metadata") < h.events.indexOf("delete:result"));
  assert.equal(h.files.get("metadata").logout_all_devices_status, "succeeded");
}

{
  const h = harness(); h.files.set("result", activatedResult());
  h.child.kill = () => {
    setTimeout(() => {
      h.files.set("result", activatedResult({ logout_all_devices_status: "unknown", logout_all_devices_attempted_at: now }));
      h.events.push("child-closed"); h.child.signalCode = "SIGTERM"; h.child.emit("close", null, "SIGTERM");
    }, 5);
  };
  await h.ctx.cancelJob(h.job);
  assert.equal(h.job.logoutAllDevicesStatus, "unknown");
  assert.equal(h.job.status, "reauth_required");
  assert.ok(h.events.indexOf("child-closed") < h.events.indexOf("metadata"));
  assert.equal(h.files.has("checkpoint"), false);
}

{
  const h = harness();
  Object.assign(h.job, { status: "failed", runMode: null, totpSecret: "", totpCredentialInvalidated: true,
    loginMode: "password", mailApiUrl: null, mailRequestBody: "" });
  await h.ctx.updateJobCredentials(h.job, { preserveExistingCredentials: true });
  assert.equal(h.stored().totpSecret, oldKey);
  assert.equal(h.job.totpCredentialInvalidated, true);
}

{
  const h = harness();
  h.files.set("result", activatedResult({ reset_totp_status: "unknown", reset_totp_phase: "recovery_required" }));
  const recovery = await h.ctx.recoverActivatedTotpCredential({ email: h.job.email, resultPath: "result", credentials: { password: h.job.password } });
  await h.ctx.finalizeRestoredTotpJob(h.job, recovery);
  assert.equal(h.job.status, "failed");
  assert.equal(h.job.totpRecoveryPending, true);
  assert.equal(h.job.totpCredentialCommitted, true);
  assert.equal(h.job.totpCredentialInvalidated, false);
  assert.equal(h.job.totpSecret, newKey);
  assert.equal(h.files.has("result"), true);
  assert.equal(h.ctx.getAutoRepairEligibility(h.job).eligible, false);
}

{
  const h = harness();
  Object.assign(h.job, { status: "completed", runMode: null, resultSaved: true });
  await h.ctx.credentialStore.save(h.job.email, { password: "updated-password", totpSecret: newKey, proxyUrl: "" });
  const snapshot = await h.ctx.readAccountSource(h.job);
  h.ctx.assertAccountSourceSnapshotCurrent(snapshot);
  assert.equal(snapshot.account.totpSecret, newKey, "source must read persisted replacement, not stale job memory");
  assert.equal(snapshot.account.password, "updated-password");
  assert.deepEqual(Object.keys(snapshot.account).sort(), ["email", "loginMode", "mailApiUrl", "mailRequestBody", "password", "totpSecret"]);
  let headers; let payload;
  await h.ctx.exportSourceAccounts({ writeHead(status, values) { assert.equal(status, 200); headers = values; }, end(value) { payload = String(value); } }, [h.job.id]);
  assert.equal(headers["cache-control"], "no-store");
  assert.equal(payload.replace(/^\uFEFF/, "").trim(), `${h.job.email}----updated-password----${newKey}`);
  assert.equal(h.job.logs.includes(newKey), false);
  for (const flag of ["totpCredentialInvalidated", "totpRecoveryPending"]) {
    h.job[flag] = true;
    await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 });
    h.job[flag] = false;
  }
  h.job.runMode = "totp_setup";
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 });
  h.job.runMode = null;
  h.controls.readHook = async () => { throw new Error(newKey); };
  await assert.rejects(h.ctx.readAccountSource(h.job), (error) => error.status === 409 && !error.message.includes(newKey));
}

{
  const h = harness();
  Object.assign(h.job, { status: "completed", runMode: null });
  let release; let readStarted;
  const pendingRead = new Promise((resolve) => { release = resolve; });
  const started = new Promise((resolve) => { readStarted = resolve; });
  h.controls.readHook = async () => { readStarted(); await pendingRead; };
  const sourcePromise = h.ctx.readAccountSource(h.job);
  await started;
  let resetEntered = false;
  const resetPromise = h.ctx.withEmailJobLock(h.job.email, async () => { resetEntered = true; h.job.totpCredentialInvalidated = true; });
  await Promise.resolve();
  assert.equal(resetEntered, false, "reset must not enter while credential snapshot awaits storage");
  release();
  const snapshot = await sourcePromise;
  await resetPromise;
  assert.throws(() => h.ctx.assertAccountSourceSnapshotCurrent(snapshot), { status: 409 });
}

{
  const h = harness();
  Object.assign(h.job, { status: "completed", runMode: null });
  const second = { ...h.job, id: "second", email: "second@example.test" };
  h.ctx.jobs.set(second.id, second);
  h.controls.readHook = async (email) => {
    if (email === second.email) await h.ctx.withEmailJobLock(h.job.email, async () => { h.job.totpCredentialInvalidated = true; });
  };
  let wrote = false;
  await assert.rejects(h.ctx.exportSourceAccounts({ writeHead() { wrote = true; }, end() { wrote = true; } }, [h.job.id, second.id]), { status: 409 });
  assert.equal(wrote, false, "batch must reject a row invalidated while a later credential was loading");
}

{
  const h = harness();
  Object.assign(h.job, { status: "completed", runMode: null });
  const snapshot = await h.ctx.readAccountSource(h.job);
  h.job.password = "changed-after-read";
  assert.throws(() => h.ctx.assertAccountSourceSnapshotCurrent(snapshot), { status: 409 });
  h.ctx.jobs.delete(h.job.id);
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 404 });
}

{
  const h = harness();
  Object.assign(h.job, { status: "completed", runMode: null, password: "", totpSecret: "",
    hasPasswordCredential: false, hasTotpCredential: false, loginMode: "email_otp",
    mailApiUrl: "https://mail.example.test/otp", mailRequestBody: "" });
  h.controls.readHook = async () => { throw new Error("credential store is unavailable"); };
  const { account } = await h.ctx.readAccountSource(h.job);
  assert.equal(account.password, "");
  assert.equal(account.totpSecret, "");
  assert.equal(account.mailApiUrl, h.job.mailApiUrl);
  let payload;
  await h.ctx.exportSourceAccounts({ writeHead() {}, end(value) { payload = String(value); } }, [h.job.id]);
  assert.equal(payload.replace(/^\uFEFF/, "").trim(), `${h.job.email}----${h.job.mailApiUrl}`);
  assert.equal(h.events.includes("store-read"), true, "mail-only accounts still try current persisted credentials without requiring a store");
}

{
  const h = harness();
  Object.assign(h.job, { status: "completed", runMode: null });
  const sibling = { ...h.job, id: "same-email-history", email: h.job.email.toUpperCase(), status: "working", runMode: "totp_setup" };
  h.ctx.jobs.set(sibling.id, sibling);
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 });
  Object.assign(sibling, { status: "failed", runMode: null, totpCredentialInvalidated: true });
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 });
  sibling.totpCredentialInvalidated = false;
  const snapshot = await h.ctx.readAccountSource(h.job);
  const version = h.ctx.accountSourceVersion(h.job);
  sibling.totpSecret = newKey;
  sibling.updatedAt = "2026-09-29T00:01:00.000Z";
  assert.throws(() => h.ctx.assertAccountSourceSnapshotCurrent(snapshot), { status: 409 });
  assert.notEqual(h.ctx.accountSourceVersion(h.job), version);
  assert.equal(h.ctx.accountSourceVersion(h.job).includes(newKey), false);
  Object.assign(h.job, { password: "", totpSecret: "", hasPasswordCredential: false, hasTotpCredential: false, loginMode: "email_otp" });
  await h.ctx.credentialStore.save(h.job.email, { password: "updated-sibling-password", totpSecret: newKey, proxyUrl: "" });
  const current = await h.ctx.readAccountSource(h.job);
  assert.equal(current.account.password, "updated-sibling-password");
  assert.equal(current.account.totpSecret, newKey, "historical job must still read a same-email sibling's current key");
}

console.log("Console TOTP lifecycle and credential-view/export safety tests passed.");
