import assert from "node:assert/strict";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs/promises";
import path from "node:path";
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
  "updateJobCredentials", "updateJobProxy", "finishPasswordAdd", "deleteJobsByEmail", "getAutoRepairEligibility",
  "supportsPersistentCredentialStorage", "rememberSessionLoginCredentials",
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

function harness(platform = "win32") {
  const events = [];
  const files = new Map();
  const controls = { saveFails: false, readMismatch: false, metadataFails: false, removeFails: false, readHook: null };
  let stored = { password: "test-password", totpSecret: oldKey, proxyUrl: "" };
  const ctx = vm.createContext({
    crypto, path, Buffer, setTimeout, clearTimeout, shuttingDown: false, jobs: new Map(), emailJobLocks: new Map(),
    process: { platform }, sessionLoginCredentials: new Map(),
    fs: {
      async readFile(file) {
        if (!files.has(file)) throw Object.assign(new Error("missing"), { code: "ENOENT" });
        return JSON.stringify(files.get(file));
      },
      async unlink(file) { events.push("delete:" + file); files.delete(file); },
      async rename(from, to) { files.set(to, files.get(from)); files.delete(from); },
      async rm(file) { if (controls.removeFails) throw new Error("file cleanup failed"); files.delete(file); },
    },
    credentialStore: {
      async save(_email, data) {
        events.push("store-save");
        if (platform !== "win32" && platform !== "darwin") throw Object.assign(new Error("unsupported"), { status: 501 });
        if (controls.saveFails) throw new Error("store unavailable");
        stored = { ...data };
      },
      async load(email) {
        events.push("store-read"); await controls.readHook?.(email);
        if (platform !== "win32" && platform !== "darwin") return { password: "", totpSecret: "", proxyUrl: "" };
        return { ...stored, totpSecret: controls.readMismatch ? "" : stored.totpSecret };
      },
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
    mailSeenCandidateKeys: new Set(), mailCandidateCounts: new Map(),
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

{
  const h = harness("linux");
  Object.assign(h.job, { status: "completed", runMode: null });
  assert.equal(await h.ctx.saveStoredLoginCredentials(h.job.email, h.job), false);
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 }, "a save/recovery attempt must not seed session credentials");
  h.ctx.rememberSessionLoginCredentials(h.job.email, { password: h.job.password, totpSecret: oldKey });
  const snapshot = await h.ctx.readAccountSource(h.job);
  assert.equal(snapshot.account.password, h.job.password);
  assert.equal(snapshot.account.totpSecret, oldKey);
  let payload;
  await h.ctx.exportSourceAccounts({ writeHead(status) { assert.equal(status, 200); }, end(value) { payload = String(value); } }, [h.job.id]);
  assert.equal(payload.replace(/^\uFEFF/, "").trim(), `${h.job.email}----test-password----${oldKey}`);
  assert.equal(h.events.includes("store-read"), false, "memory-only source must not require unavailable storage");

  h.ctx.rememberSessionLoginCredentials(h.job.email.toUpperCase(), { password: "current-password", totpSecret: newKey });
  assert.throws(() => h.ctx.assertAccountSourceSnapshotCurrent(snapshot), { status: 409 });
  const sibling = { ...h.job, id: "stale-history", email: h.job.email.toUpperCase() };
  h.ctx.jobs.set(sibling.id, sibling);
  await h.ctx.updateJobProxy(sibling, "http://proxy.example:8080");
  await h.ctx.updateJobCredentials(sibling, { preserveExistingCredentials: true });
  let current = await h.ctx.readAccountSource(sibling);
  assert.equal(current.account.password, "current-password", "proxy-only saves must not restore a stale sibling password");
  assert.equal(current.account.totpSecret, newKey, "proxy-only saves must not restore a stale sibling key");
  await assert.rejects(h.ctx.updateJobCredentials(sibling, { password: "uncommitted-password", totpSecret: oldKey }), { status: 409 });
  current = await h.ctx.readAccountSource(h.job);
  assert.equal(current.account.password, "current-password", "failed durable-key replacement must not change session authority");
  assert.equal(current.account.totpSecret, newKey);
  h.ctx.rememberSessionLoginCredentials(sibling.email, { password: "accepted-password" });
  current = await h.ctx.readAccountSource(h.job);
  assert.equal(current.account.password, "accepted-password");
  assert.equal(current.account.totpSecret, newKey, "password-only commits must preserve the current same-email key");

  for (const flag of ["totpCredentialInvalidated", "totpRecoveryPending"]) {
    sibling[flag] = true;
    await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 });
    let wrote = false;
    await assert.rejects(h.ctx.exportSourceAccounts({ writeHead() { wrote = true; }, end() { wrote = true; } }, [h.job.id]), { status: 409 });
    assert.equal(wrote, false);
    sibling[flag] = false;
  }
  sibling.runMode = "password_add";
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 });
  sibling.runMode = null;
  h.ctx.sessionLoginCredentials.clear();
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 }, "restored job memory cannot repopulate a lost server session");
}

for (const platform of ["win32", "darwin"]) {
  const h = harness(platform);
  Object.assign(h.job, { status: "completed", runMode: null });
  h.ctx.sessionLoginCredentials.set(h.job.email, { password: "cached-password", totpSecret: oldKey });
  h.controls.readHook = async () => { throw new Error("store unavailable"); };
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 }, `${platform} read errors must not fall back to memory`);
  h.controls.readHook = null;
  await h.ctx.credentialStore.save(h.job.email, { password: "", totpSecret: "" });
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 }, `${platform} empty reads must not fall back to memory`);
}

{
  const h = harness("linux");
  Object.assign(h.job, { status: "completed", runMode: null, totpSecret: "", hasTotpCredential: false });
  h.ctx.rememberSessionLoginCredentials(h.job.email, { password: h.job.password, totpSecret: "" });
  await h.ctx.updateJobCredentials(h.job, { password: "accepted-account-edit", totpSecret: "" });
  assert.equal((await h.ctx.readAccountSource(h.job)).account.password, "accepted-account-edit");
  h.ctx.rememberSessionLoginCredentials(h.job.email, { password: "latest-sibling-password" });
  const previousVersion = h.ctx.accountSourceVersion(h.job);
  await h.ctx.updateJobCredentials(h.job, { password: "accepted-account-edit", totpSecret: "" });
  assert.equal((await h.ctx.readAccountSource(h.job)).account.password, "accepted-account-edit");
  assert.notEqual(h.ctx.accountSourceVersion(h.job), previousVersion, "an unchanged historical job can still change current session credentials and must invalidate open views");
  assert.equal(h.ctx.accountSourceVersion(h.job).includes("accepted-account-edit"), false);
  h.controls.metadataFails = true;
  await assert.rejects(h.ctx.updateJobCredentials(h.job, { password: "failed-account-edit", totpSecret: "" }), /metadata write failed/);
  assert.equal((await h.ctx.readAccountSource(h.job)).account.password, "accepted-account-edit", "failed local edits must retain the last accepted session credentials");
}

{
  const h = harness("linux");
  h.ctx.rememberSessionLoginCredentials(h.job.email, { password: "old-sibling-password", totpSecret: newKey });
  Object.assign(h.job, { runMode: "password_add", passwordAddResultPath: "password-result", pendingNewPassword: "verified-new-password" });
  h.files.set("password-result", { version: 1, email: h.job.email, password: h.job.pendingNewPassword });
  h.controls.metadataFails = true;
  await assert.rejects(h.ctx.finishPasswordAdd(h.job, 0, null), /metadata write failed/);
  const current = await h.ctx.readAccountSource(h.job);
  assert.equal(current.account.password, "verified-new-password", "a verified remote password change must never expose the old password after metadata failure");
  assert.equal(current.account.totpSecret, newKey);
}

{
  const h = harness("linux");
  Object.assign(h.job, { status: "completed", runMode: null, outputPath: "output/result.json" });
  h.child.kill = () => {};
  h.ctx.rememberSessionLoginCredentials(h.job.email, { password: h.job.password, totpSecret: oldKey });
  h.controls.removeFails = true;
  await assert.rejects(h.ctx.deleteJobsByEmail(h.job.email), /file cleanup failed/);
  assert.equal(h.ctx.sessionLoginCredentials.has(h.job.email), false, "logical deletion must clear memory even when disk cleanup fails");
  h.job.deleted = false;
  h.ctx.jobs.set(h.job.id, h.job);
  await assert.rejects(h.ctx.readAccountSource(h.job), { status: 409 });
}

{
  const h = harness("linux");
  h.ctx.rememberSessionLoginCredentials(h.job.email, { password: h.job.password, totpSecret: oldKey });
  h.files.set("result", resetResult());
  await h.ctx.acknowledgeTotpResetState(h.job, h.child, "current");
  assert.equal(h.events.at(-1).ack.ok, false, "session credentials must never acknowledge durable reset readiness");
  assert.equal(h.files.has("result"), true);
  h.files.set("result", activatedResult());
  const recovery = await h.ctx.recoverActivatedTotpCredential({ email: h.job.email, resultPath: "result", credentials: h.job });
  assert.equal(recovery.recovered, false);
  assert.equal(h.ctx.sessionLoginCredentials.get(h.job.email).totpSecret, oldKey);
}

console.log("Console TOTP lifecycle and credential-view/export safety tests passed.");
