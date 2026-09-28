import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createCredentialStore } from "../src/credential-store.mjs";

if (process.platform !== "win32") {
  console.log("TOTP real DPAPI integration: Windows required; skipped");
  process.exit(0);
}
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-reset-integration-"));
const outputRoot = path.join(temporary, "jobs");
const localAppData = path.join(temporary, "local-app-data");
const credentialRoot = path.join(localAppData, "toSub2", "credentials");
const store = createCredentialStore({ windowsRoot: credentialRoot });
const id = "11111111-2222-4333-8444-555555555555";
const email = "reset-integration@example.test";
const jobRoot = path.join(outputRoot, id);
const checkpointPath = path.join(jobRoot, "login-checkpoint.json");
const metadataPath = path.join(jobRoot, "job-meta.json");
const resultPath = path.join(jobRoot, "totp-setup-result.json");
const oldKey = "JBSWY3DPEHPK3PXP";
const newKey = "NB2W45DFOIZAQWER";
const verificationFailure = process.argv.includes("--verification-failure");
const oldFactor = { id: "old-integration-totp", factor_type: "totp", is_recovery: false };
const newFactor = { id: "new-integration-totp", factor_type: "totp", is_recovery: false };
const counts = { disable: 0, enroll: 0, activate: 0, logout: 0 };
let factors = [oldFactor];
let mockBase;
let consoleBase;
let consoleProcess;
let consoleToken;
let output = "";
const faults = [];
const mock = http.createServer((req, res) => {
  handle(req, res).catch((error) => {
    faults.push(error);
    res.writeHead(500).end();
  });
});

try {
  await new Promise((resolve) => mock.listen(0, "127.0.0.1", resolve));
  mockBase = `http://127.0.0.1:${mock.address().port}`;
  await fs.mkdir(jobRoot, { recursive: true });
  await store.save(email, { password: "mock-integration-password", totpSecret: oldKey, proxyUrl: "" });
  await fs.writeFile(metadataPath, JSON.stringify({
    version: 1, email, status: "resume_available", prompt: "测试检查点", result_saved: false,
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  }));
  await fs.writeFile(checkpointPath, JSON.stringify({
    version: 1, stage: "email_verified", email, web: { deviceId: "test-current-device" },
    cookies: [{ name: "oai-did", value: "test-current-device", domain: "127.0.0.1", path: "/" },
      { name: "__Secure-next-auth.session-token", value: "test-current-web-cookie", domain: "127.0.0.1", path: "/" }],
  }));
  await startConsole();
  const initial = await findJob();
  assert.equal(initial.canResetTotp, true, JSON.stringify(initial));
  assert.equal(initial.canSetupTotp, false);
  for (const headers of [{}, { "x-console-token": "incorrect-token" }]) {
    const unauthorized = await fetch(`${consoleBase}/api/jobs/${id}/source`, { headers });
    assert.equal(unauthorized.status, 403);
    assert.equal(unauthorized.headers.get("cache-control"), "no-store");
    const body = await unauthorized.text();
    assert.equal(body.includes(oldKey), false);
    assert.equal(body.includes("mock-integration-password"), false);
  }
  await assertAccountSource(oldKey);
  const submitted = await api(`/api/jobs/${id}/setup-2fa`, { resetTotp: true, logoutAllDevicesAfterTotp: true });
  assert.equal(submitted.status, 200, await submitted.text());
  const completed = await waitFor(async () => {
    const job = await findJob();
    return ["succeeded", "failed", "unknown", "skipped"].includes(job.logoutAllDevicesStatus)
      && !["queued", "working", "totp_starting"].includes(job.status) ? job : null;
  });
  assert.equal(faults.length, 0, faults.map((error) => error.stack).join(String.fromCharCode(10)));
  const expectedLogout = verificationFailure ? "skipped" : "succeeded";
  const expectedReset = verificationFailure ? "unknown" : "activated";
  assert.deepEqual(counts, { disable: 1, enroll: 1, activate: 1, logout: verificationFailure ? 0 : 1 }, output);
  assert.equal(completed.logoutAllDevicesStatus, expectedLogout, JSON.stringify(completed));
  assert.equal(completed.totpResetStatus, expectedReset, JSON.stringify(completed));
  if (!verificationFailure) assert.equal(completed.hasTotpKey, true);
  if (verificationFailure) {
    assert.equal(completed.status, "failed", "failed verification must not be reported as successful reset");
    assert.equal(completed.canResetTotp, false, "partial reset cannot silently repeat factor removal");
    assert.equal(await exists(resultPath), true, "unverified activation evidence must survive for recovery");
  }
  assert.equal(completed.canResume, false, "old checkpoint cannot be offered after logout");
  assert.equal(await exists(checkpointPath), false);
  assert.equal((await store.load(email)).totpSecret, newKey, "real encrypted store must contain the new key");
  const meta = JSON.parse(await fs.readFile(metadataPath, "utf8"));
  assert.equal(meta.logout_all_devices_status, expectedLogout);
  assert.equal(meta.reset_totp_status, expectedReset);
  if (!verificationFailure) assert.equal(meta.totp_credential_invalidated, false);
  await assertAccountSource(verificationFailure ? null : newKey);
  const listed = await (await api("/api/jobs")).text();
  assert.equal(listed.includes(newKey), false, "job list must not expose the replacement key");
  assert.equal(listed.includes("mock-integration-password"), false, "job list must not expose passwords");
  const logs = await (await api(`/api/jobs/${id}/logs`)).text();
  assert.equal(logs.includes(newKey), false, "protocol logs must not expose the replacement key");
  const beforeRestart = { ...counts };
  await stopConsole();
  await startConsole();
  const restored = await findJob();
  if (!verificationFailure) assert.equal(restored.hasTotpKey, true, JSON.stringify(restored));
  assert.equal(restored.totpResetStatus, expectedReset);
  assert.equal(restored.logoutAllDevicesStatus, expectedLogout);
  assert.equal((await store.load(email)).totpSecret, newKey, "the activated replacement key survives restart even if verification failed");
  if (verificationFailure) assert.equal(await exists(resultPath), true);
  assert.equal(restored.canResume, false);
  assert.deepEqual(counts, beforeRestart, "service restoration must not replay any mutation");
  await assertAccountSource(verificationFailure ? null : newKey);
  console.log(verificationFailure
    ? "TOTP integration: failed post-activation verification preserves the new encrypted key and private recovery evidence across restart; zero logout/replay passed"
    : "TOTP integration: real server, protocol child, isolated DPAPI readback, one logout and restart without replay passed");
} finally {
  await stopConsole();
  mock.closeAllConnections();
  await new Promise((resolve) => mock.close(resolve));
  assert.ok(path.resolve(temporary).startsWith(path.resolve(os.tmpdir()) + path.sep));
  assert.ok(path.basename(temporary).startsWith("tosub2-reset-integration-"));
  await fs.rm(temporary, { recursive: true, force: true });
}

async function handle(req, res) {
  const url = new URL(req.url, mockBase);
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString("utf8");
  if (url.pathname === "/") return json(res, { accessToken: "mock-integration-web-access-token-1234" });
  if (url.pathname === "/api/auth/session") return json(res, { account: { id: "test-current-account" } });
  if (url.pathname === "/backend-api/accounts/mfa_info" && verificationFailure && counts.activate) {
    res.writeHead(503, { "content-type": "application/json" }).end(JSON.stringify({ error: "mock verification unavailable" }));
    return;
  }
  if (url.pathname === "/backend-api/accounts/mfa_info") return json(res, {
    mfa_enabled: factors.length > 0, mfa_enabled_v2: factors.length > 0, factors: { totp: factors },
  });
  assert.equal(req.headers["chatgpt-account-id"], "test-current-account");
  if (url.pathname === "/backend-api/accounts/mfa/user/disable_in_house") {
    counts.disable++;
    assert.deepEqual(JSON.parse(body), { factor_id: oldFactor.id });
    const meta = JSON.parse(await fs.readFile(metadataPath, "utf8"));
    assert.equal(meta.totp_credential_invalidated, true, "durable parent intent must precede the removal request");
    assert.equal((await store.load(email)).totpSecret, oldKey, "old encrypted backup remains until replacement is saved");
    const duringReset = await api(`/api/jobs/${id}/source`);
    assert.equal(duringReset.status, 409, "old key must be unavailable once reset has begun");
    assert.equal((await duringReset.text()).includes(oldKey), false);
    factors = [];
    return json(res, { message: "Factor disabled", passkey_credential_manager_sync: null });
  }
  if (url.pathname === "/backend-api/accounts/mfa/enroll") {
    counts.enroll++;
    assert.deepEqual(JSON.parse(body), { factor_type: "totp", source: "settings" });
    return json(res, { secret: newKey, session_id: "new-test-enrollment", factor: newFactor });
  }
  if (url.pathname === "/backend-api/accounts/mfa/user/activate_enrollment") {
    counts.activate++;
    assert.equal(JSON.parse(body).session_id, "new-test-enrollment");
    factors = [newFactor];
    return json(res, { success: true });
  }
  if (url.pathname === "/backend-api/accounts/logout_all") {
    counts.logout++;
    assert.equal(body, "");
    assert.equal(req.headers["content-type"], undefined);
    assert.equal((await store.load(email)).totpSecret, newKey, "persisted/readback new key must precede logout");
    const result = JSON.parse(await fs.readFile(resultPath, "utf8"));
    assert.equal(result.activation_succeeded, true);
    assert.equal(result.activation_verified, true);
    assert.equal(result.logout_all_devices_status, "unknown");
    assert.equal(await exists(checkpointPath), false);
    res.writeHead(200).end();
    return;
  }
  throw new Error("Unexpected mock request: " + url.pathname);
}

function json(res, body) { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(body)); }
async function exists(file) { try { await fs.access(file); return true; } catch { return false; } }
async function api(route, data) {
  return fetch(consoleBase + route, { method: data ? "POST" : "GET", headers: {
    "x-console-token": consoleToken, ...(data ? { "content-type": "application/json" } : {}),
  }, ...(data ? { body: JSON.stringify(data) } : {}) });
}
async function findJob() { return (await (await api("/api/jobs")).json()).jobs.find((job) => job.id === id); }
async function assertAccountSource(expectedKey) {
  const response = await api(`/api/jobs/${id}/source`);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const exported = await api("/api/jobs/export-source", { ids: [id] });
  assert.equal(exported.headers.get("cache-control"), "no-store");
  if (expectedKey === null) {
    assert.equal(response.status, 409, "unsafe recovery key must not be shown as current");
    assert.equal(exported.status, 409, "unsafe recovery key must not be exported as current");
    const errors = (await response.text()) + (await exported.text());
    assert.equal(errors.includes(oldKey), false);
    assert.equal(errors.includes(newKey), false);
    return;
  }
  assert.equal(response.status, 200, await response.clone().text());
  const { account } = await response.json();
  assert.deepEqual(Object.keys(account).sort(), ["email", "loginMode", "mailApiUrl", "mailRequestBody", "password", "totpSecret"]);
  assert.equal(account.email, email);
  assert.equal(account.password, "mock-integration-password");
  assert.equal(account.totpSecret, expectedKey);
  assert.equal(account.loginMode, "password");
  assert.equal(account.mailApiUrl, null);
  assert.equal(account.mailRequestBody, "");
  assert.equal(exported.status, 200);
  assert.equal((await exported.text()).replace(/^\uFEFF/, "").trim(), `${email}----mock-integration-password----${expectedKey}`);
}
async function startConsole() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  consoleBase = `http://127.0.0.1:${port}`;
  consoleProcess = spawn(process.execPath, [path.join(root, "src/console-server.mjs"), "--port", String(port)], {
    cwd: root, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, LOCALAPPDATA: localAppData, ONBOARDING_OUTPUT_ROOT: outputRoot,
      ONBOARDING_PROTOCOL_SCRIPT: path.join(root, "src/protocol-login.mjs"),
      CHATGPT_BASE: mockBase, AUTH_BASE: mockBase, CHATGPT_PROXY_URL: "", TOSUB2_TLS_PROFILE: "chrome146", NODE_ENV: "test" },
  });
  for (const stream of [consoleProcess.stdout, consoleProcess.stderr]) stream.on("data", (chunk) => { output = (output + chunk).slice(-30000); });
  const bootstrap = await waitFor(async () => {
    try { const response = await fetch(consoleBase + "/api/bootstrap"); return response.ok ? response.json() : null; } catch { return null; }
  });
  consoleToken = bootstrap.token;
  assert.equal(bootstrap.features.totpReset, true);
  assert.equal(bootstrap.features.logoutAllDevicesAfterTotp, true);
  assert.equal(bootstrap.features.sourceView, true);
  assert.equal(JSON.stringify(bootstrap).includes(oldKey), false);
  assert.equal(JSON.stringify(bootstrap).includes(newKey), false);
}
async function stopConsole() {
  if (!consoleProcess || consoleProcess.exitCode !== null) return;
  try { await api("/api/jobs/cancel-all", {}); } catch {}
  const current = consoleProcess;
  const closed = new Promise((resolve) => current.once("close", resolve));
  current.kill("SIGTERM");
  await closed;
  consoleProcess = null;
}
async function waitFor(check) {
  const deadline = Date.now() + 25000;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  throw new Error("Integration timeout: " + output);
}
