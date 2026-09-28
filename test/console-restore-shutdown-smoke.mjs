import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const persistentCredentialsSupported = ["win32", "darwin"].includes(process.platform);
const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-restore-"));
const outputRoot = path.join(tempRoot, "output");
const protocolInvocationsPath = path.join(tempRoot, "protocol-invocations.jsonl");
const trackedProtocolPath = path.join(tempRoot, "tracked-protocol.mjs");
await fs.writeFile(trackedProtocolPath, [
  'import fs from "node:fs/promises";',
  "await fs.appendFile(" + JSON.stringify(protocolInvocationsPath) + ", JSON.stringify(process.argv.slice(2)) + String.fromCharCode(10));",
  "await import(" + JSON.stringify(pathToFileURL(path.join(projectRoot, "test", "mock-protocol-login.mjs")).href) + ");",
].join("\n"), "utf8");
const restoredId = "11111111-1111-4111-8111-111111111111";
const restoredDir = path.join(outputRoot, restoredId);
const restoredEmail = "restore-failed@example.com";
const interruptedId = "22222222-2222-4222-8222-222222222222";
const interruptedEmail = "restore-interrupted@example.com";
const interruptedPasswordId = "33333333-3333-4333-8333-333333333333";
const interruptedPasswordEmail = "restore-password@example.com";
const interruptedTotpId = "44444444-4444-4444-8444-444444444444";
const interruptedTotpEmail = "restore-totp@example.com";
const restoredOperationAt = "2026-08-12T08:30:00.000Z";
const port = await findAvailablePort();
const baseUrl = `http://127.0.0.1:${port}`;
const sub2apiPort = await findAvailablePort();
const sub2apiUrl = `http://127.0.0.1:${sub2apiPort}`;
let resolveMonitorRequest;
const monitorRequestStarted = new Promise((resolve) => { resolveMonitorRequest = resolve; });
const sub2api = http.createServer((req, res) => {
  if (req.headers["x-api-key"] !== "shutdown-test-key") {
    res.writeHead(401).end();
    return;
  }
  if (req.method === "GET" && req.url?.startsWith("/api/v1/admin/accounts?")) {
    resolveMonitorRequest();
    return;
  }
  res.writeHead(404).end();
});
await new Promise((resolve) => sub2api.listen(sub2apiPort, "127.0.0.1", resolve));

await fs.mkdir(restoredDir, { recursive: true });
await fs.writeFile(path.join(restoredDir, "sub2api-import-oauth.json"), `${JSON.stringify({
  type: "sub2api-data",
  version: 1,
  accounts: [{ name: `oauth---${restoredEmail}`, credentials: { email: restoredEmail }, extra: { email: restoredEmail } }],
}, null, 2)}\n`);
await fs.writeFile(path.join(restoredDir, "job-meta.json"), `${JSON.stringify({
  version: 1,
  email: restoredEmail,
  status: "failed",
  prompt: "本次重新授权失败",
  last_error: "模拟的最近错误",
  result_saved: true,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  last_operation_at: restoredOperationAt,
  last_operation_type: "relogin",
}, null, 2)}\n`);
await fs.mkdir(path.join(outputRoot, interruptedId), { recursive: true });
await fs.writeFile(path.join(outputRoot, interruptedId, "job-meta.json"), `${JSON.stringify({
  version: 1,
  email: interruptedEmail,
  status: "email_otp",
  prompt: "请输入邮箱验证码",
  last_error: null,
  result_saved: false,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
}, null, 2)}\n`);
const interruptedPasswordDir = path.join(outputRoot, interruptedPasswordId);
await fs.mkdir(interruptedPasswordDir, { recursive: true });
await fs.writeFile(path.join(interruptedPasswordDir, "login-checkpoint.json"), `${JSON.stringify({
  version: 1,
  stage: "email_verified",
  updated_at: new Date().toISOString(),
  email: interruptedPasswordEmail,
  cookies: [],
}, null, 2)}\n`, { mode: 0o600 });
await fs.writeFile(path.join(interruptedPasswordDir, "password-add-result.json"), `${JSON.stringify({
  version: 1,
  email: interruptedPasswordEmail,
  password: "Recovered_Test_4826!",
  added_at: "2026-08-17T05:00:00.000Z",
}, null, 2)}\n`, { mode: 0o600 });
await fs.writeFile(path.join(interruptedPasswordDir, "job-meta.json"), `${JSON.stringify({
  version: 1,
  email: interruptedPasswordEmail,
  status: "password_add_starting",
  prompt: "正在添加密码",
  result_saved: false,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  login_checkpoint_available: true,
}, null, 2)}\n`);
const interruptedTotpDir = path.join(outputRoot, interruptedTotpId);
await fs.mkdir(interruptedTotpDir, { recursive: true });
await fs.writeFile(path.join(interruptedTotpDir, "login-checkpoint.json"), `${JSON.stringify({
  version: 1,
  stage: "email_verified",
  updated_at: new Date().toISOString(),
  email: interruptedTotpEmail,
  cookies: [],
}, null, 2)}\n`, { mode: 0o600 });
await fs.writeFile(path.join(interruptedTotpDir, "totp-setup-result.json"), `${JSON.stringify({
  version: 1,
  activation_mode: "automatic",
  activation_succeeded: true,
  activated_at: "2026-08-17T05:10:00.000Z",
  email: interruptedTotpEmail,
  secret: "NB2W45DFOIZAQWER",
  otpauth_uri: `otpauth://totp/OpenAI%3A${encodeURIComponent(interruptedTotpEmail)}?secret=NB2W45DFOIZAQWER&issuer=OpenAI`,
}, null, 2)}\n`, { mode: 0o600 });
await fs.writeFile(path.join(interruptedTotpDir, "job-meta.json"), `${JSON.stringify({
  version: 1,
  email: interruptedTotpEmail,
  status: "totp_starting",
  prompt: "正在设置 2FA",
  result_saved: false,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  login_checkpoint_available: true,
}, null, 2)}\n`);

// Windows child.kill("SIGTERM") terminates Node without running signal handlers.
// Deliver the same shutdown event cooperatively so this test still verifies
// the real handler's request cancellation, metadata flush, and natural exit.
const cooperativeShutdown = process.platform === "win32";
const shutdownPreload = `data:text/javascript,${encodeURIComponent(`
  process.once("message", (message) => {
    if (message !== "tosub2-test-shutdown") throw new Error("Unexpected test IPC message");
    process.disconnect();
    if (!process.emit("SIGTERM")) throw new Error("Shutdown handler is not installed");
  });
`)}`;
let logs = "";
let { child, childExit } = startConsole();

try {
  const bootstrap = await waitForJson(`${baseUrl}/api/bootstrap`);
  const headers = { "content-type": "application/json", "x-console-token": bootstrap.token };
  const page = await fetch(`${baseUrl}/api/jobs`, { headers }).then((response) => response.json());
  const restored = page.jobs.find((job) => job.id === restoredId);
  assert.equal(restored.status, "failed");
  assert.equal(restored.canDownload, true);
  assert.equal(restored.prompt, "本次重新授权失败");
  assert.equal(restored.lastError, "模拟的最近错误");
  assert.equal(restored.lastOperationAt, restoredOperationAt);
  assert.equal(restored.lastOperationType, "relogin");
  const interrupted = page.jobs.find((job) => job.id === interruptedId);
  assert.equal(interrupted.status, "failed");
  assert.equal(interrupted.canDownload, false);
  assert.equal(interrupted.canRetry, true);
  assert.equal(interrupted.lastOperationType, "initial_authorization");
  assert.match(interrupted.prompt, /服务重启中断/);
  const recoveredPassword = page.jobs.find((job) => job.id === interruptedPasswordId);
  assert.equal(recoveredPassword.status, "resume_available");
  assert.equal(recoveredPassword.loginMode, "password");
  assert.equal(recoveredPassword.canAddPassword, false);
  assert.equal(recoveredPassword.canRetry, true);
  assert.equal(recoveredPassword.passwordAddedAt, "2026-08-17T05:00:00.000Z");
  if (persistentCredentialsSupported) {
    assert.equal(recoveredPassword.passwordAddError, null);
    assert.match(recoveredPassword.prompt, /已恢复成功添加的新密码/);
    await assert.rejects(fs.access(path.join(interruptedPasswordDir, "password-add-result.json")));
  } else {
    assert.match(recoveredPassword.passwordAddError, /不支持持久凭据存储/);
    assert.doesNotMatch(recoveredPassword.prompt, /已恢复成功|安全保存/);
    const passwordEvidence = JSON.parse(await fs.readFile(path.join(interruptedPasswordDir, "password-add-result.json"), "utf8"));
    assert.equal(passwordEvidence.password, "Recovered_Test_4826!", "the only password recovery copy must be retained");
    await assertSourceUnavailable(interruptedPasswordId, headers, [passwordEvidence.password]);
  }
  const recoveredTotp = page.jobs.find((job) => job.id === interruptedTotpId);
  assert.equal(recoveredTotp.status, "resume_available");
  assert.equal(recoveredTotp.hasTotpKey, true);
  assert.equal(recoveredTotp.canSetupTotp, false);
  if (persistentCredentialsSupported) {
    assert.equal(recoveredTotp.canRetry, true);
    assert.equal(recoveredTotp.totpRecoveryPending, false);
    assert.equal(recoveredTotp.totpSetupError, null);
    assert.match(recoveredTotp.prompt, /已恢复成功激活的 2FA 密钥/);
    await assert.rejects(fs.access(path.join(interruptedTotpDir, "totp-setup-result.json")));
  } else {
    assert.equal(recoveredTotp.canRetry, false);
    assert.equal(recoveredTotp.canForceRelogin, false);
    assert.equal(recoveredTotp.autoRepairEligible, false);
    assert.equal(recoveredTotp.totpRecoveryPending, true);
    assert.match(recoveredTotp.totpSetupError, /不支持持久凭据存储/);
    assert.doesNotMatch(recoveredTotp.prompt, /已恢复成功|安全保存/);
    const totpEvidencePath = path.join(interruptedTotpDir, "totp-setup-result.json");
    const totpEvidence = JSON.parse(await fs.readFile(totpEvidencePath, "utf8"));
    assert.equal(totpEvidence.activation_succeeded, true);
    assert.equal(totpEvidence.secret, "NB2W45DFOIZAQWER", "unpersisted activation evidence must remain available");
    await assertSourceUnavailable(interruptedTotpId, headers, [totpEvidence.secret]);
    const retry = await fetch(`${baseUrl}/api/jobs/${interruptedTotpId}/retry`, {
      method: "POST", headers, body: JSON.stringify({}),
    });
    assert.equal(retry.status, 409, "pending TOTP recovery must not start another protocol run");
    assert.match((await retry.json()).error, /2FA 恢复未完成/);
    assert.deepEqual(JSON.parse(await fs.readFile(totpEvidencePath, "utf8")), totpEvidence, "rejected retry must preserve the recovery result");
  }

  const originalImportedPassword = "PendingPassword_481!";
  const importedPassword = "UpdatedPendingPassword_481!";
  const missingPassword = "PendingPassword_482!";
  const missingTotp = "JBSWY3DPEHPK3PXP";
  const importResponse = await fetch(`${baseUrl}/api/jobs/batch`, {
    method: "POST", headers, body: JSON.stringify({ text: [
      "restore-imported-plain@example.com",
      `restore-imported-password@example.com----${originalImportedPassword}`,
      `restore-imported-missing@example.com----${missingPassword}----${missingTotp}`,
    ].join("\n") }),
  });
  const importText = await importResponse.text();
  assert.equal(importResponse.status, 201, importText);
  const imported = JSON.parse(importText);
  assert.equal(imported.created, 3);
  assert.equal(imported.updated, 0);
  assert.equal(imported.jobs.length, 3);
  for (const job of imported.jobs) assertImportedState(job);
  const updateImportResponse = await fetch(`${baseUrl}/api/jobs/batch`, {
    method: "POST", headers, body: JSON.stringify({
      text: `restore-imported-password@example.com----${importedPassword}`,
    }),
  });
  const updateImportText = await updateImportResponse.text();
  assert.equal(updateImportResponse.status, 201, updateImportText);
  const updatedImport = JSON.parse(updateImportText);
  assert.equal(updatedImport.created, 0);
  assert.equal(updatedImport.updated, 1);
  assert.equal(updatedImport.jobs[0].id, imported.jobs[1].id);
  assertImportedState(updatedImport.jobs[0], "account_update");
  assert.equal(updatedImport.jobs[0].completedAt, imported.jobs[1].completedAt);
  assert.ok(Date.parse(updatedImport.jobs[0].lastOperationAt) >= Date.parse(imported.jobs[1].lastOperationAt));
  imported.jobs[1] = updatedImport.jobs[0];
  await delay(150);
  await assertImportedJobsRemainIdle(headers, imported.jobs, [originalImportedPassword, importedPassword, missingPassword, missingTotp]);
  assert.deepEqual(await readProtocolInvocations(), [], "import must not spawn a protocol process");

  const createResponse = await fetch(`${baseUrl}/api/jobs`, {
    method: "POST",
    headers,
    body: JSON.stringify({ email: "mfa-prompt@example.com" }),
  });
  assert.equal(createResponse.status, 201);
  const created = await createResponse.json();
  await waitForJob(headers, created.job.id, (job) => job.status === "mfa_otp");

  const monitorConfigResponse = await fetch(`${baseUrl}/api/sub2api/monitor`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      enabled: true,
      config: { baseUrl: sub2apiUrl, adminApiKey: "shutdown-test-key" },
    }),
  });
  assert.equal(monitorConfigResponse.status, 200, await monitorConfigResponse.text());
  void fetch(`${baseUrl}/api/sub2api/monitor/check`, { method: "POST", headers }).catch(() => {});
  await Promise.race([
    monitorRequestStarted,
    delay(3_000).then(() => { throw new Error("monitor request did not start"); }),
  ]);
  const shutdownStartedAt = Date.now();
  if (cooperativeShutdown) {
    await new Promise((resolve, reject) => {
      child.send("tosub2-test-shutdown", (error) => error ? reject(error) : resolve());
    });
  } else {
    child.kill("SIGTERM");
  }
  const exit = await Promise.race([childExit, delay(10_000).then(() => null)]);
  assert.ok(exit, "console did not exit after SIGTERM");
  assert.equal(exit.code, 0, logs);
  assert.equal(exit.signal, null, logs);
  assert.ok(Date.now() - shutdownStartedAt < 5_000, "shutdown should abort the pending Sub2API monitor request");
  const metadata = JSON.parse(await fs.readFile(path.join(outputRoot, created.job.id, "job-meta.json"), "utf8"));
  assert.equal(metadata.status, "canceled");
  assert.equal(metadata.prompt, "流程已取消");
  const invocationsBeforeRestart = await readProtocolInvocations();
  assert.equal(invocationsBeforeRestart.length, 1, "only explicitly creating a single job starts authorization");
  assert.ok(invocationsBeforeRestart[0].includes("mfa-prompt@example.com"));

  // Simulate loss of one imported account's encrypted credential file, using
  // only this test's isolated store. Linux never had a persistent copy.
  const missingCredentialId = crypto.createHash("sha256")
    .update("restore-imported-missing@example.com").digest("hex");
  const missingCredentialPath = process.platform === "win32"
    ? path.join(tempRoot, "local-app-data", "toSub2", "credentials", `${missingCredentialId}.dpapi`)
    : path.join(tempRoot, "credentials", `${missingCredentialId}.enc`);
  if (persistentCredentialsSupported) await fs.access(missingCredentialPath);
  await fs.rm(missingCredentialPath, { force: true });

  ({ child, childExit } = startConsole());
  const restartedBootstrap = await waitForJson(`${baseUrl}/api/bootstrap`);
  const restartedHeaders = { "content-type": "application/json", "x-console-token": restartedBootstrap.token };
  await delay(200);
  await assertImportedJobsRemainIdle(restartedHeaders, imported.jobs, [importedPassword, missingPassword, missingTotp]);
  assert.deepEqual(await readProtocolInvocations(), invocationsBeforeRestart,
    "restarting with missing credentials must not start authorization for imported accounts");
  const missingSource = await fetch(`${baseUrl}/api/jobs/${imported.jobs[2].id}/source`, { headers: restartedHeaders });
  assert.equal(missingSource.status, 409, "the missing credential fixture must actually lack exportable credentials");
  const missingSourceText = await missingSource.text();
  for (const secret of [missingPassword, missingTotp]) assert.equal(missingSourceText.includes(secret), false);
  if (persistentCredentialsSupported) {
    const retainedSource = await fetch(`${baseUrl}/api/jobs/${imported.jobs[1].id}/source`, { headers: restartedHeaders });
    assert.equal(retainedSource.status, 200, "another imported account retains its stored credentials");
    assert.equal((await retainedSource.json()).account.password, importedPassword);
  }
  if (cooperativeShutdown) {
    await new Promise((resolve, reject) => child.send("tosub2-test-shutdown", (error) => error ? reject(error) : resolve()));
  } else {
    child.kill("SIGTERM");
  }
  const restartedExit = await Promise.race([childExit, delay(10_000).then(() => null)]);
  assert.ok(restartedExit, "restarted console did not shut down");
  assert.equal(restartedExit.code, 0, logs);
  assert.equal(restartedExit.signal, null, logs);
  assert.deepEqual(await readProtocolInvocations(), invocationsBeforeRestart);
  console.log("console restore and graceful shutdown tests passed");
} finally {
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  await Promise.race([childExit, delay(2_000)]);
  sub2api.closeAllConnections?.();
  await new Promise((resolve) => sub2api.close(resolve));
  await fs.rm(tempRoot, { recursive: true, force: true });
}

function startConsole() {
  const processHandle = spawn(process.execPath, [
    ...(cooperativeShutdown ? ["--import", shutdownPreload] : []),
    path.join(projectRoot, "src", "console-server.mjs"),
    "--host", "127.0.0.1", "--port", String(port),
  ], {
    cwd: projectRoot,
    env: {
      ...process.env,
      ONBOARDING_OUTPUT_ROOT: outputRoot,
      ONBOARDING_PROTOCOL_SCRIPT: trackedProtocolPath,
      LOCALAPPDATA: path.join(tempRoot, "local-app-data"),
      TOSUB2_MAC_CREDENTIAL_ROOT: path.join(tempRoot, "credentials"),
      TOSUB2_TLS_PROFILE: "chrome142",
    },
    stdio: cooperativeShutdown ? ["ignore", "pipe", "pipe", "ipc"] : ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  processHandle.stdout.setEncoding("utf8");
  processHandle.stderr.setEncoding("utf8");
  processHandle.stdout.on("data", (chunk) => { logs += chunk; });
  processHandle.stderr.on("data", (chunk) => { logs += chunk; });
  return {
    child: processHandle,
    childExit: new Promise((resolve) => processHandle.once("exit", (code, signal) => resolve({ code, signal }))),
  };
}

function assertImportedState(job, operationType = "account_import") {
  assert.equal(job?.status, "imported");
  assert.equal(job.attempt, 0);
  assert.equal(job.lastOperationType, operationType);
  assert.equal(job.canDownload, false);
  assert.equal(job.queuePosition, 0);
}

async function assertImportedJobsRemainIdle(headers, importedJobs, secrets) {
  const response = await fetch(`${baseUrl}/api/jobs`, { headers });
  assert.equal(response.status, 200);
  const page = await response.json();
  for (const imported of importedJobs) {
    const current = page.jobs.find((job) => job.id === imported.id);
    assertImportedState(current, imported.lastOperationType);
    assert.equal(current.lastOperationAt, imported.lastOperationAt);
    const jobDir = path.join(outputRoot, imported.id);
    assert.deepEqual(await fs.readdir(jobDir), ["job-meta.json"], "idle imports must not create authorization or checkpoint files");
    const metadataText = await fs.readFile(path.join(jobDir, "job-meta.json"), "utf8");
    const metadata = JSON.parse(metadataText);
    assert.equal(metadata.status, "imported");
    assert.equal(metadata.attempt, 0);
    assert.equal(metadata.result_saved, false);
    assert.equal(metadata.queued_mode, null);
    assert.equal(metadata.queued_at, null);
    assert.equal(metadata.last_operation_type, imported.lastOperationType);
    for (const secret of secrets) assert.equal(metadataText.includes(secret), false, "job metadata must not contain credentials");
  }
}

async function readProtocolInvocations() {
  try {
    const text = await fs.readFile(protocolInvocationsPath, "utf8");
    return text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function assertSourceUnavailable(id, headers, secrets) {
  const source = await fetch(`${baseUrl}/api/jobs/${id}/source`, { headers });
  const exported = await fetch(`${baseUrl}/api/jobs/export-source`, {
    method: "POST", headers, body: JSON.stringify({ ids: [id] }),
  });
  assert.equal(source.status, 409, "restored file contents are not authoritative current credentials");
  assert.equal(exported.status, 409, "unsafe recovery credentials must not be exported");
  const errors = (await source.text()) + (await exported.text());
  for (const secret of secrets) assert.equal(errors.includes(secret), false);
}

async function waitForJson(url) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
    } catch {}
    await delay(50);
  }
  throw new Error(`server did not start: ${url}`);
}

async function waitForJob(headers, id, predicate) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const page = await fetch(`${baseUrl}/api/jobs`, { headers }).then((response) => response.json());
    const job = page.jobs.find((item) => item.id === id);
    if (job && predicate(job)) return job;
    await delay(25);
  }
  throw new Error(`job ${id} did not reach expected state`);
}

async function findAvailablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
