import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "tosub2-totp-reset-logout-"));
const secret = "NB2W45DFOIZAQWER";
const accessToken = "mock-current-chatgpt-web-access-token";
const oldFactor = { id: "old-totp-factor", factor_type: "totp", is_recovery: false };
const newFactor = { id: "new-totp-factor", factor_type: "totp", is_recovery: false };
const cases = [
  { name: "default-off", status: "not_requested", logout: 0 },
  { name: "logout-success", optIn: true, status: "succeeded", logout: 1, replay: true },
  { name: "logout-persist-failed", optIn: true, credentialAck: false, status: "skipped", logout: 0 },
  { name: "logout-no-ipc", optIn: true, ipc: false, status: "skipped", logout: 0 },
  { name: "logout-wrong-ack", optIn: true, credentialAck: "wrong", status: "skipped", logout: 0 },
  { name: "logout-already-enabled", optIn: true, enabled: true, status: "skipped", logout: 0, enroll: 0 },
  { name: "logout-activation-failed", optIn: true, mode: "activation-failed", status: "skipped", logout: 0, exit: 1 },
  { name: "logout-http-error", optIn: true, mode: "logout-http-error", status: "failed", logout: 1 },
  { name: "logout-server-error", optIn: true, mode: "logout-server-error", status: "unknown", logout: 1 },
  { name: "logout-html-challenge", optIn: true, mode: "logout-html-challenge", status: "unknown", logout: 1 },
  { name: "logout-json-error", optIn: true, mode: "logout-json-error", status: "unknown", logout: 1 },
  { name: "logout-disconnect", optIn: true, mode: "logout-disconnect", status: "unknown", logout: 1 },
  { name: "logout-timeout", optIn: true, mode: "logout-timeout", status: "unknown", logout: 1 },
  { name: "logout-redirect", optIn: true, mode: "logout-redirect", status: "failed", logout: 1 },
  { name: "reset-success", reset: true, resetStatus: "activated", status: "not_requested", logout: 0, disable: 1, replay: true },
  { name: "reset-and-logout-success", reset: true, optIn: true, resetStatus: "activated", status: "succeeded", logout: 1, disable: 1 },
  { name: "reset-no-ipc", reset: true, ipc: false, absentResult: true, disable: 0, enroll: 0, exit: 1 },
  { name: "reset-multiple-factors", reset: true, mode: "multiple-factors", resetStatus: "failed", disable: 0, enroll: 0, exit: 1 },
  { name: "reset-wrong-factor-type", reset: true, mode: "wrong-factor-type", resetStatus: "failed", disable: 0, enroll: 0, exit: 1 },
  { name: "reset-recovery-factor", reset: true, mode: "recovery-factor", resetStatus: "failed", disable: 0, enroll: 0, exit: 1 },
  { name: "reset-no-account", reset: true, mode: "no-account", resetStatus: "failed", disable: 0, enroll: 0, exit: 1 },
  { name: "reset-state-save-failed", reset: true, resetAck: false, resetStatus: "failed", disable: 0, enroll: 0, exit: 1, replay: true },
  { name: "reset-wrong-state-ack", reset: true, resetAck: "wrong", resetStatus: "failed", disable: 0, enroll: 0, exit: 1 },
  { name: "reset-disable-error", reset: true, mode: "disable-error", resetStatus: "failed", disable: 1, enroll: 0, exit: 1 },
  { name: "reset-disable-server-error", reset: true, mode: "disable-server-error", resetStatus: "unknown", disable: 1, enroll: 0, exit: 1 },
  { name: "reset-disable-timeout", reset: true, mode: "disable-timeout", resetStatus: "unknown", disable: 1, enroll: 0, exit: 1, replay: true },
  { name: "reset-disable-disconnect", reset: true, mode: "disable-disconnect", resetStatus: "unknown", disable: 1, enroll: 0, exit: 1 },
  { name: "reset-disable-wrong-response", reset: true, mode: "disable-wrong-response", resetStatus: "unknown", disable: 1, enroll: 0, exit: 1 },
  { name: "reset-post-disable-query-failed", reset: true, mode: "post-disable-query-failed", resetStatus: "unknown", disable: 1, enroll: 0, exit: 1 },
  { name: "reset-old-factor-remains", reset: true, mode: "old-factor-remains", resetStatus: "unknown", disable: 1, enroll: 0, exit: 1 },
  { name: "reset-enroll-failed", reset: true, mode: "enroll-failed", resetStatus: "unknown", disable: 1, enroll: 1, activate: 0, exit: 1 },
  { name: "reset-enroll-timeout", reset: true, mode: "enroll-timeout", resetStatus: "unknown", disable: 1, enroll: 1, activate: 0, exit: 1, replay: true },
  { name: "reset-enroll-same-factor", reset: true, mode: "enroll-same-factor", resetStatus: "unknown", disable: 1, enroll: 1, activate: 0, exit: 1 },
  { name: "reset-activation-failed", reset: true, mode: "activation-failed", resetStatus: "unknown", disable: 1, activate: 1, exit: 1 },
  { name: "reset-activation-rejected", reset: true, mode: "activation-rejected", resetStatus: "failed", disable: 1, activate: 1, exit: 1 },
  { name: "reset-activation-timeout", reset: true, mode: "activation-timeout", resetStatus: "unknown", disable: 1, activate: 1, exit: 1, replay: true },
  { name: "reset-activation-query-failed", reset: true, mode: "activation-query-failed", resetStatus: "unknown", disable: 1, activate: 1, exit: 1 },
  { name: "reset-new-key-save-failed", reset: true, optIn: true, credentialAck: false, resetStatus: "unknown", disable: 1, status: "skipped", logout: 0, exit: 1 },
  { name: "reset-crash-after-disable", reset: true, mode: "crash-after-disable", disable: 1, enroll: 0, crash: true, replay: true },
  { name: "reset-crash-after-activation", reset: true, mode: "crash-after-activation", disable: 1, activate: 1, crash: true, replay: true },
];

try {
  for (const scenario of cases) await runScenario(scenario);
  console.log(`TOTP reset/logout local smoke tests passed (${cases.length} scenarios).`);
} finally {
  await fs.rm(tempRoot, { recursive: true, force: true });
}

async function runScenario(scenario) {
  const directory = path.join(tempRoot, scenario.name);
  await fs.mkdir(directory);
  const resultPath = path.join(directory, "result.json");
  const checkpointPath = path.join(directory, "checkpoint.json");
  const metadataPath = path.join(directory, "parent-reset.json");
  const vaultPath = path.join(directory, "parent-credential.json");
  const operationId = `test-operation-${scenario.name}`;
  const counts = { all: 0, disable: 0, enroll: 0, activate: 0, logout: 0, redirected: 0 };
  const acknowledged = { reset: false, credential: false };
  const faults = [];
  let factors = scenario.reset || scenario.enabled ? [{ ...oldFactor }] : [];
  if (scenario.mode === "multiple-factors") factors.push({ ...oldFactor, id: "second-totp-factor" });
  if (scenario.mode === "recovery-factor") factors = [{ ...oldFactor, is_recovery: true }];
  if (scenario.mode === "wrong-factor-type") factors = [{ ...oldFactor, factor_type: "sms" }];
  let currentChild;
  let base;
  const server = http.createServer((req, res) => {
    handle(req, res).catch((error) => { faults.push(error); res.writeHead(500); res.end(); });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  await fs.writeFile(checkpointPath, JSON.stringify({
    version: 1, stage: "email_verified", email: "local-security-test@example.com",
    cookies: [
      { name: "oai-did", value: "current-device", domain: "127.0.0.1", path: "/" },
      { name: "__Secure-next-auth.session-token", value: "current-web-cookie", domain: "127.0.0.1", path: "/" },
    ], web: { deviceId: "current-device" },
  }));
  try {
    const first = await runChild();
    assert.equal(first.code, scenario.crash ? 1 : (scenario.exit || 0), `${scenario.name}: ${first.output}`);
    for (const value of [secret, accessToken, "raw-response-credential-canary", "[proxy-risk-retry]"]) {
      assert.equal(first.output.includes(value), false, `${scenario.name}: private data or retry signal leaked`);
    }
    assert.equal(counts.logout, scenario.logout || 0, `${scenario.name}: logout count`);
    assert.equal(counts.disable, scenario.disable || 0, `${scenario.name}: disable count`);
    assert.equal(counts.redirected, 0, `${scenario.name}: never follow mutation redirects`);
    if (scenario.enroll !== undefined) assert.equal(counts.enroll, scenario.enroll, scenario.name);
    if (scenario.activate !== undefined) assert.equal(counts.activate, scenario.activate, scenario.name);
    assert.equal(faults.length, 0, `${scenario.name}: ${faults.map((error) => error.stack).join("\n")}`);
    if (scenario.absentResult) {
      assert.equal(counts.all, 0);
      assert.equal(await exists(resultPath), false);
      console.log(`ok ${scenario.name}`);
      return;
    }
    const result = JSON.parse(await fs.readFile(resultPath, "utf8"));
    if (scenario.status) assert.equal(result.logout_all_devices_status, scenario.status, scenario.name);
    if (scenario.resetStatus) assert.equal(result.reset_totp_status, scenario.resetStatus, scenario.name);
    if (scenario.optIn || scenario.reset) assert.equal(result.operation_id, operationId);
    if (counts.logout) {
      assert.ok(result.logout_all_devices_attempted_at, scenario.name);
      assert.equal(result.activation_succeeded, true);
      assert.equal(acknowledged.credential, true);
    }
    if (counts.disable || result.reset_totp_attempted_at) {
      assert.equal(result.old_factor_invalidated, true);
      assert.equal(await exists(checkpointPath), false, `${scenario.name}: checkpoint must not be recreated`);
    }
    if (scenario.resetStatus === "activated") {
      assert.equal(result.activation_succeeded, true);
      assert.equal(result.activation_verified, true);
      assert.equal(result.reset_totp_phase, "credential_persisted");
      assert.equal(JSON.parse(await fs.readFile(vaultPath, "utf8")).totpSecret, secret);
    }
    if (["activation-query-failed", "crash-after-activation"].includes(scenario.mode)) {
      assert.equal(result.activation_succeeded, true, "accepted activation must survive follow-up failure");
      assert.equal(result.activation_verified, false);
      assert.equal(result.secret, secret);
      assert.equal(acknowledged.credential, false);
    }
    if (scenario.mode === "activation-timeout") {
      assert.equal(result.activation_succeeded, false);
      assert.equal(result.reset_totp_last_phase, "activation_intent");
      assert.equal(result.secret, secret);
    }
    if (scenario.replay) {
      const before = { ...counts };
      const repeated = await runChild();
      assert.equal(repeated.code, 1, `${scenario.name}: retry should stop`);
      assert.match(repeated.output, /TOTP_RECOVERY_REQUIRED/);
      assert.deepEqual(counts, before, `${scenario.name}: replay must make no requests`);
    }
    console.log(`ok ${scenario.name}`);
  } finally {
    if (currentChild?.exitCode === null && currentChild?.signalCode === null) currentChild.kill();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }

  async function handle(req, res) {
    counts.all += 1;
    const url = new URL(req.url, base);
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString("utf8");
    if (url.pathname === "/") return json(res, { accessToken }, "text/html");
    if (url.pathname === "/api/auth/session") return json(res, scenario.mode === "no-account" ? {} : { account: { id: "current-account" } });
    if (url.pathname === "/backend-api/accounts/mfa_info") {
      if (scenario.mode === "crash-after-activation" && counts.activate) { currentChild.kill("SIGKILL"); return; }
      if (scenario.mode === "post-disable-query-failed" && counts.disable) return json(res, {}, undefined, 503);
      if (scenario.mode === "activation-query-failed" && counts.activate) return json(res, {}, undefined, 503);
      return json(res, { mfa_enabled: factors.length > 0, mfa_enabled_v2: factors.length > 0, factors: { totp: factors } });
    }
    if (url.pathname === "/backend-api/accounts/mfa/user/disable_in_house") {
      counts.disable += 1;
      checkHeaders(req, true);
      assert.deepEqual(JSON.parse(body), { factor_id: oldFactor.id });
      const durable = JSON.parse(await fs.readFile(resultPath, "utf8"));
      assert.equal(durable.reset_totp_phase, "disable_intent");
      assert.equal(durable.old_factor_invalidated, true);
      assert.equal(acknowledged.reset, true);
      assert.equal(await exists(checkpointPath), false);
      if (scenario.mode === "disable-error") return json(res, { detail: "raw-response-credential-canary" }, undefined, 403);
      if (scenario.mode === "disable-server-error") return json(res, { detail: "raw-response-credential-canary" }, undefined, 500);
      if (scenario.mode === "disable-timeout") return;
      if (scenario.mode === "disable-disconnect") { req.socket.destroy(); return; }
      if (scenario.mode === "disable-wrong-response") return json(res, { success: true });
      if (scenario.mode !== "old-factor-remains") factors = [];
      if (scenario.mode === "crash-after-disable") { currentChild.kill("SIGKILL"); return; }
      return json(res, { message: "Factor disabled", passkey_credential_manager_sync: null });
    }
    if (url.pathname === "/backend-api/accounts/mfa/enroll") {
      counts.enroll += 1;
      assert.deepEqual(JSON.parse(body), { factor_type: "totp", source: "settings" });
      if (scenario.reset) checkHeaders(req, true);
      if (scenario.mode === "enroll-failed") return json(res, { detail: "raw-response-credential-canary" }, undefined, 503);
      if (scenario.mode === "enroll-timeout") return;
      return json(res, { secret, session_id: "new-enrollment-session", factor: scenario.mode === "enroll-same-factor" ? oldFactor : newFactor });
    }
    if (url.pathname === "/backend-api/accounts/mfa/user/activate_enrollment") {
      counts.activate += 1;
      const payload = JSON.parse(body);
      assert.deepEqual(Object.keys(payload).sort(), ["code", "factor_type", "session_id", "source"]);
      assert.equal(payload.source, "settings");
      assert.equal(payload.session_id, "new-enrollment-session");
      assert.match(payload.code, /^\d{6}$/);
      if (scenario.reset) checkHeaders(req, true);
      if (scenario.mode === "activation-failed") return json(res, { detail: "activation rejected" }, undefined, 503);
      if (scenario.mode === "activation-rejected") return json(res, { detail: "activation rejected" }, undefined, 400);
      if (scenario.mode === "activation-timeout") return;
      factors = [{ ...newFactor }];
      return json(res, { success: true });
    }
    if (url.pathname === "/backend-api/accounts/logout_all") {
      counts.logout += 1;
      assert.equal(url.search, "");
      assert.equal(body, "");
      assert.equal(req.headers["content-length"], "0");
      assert.equal(req.headers["content-type"], undefined);
      assert.equal(acknowledged.credential, true);
      checkHeaders(req, false);
      const durable = JSON.parse(await fs.readFile(resultPath, "utf8"));
      assert.equal(durable.logout_all_devices_status, "unknown");
      assert.ok(durable.logout_all_devices_attempted_at);
      assert.equal(await exists(checkpointPath), false);
      if (scenario.mode === "logout-http-error") return json(res, { detail: "raw-response-credential-canary" }, undefined, 403);
      if (scenario.mode === "logout-server-error") return json(res, { detail: "raw-response-credential-canary" }, undefined, 500);
      if (scenario.mode === "logout-json-error") return json(res, { error: "raw-response-credential-canary" });
      if (scenario.mode === "logout-html-challenge") { res.writeHead(200, { "content-type": "text/html" }); res.end("<html>raw-response-credential-canary</html>"); return; }
      if (scenario.mode === "logout-disconnect") { req.socket.destroy(); return; }
      if (scenario.mode === "logout-timeout") return;
      if (scenario.mode === "logout-redirect") { res.writeHead(307, { location: `${base}/redirected` }); res.end(); return; }
      res.writeHead(200); res.end(); return;
    }
    if (url.pathname === "/redirected") counts.redirected += 1;
    return json(res, {}, undefined, 404);
  }

  function checkHeaders(req, isJson) {
    assert.equal(req.method, "POST");
    assert.equal(req.headers.authorization, `Bearer ${accessToken}`);
    assert.equal(req.headers["chatgpt-account-id"], "current-account");
    assert.equal(req.headers["oai-did"], "current-device");
    assert.match(req.headers.cookie, /current-web-cookie/);
    assert.equal(req.headers.accept, "*/*");
    assert.equal(req.headers.origin, base);
    assert.equal(req.headers.referer, `${base}/`);
    assert.equal(req.headers["sec-fetch-mode"], "cors");
    assert.equal(req.headers["sec-fetch-site"], "same-origin");
    assert.equal(req.headers["sec-fetch-dest"], "empty");
    assert.equal(req.headers["sec-fetch-user"], undefined);
    assert.equal(req.headers["upgrade-insecure-requests"], undefined);
    assert.equal(req.headers.priority, "u=1, i");
    if (isJson) assert.equal(req.headers["content-type"], "application/json");
    const major = new RegExp("Chrome/([0-9]+)").exec(req.headers["user-agent"])?.[1];
    assert.ok(major);
    assert.ok(req.headers["sec-ch-ua"].includes(`v="${major}"`));
  }

  async function runChild() {
    const child = spawn(process.execPath, [
      path.join(root, "src/protocol-login.mjs"), "--setup-totp", "--native-http",
      "--email", "local-security-test@example.com", "--resume-checkpoint", checkpointPath,
      "--totp-result", resultPath, "--chatgpt-base", base, "--auth-base", base,
      ...(scenario.optIn ? ["--logout-all-devices-after-totp"] : []),
      ...(scenario.reset ? ["--reset-totp"] : []),
    ], {
      cwd: root, windowsHide: true,
      env: { ...process.env, CHATGPT_PROXY_URL: "", NODE_ENV: "test", TOSUB2_TOTP_OPERATION_ID: operationId,
        TOSUB2_TEST_TOTP_ACK_TIMEOUT_MS: "180", TOSUB2_TEST_LOGOUT_TIMEOUT_MS: "180", TOSUB2_TEST_TOTP_RESET_TIMEOUT_MS: "180" },
      stdio: scenario.ipc === false ? ["pipe", "pipe", "pipe"] : ["pipe", "pipe", "pipe", "ipc"],
    });
    currentChild = child;
    child.stdin.end();
    let output = "";
    for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { output += chunk; });
    child.on("message", (message) => {
      acknowledge(message).catch((error) => { faults.push(error); child.kill(); });
    });
    const exit = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { child.kill(); reject(new Error(`${scenario.name}: child timeout`)); }, 12_000);
      child.once("error", (error) => { clearTimeout(timer); reject(error); });
      child.once("close", (code) => { clearTimeout(timer); resolve(code ?? 1); });
    });
    return { code: exit, output };

    async function acknowledge(message) {
      assert.deepEqual(Object.keys(message).sort(), ["operationId", "type"]);
      assert.equal(message.operationId, operationId);
      const privateResult = JSON.parse(await fs.readFile(resultPath, "utf8"));
      assert.equal(privateResult.operation_id, operationId);
      if (message.type === "totp-reset-state") {
        assert.equal(privateResult.reset_totp_phase, "disable_intent");
        if (scenario.resetAck === "wrong") {
          child.send({ type: "totp-reset-state-persisted", operationId: "wrong-operation", ok: true });
          return;
        }
        if (scenario.resetAck !== false) {
          await fs.writeFile(metadataPath, JSON.stringify({ oldBackupRetained: true, invalidated: true }));
          assert.equal(JSON.parse(await fs.readFile(metadataPath, "utf8")).invalidated, true);
          acknowledged.reset = true;
        }
        child.send({ type: "totp-reset-state-persisted", operationId, ok: scenario.resetAck !== false });
      } else {
        assert.equal(message.type, "totp-credential-ready");
        assert.equal(privateResult.activation_succeeded, true);
        if (scenario.reset) assert.equal(privateResult.reset_totp_phase, "activated_verified");
        if (scenario.credentialAck === "wrong") {
          child.send({ type: "totp-credential-persisted", operationId: "wrong-operation", ok: true });
          return;
        }
        if (scenario.credentialAck !== false) {
          await fs.writeFile(vaultPath, JSON.stringify({ totpSecret: privateResult.secret }));
          assert.equal(JSON.parse(await fs.readFile(vaultPath, "utf8")).totpSecret, secret);
          acknowledged.credential = true;
        }
        child.send({ type: "totp-credential-persisted", operationId, ok: scenario.credentialAck !== false });
      }
    }
  }
}

function json(res, data, contentType = "application/json", status = 200) {
  res.writeHead(status, { "content-type": contentType });
  res.end(JSON.stringify(data));
}

async function exists(filePath) {
  try { await fs.access(filePath); return true; } catch { return false; }
}
