import assert from "node:assert/strict";
import { build } from "esbuild";
import { JSDOM } from "jsdom";
import { fileURLToPath } from "node:url";

const bundle = await build({
  entryPoints: [fileURLToPath(new URL("../web/src/main.jsx", import.meta.url))],
  bundle: true, write: false, format: "iife", platform: "browser", loader: { ".css": "empty" },
  define: { "process.env.NODE_ENV": '"test"' }, logLevel: "silent",
});
const existing = { id: "ui-existing", email: "existing@example.test", status: "completed", prompt: "测试账号",
  canSetupTotp: false, canResetTotp: true, hasTotpKey: true, totpKnownEnabled: true,
  totpSetupUnavailableReason: "已启用 2FA", logoutAllDevicesStatus: "not_requested" };
const fresh = { ...existing, id: "ui-fresh", email: "fresh@example.test", canSetupTotp: true,
  canResetTotp: false, hasTotpKey: false, totpKnownEnabled: false, totpSetupUnavailableReason: null };
const fixture = (revision = 1, email = existing.email) => ({ email, password: `fixture-password-${revision}!`,
  totpSecret: `FIXTURE-TOTP-${revision}`, mailApiUrl: `https://mail.example.test/fixture/${revision}`,
  mailRequestBody: JSON.stringify({ fixtureOnly: true, revision }), loginMode: "password" });

await testTotpDialogs();
await testSetupAndBatch();
await testImportThenChooseAction();
await testSourceLifecycle();
await testLateResponses();
await testFailuresAndExports();
console.log("TOTP/source React UI: confirmations, default-off opt-in, guards, masks, copying, fresh exports, errors, and late-response isolation passed");

async function mount(initialJobs, featureOverrides = {}) {
  const dom = new JSDOM('<!doctype html><div id="root"></div>', { url: "http://127.0.0.1:49991/", runScripts: "outside-only" });
  const { window } = dom;
  const document = window.document;
  const state = { jobs: structuredClone(initialJobs), accounts: Object.fromEntries(initialJobs.map((job) => [job.id, fixture(1, job.email)])) };
  const calls = { poll: 0, actions: [], imports: [], authorizations: [], sources: [], exports: [], confirms: [], clipboard: [], downloads: [], faults: [] };
  const handlers = { action: null, import: null, source: null, export: null, clipboardReject: false };
  const blobs = new Map();
  const timeout = window.setTimeout.bind(window);
  window.setTimeout = (fn, delay, ...args) => timeout(fn, delay === 900 ? 45 : delay, ...args);
  window.confirm = (message) => { calls.confirms.push(message); return true; };
  Object.defineProperty(window.navigator, "clipboard", { value: { writeText: async (value) => {
    if (handlers.clipboardReject) throw new Error("fixture clipboard rejection");
    calls.clipboard.push(value);
  } } });
  window.URL.createObjectURL = (blob) => { const url = `blob:fixture-${blobs.size + 1}`; blobs.set(url, blob); return url; };
  window.URL.revokeObjectURL = () => {};
  window.HTMLAnchorElement.prototype.click = function click() { calls.downloads.push({ name: this.download, blob: blobs.get(this.href) }); };
  window.fetch = async (input, options = {}) => {
    const url = String(input);
    if (url === "/api/bootstrap") return Response.json({ token: "ui-token", features: { bulkActions: true,
      totpSetup: true, totpReset: true, logoutAllDevicesAfterTotp: true, sourceExport: true, ...featureOverrides } });
    if (url.startsWith("/api/jobs?page=")) { calls.poll += 1; return Response.json({ jobs: state.jobs, selection: state.jobs, stats: { active: 0, queued: 0, completed: state.jobs.length } }); }
    if (url === "/api/mail-request-config") return Response.json({});
    if (url === "/api/jobs/batch") {
      const call = { url, options, body: JSON.parse(options.body) }; calls.imports.push(call);
      assert.ok(handlers.import, "the test must explicitly provide an import fixture");
      return handlers.import(call);
    }
    if (url.endsWith("/retry") || url === "/api/jobs/reauthorize-batch") {
      const call = { url, options, body: JSON.parse(options.body) }; calls.authorizations.push(call);
      return Response.json({ started: call.body.ids?.length || 1 });
    }
    if (url.endsWith("/setup-2fa") || url === "/api/jobs/setup-2fa-batch") {
      const call = { url, options, body: JSON.parse(options.body) }; calls.actions.push(call);
      return handlers.action ? handlers.action(call) : Response.json({ started: 1, skipped: call.body.ids ? state.jobs.length - 1 : 0 });
    }
    if (url.endsWith("/source")) {
      const call = { url, options, id: url.split("/")[3] }; calls.sources.push(call);
      return handlers.source ? handlers.source(call) : Response.json({ account: state.accounts[call.id] });
    }
    if (url === "/api/jobs/export-source") {
      const call = { url, options, body: JSON.parse(options.body) }; calls.exports.push(call);
      return handlers.export ? handlers.export(call) : new Response(call.body.ids.map((id) => JSON.stringify(state.accounts[id])).join("\n"),
        { headers: { "content-type": "text/plain", "content-disposition": 'attachment; filename="fixture-accounts.txt"' } });
    }
    calls.faults.push(url); return Response.json({ error: "Unexpected fixture request" }, { status: 500 });
  };
  window.eval(bundle.outputFiles[0].text);
  await until(() => document.querySelectorAll("tr.job-row").length === initialJobs.length);
  return { dom, window, document, state, calls, handlers,
    button: (label, scope = document) => [...scope.querySelectorAll("button")].find((button) => button.textContent.trim() === label),
    aria: (label, scope = document) => [...scope.querySelectorAll("button")].find((button) => button.getAttribute("aria-label") === label),
    dialog: () => document.querySelector('[role="dialog"]'),
    toggle: () => document.querySelector(".totp-action-dialog .totp-logout-toggle input"),
    row: (email) => [...document.querySelectorAll("tr.job-row")].find((row) => row.textContent.includes(email)),
    close: () => { dom.window.close(); assert.deepEqual(calls.faults, [], "requests stay inside fake harness"); },
  };
}

async function testTotpDialogs() {
  const ui = await mount([existing]);
  try {
    assert.equal(ui.toggle(), null, "logout belongs only in the action dialog");
    assert.equal(ui.button("批量重置 2FA").disabled, true);
    assert.equal(ui.button("已设置 2FA").disabled, true);
    assert.equal(ui.button("重置 2FA").disabled, false);
    ui.button("重置 2FA").click(); await until(() => ui.toggle());
    assert.equal(ui.toggle().checked, false); assert.equal(ui.calls.actions.length, 0);
    assert.match(ui.dialog().textContent, /旧验证器/);
    ui.toggle().click(); ui.button("取消", ui.dialog()).click(); await until(() => !ui.dialog());
    assert.equal(ui.calls.actions.length, 0, "cancel sends no mutation");
    ui.button("重置 2FA").click(); await until(() => ui.toggle());
    assert.equal(ui.toggle().checked, false, "opening resets logout choice");
    ui.toggle().click(); const pending = deferred(); ui.handlers.action = () => pending.promise;
    const confirm = ui.button("确认重置 2FA", ui.dialog()); confirm.click(); confirm.click();
    await until(() => ui.calls.actions.length === 1 && ui.toggle().disabled);
    assert.equal(ui.aria("关闭窗口", ui.dialog()).disabled, true);
    ui.dialog().dispatchEvent(new ui.window.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    assert.ok(ui.dialog(), "pending mutation cannot be dismissed");
    assert.equal(ui.calls.actions[0].body.resetTotp, true);
    assert.equal(ui.calls.actions[0].body.logoutAllDevicesAfterTotp, true); token(ui.calls.actions[0]);
    pending.resolve(Response.json({ started: 1, skipped: 0 })); await until(() => !ui.dialog());
    const count = ui.calls.poll; await until(() => ui.calls.poll >= count + 3);
    assert.equal(ui.calls.actions.length, 1); assert.equal(ui.calls.sources.length, 0);
    assert.deepEqual(ui.calls.confirms, [], "2FA no longer uses window.confirm");
  } finally { ui.close(); }
}

async function testSetupAndBatch() {
  let ui = await mount([fresh]);
  try {
    assert.equal(ui.button("重置 2FA"), undefined);
    ui.button("设置 2FA").click(); await until(() => ui.toggle());
    assert.equal(ui.toggle().checked, false); ui.button("确认设置 2FA", ui.dialog()).click();
    await until(() => ui.calls.actions.length === 1 && !ui.dialog());
    assert.equal(ui.calls.actions[0].body.resetTotp, false); assert.equal(ui.calls.actions[0].body.logoutAllDevicesAfterTotp, false);
    ui.handlers.action = () => Response.json({ error: "测试设置请求被拒绝" }, { status: 409 });
    ui.button("设置 2FA").click(); await until(() => ui.toggle()); ui.button("确认设置 2FA", ui.dialog()).click();
    await until(() => ui.dialog()?.querySelector('[role="alert"]'));
    assert.match(ui.dialog().textContent, /测试设置请求被拒绝/); assert.equal(ui.calls.actions.length, 2);
    ui.button("取消", ui.dialog()).click(); await until(() => !ui.dialog());
  } finally { ui.close(); }
  ui = await mount([existing, fresh]);
  try {
    ui.button("本页全选").click(); await until(() => !ui.button("批量重置 2FA").disabled);
    ui.button("批量重置 2FA").click(); await until(() => ui.toggle());
    assert.match(ui.dialog().textContent, /1 个账号重置/); assert.match(ui.dialog().textContent, /1 个账号不符合/);
    assert.equal(ui.toggle().checked, false); ui.button("确认重置 2FA", ui.dialog()).click();
    await until(() => ui.calls.actions.length === 1 && !ui.dialog());
    assert.deepEqual(ui.calls.actions[0].body.ids, [existing.id, fresh.id]);
    assert.equal(ui.calls.actions[0].body.resetTotp, true); assert.equal(ui.calls.actions[0].body.logoutAllDevicesAfterTotp, false);
    ui.button("本页全选").click(); await until(() => !ui.button("批量设置 2FA").disabled);
    ui.button("批量设置 2FA").click(); await until(() => ui.toggle());
    assert.equal(ui.toggle().checked, false); ui.button("确认设置 2FA", ui.dialog()).click();
    await until(() => ui.calls.actions.length === 2 && !ui.dialog());
    assert.equal(ui.calls.actions[1].body.resetTotp, false); assert.deepEqual(ui.calls.confirms, []);
  } finally { ui.close(); }
  ui = await mount([{ ...existing, logoutAllDevicesStatus: "unknown", logoutAllDevicesError: "测试断连" }]);
  try { assert.match(ui.document.querySelector(".logout-result.unknown").textContent, /结果未确认/); assert.equal(ui.calls.actions.length, 0); } finally { ui.close(); }
  ui = await mount([fresh], { logoutAllDevicesAfterTotp: false });
  try {
    ui.button("设置 2FA").click(); await until(() => ui.dialog());
    assert.equal(ui.toggle(), null, "unavailable optional feature is not rendered");
    ui.button("确认设置 2FA", ui.dialog()).click(); await until(() => ui.calls.actions.length === 1 && !ui.dialog());
    assert.equal(ui.calls.actions[0].body.logoutAllDevicesAfterTotp, false);
  } finally { ui.close(); }
}

async function testImportThenChooseAction() {
  const imported = { ...fresh, id: "ui-imported", email: "imported@example.test", status: "imported",
    prompt: "已导入，请选择要执行的功能", lastOperationType: "account_import", attempt: 0,
    canRetry: true, canForceRelogin: true, canDownload: false, canRegenerate: false };
  const ui = await mount([existing]);
  try {
    await until(() => ui.button("批量添加"));
    ui.handlers.import = (call) => {
      assert.equal(call.body.text, imported.email);
      assert.deepEqual(Object.keys(call.body), ["text"], "an empty global proxy must not erase an existing account proxy during import");
      ui.state.jobs = [imported, existing];
      return Response.json({ jobs: [imported], created: 1, updated: 0 }, { status: 201 });
    };
    ui.button("批量添加").click(); await until(() => ui.dialog());
    assert.match(ui.dialog().textContent, /仅导入列表.*自行选择/);
    assert.doesNotMatch(ui.dialog().textContent, /自动排队/);
    const input = ui.document.querySelector("#batch-input");
    Object.getOwnPropertyDescriptor(ui.window.HTMLTextAreaElement.prototype, "value").set.call(input, imported.email);
    input.dispatchEvent(new ui.window.Event("input", { bubbles: true }));
    await until(() => ui.button("导入 1 个账号", ui.dialog()));
    ui.button("导入 1 个账号", ui.dialog()).click();
    await until(() => !ui.dialog() && ui.row(imported.email));
    assert.equal(ui.calls.imports.length, 1); token(ui.calls.imports[0]);
    const count = ui.calls.poll; await until(() => ui.calls.poll >= count + 3);
    assert.equal(ui.calls.authorizations.length, 0, "import and subsequent polling never authorize automatically");
    assert.equal(ui.calls.actions.length, 0, "import never starts a security action");
    const row = ui.row(imported.email);
    assert.equal(row.querySelector(".status-badge").textContent, "待操作");
    assert.match(row.textContent, /导入账号/);
    assert.ok(ui.button("开始授权", row));
    assert.equal(ui.button("重新登录并授权", row), undefined);
    assert.equal(row.querySelector('[title="取消任务"]'), null);
    assert.equal(ui.button("下载授权文件", row), undefined);
    assert.equal(ui.button("设置 2FA", row).disabled, false);
    ui.button("设置 2FA", row).click(); await until(() => ui.toggle());
    ui.button("取消", ui.dialog()).click(); await until(() => !ui.dialog());
    assert.equal(ui.calls.actions.length, 0);
    ui.button("开始授权", row).click(); await until(() => ui.calls.authorizations.length === 1);
    assert.equal(ui.calls.authorizations[0].url, `/api/jobs/${imported.id}/retry`); token(ui.calls.authorizations[0]);
    row.querySelector('input[type="checkbox"]').click();
    await until(() => ui.button("批量开始授权") && !ui.button("批量开始授权").disabled);
    ui.button("批量开始授权").click(); await until(() => ui.calls.authorizations.length === 2);
    assert.equal(ui.calls.authorizations[1].url, "/api/jobs/reauthorize-batch");
    assert.deepEqual(ui.calls.authorizations[1].body.ids, [imported.id]); token(ui.calls.authorizations[1]);
  } finally { ui.close(); }
}

async function testSourceLifecycle() {
  const ui = await mount([existing]);
  try {
    const first = fixture(1); await until(() => ui.calls.poll >= 3);
    assert.equal(ui.calls.sources.length, 0); masked(ui, first);
    const opener = ui.button("查看资料", ui.row(existing.email)); opener.focus(); opener.click();
    await loaded(ui); assert.equal(ui.calls.sources.length, 1);
    assert.equal(ui.calls.sources[0].options.cache, "no-store"); token(ui.calls.sources[0]);
    assert.ok(ui.calls.sources[0].options.signal); masked(ui, first);
    assert.ok(ui.dialog().textContent.includes(existing.email));
    ui.aria("显示密码", ui.dialog()).click(); await until(() => ui.dialog().textContent.includes(first.password));
    ui.aria("隐藏密码", ui.dialog()).click(); await until(() => !ui.dialog().textContent.includes(first.password));
    ui.aria("复制2FA 密钥", ui.dialog()).click(); await until(() => ui.calls.clipboard.length === 1);
    assert.equal(ui.calls.clipboard[0], first.totpSecret); masked(ui, first);
    ui.aria("复制密码", ui.dialog()).click(); await until(() => ui.calls.clipboard.length === 2);
    assert.equal(ui.calls.clipboard[1], first.password); masked(ui, first);
    ui.aria("显示2FA 密钥", ui.dialog()).click(); await until(() => ui.dialog().textContent.includes(first.totpSecret));
    ui.dialog().dispatchEvent(new ui.window.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    await until(() => !ui.dialog()); masked(ui, first); assert.equal(ui.document.activeElement, opener);
    const second = fixture(2); ui.state.accounts[existing.id] = second; opener.click();
    await until(() => ui.calls.sources.length === 2); await loaded(ui); masked(ui, first, second);
    ui.aria("显示2FA 密钥", ui.dialog()).click(); await until(() => ui.dialog().textContent.includes(second.totpSecret));
    assert.equal(ui.dialog().textContent.includes(first.totpSecret), false);
    const pending = deferred(); ui.handlers.source = () => pending.promise;
    ui.button("刷新资料", ui.dialog()).click(); await until(() => ui.calls.sources.length === 3 && ui.document.querySelector(".account-source-loading"));
    masked(ui, first, second); pending.resolve(Response.json({ account: fixture(3) })); await loaded(ui); masked(ui, fixture(3));
    ui.handlers.clipboardReject = true; ui.aria("复制密码", ui.dialog()).click();
    await until(() => ui.dialog().textContent.includes("复制失败")); masked(ui, fixture(3));
    ui.handlers.clipboardReject = false; ui.aria("显示2FA 密钥", ui.dialog()).click();
    await until(() => ui.dialog().textContent.includes(fixture(3).totpSecret));
    const polled = deferred(); ui.handlers.source = () => polled.promise;
    ui.state.jobs = [{ ...existing, updatedAt: "fixture-state-change" }];
    await until(() => ui.calls.sources.length === 4 && ui.document.querySelector(".account-source-loading")); masked(ui, fixture(3));
    polled.resolve(Response.json({ account: fixture(4) })); await loaded(ui); masked(ui, fixture(4));
    const count = ui.calls.poll; await until(() => ui.calls.poll >= count + 3);
    assert.equal(ui.calls.sources.length, 4, "unchanged polling does not repeatedly retrieve credentials");
    ui.aria("显示2FA 密钥", ui.dialog()).click(); await until(() => ui.dialog().textContent.includes(fixture(4).totpSecret));
    const peerChange = deferred(); ui.handlers.source = () => peerChange.promise;
    const beforePeerChange = structuredClone(ui.state.jobs[0]);
    ui.state.jobs = [{ ...beforePeerChange, accountSourceVersion: "fixture-peer-credential-change" }];
    assert.deepEqual(Object.keys(ui.state.jobs[0]).filter((key) => ui.state.jobs[0][key] !== beforePeerChange[key]), ["accountSourceVersion"]);
    await until(() => ui.calls.sources.length === 5 && ui.document.querySelector(".account-source-loading"));
    masked(ui, fixture(4));
    assert.equal(ui.calls.sources[4].options.cache, "no-store"); token(ui.calls.sources[4]);
    peerChange.resolve(Response.json({ account: fixture(9) })); await loaded(ui); masked(ui, fixture(4), fixture(9));
    assert.ok(ui.aria("显示2FA 密钥", ui.dialog()), "peer credential update resets reveal state");
    assert.equal(ui.aria("隐藏2FA 密钥", ui.dialog()), undefined);
    ui.aria("显示2FA 密钥", ui.dialog()).click(); await until(() => ui.dialog().textContent.includes(fixture(9).totpSecret));
    assert.equal(ui.dialog().textContent.includes(fixture(4).totpSecret), false);
    ui.button("关闭", ui.dialog()).click(); await until(() => !ui.dialog()); masked(ui, first, second, fixture(3), fixture(4), fixture(9));
  } finally { ui.close(); }
}

async function testLateResponses() {
  const ui = await mount([existing]);
  try {
    const pending = deferred(); ui.handlers.source = () => pending.promise;
    ui.button("查看资料", ui.row(existing.email)).click(); await until(() => ui.calls.sources.length === 1);
    ui.button("关闭", ui.dialog()).click(); await until(() => !ui.dialog());
    assert.equal(ui.calls.sources[0].options.signal.aborted, true);
    ui.handlers.source = null; ui.state.accounts[existing.id] = fixture(6);
    ui.button("查看资料", ui.row(existing.email)).click(); await until(() => ui.calls.sources.length === 2); await loaded(ui);
    pending.resolve(Response.json({ account: fixture(5) })); await settle(); masked(ui, fixture(5), fixture(6));
    ui.aria("显示2FA 密钥", ui.dialog()).click(); await until(() => ui.dialog().textContent.includes(fixture(6).totpSecret));
    assert.equal(ui.dialog().textContent.includes(fixture(5).totpSecret), false);
    const stale = deferred(); const latest = deferred(); ui.handlers.source = () => stale.promise;
    ui.button("刷新资料", ui.dialog()).click(); await until(() => ui.calls.sources.length === 3);
    ui.handlers.source = () => latest.promise;
    ui.state.jobs = [{ ...existing, lastOperationAt: "fixture-new-operation", totpCredentialInvalidated: true }];
    await until(() => ui.calls.sources.length === 4); assert.equal(ui.calls.sources[2].options.signal.aborted, true);
    latest.resolve(Response.json({ account: { ...fixture(8), totpSecret: null } })); await loaded(ui);
    stale.resolve(Response.json({ account: fixture(7) })); await settle(); masked(ui, fixture(6), fixture(7), fixture(8));
    assert.equal(ui.aria("显示2FA 密钥", ui.dialog()), undefined);
    assert.equal(ui.aria("复制2FA 密钥", ui.dialog()).disabled, true);
    ui.aria("显示密码", ui.dialog()).click(); await until(() => ui.dialog().textContent.includes(fixture(8).password));
    assert.equal(ui.dialog().textContent.includes(fixture(7).password), false);
  } finally { ui.close(); }
}

async function testFailuresAndExports() {
  let ui = await mount([existing]);
  try {
    ui.handlers.source = () => Response.json({ error: "测试资料读取被拒绝" }, { status: 403 });
    ui.button("查看资料", ui.row(existing.email)).click(); await until(() => ui.dialog()?.querySelector('[role="alert"]'));
    assert.match(ui.dialog().textContent, /测试资料读取被拒绝/); masked(ui, fixture(1));
    assert.equal(ui.button("导出账号资料", ui.dialog()).disabled, true);
    ui.handlers.source = null; ui.button("刷新资料", ui.dialog()).click(); await loaded(ui); masked(ui, fixture(1));
    ui.aria("显示密码", ui.dialog()).click(); await until(() => ui.dialog().textContent.includes(fixture(1).password));
    ui.handlers.source = () => Response.json({ error: "测试刷新资料被拒绝" }, { status: 403 });
    ui.button("刷新资料", ui.dialog()).click(); await until(() => ui.dialog().textContent.includes("测试刷新资料被拒绝"));
    masked(ui, fixture(1));
    ui.handlers.source = null; ui.button("刷新资料", ui.dialog()).click(); await loaded(ui); masked(ui, fixture(1));
    const pending = deferred(); ui.handlers.export = () => pending.promise;
    const exportButton = ui.button("导出账号资料", ui.dialog()); exportButton.click(); exportButton.click();
    await until(() => ui.calls.exports.length === 1 && ui.button("导出账号资料", ui.dialog()).disabled);
    pending.resolve(Response.json({ error: "测试资料导出被拒绝" }, { status: 423 }));
    await until(() => ui.dialog().textContent.includes("测试资料导出被拒绝"));
    assert.equal(ui.calls.downloads.length, 0); assert.equal(ui.calls.exports.length, 1); masked(ui, fixture(1));
    ui.handlers.export = null; ui.state.accounts[existing.id] = fixture(10);
    ui.button("导出账号资料", ui.dialog()).click(); await until(() => ui.calls.downloads.length === 1);
    const download = await ui.calls.downloads[0].blob.text();
    assert.ok(download.includes(fixture(10).totpSecret), "export reads current server data instead of modal snapshot");
    assert.equal(download.includes(fixture(1).totpSecret + '"'), false);
    assert.deepEqual(ui.calls.exports[1].body, { ids: [existing.id] }); token(ui.calls.exports[1]);
    assert.equal(ui.calls.exports[1].options.cache, "no-store"); assert.equal(ui.calls.sources.length, 4); masked(ui, fixture(1), fixture(10));
  } finally { ui.close(); }
  ui = await mount([existing, fresh]);
  try {
    ui.state.accounts[existing.id] = fixture(11); ui.state.accounts[fresh.id] = fixture(12, fresh.email);
    ui.button("导出账号资料", ui.row(existing.email)).click(); await until(() => ui.calls.downloads.length === 1);
    assert.deepEqual(ui.calls.exports[0].body, { ids: [existing.id] });
    assert.ok((await ui.calls.downloads[0].blob.text()).includes(fixture(11).totpSecret)); assert.equal(ui.calls.sources.length, 0);
    ui.button("本页全选").click(); await until(() => !ui.button("批量导出账号资料").disabled);
    ui.button("批量导出账号资料").click(); await until(() => ui.calls.downloads.length === 2);
    assert.deepEqual(ui.calls.exports[1].body, { ids: [existing.id, fresh.id] });
    const bulk = await ui.calls.downloads[1].blob.text(); assert.ok(bulk.includes(fixture(11).totpSecret)); assert.ok(bulk.includes(fixture(12).totpSecret));
    assert.equal(ui.calls.sources.length, 0); masked(ui, fixture(11), fixture(12));
  } finally { ui.close(); }
}

function masked(ui, ...accounts) {
  const html = ui.document.documentElement.outerHTML;
  const text = ui.document.documentElement.textContent;
  for (const account of accounts) for (const field of ["password", "totpSecret", "mailApiUrl", "mailRequestBody"]) {
    if (account[field]) assert.equal(html.includes(account[field]) || text.includes(account[field]), false, `${field} must not appear in masked/closed DOM`);
  }
}
function token(call) { assert.equal(new Headers(call.options.headers).get("x-console-token"), "ui-token"); }
function deferred() { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; }
async function loaded(ui) { await until(() => ui.document.querySelector(".account-source-fields")); }
async function settle() { await new Promise((resolve) => setTimeout(resolve, 35)); }
async function until(predicate) {
  const deadline = Date.now() + 4000;
  while (!predicate()) { if (Date.now() > deadline) throw new Error("Timed out waiting for UI state"); await new Promise((resolve) => setTimeout(resolve, 10)); }
}
