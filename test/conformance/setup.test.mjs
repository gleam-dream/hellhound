import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execute = promisify(execFile);

// Exercise the actual driver process and its receipts against a local oracle
// API fixture. No reference RP build is present. The driver's fixed suite port
// must be unused; never stop or reuse a running conformance suite for this test.
test("conformance driver preserves setup outcomes before starting the RP", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "warden-setup-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const driver = path.join(root, "test/conformance");
  fs.mkdirSync(driver, { recursive: true });
  for (const file of ["run.mjs", "verdict.mjs", "known-outcomes.json"]) {
    fs.copyFileSync(new URL(file, import.meta.url), path.join(driver, file));
  }
  const key = path.join(root, "server.key");
  const cert = path.join(root, "server.pem");
  await execute("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-sha256",
    "-keyout",
    key,
    "-out",
    cert,
    "-days",
    "1",
    "-subj",
    "/CN=Warden setup fixture",
    "-addext",
    "subjectAltName=DNS:localhost.emobix.co.uk",
  ]);
  fs.chmodSync(key, 0o600);
  let scenario;
  let requests;
  const oracleLog = [{ message: "fixture setup outcome", owner: "oracle" }];
  const server = https.createServer(
    { key: fs.readFileSync(key), cert: fs.readFileSync(cert) },
    (req, res) => {
      const url = new URL(req.url, "https://localhost.emobix.co.uk:8443");
      requests.push(`${req.method} ${url.pathname}`);
      req.resume();
      let body;
      if (req.method === "POST" && url.pathname === "/api/plan") {
        body = { id: "plan", modules: [{ testModule: "fixture-setup" }] };
      } else if (req.method === "POST" && url.pathname === "/api/runner") {
        body = { id: "module" };
      } else if (req.method === "GET" && url.pathname === "/api/info/module") {
        body = {
          id: "module",
          status: scenario.status,
          result: scenario.result,
        };
      } else if (req.method === "GET" && url.pathname === "/api/log/module") {
        body = oracleLog;
      } else if (
        req.method === "GET" &&
        url.pathname === "/api/runner/browser/module"
      ) {
        body = { urls: [] };
      } else if (
        req.method === "GET" &&
        url.pathname === "/api/plan/exporthtml/plan"
      ) {
        res.end("fixture export");
        return;
      } else {
        res.writeHead(404);
        res.end("unexpected oracle request");
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(body));
    },
  );
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(8443, "127.0.0.1", resolve);
  });
  t.after(
    () =>
      new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      }),
  );
  for (const sample of [
    { plan: "basic", status: "INTERRUPTED", result: "FAILED" },
    { plan: "basic", status: "FINISHED", result: "SKIPPED" },
    { plan: "thirdparty", status: "INTERRUPTED", result: "FAILED" },
    { plan: "basic", status: "CREATED", result: "NONE" },
    { plan: "basic", status: "WAITING", result: "NONE" },
  ]) {
    await t.test(
      `${sample.plan}: ${sample.status}/${sample.result}`,
      async () => {
        scenario = sample;
        requests = [];
        fs.rmSync(path.join(root, "build"), { recursive: true, force: true });
        const env = {
          ...process.env,
          NODE_EXTRA_CA_CERTS: cert,
          WARDEN_CONFORMANCE_POLICY: "strict",
        };
        delete env.NODE_TLS_REJECT_UNAUTHORIZED;
        delete env.MODULES;
        let exitCode = 0;
        try {
          await execute(
            process.execPath,
            [path.join(driver, "run.mjs"), sample.plan],
            {
              cwd: root,
              env,
              timeout: 45000,
            },
          );
        } catch (error) {
          assert.equal(
            error.killed,
            false,
            "driver must finish within its deadline",
          );
          exitCode = error.code;
        }
        assert.equal(exitCode, 1, "strict acceptance must remain false");
        const out = path.join(root, "build/conformance");
        const receipt = JSON.parse(
          fs.readFileSync(path.join(out, `summary-${sample.plan}.json`)),
        );
        assert.equal(receipt.acceptance.ok, false);
        assert.equal(receipt.acceptance.certification, false);
        assert.equal(receipt.summary.length, 1);
        const row = receipt.summary[0];
        if (sample.status === "WAITING") {
          // Positive control: a ready module reaches the absent RP build.
          assert.equal(row.status, "DRIVER_ERROR");
          assert.match(row.notes.join(" "), /consumer\/build\/dev\/erlang/);
        } else {
          assert.equal(row.id, "module");
          assert.equal(row.status, sample.status);
          assert.equal(row.result, sample.result);
          assert.match(
            row.notes.join(" "),
            /setup.*reference RP was not started/,
          );
          assert.deepEqual(
            JSON.parse(
              fs.readFileSync(path.join(out, "fixture-setup-query.log.json")),
            ),
            oracleLog,
          );
          assert(
            !requests.some((request) =>
              request.includes("/api/runner/browser/"),
            ),
            "no initiation after terminal or unready setup",
          );
        }
        assert(
          !fs.existsSync(path.join(root, "consumer")),
          "fixture has no RP build",
        );
      },
    );
  }
});
