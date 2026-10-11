import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "../..");
const controller = path.join(import.meta.dirname, "fixture-control.mjs");

async function run(args, options = {}) {
  const child = spawn(process.execPath, [controller, ...args], {
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  let output = "";
  child.stdout.on("data", (data) => (output += data));
  child.stderr.on("data", (data) => (output += data));
  const [code, signal] = await once(child, "close");
  return { code, signal, output };
}

async function server(port = 0) {
  const listener = net.createServer((socket) => socket.end());
  listener.listen(port, "127.0.0.1");
  await once(listener, "listening");
  return listener;
}

async function freePort() {
  const listener = await server();
  const { port } = listener.address();
  await new Promise((resolve) => listener.close(resolve));
  return port;
}

async function responds(port) {
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    socket.setTimeout(1000);
    socket.on("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

async function workspace(t) {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "warden-owner-test-"),
  );
  const base = path.join(directory, "fixture");
  const entry = path.join(directory, "provider.mjs");
  const port = await freePort();
  await fs.writeFile(
    entry,
    `import net from 'node:net';\nnet.createServer(s => s.end()).listen(${port}, '127.0.0.1');\n`,
  );
  t.after(async () => {
    await run(["down", base], {
      env: { ...process.env, WARDEN_FIXTURE_OWNER: "" },
    });
    await fs.rm(directory, { recursive: true, force: true });
  });
  return { directory, base, entry, port };
}

test("node-provider down leaves an unrelated listener running", async (t) => {
  // This process is owned by the test. The old script kills it by port alone.
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "warden-down-test-"),
  );
  await fs.mkdir(path.join(directory, "scripts"));
  await fs.mkdir(path.join(directory, "test/providers"), { recursive: true });
  await fs.copyFile(
    path.join(root, "scripts/node-provider"),
    path.join(directory, "scripts/node-provider"),
  );
  await fs
    .copyFile(
      controller,
      path.join(directory, "test/providers/fixture-control.mjs"),
    )
    .catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
  const child = spawn(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      "import net from 'node:net'; net.createServer(s => s.end()).listen(19443, '127.0.0.1', () => console.log('ready'));",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  const closed = once(child, "close");
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
    await fs.rm(directory, { recursive: true, force: true });
  });
  await Promise.race([
    once(child.stdout, "data"),
    closed.then(() => {
      throw new Error("test port 19443 is unavailable");
    }),
  ]);
  const down = spawn(
    "sh",
    [path.join(directory, "scripts/node-provider"), "down"],
    { stdio: "pipe" },
  );
  assert.equal((await once(down, "close"))[0], 0);
  assert.equal(await responds(19443), true, "unrelated listener survives down");
});

test("normal startup and shutdown retain no listener or owner record", async (t) => {
  const { base, entry, port } = await workspace(t);
  const started = await run(["up", base, entry, String(port)]);
  assert.equal(started.code, 0, started.output);
  assert.equal(await responds(port), true);
  assert.equal((await fs.stat(base + ".owner")).isDirectory(), true);
  assert.equal((await run(["down", base])).code, 0);
  assert.equal(await responds(port), false);
  await assert.rejects(fs.stat(base + ".owner"), { code: "ENOENT" });
  assert.equal((await run(["down", base])).code, 0);
});

test("an occupied port and stale legacy PID cannot authorize shutdown", async (t) => {
  const { base, entry } = await workspace(t);
  const listener = await server();
  t.after(() => new Promise((resolve) => listener.close(resolve)));
  const { port } = listener.address();
  await fs.writeFile(base + ".pid", String(process.pid));
  const started = await run(["up", base, entry, String(port)]);
  assert.notEqual(started.code, 0);
  assert.equal((await run(["down", base])).code, 0);
  assert.equal(await responds(port), true);
});

test("another invocation cannot stop or replace an owned fixture", async (t) => {
  const { base, entry, port } = await workspace(t);
  const env = { ...process.env, WARDEN_FIXTURE_OWNER: "owner-a" };
  const other = { ...process.env, WARDEN_FIXTURE_OWNER: "owner-b" };
  assert.equal((await run(["up", base, entry, String(port)], { env })).code, 0);
  assert.notEqual(
    (await run(["up", base, entry, String(port)], { env: other })).code,
    0,
  );
  assert.notEqual((await run(["down", base], { env: other })).code, 0);
  assert.equal(await responds(port), true);
  assert.equal((await run(["down", base], { env })).code, 0);
});

test("failed startup removes only its own state", async (t) => {
  const { base, entry, port } = await workspace(t);
  await fs.writeFile(entry, "throw new Error('deliberate startup failure');\n");
  assert.notEqual((await run(["up", base, entry, String(port)])).code, 0);
  assert.equal(await responds(port), false);
  await assert.rejects(fs.stat(base + ".owner"), { code: "ENOENT" });
});

test("interrupted startup stops its owned process", async (t) => {
  const { base, entry, port } = await workspace(t);
  const marker = path.join(path.dirname(base), "starting");
  await fs.writeFile(
    entry,
    `import fs from 'node:fs';\nimport net from 'node:net';\nnet.createServer().listen(${port}, '127.0.0.1', () => fs.writeFileSync(${JSON.stringify(marker)}, 'starting'));\nawait new Promise(() => {});\n`,
  );
  const child = spawn(
    process.execPath,
    [controller, "up", base, entry, String(port)],
    { stdio: "ignore" },
  );
  const closed = once(child, "close");
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  });
  for (let i = 0; i < 100 && !(await fs.stat(marker).catch(() => false)); i++)
    await delay(20);
  assert.equal(await responds(port), true);
  child.kill("SIGTERM");
  assert.notEqual((await closed)[0], 0);
  assert.equal(await responds(port), false);
  await assert.rejects(fs.stat(base + ".owner"), { code: "ENOENT" });
});

test("malformed ownership state refuses cleanup", async (t) => {
  const { base } = await workspace(t);
  await fs.mkdir(base + ".owner");
  await fs.writeFile(path.join(base + ".owner", "control.json"), "not JSON");
  assert.notEqual((await run(["down", base])).code, 0);
  assert.equal(
    await fs.readFile(path.join(base + ".owner", "control.json"), "utf8"),
    "not JSON",
  );
});

test("an unavailable control socket leaves the owner record for inspection", async (t) => {
  const { base } = await workspace(t);
  await fs.mkdir(base + ".owner");
  const record = JSON.stringify({
    version: 1,
    token: "stale",
    socket: path.join(path.dirname(base), "absent.sock"),
  });
  await fs.writeFile(path.join(base + ".owner", "control.json"), record);
  assert.notEqual((await run(["down", base])).code, 0);
  assert.equal(
    await fs.readFile(path.join(base + ".owner", "control.json"), "utf8"),
    record,
  );
});

test("the fixture itself rejects a forged ownership token", async (t) => {
  const { base, entry, port } = await workspace(t);
  assert.equal((await run(["up", base, entry, String(port)])).code, 0);
  const file = path.join(base + ".owner", "control.json");
  const original = await fs.readFile(file, "utf8");
  try {
    await fs.writeFile(
      file,
      JSON.stringify({ ...JSON.parse(original), token: "forged" }),
    );
    assert.notEqual(
      (
        await run(["down", base], {
          env: { ...process.env, WARDEN_FIXTURE_OWNER: "" },
        })
      ).code,
      0,
    );
    assert.equal(await responds(port), true);
  } finally {
    await fs.writeFile(file, original);
  }
});

async function wrapperWorkspace(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "warden-wrapper-"));
  const base = path.join(directory, "build/node-provider");
  const entry = path.join(directory, "test/providers/node-oidc/provider.mjs");
  const marker = path.join(directory, "discovery-wait");
  const readiness = path.join(directory, "discovery-ready");
  for (const name of ["scripts", "bin", "test/providers/node-oidc"])
    await fs.mkdir(path.join(directory, name), { recursive: true });
  await fs.copyFile(
    path.join(root, "scripts/node-provider"),
    path.join(directory, "scripts/node-provider"),
  );
  await fs.copyFile(
    controller,
    path.join(directory, "test/providers/fixture-control.mjs"),
  );
  await fs.writeFile(
    path.join(directory, "scripts/test-pki"),
    "#!/bin/sh\nexit 0\n",
    { mode: 0o755 },
  );
  await fs.writeFile(path.join(directory, "bin/npm"), "#!/bin/sh\nexit 0\n", {
    mode: 0o755,
  });
  // Discovery refusal is external to the wrapper; the real controller owns a
  // real listener. The marker proves startup passed control-channel admission.
  await fs.writeFile(
    path.join(directory, "bin/curl"),
    `#!/bin/sh\n[ -f '${readiness}' ] && exit 0\ntouch '${marker}'\nexit 22\n`,
    { mode: 0o755 },
  );
  await fs.writeFile(
    entry,
    "import net from 'node:net'; net.createServer(s => s.end()).listen(19443, '127.0.0.1');\n",
  );
  const env = {
    ...process.env,
    PATH: path.join(directory, "bin") + path.delimiter + process.env.PATH,
    WARDEN_FIXTURE_OWNER: "wrapper-owner",
  };
  t.after(async () => {
    await run(["down", base], {
      env: { ...process.env, WARDEN_FIXTURE_OWNER: "" },
    });
    await fs.rm(directory, { recursive: true, force: true });
  });
  return { directory, base, entry, marker, readiness, env };
}

test("node-provider interruption during discovery removes its own fixture", async (t) => {
  const { directory, base, marker, env } = await wrapperWorkspace(t);
  const child = spawn(
    "sh",
    [path.join(directory, "scripts/node-provider"), "up"],
    { env, stdio: "pipe" },
  );
  const closed = once(child, "close");
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed;
  });
  for (let i = 0; i < 100 && !(await fs.stat(marker).catch(() => false)); i++)
    await delay(20);
  assert.ok(await fs.stat(marker));
  assert.equal(await responds(19443), true);
  child.kill("SIGTERM");
  assert.notEqual((await closed)[0], 0);
  assert.equal(await responds(19443), false);
  await assert.rejects(fs.stat(base + ".owner"), { code: "ENOENT" });
});

test("node-provider failed startup preserves another invocation's fixture", async (t) => {
  const { directory, base, entry, env } = await wrapperWorkspace(t);
  const owner = { ...env, WARDEN_FIXTURE_OWNER: "earlier-owner" };
  assert.equal(
    (await run(["up", base, entry, "19443"], { env: owner })).code,
    0,
  );
  const child = spawn(
    "sh",
    [path.join(directory, "scripts/node-provider"), "up"],
    { env, stdio: "pipe" },
  );
  assert.notEqual((await once(child, "close"))[0], 0);
  assert.equal(await responds(19443), true);
  const record = JSON.parse(
    await fs.readFile(path.join(base + ".owner", "control.json"), "utf8"),
  );
  assert.equal(record.token, "earlier-owner");
});

test("node-provider readiness failure removes its own fixture", async (t) => {
  const { directory, base, env } = await wrapperWorkspace(t);
  const child = spawn(
    "sh",
    [path.join(directory, "scripts/node-provider"), "up"],
    { env, stdio: "ignore" },
  );
  assert.equal((await once(child, "close"))[0], 1);
  assert.equal(await responds(19443), false);
  await assert.rejects(fs.stat(base + ".owner"), { code: "ENOENT" });
});

test("successful node-provider startup survives refused subsequent starts", async (t) => {
  const { directory, base, readiness, env } = await wrapperWorkspace(t);
  await fs.writeFile(readiness, "ready");
  async function start(token) {
    const child = spawn(
      "sh",
      [path.join(directory, "scripts/node-provider"), "up"],
      { env: { ...env, WARDEN_FIXTURE_OWNER: token }, stdio: "ignore" },
    );
    return (await once(child, "close"))[0];
  }
  assert.equal(await start("wrapper-owner"), 0);
  const owner = await fs.readFile(base + ".owner/control.json", "utf8");
  for (const token of ["wrapper-owner", "another-wrapper-owner"]) {
    assert.equal(await start(token), 1);
    assert.equal(await responds(19443), true);
    assert.equal(
      await fs.readFile(base + ".owner/control.json", "utf8"),
      owner,
    );
  }
});
