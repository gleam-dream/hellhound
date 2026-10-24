// Private lifecycle for disposable Node providers. Shutdown is a request to the
// fixture itself; neither a public port nor a stored PID authorizes a signal.
import { fork } from "node:child_process";
import crypto from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import {
  setTimeout as delay,
  setImmediate as nextTurn,
} from "node:timers/promises";
import { pathToFileURL } from "node:url";

const statePath = (base) => path.join(base + ".owner", "control.json");

function readState(base) {
  const state = JSON.parse(fs.readFileSync(statePath(base), "utf8"));
  if (
    state.version !== 1 ||
    typeof state.token !== "string" ||
    !state.token ||
    typeof state.socket !== "string"
  ) {
    throw new Error("invalid fixture ownership record");
  }
  return state;
}

function removeOwned(base, state, directory) {
  try {
    const current = readState(base);
    if (current.token === state.token && current.socket === state.socket) {
      fs.rmSync(base + ".owner", { recursive: true, force: true });
    }
  } catch (error) {
    if (error.code !== "ENOENT")
      console.error("retained unrecognized ownership record");
  }
  fs.rmSync(directory, { recursive: true, force: true });
}

async function check(base, port) {
  if (fs.existsSync(base + ".owner"))
    throw new Error(
      "fixture already has an ownership record; inspect or stop it first",
    );
  const listener = net.createServer();
  listener.listen(port, "127.0.0.1");
  await once(listener, "listening");
  await new Promise((resolve) => listener.close(resolve));
}

async function up(base, entry, port) {
  await check(base, port);
  fs.mkdirSync(path.dirname(base), { recursive: true });
  // Exclusive directory creation serializes starts for this fixture.
  fs.mkdirSync(base + ".owner", { mode: 0o700 });
  let directory;
  let state;
  let child;
  let closed;
  let log;
  let ready = false;
  let interrupt;
  try {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "hellhound-fixture-"));
    state = {
      version: 1,
      token:
        process.env.HELLHOUND_FIXTURE_OWNER ||
        crypto.randomBytes(32).toString("hex"),
      socket: path.join(directory, "control.sock"),
    };
    fs.writeFileSync(statePath(base), JSON.stringify(state), {
      mode: 0o600,
      flag: "wx",
    });
    log = fs.openSync(base + ".log", "w", 0o600);
    child = fork(
      import.meta.filename,
      ["serve", base, entry, String(port), directory],
      {
        detached: true,
        stdio: ["ignore", log, log, "ipc"],
      },
    );
    closed = once(child, "close");
    await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("fixture startup timed out")),
        15000,
      );
      const fail = () =>
        reject(new Error("fixture startup failed; inspect " + base + ".log"));
      interrupt = () => reject(new Error("fixture startup interrupted"));
      for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"])
        process.once(signal, interrupt);
      child.once("error", reject);
      child.once("exit", fail);
      child.once("message", (message) => {
        if (message === "ready") resolve();
        else reject(new Error("unexpected fixture startup response"));
      });
      closed.then(
        () => clearTimeout(timer),
        () => clearTimeout(timer),
      );
      child.once("message", () => clearTimeout(timer));
    });
    ready = true;
    child.disconnect();
    child.unref();
  } finally {
    if (interrupt)
      for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"])
        process.removeListener(signal, interrupt);
    if (!ready) {
      if (child && child.exitCode === null && child.signalCode === null) {
        // The unreaped ChildProcess handle belongs to this startup attempt.
        child.kill("SIGTERM");
        const kill = setTimeout(() => child.kill("SIGKILL"), 2000);
        await closed.finally(() => clearTimeout(kill));
      }
      if (state) removeOwned(base, state, directory);
      else {
        fs.rmdirSync(base + ".owner");
        if (directory) fs.rmSync(directory, { recursive: true, force: true });
      }
    }
    if (log !== undefined) fs.closeSync(log);
  }
}

async function serve(base, entry, port, directory) {
  const state = readState(base);
  let ready = false;
  process.once("exit", () => removeOwned(base, state, directory));
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"])
    process.once(signal, () => process.exit(1));
  process.once("disconnect", () => {
    if (!ready) process.exit(1);
  });
  const listener = net.createServer((socket) => {
    socket.setTimeout(2000, () => socket.destroy());
    socket.on("error", () => {});
    let text = "";
    socket.on("data", (data) => {
      text += data;
      if (text.length > 4096) return socket.destroy();
      if (!text.includes("\n")) return;
      let request;
      try {
        request = JSON.parse(text.trim());
      } catch {
        return socket.destroy();
      }
      if (request.token !== state.token || request.action !== "stop")
        return socket.end('{"ok":false}\n');
      socket.end('{"ok":true}\n', () => process.exit(0));
    });
  });
  listener.listen(state.socket);
  await once(listener, "listening");
  await import(pathToFileURL(entry));
  await nextTurn();
  // Imports that fail to bind (including a port race) exit before admission.
  const probe = net.connect(port, "127.0.0.1");
  await once(probe, "connect");
  probe.destroy();
  ready = true;
  process.send("ready");
}

async function down(base) {
  if (!fs.existsSync(base + ".owner")) return;
  const state = readState(base);
  const token = process.env.HELLHOUND_FIXTURE_OWNER || state.token;
  if (token !== state.token)
    throw new Error("fixture belongs to another invocation");
  const socket = net.connect(state.socket);
  try {
    socket.setTimeout(2000, () =>
      socket.destroy(new Error("fixture control timed out")),
    );
    await once(socket, "connect");
    let reply = "";
    socket.on("data", (data) => (reply += data));
    const ended = once(socket, "end");
    socket.end(JSON.stringify({ token, action: "stop" }) + "\n");
    await ended;
    if (JSON.parse(reply).ok !== true)
      throw new Error("fixture refused shutdown");
    for (let i = 0; i < 100 && fs.existsSync(base + ".owner"); i++)
      await delay(20);
    if (fs.existsSync(base + ".owner"))
      throw new Error("fixture shutdown was not acknowledged");
  } finally {
    socket.destroy();
  }
}

try {
  const [command, suppliedBase, suppliedEntry, suppliedPort, directory] =
    process.argv.slice(2);
  if (!suppliedBase)
    throw new Error(
      "usage: fixture-control.mjs up BASE MODULE PORT | down BASE",
    );
  const base = path.resolve(suppliedBase);
  if (command === "down") await down(base);
  else if (command === "up" || command === "serve") {
    const port = Number(suppliedPort);
    if (!suppliedEntry || !Number.isInteger(port) || port < 1 || port > 65535)
      throw new Error("module and port required");
    const entry = path.resolve(suppliedEntry);
    if (command === "up") await up(base, entry, port);
    else await serve(base, entry, port, directory);
  } else throw new Error("unknown fixture command");
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
