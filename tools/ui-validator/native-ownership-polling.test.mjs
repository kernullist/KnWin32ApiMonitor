import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";
import { setImmediate as flush } from "node:timers/promises";
import ts from "typescript";

const source = fs.readFileSync(new URL("../../apps/knmon-ui/src/nativeOwnershipPolling.ts", import.meta.url), "utf8");
const exports = {};
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText,
  { exports }, { filename: "nativeOwnershipPolling.cjs" });
const { createNativeOwnershipPolling, mergeSessionSnapshot, retainUnchangedSnapshot, isDaemonSession, selectTraceDrainSession } = exports;

function deferred()
{
  let resolve;
  let reject;
  const promise = new Promise((yes, no) =>
  {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function clockFixture()
{
  let now = 0;
  let sequence = 0;
  const timers = new Map();
  return {
    get now()
    {
      return now;
    },
    get pending()
    {
      return timers.size;
    },
    schedule(callback, delay)
    {
      assert.ok(Number.isInteger(delay) && delay >= 0 && delay <= 5000);
      const id = ++sequence;
      timers.set(id, { time: now + delay, callback });
      return id;
    },
    cancel(id)
    {
      timers.delete(id);
    },
    async advance(milliseconds)
    {
      const until = now + milliseconds;
      let iterations = 0;
      await flush();
      while (true)
      {
        assert.ok(++iterations < 1000, "Polling must not spin without a delay.");
        const entry = [...timers.entries()].filter(([, timer]) => timer.time <= until)
          .sort((left, right) => left[1].time - right[1].time || left[0] - right[0])[0];
        if (!entry)
        {
          break;
        }
        timers.delete(entry[0]);
        now = entry[1].time;
        entry[1].callback();
        await flush();
      }
      now = until;
    }
  };
}

function fixture(overrides = {})
{
  const clock = clockFixture();
  const calls = { operations: [], sessions: [], daemons: [] };
  const local = [];
  const daemons = [];
  const errors = [];
  const readers = {};
  for (const name of Object.keys(calls))
  {
    readers[name] = () =>
    {
      calls[name].push(clock.now);
      return overrides[name] ? overrides[name]() : Promise.resolve([]);
    };
  }
  const polling = createNativeOwnershipPolling({ ...readers,
    onLocal: (operations, sessions) => local.push({ operations, sessions }),
    onDaemons: (sessions) => daemons.push(sessions),
    onError: (source, error) => errors.push({ source, error })
  }, clock);
  return { polling, clock, calls, local, daemons, errors };
}

test("ordinary capture polls local state promptly and discovers daemons at one tenth the rate", async () =>
{
  const f = fixture();
  f.polling.setActivity(true, false);
  await f.clock.advance(10000);
  assert.equal(f.calls.operations.length, 21);
  assert.equal(f.calls.sessions.length, 21);
  assert.deepEqual(f.calls.daemons, [0, 5000, 10000]);
  f.polling.setActivity(false, false);
  await f.clock.advance(5000);
  assert.equal(f.calls.operations.length, 21);
  assert.deepEqual(f.calls.daemons, [0, 5000, 10000, 15000]);
  f.polling.dispose();
  assert.equal(f.clock.pending, 0);
});

test("a slow or failed daemon query cannot delay local terminal state or start overlapping daemon reads", async () =>
{
  const waiting = deferred();
  let blocked = true;
  const f = fixture({ daemons: () => blocked ? waiting.promise : Promise.resolve([]),
    sessions: async () => [{ sessionId: "local", sessionState: "stopped" }] });
  f.polling.setActivity(true, false);
  await f.clock.advance(15000);
  assert.equal(f.calls.daemons.length, 1);
  assert.equal(f.local.length, 31);
  assert.ok(f.local.every((value) => value.sessions[0].sessionState === "stopped"));
  blocked = false;
  waiting.reject(new Error("Daemon unavailable"));
  await f.clock.advance(5000);
  assert.equal(f.errors.length, 1);
  assert.equal(f.errors[0].source, "daemon");
  assert.equal(f.daemons.length, 1);
  assert.equal(f.local.length, 41);
  f.polling.dispose();
});

for (const synchronous of [false, true])
{
  test(`a ${synchronous ? "synchronous" : "rejected"} local read failure retains the other outstanding read`, async () =>
  {
    const waiting = deferred();
    const failure = new Error("Read failed");
    const f = fixture({ operations: () => waiting.promise, sessions: () =>
    {
      if (synchronous)
      {
        throw failure;
      }
      return Promise.reject(failure);
    } });
    f.polling.setActivity(true, false);
    await f.clock.advance(10000);
    assert.equal(f.calls.operations.length, 1);
    assert.equal(f.calls.sessions.length, 1);
    assert.equal(f.errors.length, 0);
    assert.equal(f.daemons.length, 3);
    waiting.resolve([]);
    await f.clock.advance(499);
    assert.equal(f.errors.length, 1);
    assert.equal(f.errors[0].error, failure);
    await f.clock.advance(1);
    assert.equal(f.calls.operations.length, 2);
    f.polling.dispose();
  });
}

test("disable and reenable retain one in-flight read and discard its obsolete result", async () =>
{
  const waiting = deferred();
  let count = 0;
  const f = fixture({ sessions: () => ++count === 1 ? waiting.promise : Promise.resolve([{ sessionState: "stopped" }]) });
  f.polling.setActivity(true, false);
  await f.clock.advance(0);
  for (let index = 0; index < 10; ++index)
  {
    f.polling.setActivity(false, false);
    f.polling.setActivity(true, false);
  }
  await f.clock.advance(2000);
  assert.equal(count, 1);
  waiting.resolve([{ sessionState: "running" }]);
  await f.clock.advance(0);
  assert.equal(count, 2);
  assert.equal(f.local.length, 1);
  assert.equal(f.local[0].sessions[0].sessionState, "stopped");
  f.polling.dispose();
});

for (const daemon of [false, true])
{
  test(`a ${daemon ? "daemon" : "local"} command response invalidates an older poll without overlapping requests`, async () =>
  {
    const waiting = deferred();
    let count = 0;
    const name = daemon ? "daemons" : "sessions";
    const f = fixture({ [name]: () => ++count === 1 ? waiting.promise : Promise.resolve([{ sessionState: "stopped" }]) });
    f.polling.setActivity(true, true);
    await f.clock.advance(0);
    for (let index = 0; index < 20; ++index)
    {
      if (daemon)
      {
        f.polling.refreshDaemons();
      }
      else
      {
        f.polling.refreshLocal();
      }
    }
    await f.clock.advance(1000);
    assert.equal(count, 1);
    waiting.resolve([{ sessionState: "running" }]);
    await f.clock.advance(0);
    const updates = daemon ? f.daemons : f.local.map((value) => value.sessions);
    assert.equal(count, 2);
    assert.equal(updates.length, 1);
    assert.equal(updates[0][0].sessionState, "stopped");
    f.polling.dispose();
  });
}

test("known daemon activity switches discovery cadence without starting local reads", async () =>
{
  const f = fixture();
  f.polling.setActivity(false, true);
  await f.clock.advance(1000);
  assert.deepEqual(f.calls.daemons, [0, 500, 1000]);
  assert.equal(f.calls.sessions.length, 0);
  f.polling.setActivity(false, false);
  await f.clock.advance(10000);
  assert.deepEqual(f.calls.daemons, [0, 500, 1000, 1000, 6000, 11000]);
  f.polling.dispose();
});

test("disposed polls publish neither late success nor failure and cannot be restarted", async () =>
{
  const local = deferred();
  const daemon = deferred();
  const f = fixture({ sessions: () => local.promise, daemons: () => daemon.promise });
  f.polling.setActivity(true, true);
  await f.clock.advance(0);
  f.polling.dispose();
  f.polling.setActivity(true, false);
  f.polling.refreshLocal();
  f.polling.refreshDaemons();
  local.resolve([]);
  daemon.reject(new Error("Obsolete failure"));
  await f.clock.advance(20000);
  assert.equal(f.local.length + f.daemons.length + f.errors.length, 0);
  assert.equal(f.clock.pending, 0);
  assert.equal(f.calls.sessions.length, 1);
  assert.equal(f.calls.daemons.length, 1);
});

test("separate snapshots preserve the other session domain and daemon identity precedence", () =>
{
  const local = { sessionId: "local", sessionKind: "attach", daemonProcessId: 0, sessionState: "running" };
  const daemon = { sessionId: "daemon", sessionKind: "daemon_attach", daemonProcessId: 1, sessionState: "running" };
  const current = [daemon, local];
  const same = mergeSessionSnapshot(current, [{ ...local }], false);
  assert.equal(same, current);
  assert.equal(mergeSessionSnapshot(current, [{ ...daemon }], true), current);
  assert.deepEqual(Array.from(mergeSessionSnapshot(current, [], false)), [daemon]);
  assert.deepEqual(Array.from(mergeSessionSnapshot(current, [], true)), [local]);
  const terminal = { ...local, sessionState: "stopped" };
  assert.deepEqual(Array.from(mergeSessionSnapshot(current, [terminal, daemon], false)), [daemon, terminal]);
  assert.deepEqual(Array.from(mergeSessionSnapshot(current, [{ ...local, sessionId: "daemon" }], false)), [daemon]);
  assert.ok(isDaemonSession({ ...local, daemonProcessId: 7 }));
  assert.ok(isDaemonSession({ ...daemon, daemonProcessId: 0 }));
  assert.ok(!isDaemonSession(local));
});

test("snapshot reuse compares all flat fields including cancellation, loss, errors and removed fields", () =>
{
  const current = [{ sessionId: "local", stopRequested: false, lastError: "", hostDroppedBatches: 0 }];
  assert.equal(retainUnchangedSnapshot(current, [{ ...current[0] }]), current);
  for (const patch of [{ stopRequested: true }, { hostDroppedBatches: 1 }, { lastError: "failed" }, { extra: 0 }])
  {
    assert.notEqual(retainUnchangedSnapshot(current, [{ ...current[0], ...patch }]), current);
  }
  assert.notEqual(retainUnchangedSnapshot(current, [{ sessionId: "local" }]), current);
  assert.notEqual(retainUnchangedSnapshot(current, []), current);
});

test("the selected attach or launch continues through every terminal state until its tail is drained", () =>
{
  const other = { sessionId: "daemon", sessionKind: "daemon_attach", daemonProcessId: 1, sessionState: "running" };
  for (const sessionKind of ["attach_capture_stream", "launch_capture_stream"])
  {
    for (const sessionState of ["running", "stop_requested", "draining", "stopped", "failed", "stale", "recovery_required"])
    {
      const session = { sessionId: "selected", sessionKind, sessionState, daemonProcessId: 0 };
      const sessions = [other, session];
      assert.equal(selectTraceDrainSession(sessions, "selected", "live", new Set()), session);
      assert.equal(selectTraceDrainSession(sessions, "selected", "live", new Set(["selected"])), null);
      assert.equal(selectTraceDrainSession(sessions, "selected", "replay", new Set()), null);
      assert.equal(selectTraceDrainSession(sessions, "daemon", "live", new Set()), null);
      assert.equal(selectTraceDrainSession(sessions, "missing", "live", new Set()), null);
      assert.equal(selectTraceDrainSession(sessions, null, "live", new Set()), null);
    }
  }
});
