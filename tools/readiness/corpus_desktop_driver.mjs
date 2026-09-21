import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const request = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const output = path.dirname(process.argv[2]);
const report = { schemaVersion: 1, status: "failed", targetPid: request.targetPid, errors: [] };
const pending = new Map();
let sequence = 0;
const socket = new WebSocket(request.endpoint);

function requireValue(value, message)
{
  if (!value)
  {
    throw new Error(message);
  }
}

function call(method, params = {})
{
  return new Promise((resolve, reject) =>
  {
    const id = ++sequence;
    const timer = setTimeout(() =>
    {
      pending.delete(id);
      reject(new Error(`CDP command timed out: ${method}`));
    }, 5000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params }));
  });
}

socket.addEventListener("message", (event) =>
{
  const response = JSON.parse(event.data);
  if (response.method === "Runtime.exceptionThrown")
  {
    report.errors.push(response.params.exceptionDetails);
  }
  const operation = pending.get(response.id);
  if (operation)
  {
    clearTimeout(operation.timer);
    pending.delete(response.id);
    if (response.error)
    {
      operation.reject(new Error(JSON.stringify(response.error)));
    }
    else
    {
      operation.resolve(response.result);
    }
  }
});

async function evaluate(expression)
{
  const value = await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  requireValue(!value.exceptionDetails, `DOM observation failed: ${JSON.stringify(value.exceptionDetails)}`);
  return value.result.value;
}

async function waitFor(expression, label, timeout = 15000)
{
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline)
  {
    const value = await evaluate(`Boolean(${expression})`);
    if (value)
    {
      return value;
    }
    await delay(100);
  }
  throw new Error(`UI condition timed out: ${label}`);
}

async function click(expression)
{
  const point = await evaluate(`(() =>
  {
    const element = ${expression};
    if (!element || element.disabled)
    {
      return null;
    }
    element.scrollIntoView({ block: "center", inline: "center" });
    const bounds = element.getBoundingClientRect();
    const x = bounds.left + bounds.width / 2;
    const y = bounds.top + bounds.height / 2;
    return bounds.width > 0 && bounds.height > 0 && element.contains(document.elementFromPoint(x, y)) ? { x, y } : null;
  })()`);
  requireValue(point, "UI action target is absent, disabled or occluded.");
  await call("Input.dispatchMouseEvent", { type: "mouseMoved", ...point });
  await call("Input.dispatchMouseEvent", { type: "mousePressed", button: "left", clickCount: 1, ...point });
  await call("Input.dispatchMouseEvent", { type: "mouseReleased", button: "left", clickCount: 1, ...point });
}

function phase(name)
{
  fs.appendFileSync(path.join(output, "phase.txt"), `${name}\n`, "ascii");
}

function atomicJson(name, value)
{
  const temporary = path.join(output, `${name}.tmp`);
  fs.writeFileSync(temporary, JSON.stringify(value));
  fs.renameSync(temporary, path.join(output, name));
}

const button = selector => `document.querySelector(${JSON.stringify(selector)})`;

async function snapshot()
{
  return evaluate(`(() =>
  {
    const text = selector => document.querySelector(selector)?.innerText ?? "";
    return { status: text(".statusbar"), stats: text(".trace-stats"), output: text(".output-log"),
      sessionState: document.querySelector(".session-strip strong")?.textContent ?? null,
      captureDetail: document.querySelector("#capture-detail")?.value,
      stackFrames: document.querySelector("#stack-frames")?.value,
      controlsLocked: document.querySelector("#capture-detail")?.disabled,
      rows: [...document.querySelectorAll(".trace-virtual-row")].map(element =>
        [...element.querySelectorAll(":scope > span")].map(cell => cell.innerText)) };
  })()`);
}

async function selectOption(selector, values, value)
{
  requireValue(values.includes(value), "Invalid capture control request.");
  await click(button(selector));
  await call("Input.dispatchKeyEvent", { type: "keyDown", key: "Home", code: "Home", windowsVirtualKeyCode: 36 });
  await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Home", code: "Home", windowsVirtualKeyCode: 36 });
  for (let index = 0; index < values.indexOf(value); ++index)
  {
    await call("Input.dispatchKeyEvent", { type: "keyDown", key: "ArrowDown", code: "ArrowDown", windowsVirtualKeyCode: 40 });
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: "ArrowDown", code: "ArrowDown", windowsVirtualKeyCode: 40 });
  }
  await call("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await waitFor(`${button(selector)}?.value === ${JSON.stringify(value)}`, "selected capture control");
}

try
{
  await Promise.race([
    new Promise((resolve, reject) =>
    {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", () => reject(new Error("Owned WebView CDP connection failed.")), { once: true });
    }),
    delay(5000).then(() =>
    {
      throw new Error("CDP connection deadline exceeded.");
    })
  ]);
  await call("Runtime.enable");
  await waitFor('location.href === "http://tauri.localhost/" && document.querySelector(".statusbar")', "bundled desktop page");
  await click(`[...document.querySelectorAll(".inspector-tabs button")].find(element => element.textContent === "Output")`);
  await waitFor('location.href === "http://tauri.localhost/" && document.querySelector(".output-log")?.innerText.includes("native_enum_completed: list_native_target_processes;") && document.querySelector("#capture-detail")?.disabled === false && document.querySelector(\'button[title="Refresh process list"]\')?.disabled === false', "initial native enumeration and controls", 25000);
  report.idle = await snapshot();
  report.initialSessions = await evaluate('window.__TAURI_INTERNALS__.invoke("list_native_sessions")');
  phase("idle");
  await delay(1500);
  const anyTab = text => `[...document.querySelectorAll("button")].find(element => element.textContent === ${JSON.stringify(text)})`;
  await click(anyTab("API Library"));
  await click(`[...document.querySelectorAll(".api-scope-actions button")].find(element => element.textContent === "None")`);
  for (const [family, apis] of [["File Io", ["CreateFileW", "WriteFile", "ReadFile", "CloseHandle"]],
    ["Memory", ["VirtualAlloc", "VirtualFree"]]])
  {
    const familyRow = `[...document.querySelectorAll(".api-scope-tree .tree-row")].find(element => element.querySelector(":scope > span[title]")?.textContent === ${JSON.stringify(family)})`;
    if (await evaluate(`Boolean((${familyRow})?.querySelector('button[aria-label^="Expand "]'))`))
    {
      await click(`(${familyRow}).querySelector("button.tree-caret")`);
    }
    const moduleRow = `[...(${familyRow}).parentElement.querySelectorAll(".tree-row")].find(element => element.querySelector(":scope > span[title]")?.textContent === "kernel32.dll")`;
    if (await evaluate(`Boolean((${moduleRow})?.querySelector('button[aria-label^="Expand "]'))`))
    {
      await click(`(${moduleRow}).querySelector("button.tree-caret")`);
    }
    for (const api of apis)
    {
      await click(`(${moduleRow}).parentElement.querySelector(${JSON.stringify(`input[aria-label="Monitor ${api}"]`)})`);
    }
  }
  report.allowlist = await evaluate('[...document.querySelectorAll(".api-scope-tree .tree-row")].filter(row => row.querySelector("input")?.checked && !row.querySelector("button.tree-caret")).map(row => row.querySelector(":scope > span[title]").title).sort()');
  requireValue(JSON.stringify(report.allowlist) === JSON.stringify(request.allowlist), "Selected API allowlist differs.");
  await click(anyTab("Targets"));
  await selectOption("#capture-detail", ["metadata", "arguments", "preview"], request.captureDetail);
  await selectOption("#stack-frames", ["0", "8", "16", "32"], String(request.stackFrames));
  await click(button('button[title="Refresh process list"]'));
  const target = `[...document.querySelectorAll(".process-row")].find(element => element.querySelector(".process-meta span")?.textContent === ${JSON.stringify(String(request.targetPid))} && element.querySelector(".process-main small")?.textContent?.toLowerCase() === ${JSON.stringify(request.targetPath.toLowerCase())})`;
  await waitFor(target, "owned corpus target");
  await click(target);
  await waitFor('document.querySelector("#capture-detail")?.disabled === false && document.querySelector(\'button[title="Refresh process list"]\')?.disabled === false', "settled target selection");
  if (request.mode !== "original")
  {
    await waitFor('document.querySelector(\'button[title="Attach to the selected running process"]\')?.disabled === false', "attach enabled");
    phase("attach");
    await click(button('button[title="Attach to the selected running process"]'));
    await waitFor('document.querySelector(".session-strip strong")?.textContent === "running"', "authenticated capture readiness", 15000);
  }
  report.ready = await snapshot();
  report.readySessions = await evaluate('window.__TAURI_INTERNALS__.invoke("list_native_sessions")');
  phase("workload-ready");
  let answered = 0;
  const observationDeadline = Date.now() + 15000;
  while (Date.now() < observationDeadline)
  {
    const queryPath = path.join(output, `query-${String(answered + 1).padStart(6, "0")}.json`);
    if (fs.existsSync(queryPath))
    {
      const query = JSON.parse(fs.readFileSync(queryPath, "utf8"));
      if (query.sequence > answered)
      {
        requireValue(query.sequence === answered + 1, "UI observation request was reordered.");
        atomicJson(`reply-${String(query.sequence).padStart(6, "0")}.json`, { sequence: query.sequence, snapshot: await snapshot() });
        answered = query.sequence;
      }
    }
    if (fs.existsSync(path.join(output, "finish.json")))
    {
      const finish = JSON.parse(fs.readFileSync(path.join(output, "finish.json"), "utf8"));
      requireValue(finish.controlId === request.controlId && answered > 0, "Invalid workload completion control.");
      break;
    }
    await delay(10);
  }
  requireValue(fs.existsSync(path.join(output, "finish.json")), "Corpus or UI drain exceeded its observation deadline.");
  report.drained = await snapshot();
  if (request.mode !== "original")
  {
    phase("stop");
    await click(button('.primary-toolbar button[title="Stop native session"]'));
    await waitFor('!document.querySelector(".session-strip") && document.querySelector(\'button[title="Export JSONL"]\')?.disabled === false && document.querySelector(".statusbar")?.innerText.startsWith("State: idle\\n")', "terminal native drain", 15000);
    report.sessions = await evaluate('window.__TAURI_INTERNALS__.invoke("list_native_sessions")');
    await click(button("#quick-api-filter"));
    await call("Input.insertText", { text: "WriteFile" });
    await waitFor('[...document.querySelectorAll(".trace-virtual-row .api-cell")].length > 0 && [...document.querySelectorAll(".trace-virtual-row .api-cell")].every(element => element.textContent === "WriteFile")', "real corpus filter");
    report.filtered = await snapshot();
    const downloads = path.join(output, "downloads");
    fs.mkdirSync(downloads);
    await call("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: downloads });
    await click(button('button[title="Export JSONL"]'));
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline)
    {
      const names = fs.readdirSync(downloads);
      if (names.length === 1 && names[0].endsWith(".jsonl"))
      {
        report.exportFile = `downloads/${names[0]}`;
        break;
      }
      await delay(100);
    }
    requireValue(report.exportFile, "Desktop corpus export did not complete.");
  }
  report.terminal = await snapshot();
  const screenshot = await call("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(output, "terminal.png"), Buffer.from(screenshot.data, "base64"));
  requireValue(report.errors.length === 0, "Renderer exception during corpus capture.");
  report.status = "passed";
}
catch (error)
{
  report.failure = String(error.stack ?? error);
  process.exitCode = 1;
  try
  {
    report.failureSnapshot = await snapshot();
  }
  catch
  {
    // Preserve the initial failure if the renderer is gone.
  }
}
finally
{
  atomicJson("driver.json", report);
  phase("finished");
  socket.close();
  for (const operation of pending.values())
  {
    clearTimeout(operation.timer);
  }
}
