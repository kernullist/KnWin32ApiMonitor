import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const request = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const output = path.dirname(process.argv[2]);
const report = { schemaVersion: 1, status: "failed", targetPid: request.targetPid, observations: [], errors: [] };
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
  const value = await call("Runtime.evaluate", { expression, returnByValue: true });
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

async function observe(name)
{
  const value = await evaluate(`(() =>
  {
    const text = selector => document.querySelector(selector)?.innerText ?? "";
    return { url: location.href, readyState: document.readyState,
      status: text(".statusbar"), stats: text(".trace-stats"), session: text(".session-strip"),
      selectedTarget: text(".process-row.selected"), output: text(".output-log"),
      eligibility: text(".eligibility-badge"), helperArchitecture: text(".target-action-grid"),
      rows: [...document.querySelectorAll(".trace-virtual-row")].map(element =>
        [...element.querySelectorAll(":scope > span")].map(cell => cell.innerText)),
      filter: document.querySelector("#quick-api-filter")?.value ?? "" };
  })()`);
  report.observations.push({ phase: name, observedAtUtc: new Date().toISOString(), ...value });
  return value;
}

const button = (selector) => `document.querySelector(${JSON.stringify(selector)})`;
try
{
  await Promise.race([
    new Promise((resolve, reject) =>
    {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", () => reject(new Error("Owned WebView CDP connection failed.")), { once: true });
    }),
    delay(5000).then(() => { throw new Error("CDP connection deadline exceeded."); })
  ]);
  await call("Runtime.enable");
  await waitFor(`location.href === "http://tauri.localhost/" && document.querySelector(".statusbar")`, "bundled desktop page");
  await observe("idle");
  phase("idle");
  await delay(3000);
  await click(button('button[title="Refresh process list"]'));
  const target = `[...document.querySelectorAll(".process-row")].find(element =>
    element.querySelector(".process-meta span")?.textContent === ${JSON.stringify(String(request.targetPid))} &&
    element.querySelector(".process-main small")?.textContent?.toLowerCase() === ${JSON.stringify(request.targetPath.toLowerCase())})`;
  await waitFor(target, "owned target row");
  await click(target);
  const attach = 'button[title="Attach to the selected running process"]';
  await waitFor(`document.querySelector(${JSON.stringify(attach)})?.disabled === false`, "attach enabled");
  await observe("selected");
  phase("attach");
  await click(button(attach));
  await waitFor('document.querySelector(".session-strip strong")?.textContent === "running"', "active native session", 25000);
  phase("capture");
  await waitFor('document.querySelectorAll(".trace-virtual-row").length > 0', "native trace rows");
  await delay(6000);
  await observe("capture");
  await click(button("#quick-api-filter"));
  await call("Input.insertText", { text: "WriteFile" });
  await waitFor('document.querySelector("#quick-api-filter")?.value === "WriteFile" && [...document.querySelectorAll(".trace-virtual-row .api-cell")].length > 0 && [...document.querySelectorAll(".trace-virtual-row .api-cell")].every(element => element.textContent === "WriteFile")', "real event filter");
  await observe("filtered");
  const screenshot = await call("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(output, "capture.png"), Buffer.from(screenshot.data, "base64"));
  phase("stop");
  await click(button('.primary-toolbar button[title="Stop native session"]'));
  await waitFor(`!document.querySelector(".session-strip") && ${button('.primary-toolbar button[title="Stop native session"]')}?.disabled === true &&
    ${button('button[title="Export JSONL"]')}?.disabled === false && document.querySelector(".statusbar")?.innerText.startsWith("State: idle\\n")`, "native stop and terminal trace drain completed", 20000);
  await observe("stopped");
  phase("settled");
  await delay(2000);
  await observe("settled");
  const downloadPath = path.join(output, "downloads");
  fs.mkdirSync(downloadPath);
  await call("Browser.setDownloadBehavior", { behavior: "allow", downloadPath });
  await click(button('button[title="Export JSONL"]'));
  const downloadDeadline = Date.now() + 10000;
  while (Date.now() < downloadDeadline)
  {
    const files = fs.readdirSync(downloadPath);
    if (files.length === 1 && files[0].endsWith(".jsonl"))
    {
      report.exportFile = path.join("downloads", files[0]);
      break;
    }
    await delay(100);
  }
  requireValue(report.exportFile, "UI JSONL export did not complete.");
  requireValue(report.errors.length === 0, "Renderer raised an unhandled exception.");
  report.status = "passed";
}
catch (error)
{
  report.failure = String(error.stack ?? error);
  try
  {
    await observe("failure");
  }
  catch
  {
    // The renderer may already have exited; retain the original failure.
  }
  process.exitCode = 1;
}
finally
{
  phase("finished");
  fs.writeFileSync(path.join(output, "driver.json"), JSON.stringify(report, null, 2));
  socket.close();
  for (const operation of pending.values())
  {
    clearTimeout(operation.timer);
  }
}
