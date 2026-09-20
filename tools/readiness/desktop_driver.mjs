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
    const stack = document.querySelector(".stack-list");
    const decode = [...document.querySelectorAll(".highlight-rule-card")].find(element => element.querySelector("strong")?.textContent === "Decode failure");
    const setting = selector =>
    {
      const select = document.querySelector(selector);
      if (!select)
      {
        return null;
      }
      const style = getComputedStyle(select);
      const label = select.selectedOptions[0]?.label ?? "";
      const measure = document.createElement("canvas").getContext("2d");
      measure.font = style.font;
      return { value: select.value, disabled: select.disabled, label, clientWidth: select.clientWidth,
        textWidth: measure.measureText(label).width,
        inlinePadding: Number.parseFloat(style.paddingLeft) + Number.parseFloat(style.paddingRight) };
    };
    return { url: location.href, readyState: document.readyState,
      status: text(".statusbar"), stats: text(".trace-stats"), session: text(".session-strip"),
      selectedTarget: text(".process-row.selected"), output: text(".output-log"),
      eligibility: text(".eligibility-badge"), helperArchitecture: text(".target-action-grid"),
      refreshEnabled: document.querySelector('button[title="Refresh process list"]')?.disabled === false,
      stackSetting: setting("#stack-frames"),
      detailSetting: setting("#capture-detail"),
      decodeFailureCount: decode?.querySelector("em")?.textContent ?? null,
      stack: stack ? { source: stack.dataset.stackSource, eventId: stack.dataset.stackEventId,
        message: text(".stack-status"), context: [...stack.querySelectorAll(".stack-hook-context code")].map(element => element.textContent),
        entries: stack.querySelectorAll(".stack-row").length,
        addresses: [...stack.querySelectorAll(".stack-row code")].map(element => element.textContent) } : null,
      rows: [...document.querySelectorAll(".trace-virtual-row")].map(element =>
        [...element.querySelectorAll(":scope > span")].map(cell => cell.innerText)),
      filter: document.querySelector("#quick-api-filter")?.value ?? "" };
  })()`);
  report.observations.push({ phase: name, observedAtUtc: new Date().toISOString(), ...value });
  return value;
}

const button = (selector) => `document.querySelector(${JSON.stringify(selector)})`;

async function openStackInspector()
{
  await click(`[...document.querySelectorAll(".inspector-tabs button")].find(element => element.textContent === "Call Stack")`);
  await waitFor('document.querySelector(".stack-list")', "stack observation inspector");
}

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
  await waitFor('document.querySelector("#capture-detail")?.disabled === false && document.querySelector("#stack-frames")?.disabled === false && document.querySelector(\'button[title="Refresh process list"]\')?.disabled === false', "initial native controls ready", 25000);
  await observe("idle");
  phase("idle");
  await delay(3000);
  const refresh = 'button[title="Refresh process list"]';
  await waitFor(`${button(refresh)}?.disabled === false`, "native target refresh enabled");
  await click(button(refresh));
  const target = `[...document.querySelectorAll(".process-row")].find(element =>
    element.querySelector(".process-meta span")?.textContent === ${JSON.stringify(String(request.targetPid))} &&
    element.querySelector(".process-main small")?.textContent?.toLowerCase() === ${JSON.stringify(request.targetPath.toLowerCase())})`;
  await waitFor(target, "owned target row");
  await click(target);
  const attach = 'button[title="Attach to the selected running process"]';
  await waitFor(`document.querySelector(${JSON.stringify(attach)})?.disabled === false`, "attach enabled");
  requireValue(["metadata", "arguments", "preview"].includes(request.captureDetail), "Unsupported capture detail request.");
  await waitFor('document.querySelector("#capture-detail")?.value === "preview" && document.querySelector("#capture-detail")?.disabled === false', "preview capture by default");
  if (request.captureDetail !== "preview")
  {
    await click(button("#capture-detail"));
    for (let index = 0; index < 2 - ["metadata", "arguments", "preview"].indexOf(request.captureDetail); ++index)
    {
      await call("Input.dispatchKeyEvent", { type: "keyDown", key: "ArrowUp", code: "ArrowUp", windowsVirtualKeyCode: 38 });
      await call("Input.dispatchKeyEvent", { type: "keyUp", key: "ArrowUp", code: "ArrowUp", windowsVirtualKeyCode: 38 });
    }
    await call("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await waitFor(`document.querySelector("#capture-detail")?.value === ${JSON.stringify(request.captureDetail)}`, "requested capture detail");
  }
  requireValue([0, 8, 16, 32].includes(request.stackFrames), "Unsupported stack frame request.");
  await waitFor('document.querySelector("#stack-frames")?.value === "0" && document.querySelector("#stack-frames")?.disabled === false', "stack capture disabled by default");
  if (request.stackFrames !== 0)
  {
    await click(button("#stack-frames"));
    for (let index = 0; index < [0, 8, 16, 32].indexOf(request.stackFrames); ++index)
    {
      await call("Input.dispatchKeyEvent", { type: "keyDown", key: "ArrowDown", code: "ArrowDown", windowsVirtualKeyCode: 40 });
      await call("Input.dispatchKeyEvent", { type: "keyUp", key: "ArrowDown", code: "ArrowDown", windowsVirtualKeyCode: 40 });
    }
    await call("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await call("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
    await waitFor(`document.querySelector("#stack-frames")?.value === ${JSON.stringify(String(request.stackFrames))}`, "requested stack frame limit");
  }
  await observe("selected");
  phase("attach");
  await click(button(attach));
  await waitFor('document.querySelector(".session-strip strong")?.textContent === "running"', "active native session", 25000);
  phase("capture");
  await waitFor('document.querySelectorAll(".trace-virtual-row").length > 0', "native trace rows");
  await delay(6000);
  await click(`[...document.querySelectorAll(".inspector-tabs button")].find(element => element.textContent === "Parameters")`);
  await waitFor('document.querySelector(".detail-table caption")', "capture detail inspector");
  report.detailInspector = await evaluate(`(() =>
  {
    const caption = document.querySelector(".detail-table caption");
    return { detail: caption.dataset.captureDetail, eventId: caption.dataset.captureEventId, message: caption.innerText,
      argumentRows: document.querySelectorAll(".detail-table tbody tr").length };
  })()`);
  const detailScreenshot = await call("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(output, "detail.png"), Buffer.from(detailScreenshot.data, "base64"));
  await openStackInspector();
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
  report.stopOutput = await evaluate('document.querySelector(".output-log")?.innerText ?? ""');
  await openStackInspector();
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
