import {
  Activity,
  Braces,
  ChevronRight,
  CircleDot,
  Cpu,
  Database,
  Download,
  FileText,
  Filter,
  FolderOpen,
  GitBranch,
  HardDrive,
  Layers,
  Play,
  RefreshCcw,
  Rocket,
  Search,
  Server,
  Square,
  Trash2
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  captureSampleFileIoEvents,
  launchSampleEarlyBirdCapture,
  listNativeTargetProcesses,
  listTargetProcesses,
  startBackendSession,
  stopBackendSession
} from "./backend";
import { apiTree, captureProfiles, createMockFileIoEvent, initialTraceEvents } from "./mockData";
import { downloadJsonl, estimateSessionBytes } from "./session";
import type { AgentApiCallEvent, ApiNode, AuditEvent, BackendMode, CaptureResult, InspectorTab, LaunchResult, TargetProcess, TraceEvent } from "./types";

type LeftTab = "targets" | "apis" | "profiles";
type TraceMode = "flat" | "call-tree";
type TargetSource = "mock" | "native";

const inspectorTabs: Array<{ id: InspectorTab; label: string }> = [
  { id: "parameters", label: "Parameters" },
  { id: "buffer", label: "Buffer" },
  { id: "stack", label: "Call Stack" },
  { id: "return", label: "Return/Error" },
  { id: "output", label: "Output" }
];

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }

  return `${(value / 1024 / 1024).toFixed(2)} MB`;
}

function renderApiTree(nodes: ApiNode[], depth = 0): JSX.Element {
  return (
    <div className="tree-group">
      {nodes.map((node) => (
        <div key={node.id}>
          <div className="tree-row" style={{ paddingLeft: 8 + depth * 16 }}>
            {node.children ? <ChevronRight size={13} className="tree-caret" /> : <span className="tree-leaf" />}
            <input type="checkbox" checked={node.checked} readOnly />
            <FileText size={14} className={node.checked ? "tree-icon enabled" : "tree-icon"} />
            <span>{node.label}</span>
          </div>
          {node.children ? renderApiTree(node.children, depth + 1) : null}
        </div>
      ))}
    </div>
  );
}

function compactArgs(event: TraceEvent): string {
  return event.arguments
    .slice(0, 3)
    .map((argument) => `${argument.name}=${argument.decodedValue}`)
    .join(", ");
}

function makeAuditEvent(eventType: string, operation: string, message: string, win32ErrorCode = 0): AuditEvent {
  return {
    schemaVersion: "0.1.0",
    operationId: "ui",
    eventType,
    timestampUtc: new Date().toISOString(),
    subsystem: "ui",
    operation,
    win32ErrorCode,
    ntStatus: "0x00000000",
    message
  };
}

function createAgentLoadedEvent(result: LaunchResult, eventId: number): TraceEvent {
  return {
    schemaVersion: result.schemaVersion,
    eventId,
    relativeTimeMs: eventId * 137,
    pid: result.targetProcessId,
    tid: result.targetThreadId,
    process: "knmon-sample-fileio.exe",
    module: "knmon-agent64.dll",
    api: result.handshake.received ? "agent_loaded" : "capture_backend_status",
    arguments: [
      {
        index: 0,
        type: "LPCWSTR",
        name: "AgentPath",
        direction: "in",
        preCallValue: result.agentPath,
        postCallValue: result.agentPath,
        rawValue: result.agentPath,
        decodedValue: result.agentPath,
        decodeStatus: "decoded"
      },
      {
        index: 1,
        type: "LPCWSTR",
        name: "InjectionMethod",
        direction: "in",
        preCallValue: result.injectionMethod,
        postCallValue: result.injectionMethod,
        rawValue: result.injectionMethod,
        decodedValue: result.injectionMethod,
        decodeStatus: "decoded"
      },
      {
        index: 2,
        type: "BOOL",
        name: "HandshakeReceived",
        direction: "out",
        preCallValue: "FALSE",
        postCallValue: result.handshake.received ? "TRUE" : "FALSE",
        rawValue: result.handshake.received ? "1" : "0",
        decodedValue: result.handshake.message,
        decodeStatus: "decoded"
      }
    ],
    returnValue: result.success ? "TRUE" : "FALSE",
    error: result.success
      ? null
      : {
          kind: "win32",
          code: `0x${result.win32ErrorCode.toString(16).padStart(8, "0")}`,
          message: result.message
        },
    durationUs: 0,
    tags: ["native-capture", "early-bird", result.handshake.received ? "agent-hello" : "status"],
    stack: [
      "knmon-native-helper.exe!LaunchWithEarlyBirdApc",
      "kernel32.dll!QueueUserAPC",
      "kernel32.dll!ResumeThread"
    ],
    bufferPreview: result.handshake.rawPayload
  };
}

function createTraceEventFromAgentApiCall(event: AgentApiCallEvent, eventId: number): TraceEvent {
  return {
    schemaVersion: event.schemaVersion,
    eventId,
    relativeTimeMs: event.sequence * 10,
    pid: event.pid,
    tid: event.tid,
    process: event.process,
    module: event.module,
    api: event.api,
    arguments: event.arguments,
    returnValue: event.returnValue,
    error: event.lastErrorCode === 0
      ? null
      : {
          kind: "win32",
          code: `0x${event.lastErrorCode.toString(16).padStart(8, "0")}`,
          message: event.lastErrorMessage
        },
    durationUs: event.durationUs,
    tags: event.tags,
    stack: event.stack,
    bufferPreview: event.bufferPreview || undefined
  };
}

function App() {
  const [leftTab, setLeftTab] = useState<LeftTab>("targets");
  const [targetSource, setTargetSource] = useState<TargetSource>("mock");
  const [targets, setTargets] = useState<TargetProcess[]>([]);
  const [backendMode, setBackendMode] = useState<BackendMode>("mock");
  const [events, setEvents] = useState<TraceEvent[]>(initialTraceEvents);
  const [selectedEventId, setSelectedEventId] = useState<number>(initialTraceEvents[0]?.eventId ?? 0);
  const [filter, setFilter] = useState("");
  const [running, setRunning] = useState(false);
  const [droppedCount, setDroppedCount] = useState(0);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("parameters");
  const [traceMode, setTraceMode] = useState<TraceMode>("flat");
  const [nativeBusy, setNativeBusy] = useState(false);
  const [launchResult, setLaunchResult] = useState<LaunchResult | null>(null);
  const [captureResult, setCaptureResult] = useState<CaptureResult | null>(null);
  const [outputEvents, setOutputEvents] = useState<AuditEvent[]>([
    makeAuditEvent("backend_ready", "mock_init", "Mock File I/O backend initialized.")
  ]);
  const nextEventId = useRef(initialTraceEvents.length + 1);

  useEffect(() => {
    let active = true;

    listTargetProcesses().then((result) => {
      if (active) {
        setTargets(result.targets);
        setBackendMode(result.mode);
      }
    });

    return () => {
      active = false;
    };
  }, []);

  function appendOutput(eventsToAppend: AuditEvent[]) {
    setOutputEvents((current) => [...eventsToAppend, ...current].slice(0, 80));
  }

  async function handleLoadMockTargets() {
    setTargetSource("mock");
    const result = await listTargetProcesses();
    setTargets(result.targets);
    setBackendMode(result.mode);
    appendOutput([makeAuditEvent("target_source_changed", "load_mock_targets", "Loaded mock target rows.")]);
  }

  async function handleLoadNativeTargets() {
    setNativeBusy(true);
    setTargetSource("native");

    try {
      const result = await listNativeTargetProcesses();
      setTargets(result.targets);
      setBackendMode(result.mode);
      appendOutput([makeAuditEvent("native_enum_completed", "list_native_target_processes", `Loaded ${result.targets.length} native target rows.`)]);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setBackendMode("mock");
      appendOutput([makeAuditEvent("native_enum_blocked", "list_native_target_processes", message)]);
    } finally {
      setNativeBusy(false);
    }
  }

  useEffect(() => {
    if (!running) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      const next = createMockFileIoEvent(nextEventId.current);
      nextEventId.current += 1;
      setEvents((current) => [...current, next].slice(-400));
      setSelectedEventId(next.eventId);
    }, 900);

    return () => {
      window.clearInterval(timer);
    };
  }, [running]);

  const filteredEvents = useMemo(() => {
    const normalized = filter.trim().toLowerCase();

    if (!normalized) {
      return events;
    }

    return events.filter((event) => {
      const haystack = [
        event.api,
        event.module,
        event.process,
        event.returnValue,
        event.error?.message ?? "",
        event.tags.join(" "),
        compactArgs(event)
      ].join(" ").toLowerCase();

      return haystack.includes(normalized);
    });
  }, [events, filter]);

  const selectedEvent = events.find((event) => event.eventId === selectedEventId) ?? filteredEvents[0] ?? events[0];
  const sessionBytes = estimateSessionBytes(events);

  async function handleStartCapture() {
    await startBackendSession();
    setRunning(true);
  }

  async function handleStopCapture() {
    await stopBackendSession();
    setRunning(false);
  }

  function handleClear() {
    setRunning(false);
    setEvents([]);
    setSelectedEventId(0);
    nextEventId.current = 1;
  }

  async function handleLaunchSample() {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("launch_requested", "launch_sample_early_bird_capture", "Controlled sample launch requested from UI.")]);
      const result = await launchSampleEarlyBirdCapture();
      setLaunchResult(result);
      setBackendMode(result.success ? "native-capture" : "native-enum");
      appendOutput(result.auditEvents.length > 0 ? result.auditEvents : [makeAuditEvent("launch_result", result.operation, result.message, result.win32ErrorCode)]);

      const traceEvent = createAgentLoadedEvent(result, nextEventId.current);
      nextEventId.current += 1;
      setEvents((current) => [...current, traceEvent]);
      setSelectedEventId(traceEvent.eventId);
      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("launch_blocked", "launch_sample_early_bird_capture", message)]);
    } finally {
      setNativeBusy(false);
    }
  }

  async function handleCaptureSampleFileIo() {
    setNativeBusy(true);

    try {
      appendOutput([makeAuditEvent("capture_requested", "capture_sample_fileio_events", "Controlled native File I/O capture requested from UI.")]);
      const result = await captureSampleFileIoEvents();
      setCaptureResult(result);
      setBackendMode(result.success ? "native-capture" : "native-enum");
      setDroppedCount(result.droppedEvents);
      appendOutput(result.auditEvents.length > 0 ? result.auditEvents : [makeAuditEvent("capture_result", result.operation, result.message, result.win32ErrorCode)]);

      if (result.capturedEvents.length > 0) {
        const traceEvents = result.capturedEvents.map((event, index) => createTraceEventFromAgentApiCall(event, nextEventId.current + index));
        nextEventId.current += traceEvents.length;
        setEvents((current) => [...current, ...traceEvents].slice(-400));
        setSelectedEventId(traceEvents[traceEvents.length - 1].eventId);
      }

      setInspectorTab("output");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      appendOutput([makeAuditEvent("capture_blocked", "capture_sample_fileio_events", message)]);
    } finally {
      setNativeBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <CircleDot size={16} />
          <span>KN Win32 API Monitor</span>
        </div>
        <div className="toolbar" aria-label="Capture toolbar">
          <button className="tool-button" type="button" title="Open session">
            <FolderOpen size={15} />
          </button>
          <button className="tool-button" type="button" title="Export JSONL" onClick={() => downloadJsonl(events)}>
            <Download size={15} />
          </button>
          <span className="toolbar-separator" />
          <button className="tool-button primary" type="button" title="Start capture" onClick={handleStartCapture} disabled={running}>
            <Play size={15} />
            <span>Start</span>
          </button>
          <button className="tool-button" type="button" title="Stop capture" onClick={handleStopCapture} disabled={!running}>
            <Square size={14} />
            <span>Stop</span>
          </button>
          <button className="tool-button danger" type="button" title="Clear session" onClick={handleClear}>
            <Trash2 size={15} />
          </button>
        </div>
        <div className="topbar-status">
          <span className={running ? "pulse running" : "pulse"} />
          <span>{running ? "capturing" : "stopped"}</span>
        </div>
      </header>

      <main className="workspace">
        <aside className="left-rail">
          <div className="segmented">
            <button type="button" className={leftTab === "targets" ? "active" : ""} onClick={() => setLeftTab("targets")}>Targets</button>
            <button type="button" className={leftTab === "apis" ? "active" : ""} onClick={() => setLeftTab("apis")}>API Library</button>
            <button type="button" className={leftTab === "profiles" ? "active" : ""} onClick={() => setLeftTab("profiles")}>Profiles</button>
          </div>

          {leftTab === "targets" ? (
            <section className="rail-section">
              <div className="source-panel">
                <div className="source-title">
                  <Cpu size={14} />
                  <span>Target Source</span>
                </div>
                <div className="source-toggle">
                  <button type="button" className={targetSource === "mock" ? "active" : ""} onClick={handleLoadMockTargets} disabled={nativeBusy}>
                    Mock
                  </button>
                  <button type="button" className={targetSource === "native" ? "active" : ""} onClick={handleLoadNativeTargets} disabled={nativeBusy}>
                    Native
                  </button>
                  <button type="button" title="Refresh current target source" onClick={targetSource === "native" ? handleLoadNativeTargets : handleLoadMockTargets} disabled={nativeBusy}>
                    <RefreshCcw size={13} />
                  </button>
                </div>
              </div>
              <div className="section-title">
                <Server size={14} />
                <span>Running Processes</span>
              </div>
              <div className="process-list">
                {targets.map((target) => (
                  <button
                    type="button"
                    className={`process-row ${target.status === "unsupported" ? "muted" : ""}`}
                    key={`${target.pid}-${target.imageName}`}
                  >
                    <span className="process-icon">{target.imageName.slice(0, 1).toUpperCase()}</span>
                    <span className="process-main">
                      <strong>{target.imageName}</strong>
                      <small>{target.imagePath ?? "path unavailable"}</small>
                    </span>
                    <span className="process-meta">
                      <span>{target.pid}</span>
                      <span>{target.architecture}</span>
                    </span>
                  </button>
                ))}
              </div>
              <div className="controlled-launch">
                <div className="section-title">
                  <Rocket size={14} />
                  <span>Controlled Launch</span>
                </div>
                <div className="launch-grid">
                  <label>Sample target</label>
                  <span>knmon-sample-fileio.exe</span>
                  <label>Agent</label>
                  <span>knmon-agent64.dll</span>
                  <label>Architecture</label>
                  <span>x64 exact match</span>
                  <label>Injection</label>
                  <span>early-bird APC</span>
                  <label>Handshake</label>
                  <span>{captureResult ? (captureResult.handshake.received ? "HELLO received" : "not received") : launchResult ? (launchResult.handshake.received ? "HELLO received" : "not received") : "not launched"}</span>
                  <label>Captured rows</label>
                  <span>{captureResult ? captureResult.capturedEvents.length : 0}</span>
                  <label>Dropped</label>
                  <span>{captureResult ? captureResult.droppedEvents : droppedCount}</span>
                </div>
                <div className="launch-actions">
                  <button type="button" className="tool-button primary" onClick={handleLaunchSample} disabled={nativeBusy}>
                    <Play size={14} />
                    <span>Launch Sample</span>
                  </button>
                  <button type="button" className="tool-button primary" onClick={handleCaptureSampleFileIo} disabled={nativeBusy}>
                    <Activity size={14} />
                    <span>Capture File I/O</span>
                  </button>
                  <button type="button" className="tool-button" disabled title="Bounded sample capture owns target lifetime for this milestone; persistent terminate control is not implemented yet.">
                    <Square size={13} />
                    <span>Terminate</span>
                  </button>
                </div>
                {launchResult ? (
                  <div className={launchResult.success ? "launch-result success" : "launch-result failure"}>
                    PID {launchResult.targetProcessId} / {launchResult.injectionMethod} / {launchResult.message}
                  </div>
                ) : null}
                {captureResult ? (
                  <div className={captureResult.success ? "launch-result success" : "launch-result failure"}>
                    PID {captureResult.targetProcessId} / {captureResult.captureMode} / events={captureResult.capturedEvents.length} / {captureResult.message}
                  </div>
                ) : null}
              </div>
            </section>
          ) : null}

          {leftTab === "apis" ? (
            <section className="rail-section">
              <div className="section-title">
                <Layers size={14} />
                <span>Capture Filter</span>
              </div>
              {renderApiTree(apiTree)}
            </section>
          ) : null}

          {leftTab === "profiles" ? (
            <section className="rail-section">
              <div className="section-title">
                <Database size={14} />
                <span>Capture Profiles</span>
              </div>
              <div className="profile-list">
                {captureProfiles.map((profile) => (
                  <button type="button" className="profile-row" key={profile.id}>
                    <strong>{profile.name}</strong>
                    <span>{profile.description}</span>
                    <small>{profile.enabledApis.length} APIs enabled</small>
                  </button>
                ))}
              </div>
            </section>
          ) : null}
        </aside>

        <section className="main-panel">
          <div className="trace-control">
            <div className="filter-box">
              <Search size={14} />
              <input
                type="search"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                placeholder="Display filter: api/module/path/error/tag"
              />
            </div>
            <div className="mode-toggle">
              <button type="button" className={traceMode === "flat" ? "active" : ""} onClick={() => setTraceMode("flat")}>
                <Activity size={14} />
                <span>Flat</span>
              </button>
              <button type="button" className={traceMode === "call-tree" ? "active" : ""} onClick={() => setTraceMode("call-tree")}>
                <GitBranch size={14} />
                <span>Call Tree</span>
              </button>
            </div>
          </div>

          <div className="trace-table-wrap">
            <table className="trace-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Time</th>
                  <th>PID</th>
                  <th>TID</th>
                  <th>Module</th>
                  <th>API</th>
                  <th>Arguments</th>
                  <th>Return</th>
                  <th>Error</th>
                  <th>Duration</th>
                  <th>Tags</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((event) => (
                  <tr
                    key={event.eventId}
                    className={selectedEvent?.eventId === event.eventId ? "selected" : ""}
                    onClick={() => setSelectedEventId(event.eventId)}
                  >
                    <td>{event.eventId}</td>
                    <td>{(event.relativeTimeMs / 1000).toFixed(3)}s</td>
                    <td>{event.pid}</td>
                    <td>{event.tid}</td>
                    <td>{event.module}</td>
                    <td className="api-cell">{event.api}</td>
                    <td className="args-cell">{compactArgs(event)}</td>
                    <td>{event.returnValue}</td>
                    <td className={event.error ? "error-cell" : ""}>{event.error ? `${event.error.code} = ${event.error.message}` : ""}</td>
                    <td>{event.durationUs} us</td>
                    <td>
                      <div className="tag-list">
                        {event.tags.map((tag) => (
                          <span key={tag}>{tag}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="inspector">
            <div className="inspector-tabs">
              {inspectorTabs.map((tab) => (
                <button
                  type="button"
                  key={tab.id}
                  className={inspectorTab === tab.id ? "active" : ""}
                  onClick={() => setInspectorTab(tab.id)}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="inspector-body">
              {selectedEvent ? (
                <>
                  {inspectorTab === "parameters" ? (
                    <table className="detail-table">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Type</th>
                          <th>Name</th>
                          <th>Pre-call</th>
                          <th>Post-call</th>
                          <th>Decoded</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedEvent.arguments.map((argument) => (
                          <tr key={`${selectedEvent.eventId}-${argument.index}`}>
                            <td>{argument.index}</td>
                            <td>{argument.type}</td>
                            <td>{argument.name}</td>
                            <td>{argument.preCallValue}</td>
                            <td>{argument.postCallValue}</td>
                            <td>{argument.decodedValue}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : null}

                  {inspectorTab === "buffer" ? (
                    <div className="buffer-view">
                      <div className="buffer-toolbar">
                        <HardDrive size={14} />
                        <span>{selectedEvent.bufferPreview ? "Hex Buffer 16 bytes" : "No buffer snapshot for this call"}</span>
                      </div>
                      <pre>{selectedEvent.bufferPreview ?? "buffer snapshot unavailable"}</pre>
                    </div>
                  ) : null}

                  {inspectorTab === "stack" ? (
                    <div className="stack-list">
                      {selectedEvent.stack.map((frame, index) => (
                        <div className="stack-row" key={frame}>
                          <span>{index}</span>
                          <code>{frame}</code>
                        </div>
                      ))}
                    </div>
                  ) : null}

                  {inspectorTab === "return" ? (
                    <div className="return-grid">
                      <label>Return Value</label>
                      <code>{selectedEvent.returnValue}</code>
                      <label>Error Source</label>
                      <code>{selectedEvent.error?.kind ?? "none"}</code>
                      <label>Error Code</label>
                      <code>{selectedEvent.error?.code ?? "0"}</code>
                      <label>Message</label>
                      <code>{selectedEvent.error?.message ?? "success"}</code>
                    </div>
                  ) : null}

                  {inspectorTab === "output" ? (
                    <div className="output-log">
                      <div><Braces size={14} /> schemaVersion={selectedEvent.schemaVersion}</div>
                      <div><Filter size={14} /> backend={backendMode}; filter="{filter || "*"}"; mode={traceMode}</div>
                      <div><Database size={14} /> sessionBytes={formatBytes(sessionBytes)}; droppedEvents={droppedCount}</div>
                      {outputEvents.map((event) => (
                        <div key={`${event.timestampUtc}-${event.eventType}-${event.message}`}>
                          <Activity size={14} />
                          {event.eventType}: {event.operation}; win32={event.win32ErrorCode}; {event.message}
                        </div>
                      ))}
                    </div>
                  ) : null}
                </>
              ) : (
                <div className="empty-state">No event selected.</div>
              )}
            </div>
          </div>
        </section>
      </main>

      <footer className="statusbar">
        <span>State: {running ? "running" : "stopped"}</span>
        <span>Events: {events.length}</span>
        <span>Dropped: {droppedCount}</span>
        <span>Session: {formatBytes(sessionBytes)}</span>
        <span>Backend: {backendMode}</span>
        <span>Protocol: 0.1.0</span>
      </footer>
    </div>
  );
}

export default App;
