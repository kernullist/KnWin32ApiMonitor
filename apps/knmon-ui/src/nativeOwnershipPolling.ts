import type { NativeOperation, NativeSession } from "./types";

export interface PollClock
{
  schedule: (callback: () => void, delayMs: number) => number;
  cancel: (timer: number) => void;
}

interface OwnershipReads
{
  operations: () => Promise<NativeOperation[]>;
  sessions: () => Promise<NativeSession[]>;
  daemons: () => Promise<NativeSession[]>;
  onLocal: (operations: NativeOperation[], sessions: NativeSession[]) => void;
  onDaemons: (sessions: NativeSession[]) => void;
  onError: (source: "local" | "daemon", error: unknown) => void;
}

const browserClock: PollClock =
{
  schedule: (callback, delayMs) => window.setTimeout(callback, delayMs),
  cancel: (timer) => window.clearTimeout(timer)
};

function serialPoll<T>(read: () => Promise<T>, publish: (value: T) => void,
  onError: (error: unknown) => void, clock: PollClock)
{
  let delay: number | undefined;
  let timer: number | undefined;
  let inFlight = false;
  let disposed = false;
  let revision = 0;
  let refreshPending = false;

  function clearTimer()
  {
    if (timer !== undefined)
    {
      clock.cancel(timer);
      timer = undefined;
    }
  }

  function schedule(wait: number)
  {
    clearTimer();
    if (!disposed && delay !== undefined && !inFlight)
    {
      timer = clock.schedule(() => void run(), wait);
    }
  }

  async function run()
  {
    clearTimer();
    if (disposed || delay === undefined || inFlight)
    {
      return;
    }
    inFlight = true;
    refreshPending = false;
    const issuedRevision = revision;
    try
    {
      const value = await read();
      if (!disposed && delay !== undefined && issuedRevision === revision)
      {
        publish(value);
      }
    }
    catch (error)
    {
      if (!disposed && delay !== undefined && issuedRevision === revision)
      {
        onError(error);
      }
    }
    finally
    {
      inFlight = false;
      if (delay !== undefined)
      {
        schedule(refreshPending ? 0 : delay);
      }
    }
  }

  function refresh()
  {
    revision += 1;
    refreshPending = true;
    schedule(0);
  }

  return {
    setDelay(next: number | undefined)
    {
      if (!disposed && next !== delay)
      {
        delay = next;
        refresh();
      }
    },
    refresh,
    dispose()
    {
      disposed = true;
      revision += 1;
      clearTimer();
    }
  };
}

export function createNativeOwnershipPolling(reads: OwnershipReads, clock = browserClock)
{
  const local = serialPoll(async () =>
  {
    // Wait for both reads even on failure; an outstanding read keeps its slot.
    const [operations, sessions] = await Promise.allSettled([
      Promise.resolve().then(reads.operations), Promise.resolve().then(reads.sessions)
    ]);
    if (operations.status === "rejected")
    {
      throw operations.reason;
    }
    if (sessions.status === "rejected")
    {
      throw sessions.reason;
    }
    return { operations: operations.value, sessions: sessions.value };
  }, (value) => reads.onLocal(value.operations, value.sessions), (error) => reads.onError("local", error), clock);
  const daemon = serialPoll(reads.daemons, reads.onDaemons, (error) => reads.onError("daemon", error), clock);

  return {
    setActivity(localActive: boolean, daemonActive: boolean)
    {
      local.setDelay(localActive ? 500 : undefined);
      daemon.setDelay(daemonActive ? 500 : 5000);
    },
    refreshLocal: local.refresh,
    refreshDaemons: daemon.refresh,
    dispose()
    {
      local.dispose();
      daemon.dispose();
    }
  };
}

export type NativeOwnershipPolling = ReturnType<typeof createNativeOwnershipPolling>;

export function isDaemonSession(session: NativeSession): boolean
{
  return session.sessionKind.startsWith("daemon_") || session.daemonProcessId > 0;
}

export function selectTraceDrainSession(sessions: NativeSession[], sessionId: string | null,
  viewMode: "live" | "replay", completed: ReadonlySet<string>): NativeSession | null
{
  return viewMode === "live" && sessionId !== null && !completed.has(sessionId)
    ? sessions.find((session) => session.sessionId === sessionId && !isDaemonSession(session)) ?? null : null;
}

export function retainUnchangedSnapshot<T extends NativeSession | NativeOperation>(current: T[], next: T[]): T[]
{
  const unchanged = current.length === next.length && next.every((value, index) =>
  {
    const previous = current[index];
    const keys = Object.keys(value) as Array<keyof T>;
    return Object.keys(previous).length === keys.length && keys.every((key) => value[key] === previous[key]);
  });
  return unchanged ? current : next;
}

export function mergeSessionSnapshot(current: NativeSession[], snapshot: NativeSession[], daemon: boolean): NativeSession[]
{
  const own = snapshot.filter((session) => isDaemonSession(session) === daemon);
  const other = current.filter((session) => isDaemonSession(session) !== daemon);
  const daemons = daemon ? own : other;
  const locals = daemon ? other : own;
  const daemonIds = new Set(daemons.map((session) => session.sessionId));
  return retainUnchangedSnapshot(current, [...daemons, ...locals.filter((session) => !daemonIds.has(session.sessionId))]);
}
