import { TraceIngestState, type TraceIngestRequest } from "./traceIngestProtocol";

const state = new TraceIngestState();
self.onmessage = (event: MessageEvent<TraceIngestRequest>) =>
{
  const delta = state.apply(event.data);
  if (delta !== null)
  {
    self.postMessage(delta);
  }
};
