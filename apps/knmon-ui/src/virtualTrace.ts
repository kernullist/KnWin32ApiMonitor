export interface VirtualTraceWindowInput {
  itemCount: number;
  rowHeight: number;
  viewportHeight: number;
  scrollTop: number;
  overscan: number;
}

export interface VirtualTraceWindow {
  startIndex: number;
  endIndex: number;
  offsetTop: number;
  totalHeight: number;
  visibleCount: number;
}

function clampNonNegativeInteger(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return 0;
  }

  return Math.floor(value);
}

export function computeVirtualTraceWindow(input: VirtualTraceWindowInput): VirtualTraceWindow {
  const itemCount = clampNonNegativeInteger(input.itemCount);
  const rowHeight = Math.max(1, clampNonNegativeInteger(input.rowHeight));
  const viewportHeight = clampNonNegativeInteger(input.viewportHeight);
  const overscan = clampNonNegativeInteger(input.overscan);
  const totalHeight = itemCount * rowHeight;
  const maxScrollTop = Math.max(0, totalHeight - viewportHeight);
  const scrollTop = Math.min(Math.max(0, clampNonNegativeInteger(input.scrollTop)), maxScrollTop);

  if (itemCount === 0) {
    return {
      startIndex: 0,
      endIndex: 0,
      offsetTop: 0,
      totalHeight: 0,
      visibleCount: 0
    };
  }

  const firstVisibleIndex = Math.floor(scrollTop / rowHeight);
  const visibleCount = Math.max(1, Math.ceil(viewportHeight / rowHeight));
  const startIndex = Math.max(0, firstVisibleIndex - overscan);
  const endIndex = Math.min(itemCount, firstVisibleIndex + visibleCount + overscan + 1);

  return {
    startIndex,
    endIndex,
    offsetTop: startIndex * rowHeight,
    totalHeight,
    visibleCount: endIndex - startIndex
  };
}
