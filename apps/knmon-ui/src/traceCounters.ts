export function summarizeTraceCounts(retained: number, ingested: number, nativeStreamed: number)
{
  const total = Math.max(ingested, nativeStreamed);
  return {
    total,
    trimmed: Math.max(0, ingested - retained),
    notIngested: Math.max(0, total - ingested)
  };
}
