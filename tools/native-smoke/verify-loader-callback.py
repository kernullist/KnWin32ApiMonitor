"""Reject external calls in the MSVC Debug loader callback and its callees."""

import argparse
import pathlib
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("dumpbin")
parser.add_argument("object_file")
args = parser.parse_args()
output = subprocess.run(
    [args.dumpbin, "/DISASM:NOBYTES", str(pathlib.Path(args.object_file).resolve())],
    check=True,
    capture_output=True,
).stdout.decode("utf-8", errors="replace")
allowed = {
    "ModuleNotification": {"Notify@ModuleGenerationTable", "ModuleCounterIncrement"},
    "Notify@ModuleGenerationTable": {"ModuleCounterIncrement", "ModuleCounterStore"},
    "ModuleCounterIncrement": set(),
    "ModuleCounterStore": set(),
}
call_count = 0
for symbol, targets in allowed.items():
    start = re.search(r"^\?" + re.escape(symbol) + r".*:\s*$", output, re.MULTILINE)
    if start is None:
        raise SystemExit(f"Missing Debug callback symbol: {symbol}")
    end = re.search(r"^\S.*:\s*$", output[start.end():], re.MULTILINE)
    body = output[start.end():start.end() + end.start() if end else len(output)]
    for call in re.findall(r"\bcall\s+([^\r\n]+)", body):
        call_count += 1
        if not any(call.startswith("?" + target + "@") for target in targets):
            raise SystemExit(f"External or unknown loader callback call: {symbol}: {call}")
print(f"Loader callback object audit passed: functions={len(allowed)} calls={call_count}")
