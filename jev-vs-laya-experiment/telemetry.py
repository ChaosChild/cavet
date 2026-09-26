"""P0 telemetry sampler: 1 Hz CPU / RAM / GPU utilization / VRAM stream for
local runs, via PowerShell performance counters in a side process.

Usage:  python telemetry.py --out runs/telemetry-<tag>.jsonl [--interval 1]
Stops when stdin closes or the process is killed; the runner just spawns it.
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PS_SCRIPT = r"""
$counters = @(
  '\Processor(_Total)\% Processor Time',
  '\Memory\Available MBytes',
  '\GPU Engine(*)\Utilization Percentage',
  '\GPU Process Memory(*)\Dedicated Usage'
)
Get-Counter -Counter $counters -SampleInterval 1 -Continuous -ErrorAction SilentlyContinue | ForEach-Object {
  $cpu = 0.0; $ram = 0.0; $gpu = 0.0; $vram = 0.0
  foreach ($s in $_.CounterSamples) {
    switch -Wildcard ($s.Path) {
      '*processor(_total)\% processor time' { $cpu = [Math]::Max($cpu, $s.CookedValue) }
      '*memory\available mbytes'            { $ram = $s.CookedValue }
      '*gpu engine(*)\utilization percentage' { $gpu += $s.CookedValue }
      '*gpu process memory(*)\dedicated usage' { $vram += $s.CookedValue }
    }
  }
  [PSCustomObject]@{
    ts = (Get-Date).ToUniversalTime().ToString('o')
    cpu_pct = [Math]::Round($cpu, 1)
    ram_avail_mb = [Math]::Round($ram, 0)
    gpu_util_pct = [Math]::Round([Math]::Min($gpu, 100.0), 1)
    vram_dedicated_mb = [Math]::Round($vram / 1MB, 0)
  } | ConvertTo-Json -Compress
}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--interval", type=int, default=1, help="accepted for documentation; the counter stream is fixed at 1 Hz")
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-Command", PS_SCRIPT],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
    )
    print(f"telemetry: writing {out} (label={args.label!r}); Ctrl+C to stop", file=sys.stderr)
    with out.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"meta": {"label": args.label, "started": datetime.now(timezone.utc).isoformat(),
                                      "interval_s": 1}}) + "\n")
        fh.flush()
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                rec = json.loads(line)
                rec["label"] = args.label
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
        except KeyboardInterrupt:
            pass
        finally:
            proc.kill()
    print("telemetry: stopped", file=sys.stderr)


if __name__ == "__main__":
    main()
