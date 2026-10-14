"""Benchmark (not a test): ms/append, full rebuild time, peak RSS, DB size at N events.
Columns: ms/append (mean of 30), full rebuild(), first open, second open (checkpoint current), peak RSS, DB size.
Usage: python3 bench_append.py [N ...]   (default 500 1000 2000 5000 10000). Each N runs in a subprocess."""
import os, subprocess, sys, tempfile, time

SAMPLES = 30


def run_one(n):
    import resource
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import vault
    d = tempfile.mkdtemp(); path = os.path.join(d, "v.db")
    db = vault.connect(path)
    for i in range(n):   # bulk load without per-append projection work, then one rebuild
        typ = ("preference.set", "decision.made", "learning.captured", "goal.set")[i % 4]
        vault.append(db, typ, f"s{i % 200}", {"value": f"v{i}", "text": f"t{i}", "key": f"k{i % 7}"},
                     vault.HUMAN, "verified", key=f"k{i % 7}" if typ == "preference.set" else None, _rebuild=False)
    t = time.perf_counter(); vault.rebuild(db); rb = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    for i in range(SAMPLES):
        vault.append(db, "learning.captured", f"b{i}", {"text": f"bench {i}"}, vault.HUMAN, "verified")
    ap = (time.perf_counter() - t) * 1000 / SAMPLES
    db.close()
    t = time.perf_counter(); vault.connect(path).close(); op = (time.perf_counter() - t) * 1000
    t = time.perf_counter(); vault.connect(path).close(); op2 = (time.perf_counter() - t) * 1000
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    print(f"{n:>7} | {ap:9.2f} | {rb:10.1f} | {op:8.1f} | {op2:9.1f} | {rss:7.1f} | {os.path.getsize(path)/1e6:7.2f}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--one":
        run_one(int(sys.argv[2])); sys.exit(0)
    ns = [int(a) for a in sys.argv[1:]] or [500, 1000, 2000, 5000, 10000]
    print("events  | ms/append | rebuild ms | open ms  | reopen ms | RSS MB  | DB MB")
    for n in ns:
        subprocess.run([sys.executable, os.path.abspath(__file__), "--one", str(n)], check=True)
