#!/usr/bin/env python3
"""Open-time overhead on a synthetic 10k-event vault: `python3 bench_open.py [N] [--repeat R]`.
Builds the vault once (agent proposals + signed human approvals + plain events), then times connect() in the
steady state (checkpoint at head) and after M new events, plus `doctor`. Uses a throwaway key + config dir."""
import os, sys, tempfile, time, statistics
d = tempfile.mkdtemp(prefix="bench-open-")
os.environ.update({"VAULT_DB": os.path.join(d, "v.db"), "VAULT_CONFIG_DIR": os.path.join(d, "cfg"),
                   "VAULT_USER_KEY": os.path.join(d, "u.key"), "VAULT_LOG": os.path.join(d, "ops.jsonl")})
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vault
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
R = 15
signed = False
try:
    import signing
    signing.generate_user_key(); signed = True
except Exception:
    signing = None
db = vault.connect()
if signed:
    signing.register_user_key(db)
t = time.perf_counter(); n = 0
while n < N:
    if n % 10 == 0:
        p, _ = vault.append(db, "note.added", f"s{n % 97}", {"text": f"proposal {n}"}, "agent:bench", "unverified", _rebuild=False)
        vault.append(db, "event.approved", f"event:{p}", {}, vault.HUMAN, "verified", target_ids=[p], _rebuild=False); n += 2
    else:
        vault.append(db, "learning.captured", f"s{n % 97}", {"text": f"bench {n}"}, vault.HUMAN, "verified", _rebuild=False); n += 1
db.commit(); vault.rebuild(db); db.close()
build = time.perf_counter() - t


def timed(f):
    xs = []
    for _ in range(R):
        t = time.perf_counter(); f(); xs.append((time.perf_counter() - t) * 1000)
    return statistics.median(xs), max(xs)


vault.connect().close()     # first open establishes the checkpoint
steady = timed(lambda: vault.connect().close())
def after_new():
    db = vault.connect()
    for i in range(20):
        vault.append(db, "learning.captured", "late", {"text": f"late {time.time()} {i}"}, vault.HUMAN, "verified", _rebuild=False)
    db.commit(); db.close()
xs = []
for _ in range(R):
    after_new(); t = time.perf_counter(); vault.connect().close(); xs.append((time.perf_counter() - t) * 1000)
import ops
t = time.perf_counter(); db = vault.connect(); ops.doctor(db); db.close(); doc = (time.perf_counter() - t) * 1000
print(f"code={'signed' if signed else 'baseline'} events={N} build_s={build:.1f} "
      f"open_steady_ms median={steady[0]:.1f} max={steady[1]:.1f} "
      f"open_after_20_new_ms median={statistics.median(xs):.1f} max={max(xs):.1f} doctor_ms={doc:.0f} "
      f"K={os.environ.get('VAULT_VERIFY_SAMPLE_K', '4')} seg={os.environ.get('VAULT_VERIFY_SEGMENT', '64')}")
