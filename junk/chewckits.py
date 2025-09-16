#!/usr/bin/env python3
import os, re
from collections import defaultdict, Counter

ROOT = "."  # change if needed
SKIP_DIRS = {"build", "dist", "__pycache__", ".venv", "venv", "env", ".eggs", "egg-info", ".git"}
SKIP_SUBSTRINGS = {"/bashScripts/junk/"}

IMPORT_RE = re.compile(
    r'^\s*(?:from\s+([A-Za-z0-9_\.]+)\s+import\s+([A-Za-z0-9_\*,\s\.]+)|import\s+([A-Za-z0-9_\.]+))'
)

project_occurrences = defaultdict(set)      # module -> {file paths}
infile_duplicates = defaultdict(list)       # file -> [(module, [line_numbers])]
all_occurrences = defaultdict(list)         # module -> [(file, line)]

for dirpath, dirnames, filenames in os.walk(ROOT):
    # prune dirs
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    rel = os.path.relpath(dirpath, ROOT)
    if any(substr in os.path.join(rel, "") for substr in SKIP_SUBSTRINGS):
        continue

    for fn in filenames:
        if not fn.endswith(".py"):
            continue
        fpath = os.path.join(dirpath, fn)
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            per_file = []
            for i, line in enumerate(f, 1):
                m = IMPORT_RE.match(line)
                if not m:
                    continue
                if m.group(1):  # from X import Y
                    base = m.group(1)
                    per_file.append((base, i))
                    all_occurrences[base].append((fpath, i))
                elif m.group(3):  # import X
                    base = m.group(3)
                    per_file.append((base, i))
                    all_occurrences[base].append((fpath, i))

            # track project-wide unique files per module
            for mod, _ln in per_file:
                project_occurrences[mod].add(fpath)

            # track in-file duplicates (same module imported multiple times in same file)
            counter = Counter(m for m, _ in per_file)
            dups_here = [(m, [ln for mm, ln in per_file if mm == m]) for m, c in counter.items() if c > 1]
            if dups_here:
                infile_duplicates[fpath].extend(dups_here)

# ---- Reports ----

# 1) in-file duplicates with line numbers
print("=== Duplicate imports within the same file ===")
if not infile_duplicates:
    print("(none)")
else:
    for fpath, items in sorted(infile_duplicates.items()):
        print(f"\n{fpath}")
        for mod, lines in items:
            print(f"  - {mod} imported {len(lines)} times on lines {lines}")

# 2) project duplicates (modules imported in many files), ignoring build/dist/etc
print("\n=== Modules imported across multiple files (clean) ===")
for mod, files in sorted(project_occurrences.items(), key=lambda kv: (-len(kv[1]), kv[0])):
    if len(files) > 1:
        print(f"{mod} -> {len(files)} files")
        for f in sorted(files):
            print(f"   {f}")
