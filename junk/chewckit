#!/usr/bin/env python3
import os, re
from collections import defaultdict

IMPORT_RE = re.compile(r'^\s*(?:from\s+([\w\.]+)|import\s+([\w\.]+))')

def find_duplicate_imports(root: str):
    imports_map = defaultdict(list)  # {module: [file1, file2, ...]}

    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(".py"):
                fpath = os.path.join(dirpath, fn)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        m = IMPORT_RE.match(line)
                        if m:
                            module = m.group(1) or m.group(2)
                            if module:
                                imports_map[module].append(fpath)

    # Report duplicates
    duplicates = {m: files for m, files in imports_map.items() if len(files) > 1}
    return duplicates

if __name__ == "__main__":
    root_dir = "."  # change to your repo root
    dups = find_duplicate_imports(root_dir)
    for mod, files in dups.items():
        print(f"{mod} is imported in {len(files)} places:")
        for f in files:
            print(f"   {f}")
