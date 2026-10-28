"""Run clang-tidy on the given source files, in parallel, once per file.

CMake writes one compile command per target that builds a file, and most of src/ is compiled into
several test targets as well as the DLL, so plain clang-tidy would analyze those files many times.
This keeps the first command for each file and runs clang-tidy on that.

    python .github/scripts/run_clang_tidy.py -p <build dir with compile_commands.json> FILE...

Run it from a VS developer prompt (x86), so clang-tidy finds the MSVC and Windows SDK headers.
Whether warnings fail the run is up to WarningsAsErrors in .clang-tidy; compile errors always do.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DIAG = re.compile(r"^.+:\d+:\d+: (?:warning|error): .*$", re.MULTILINE)


def key(path):
    return os.path.normcase(os.path.abspath(path))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", dest="build_dir", required=True, help="directory holding compile_commands.json")
    ap.add_argument("--clang-tidy", default="clang-tidy", help="clang-tidy executable")
    ap.add_argument("-j", dest="jobs", type=int, default=os.cpu_count())
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()

    db = json.loads((Path(args.build_dir) / "compile_commands.json").read_text(encoding="utf-8"))
    first = {}
    for cmd in db:
        first.setdefault(key(os.path.join(cmd["directory"], cmd["file"])), cmd)

    missing = [f for f in args.files if key(f) not in first]
    if missing:
        print("not in compile_commands.json:", *missing, sep="\n  ")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "compile_commands.json").write_text(
            json.dumps([first[key(f)] for f in args.files]), encoding="utf-8")

        def tidy(f):
            # The project is 32-bit only; without an explicit target clang-tidy parses it as x64.
            r = subprocess.run([args.clang_tidy, "-p", tmp, "--quiet", "--extra-arg=--target=i686-pc-windows-msvc", f],
                               capture_output=True, text=True, encoding="utf-8", errors="replace")
            return f, r.returncode, r.stdout + (r.stderr if r.returncode else "")

        failed, reports, diags = [], [], set()
        with ThreadPoolExecutor(args.jobs) as pool:
            for f, rc, out in pool.map(tidy, args.files):
                found = DIAG.findall(out)
                diags.update(found)
                print(f"{'FAIL' if rc else 'ok  '} {f}" + (f" ({len(found)} diagnostics)" if found else ""), flush=True)
                if rc:
                    failed.append(f)
                if rc or found:
                    reports.append((f, out))

    for f, out in reports:
        print(f"\n===== {f}\n{out.rstrip()}")
    print(f"\nclang-tidy: {len(diags)} distinct diagnostics, {len(failed)} of {len(args.files)} files failed")
    if diags and not failed and os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::warning title=clang-tidy::{len(diags)} warnings (not errors under .clang-tidy's WarningsAsErrors)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
