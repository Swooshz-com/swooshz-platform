"""Out-of-tree native build for the managed recovery boundary."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCES = [
    ROOT / "protocol.c",
    ROOT / "platform.c",
    ROOT / "supervisor.c",
    ROOT / "custodian.c",
    ROOT / "dispatcher.c",
    ROOT / "bootstrap.c",
    ROOT / "broker.c",
    ROOT / "agent.c",
    ROOT / "launch-base.c",
    ROOT.parent.parent / "tests" / "recovery-managed" / "native_unit.c",
]


class BuildUnavailable(RuntimeError):
    pass


def _compiler() -> str:
    requested = os.environ.get("CC")
    if requested:
        selected = shutil.which(requested)
        if selected:
            return selected
        raise BuildUnavailable("configured C compiler is unavailable")
    for name in ("cc", "gcc", "clang"):
        selected = shutil.which(name)
        if selected:
            return selected
    raise BuildUnavailable("native compiler unavailable")


def _run(command: list[str]) -> None:
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"native build command failed: {Path(command[0]).name}")


def build(output_dir: Path | None = None) -> Path:
    compiler = _compiler()
    flags = [
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-O2",
        "-fstack-protector-strong",
        "-D_FORTIFY_SOURCE=2",
        "-I",
        str(ROOT),
    ]
    if os.name != "nt":
        flags.extend(["-Wl,-z,relro", "-Wl,-z,now"])
    owned_temp: tempfile.TemporaryDirectory[str] | None = None
    if output_dir is None:
        owned_temp = tempfile.TemporaryDirectory(prefix="swz-recovery-build-")
        build_dir = Path(owned_temp.name)
    else:
        build_dir = output_dir.resolve()
        build_dir.mkdir(parents=True, exist_ok=True)
    try:
        objects: list[Path] = []
        for source in SOURCES:
            if not source.is_file():
                raise RuntimeError(f"native source missing: {source.name}")
            object_path = build_dir / f"{source.stem}.o"
            _run([compiler, *flags, "-c", str(source), "-o", str(object_path)])
            objects.append(object_path)
        binary = build_dir / "swz-recovery-native-unit"
        _run([compiler, *flags, *(str(item) for item in objects), "-o", str(binary)])
        if not binary.is_file() or binary.stat().st_size == 0:
            raise RuntimeError("native build did not produce a binary")
        return binary
    finally:
        if owned_temp is not None:
            owned_temp.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.verify and args.output_dir is None:
        parser.error("use --verify or --output-dir")
    try:
        binary = build(args.output_dir)
    except BuildUnavailable as error:
        print(f"NATIVE_BUILD=UNAVAILABLE:{error}", file=sys.stderr)
        return 3
    if args.output_dir is None:
        print("NATIVE_BUILD=PASS:temporary-out-of-tree")
    else:
        print(f"NATIVE_BUILD=PASS:{binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
