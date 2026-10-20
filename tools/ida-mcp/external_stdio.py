"""Administrator-configured external MCP client: stage a fresh owned input."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from owned_stdio import checked_input, main as serve_owned


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--staging-root", required=True)
    arguments = parser.parse_args()
    source = checked_input(arguments.source)
    root = Path(arguments.staging_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    output = root / uuid.uuid4().hex
    output.mkdir()
    staged = output / source.name
    shutil.copyfile(source, staged)
    sys.argv = [sys.argv[0], "--input", str(staged), "--database", str(output / "analysis.i64")]
    serve_owned()


if __name__ == "__main__":
    # Python -I excludes this file's directory. Add only its fixed local scripts.
    main()
