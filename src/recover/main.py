# -*- coding: utf-8 -*-
"""REcover IDA Pro headless entry point."""

# idapro must be imported before any ida_* module.
import idapro  # noqa: I001

import ida_auto

from pathlib import Path

import importlib.resources
import logging.config
import os
import sys

import recover
from recover.exporters import ida_pro


__author__ = "Chariton Karamitas <huku@census-labs.com>"


def main(argv: list[str] | None = None) -> int:

    argv = argv or sys.argv

    if len(argv) < 2:
        print(f"Usage: {argv[0]} <path-to-idb>", file=sys.stderr)
        return 1

    idb_path = Path(argv[1]).resolve(strict=True)

    path = importlib.resources.files("recover.data") / "logging.ini"
    logging.config.fileConfig(str(path))

    logging.info("Opening IDB at %s", idb_path)
    idapro.open_database(str(idb_path), run_auto_analysis=True)

    logging.info("Waiting for auto-analysis to finish")
    ida_auto.auto_wait()

    exporter = ida_pro.IdaPro()
    recover.export(exporter, idb_path.parent)

    idapro.close_database()

    return os.EX_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv))
