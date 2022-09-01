"""
Use cases:

1. Tests that use the snapshot fixture but don't have a recorded snapshot (they will fail upon next execution)
    Particularly useful when refactoring, moving files, etc.
2. Entries in .snapshot.json files that don't have a corresponding test
"""

import json
import os

import pytest
from _pytest.config import Config, PytestPluginManager
from _pytest.config.argparsing import Parser
from _pytest.main import Session
from _pytest.nodes import Item


def find_snapshot_files(root_dir: str) -> list[str]:
    all_files = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        skip_dirs = ["functions", "__pycache__"]
        for d in skip_dirs:
            if d in dirnames:
                dirnames.remove(d)

        for filename in filenames:
            if filename.endswith(".snapshot.json"):
                all_files.append(os.path.join(dirpath, filename))
    return all_files


def remove_snapshot_entry_from_file(file_path: str, node_id: str):
    with open(file_path, "r+") as fd:
        snapshot_content = json.loads(fd.read())
        del snapshot_content[node_id]
        fd.seek(0)
        fd.write(json.dumps(snapshot_content, indent=2))
        fd.truncate()


@pytest.hookimpl
def pytest_addoption(parser: Parser, pluginmanager: PytestPluginManager):
    parser.addoption(
        "--snapshot-orphan-detect",
        action="store_true",
        help="If set, will detect all snapshot entries without corresponding tests",
    )
    parser.addoption(
        "--snapshot-orphan-cleanup",
        action="store_true",
        help="If set, will detect all snapshot entries without corresponding tests AND delete them. Implies --snapshot-orphan-detect",
    )
    parser.addoption(
        "--snapshot-orphan-filter",
        action="store_true",
        help="Select only tests that need to have their snapshots generated. Implies --snapshot-orphan-detect",
    )


def is_snapshot_test(item: Item) -> bool:
    return hasattr(item, "_fixtureinfo") and any(
        ["snapshot" in fn for fn in item._fixtureinfo.argnames]
    )


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(session: Session, config: Config, items: list[Item]):

    should_cleanup = config.getoption("--snapshot-orphan-cleanup")
    should_detect = config.getoption("--snapshot-orphan-detect")
    should_filter = config.getoption("--snapshot-orphan-filter")

    if not (should_detect or should_cleanup or should_filter):
        return

    # gather all snapshot nodeids by first finding all snapshot files
    snapshot_files = find_snapshot_files(config.rootdir)
    snapshot_ids = set()
    for snap in snapshot_files:
        with open(snap, "r") as fd:
            content = json.loads(fd.read())
            node_ids = content.keys()
            snapshot_ids.update(node_ids)

    if should_filter:
        # Filter pytest items, so that we only execute tests that will generate new snapshot entries
        selected = []
        deselected = []
        for item in items:
            if is_snapshot_test(item) and item.nodeid not in snapshot_ids:
                selected.append(item)
            else:
                deselected.append(item)

        items[:] = selected
        config.hook.pytest_deselected(items=deselected)
    else:
        # TODO: need to make sure we also collect all pytest tests in config.rootdir
        #   otherwise we will delete a lot of files that might have tests, but the tests haven't been considered
        pytest_ids = set()
        for item in items:
            if is_snapshot_test(item):
                pytest_ids.add(item.nodeid)

        orphaned_snapshots = sorted(snapshot_ids.difference(pytest_ids))
        if orphaned_snapshots:
            for o in orphaned_snapshots:
                if should_cleanup:
                    snapshot_file_path = o.partition("::")[0]
                    snapshot_file_path = f"{snapshot_file_path[:-3]}.snapshot.json"
                    remove_snapshot_entry_from_file(snapshot_file_path, o)
                    print(
                        f"Successfully removed orphaned snapshot entry {o} from {snapshot_file_path=}"
                    )
            pytest.exit("Successfully removed orphaned snapshots!")

            if not should_cleanup:
                orphan_message = "\n".join([f"orphan: {o}" for o in orphaned_snapshots])
                pytest.exit(f"Please fix these orphaned snapshots: {orphan_message}")
