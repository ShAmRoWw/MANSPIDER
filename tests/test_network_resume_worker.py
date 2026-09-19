"""Wire the worker's successful share observation to persisted recovery."""

from types import SimpleNamespace

import pytest

from man_spider.cli import parse_options
from man_spider.error_policy import NETWORK_UNAVAILABLE_MARKER
from man_spider.lib.spiderling import Spiderling
from man_spider.lib.util import Target
from man_spider.state import ScanState, normalized_scan_configuration, target_object_key


@pytest.mark.parametrize("shares", [[], ["Data"]])
def test_worker_successful_enumeration_closes_previous_network_error(tmp_path, shares):
    state = ScanState.create(tmp_path / "state.sqlite3",
                             normalized_scan_configuration(parse_options([str(tmp_path), "-f", "secret"])), "2.0.0")
    target = Target("server")
    key = f"share-enumeration|{target_object_key(target)}"
    worker = Spiderling.__new__(Spiderling)
    worker.target = target
    worker.scan_state = state
    worker.parent = SimpleNamespace(
        state_path=str(state.path), state_run_id=state.run_id, resume_mode=True, share_whitelist=[],
        scope_matcher=SimpleNamespace(share_exclusion=lambda *_: None, should_traverse_share=lambda *_: True),
    )
    worker.smb_client = SimpleNamespace(shares=shares, share_listing_error=None, share_type=lambda *_: 0)
    try:
        row = state.claim_object(object_key=key, kind="share_enumeration", target=str(target), path=str(target))
        state.complete_object(row.object_id, "error", reason=f"{NETWORK_UNAVAILABLE_MARKER} offline")
        state.prepare_resume(retry_limit=1)
        attempts = state.object_row(row.object_id)["attempts"]
        assert list(worker.shares) == shares
        assert state.object_row(row.object_id)["status"] == "processed"
        assert state.object_row(row.object_id)["reason"] is None
        assert state.object_row(row.object_id)["attempts"] == attempts
        assert state.finish() == "complete"
    finally:
        state.close()
