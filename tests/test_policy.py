from types import SimpleNamespace

from man_spider.lib.util import Target
from man_spider.policy import apply_scope_policy, effective_content_blocks, estimate_scope


def options_for(*targets, **overrides):
    values = {
        "targets": list(targets),
        "large_domain_mode": "auto",
        "large_domain_target_threshold": 256,
        "large_domain_share_threshold": 1024,
        "non_text_policy": "auto",
        "read_formats": [],
        "skip_formats": [],
        "extensions": [],
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def result_with_share_counts(*counts):
    return SimpleNamespace(attempts=[SimpleNamespace(share_count=count) for count in counts])


def test_estimate_extrapolates_bounded_authenticated_share_observation():
    options = options_for(Target("one"), Target("two"))
    estimate = estimate_scope(options, result_with_share_counts(4))

    assert estimate.sampled_targets == 1
    assert estimate.observed_shares == 4
    assert estimate.estimated_shares == 8
    assert estimate.large_domain is False


def test_target_or_estimated_share_threshold_classifies_large_scope():
    target_heavy = options_for(
        *(Target(f"host-{index}") for index in range(4)),
        large_domain_target_threshold=4,
    )
    assert estimate_scope(target_heavy).large_domain is True

    share_heavy = options_for(
        Target("one"),
        Target("two"),
        large_domain_share_threshold=10,
    )
    estimate = estimate_scope(share_heavy, result_with_share_counts(5))
    assert estimate.estimated_shares == 10
    assert estimate.large_domain is True


def test_large_domain_mode_can_be_forced_both_ways():
    assert estimate_scope(options_for(Target("one"), large_domain_mode="always")).large_domain is True
    many = options_for(
        *(Target(f"host-{index}") for index in range(10)),
        large_domain_mode="never",
        large_domain_target_threshold=1,
    )
    assert estimate_scope(many).large_domain is False


def test_format_policy_preserves_legacy_defaults_and_expands_for_large_domains():
    options = options_for(Target("one"))
    small = effective_content_blocks(options, large_domain=False)
    large = effective_content_blocks(options, large_domain=True)

    assert ".zip" in small
    assert ".bin" not in small
    assert ".zip" in large
    assert ".bin" in large


def test_explicit_formats_and_extension_filter_override_automatic_blocks():
    options = options_for(
        Target("one"),
        read_formats=[".zip"],
        skip_formats=[".custom"],
        extensions=[".bin"],
    )
    blocked = effective_content_blocks(options, large_domain=True)

    assert ".zip" not in blocked
    assert ".bin" not in blocked
    assert ".custom" in blocked


def test_read_and_skip_non_text_modes_are_explicit():
    read_all = options_for(Target("one"), non_text_policy="read")
    assert effective_content_blocks(read_all, large_domain=True) == []

    skip_all = options_for(Target("one"), non_text_policy="skip")
    estimate = estimate_scope(skip_all)
    apply_scope_policy(skip_all, estimate)
    assert ".zip" in skip_all.blocked_content_extensions
    assert ".bin" in skip_all.blocked_content_extensions
