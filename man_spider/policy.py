import math
from dataclasses import asdict, dataclass
from pathlib import Path


DEFAULT_LARGE_DOMAIN_TARGET_THRESHOLD = 256
DEFAULT_LARGE_DOMAIN_SHARE_THRESHOLD = 1024

# Preserve the formats historically avoided by Spiderling/FileParser in the
# normal auto mode. Explicit extension includes still override this list.
LEGACY_BLOCKED_CONTENT_EXTENSIONS = {
    ".zip",
    ".gz",
    ".tar",
    ".bz2",
    ".7z",
    ".rar",
    ".xz",
    ".tgz",
    ".tbz2",
    ".png",
    ".gif",
    ".tif",
    ".tiff",
    ".bmp",
    ".jpg",
    ".jpeg",
    ".webp",
    ".enc",
    ".gpg",
    ".pgp",
    ".asc",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".msi",
}

# Extra opaque/binary container formats disabled automatically only when the
# preliminary estimate classifies the scope as large.
LARGE_DOMAIN_EXTRA_BLOCKED_EXTENSIONS = {
    ".bin",
    ".dat",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".iso",
    ".img",
    ".cab",
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".class",
    ".jar",
    ".pyc",
    ".o",
    ".obj",
    ".a",
    ".lib",
}
ALL_NON_TEXT_EXTENSIONS = LEGACY_BLOCKED_CONTENT_EXTENSIONS | LARGE_DOMAIN_EXTRA_BLOCKED_EXTENSIONS


@dataclass(frozen=True)
class ScopeEstimate:
    smb_targets: int
    local_targets: int
    sampled_targets: int
    observed_shares: int
    estimated_shares: int | None
    target_threshold: int
    share_threshold: int
    mode: str
    large_domain: bool
    reason: str

    def as_dict(self) -> dict:
        return asdict(self)


def _extension(value: str) -> str:
    value = str(value).strip().lower()
    return value if not value or value.startswith(".") else f".{value}"


def estimate_scope(options, preflight_result=None) -> ScopeEstimate:
    """Classify scope size from target count plus bounded preflight observations."""

    smb_targets = sum(not isinstance(target, Path) for target in options.targets)
    local_targets = len(options.targets) - smb_targets
    share_counts = [
        attempt.share_count
        for attempt in getattr(preflight_result, "attempts", ())
        if getattr(attempt, "share_count", None) is not None
    ]
    sampled_targets = len(share_counts)
    observed_shares = sum(share_counts)
    estimated_shares = None
    if sampled_targets and smb_targets:
        estimated_shares = math.ceil((observed_shares / sampled_targets) * smb_targets)

    mode = getattr(options, "large_domain_mode", "auto")
    target_threshold = getattr(
        options,
        "large_domain_target_threshold",
        DEFAULT_LARGE_DOMAIN_TARGET_THRESHOLD,
    )
    share_threshold = getattr(
        options,
        "large_domain_share_threshold",
        DEFAULT_LARGE_DOMAIN_SHARE_THRESHOLD,
    )
    if mode == "always":
        large_domain = True
        reason = "forced by --large-domain/--large-domain-mode=always"
    elif mode == "never":
        large_domain = False
        reason = "disabled by --no-large-domain/--large-domain-mode=never"
    elif smb_targets >= target_threshold:
        large_domain = True
        reason = f"{smb_targets} SMB targets meet the threshold of {target_threshold}"
    elif estimated_shares is not None and estimated_shares >= share_threshold:
        large_domain = True
        reason = f"estimated {estimated_shares} shares meet the threshold of {share_threshold}"
    else:
        large_domain = False
        if estimated_shares is None:
            reason = "target threshold was not met and no successful share observation was available"
        else:
            reason = f"{smb_targets} SMB targets and an estimated {estimated_shares} shares are below their thresholds"

    return ScopeEstimate(
        smb_targets=smb_targets,
        local_targets=local_targets,
        sampled_targets=sampled_targets,
        observed_shares=observed_shares,
        estimated_shares=estimated_shares,
        target_threshold=target_threshold,
        share_threshold=share_threshold,
        mode=mode,
        large_domain=large_domain,
        reason=reason,
    )


def effective_content_blocks(options, large_domain: bool) -> list[str]:
    """Resolve automatic format policy plus explicit user overrides."""

    mode = getattr(options, "non_text_policy", "auto")
    if mode == "read":
        blocked = set()
    elif mode == "skip":
        blocked = set(ALL_NON_TEXT_EXTENSIONS)
    else:
        blocked = set(LEGACY_BLOCKED_CONTENT_EXTENSIONS)
        if large_domain:
            blocked.update(LARGE_DOMAIN_EXTRA_BLOCKED_EXTENSIONS)

    explicit_reads = {
        _extension(value) for value in (*getattr(options, "read_formats", ()), *getattr(options, "extensions", ()))
    }
    blocked.difference_update(explicit_reads)
    # Selecting a filename extension may override automatic blocks, never an
    # explicit instruction to skip its content. Metadata remains selectable.
    blocked.update(_extension(value) for value in getattr(options, "skip_formats", ()))
    blocked.discard("")
    return sorted(blocked)


def apply_scope_policy(options, estimate: ScopeEstimate) -> list[str]:
    options.large_domain = estimate.large_domain
    options.scope_estimate = estimate.as_dict()
    options.blocked_content_extensions = effective_content_blocks(options, estimate.large_domain)
    return options.blocked_content_extensions


def restore_scope_policy(options, configuration: dict) -> bool:
    """Restore a persisted effective policy before validating resume identity."""

    try:
        policy = configuration["semantic"]["policy"]
        large_domain = policy["effective_large_domain"]
        blocked = policy["blocked_content_extensions"]
    except (KeyError, TypeError):
        return False
    if large_domain is None or blocked is None:
        return False
    options.large_domain = bool(large_domain)
    options.scope_estimate = policy.get("scope_estimate")
    options.blocked_content_extensions = list(blocked)
    return True


def format_scope_policy(options) -> str:
    from man_spider.lib.finding_log import display_text

    estimate = getattr(options, "scope_estimate", None) or {}
    estimated_shares = estimate.get("estimated_shares")
    estimated_text = "unavailable" if estimated_shares is None else str(estimated_shares)
    blocked = getattr(options, "blocked_content_extensions", ())
    blocked_text = ", ".join(display_text(value) for value in blocked) if blocked else "none"
    return "\n".join(
        (
            "Preliminary scope estimate:",
            f"  SMB targets: {estimate.get('smb_targets', 0)}",
            f"  sampled authenticated targets: {estimate.get('sampled_targets', 0)}",
            f"  observed shares: {estimate.get('observed_shares', 0)}",
            f"  estimated shares across scope: {estimated_text}",
            f"  large_domain: {getattr(options, 'large_domain', False)}",
            f"  reason: {display_text(estimate.get('reason', 'persisted effective policy'))}",
            f"  non_text_policy: {getattr(options, 'non_text_policy', 'auto')}",
            f"  content-disabled formats: {blocked_text}",
        )
    )
