"""Review-workload policy, kept separate from score and risk-band arithmetic."""

from dataclasses import dataclass

from .config import load_config


@dataclass(frozen=True)
class ReviewPolicy:
    name: str
    threshold: int

    def flagged(self, score: int) -> bool:
        return score > self.threshold


# These are workload policies, not score calibration. The default retains the
# historical 20-point behavior; changing one must not change the score or risk
# band reported for that score.
_DEFAULT_PROFILE_THRESHOLDS = {
    "default": 20,
    "quiet": 40,
    "strict": 10,
}


def review_policy(config: dict | None = None) -> ReviewPolicy:
    """Return the selected review policy, rejecting unsafe configuration."""
    if config is None:
        config = load_config()
    review = config.get("review", {})
    if not isinstance(review, dict):
        raise ValueError("[review] must be a table")
    configured = review.get("profiles", {})
    if not isinstance(configured, dict):
        raise ValueError("[review.profiles] must be a table")
    profiles = dict(_DEFAULT_PROFILE_THRESHOLDS)
    for profile_name, threshold in configured.items():
        if profile_name not in profiles:
            choices = ", ".join(sorted(profiles))
            raise ValueError(f"review profile names must be one of: {choices}")
        if (not isinstance(threshold, int) or isinstance(threshold, bool)
                or not 0 <= threshold <= 100):
            raise ValueError(
                f"review profile {profile_name!r} threshold must be an integer between 0 and 100"
            )
        profiles[profile_name] = threshold
    name = review.get("profile", "default")
    if not isinstance(name, str) or name not in profiles:
        choices = ", ".join(sorted(profiles))
        raise ValueError(f"review.profile must be one of: {choices}")
    return ReviewPolicy(name, profiles[name])
