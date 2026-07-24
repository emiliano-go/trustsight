import json
import os
import sys
from typing import Optional

from openai import OpenAI

from .config import load_config
from .schema import PackageFact, fact_to_dict

_USE_COLOR = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
_REASONING_COLOR = "\033[90m" if _USE_COLOR else ""
_RESET_COLOR = "\033[0m" if _USE_COLOR else ""


def _sanitize_prompt_field(s: str) -> str:
    """Strip control characters and newlines from untrusted fields to
    prevent LLM prompt injection via package metadata."""
    return s.replace("\n", " ").replace("\r", " ").replace("\x00", "")


def _build_prompt(fact: PackageFact) -> str:
    fact_dict = fact_to_dict(fact)
    diff_trunc = json.dumps(fact_dict.get("diff_summary", {}), indent=2)
    breakdown = json.dumps(
        [
            {"rule_id": e.rule_id, "severity": e.severity, "weight": e.weight, "reason": e.reason}
            for e in fact.score_breakdown
        ],
        indent=2,
    )
    novelty = json.dumps(
        {
            "url_first_seen_in_this_package": fact.novelty_context.url_first_seen_in_this_package,
            "url_first_seen_globally": fact.novelty_context.url_first_seen_globally,
            "maintainer_first_seen_for_this_package": fact.novelty_context.maintainer_first_seen_for_this_package,
            "maintainer_changed": fact.maintainer_changed,
        },
        indent=2,
    )

    risk = "Low"
    if fact.final_score > 80:
        risk = "Critical"
    elif fact.final_score > 50:
        risk = "High"
    elif fact.final_score > 20:
        risk = "Medium"

    pkg = _sanitize_prompt_field(fact.package_name)
    old_ver = _sanitize_prompt_field(fact.old_version)
    new_ver = _sanitize_prompt_field(fact.new_version)

    return f"""Package: {pkg}
Change: {old_ver} → {new_ver}
Maintainer changed: {fact.maintainer_changed}

Diff Summary:
{diff_trunc}

Score Breakdown:
{breakdown}

Novelty:
{novelty}

--- END OF DATA ---

Write exactly 2 concise sentences for a developer:
1. What technically changed in the build process (focus on new commands/sources).
2. Why the score is {risk}.
Do not repeat the numeric score. Do not use markdown. Stick to observable facts."""


def _get_client(config: dict) -> Optional[OpenAI]:
    llm_cfg = config.get("llm", {})
    provider = llm_cfg.get("provider", "ollama")

    base_url = (
        os.getenv("TRUSTSIGHT_BASE_URL")
        or llm_cfg.get("ollama_url" if provider == "ollama" else "openai", {}).get("base_url")
        or "http://localhost:11434/v1"
    )
    api_key = os.getenv("TRUSTSIGHT_API_KEY") or ""

    if provider == "ollama":
        api_key = api_key or "ollama"
    else:
        if not api_key:
            openai_cfg = llm_cfg.get("openai", {})
            api_key = openai_cfg.get("api_key", "")
        if not api_key:
            return None

    return OpenAI(base_url=base_url, api_key=api_key)


def _get_model(config: dict) -> str:
    return config.get("llm", {}).get("model", "gpt-4o-mini")


def _assert_verdict(verdict: str, fact: PackageFact) -> bool:
    """Assert that an LLM-generated verdict meets quality criteria.

    Returns ``True`` if the verdict passes all checks, ``False`` if it
    should be suppressed and replaced with the fallback.
    """
    if not verdict or len(verdict) < 20:
        return False
    if len(verdict) > 2000:
        return False
    score_str = str(fact.final_score)
    if score_str in verdict:
        return False
    has_fatal = any(e.severity == "FATAL" for e in fact.score_breakdown)
    if has_fatal and "injection" not in verdict.lower() and "unicode" not in verdict.lower() and "bidi" not in verdict.lower():
        return False
    if fact.final_score <= 10 and any(
        w in verdict.lower() for w in ["malicious", "dangerous", "critical", "attack"]
    ):
        return False
    return True


def _checked_verdict(verdict: str, fact: PackageFact, was_streamed: bool) -> str:
    """Return the verdict if it passes assertions, otherwise the fallback."""
    if _assert_verdict(verdict, fact):
        return verdict
    result = fallback_verdict(fact)
    msg = f"\n[{_REASONING_COLOR}LLM verdict suppressed; using fallback{_RESET_COLOR}]"
    if was_streamed:
        print(msg)
        print(result)
    return result


def generate_verdict_stream(
    fact: PackageFact,
    *,
    stream: bool = True,
    show_reasoning: bool = False,
) -> str:
    config = load_config()

    if not config.get("llm", {}).get("enabled", True):
        result = fallback_verdict(fact)
        if stream:
            print(result)
        return result

    max_chars = config.get("diff", {}).get("max_diff_chars_for_llm", 2000)
    prompt = _build_prompt(fact)[:max_chars]
    model = _get_model(config)
    client = _get_client(config)

    if client is None:
        result = fallback_verdict(fact)
        if stream:
            print(result)
        return result

    llm_cfg = config.get("llm", {})
    kwargs = dict(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=llm_cfg.get("max_tokens", 1024),
        temperature=llm_cfg.get("temperature", 0.3),
        top_p=llm_cfg.get("top_p", 1),
        seed=llm_cfg.get("seed", 42),
        stream=stream,
    )

    try:
        completion = client.chat.completions.create(**kwargs)

        if not stream:
            content = completion.choices[0].message.content or ""
            result = _checked_verdict(content.strip(), fact, stream)
            print(result)
            return result

        collected = []
        for chunk in completion:
            if not getattr(chunk, "choices", None):
                continue
            if not chunk.choices or getattr(chunk.choices[0], "delta", None) is None:
                continue

            delta = chunk.choices[0].delta

            if show_reasoning:
                reasoning = getattr(delta, "reasoning_content", None) or getattr(delta, "reasoning", None)
                if reasoning:
                    print(f"{_REASONING_COLOR}{reasoning}{_RESET_COLOR}", end="", flush=True)

            content = getattr(delta, "content", None)
            if content is not None:
                print(content, end="", flush=True)
                collected.append(content)

        print()
        raw = "".join(collected).strip()
        return _checked_verdict(raw, fact, stream)

    except Exception as e:
        result = fallback_verdict(fact)
        if stream:
            print(f"\nLLM error: {e}")
            print(result)
        return result


def generate_verdict(fact: PackageFact) -> str:
    return generate_verdict_stream(fact, stream=False, show_reasoning=False)


_SEVERITY_ORDER = ["FATAL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def fallback_verdict(fact: PackageFact) -> str:
    """Describe the finding without an LLM.

    This is the verdict shown whenever the LLM is disabled, unreachable,
    or its output fails the integrity assertions, so it has to be
    accurate on its own.  It previously ended every verdict with "No
    suspicious patterns detected", including on packages scoring 100/100
    with a CRITICAL rule fired.
    """
    reasons = []
    if fact.diff_summary.files_changed:
        reasons.append(f"modified {', '.join(fact.diff_summary.files_changed)}")
    if fact.source_changes.added_urls:
        reasons.append(f"added {len(fact.source_changes.added_urls)} source URL(s)")
    if fact.maintainer_changed:
        reasons.append("maintainer changed")
    if not reasons:
        reasons.append("no structural changes")
    change_summary = "; ".join(reasons)

    # Report what actually fired, worst first.
    fired = [e for e in fact.score_breakdown if e.weight > 0 or e.severity == "FATAL"]
    if not fired:
        return f"Version bump. {change_summary}. No risk signals fired."

    fired.sort(key=lambda e: (
        _SEVERITY_ORDER.index(e.severity) if e.severity in _SEVERITY_ORDER else 99,
        -e.weight,
    ))
    worst = fired[0]
    if worst.severity == "FATAL":
        return (
            f"{change_summary}. {worst.rule_id} ({worst.severity}) fired: "
            f"the package is attempting to deceive the reviewer, so the score "
            f"is capped at maximum regardless of other evidence."
        )

    top = ", ".join(f"{e.rule_id} ({e.severity})" for e in fired[:3])
    more = f" and {len(fired) - 3} more signal(s)" if len(fired) > 3 else ""
    return f"Version bump. {change_summary}. Signals: {top}{more}."
