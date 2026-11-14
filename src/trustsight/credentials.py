"""Provider tokens, held safely by default.

The upstream-scan lane and any authenticated API call need a token.  A token
is a credential, so this module defines one resolution order and one rule set
rather than leaving each call site to invent its own:

1. **systemd credentials** (a service): ``$CREDENTIALS_DIRECTORY/<provider>-token``
   populated by ``LoadCredentialEncrypted=``.  Root is needed once at install
   time to encrypt and place the file; the running service needs no privilege.
2. **OS keyring** (a user CLI): Secret Service/KWallet through the optional
   ``keyring`` package.  Encrypted at rest and unlocked at login.
3. **Secret file**: ``TRUSTSIGHT_<PROVIDER>_TOKEN_FILE``, which must be mode
   ``0600`` like the feed key.  A group/other-readable file is named, not used
   silently.
4. **Environment**: ``TRUSTSIGHT_<PROVIDER>_TOKEN``, for CI and containers only.
   An environment variable is visible to same-UID processes, so it is last.

A keyring that exists but refuses (locked, denied) is a **fail-closed** error,
never a silent downgrade to a file or to anonymous access.  A token is
provider-scoped: nothing here decides *where* it is sent, and the HTTP client
must not forward it across a host change.

Nothing in this module writes a token to ``config.toml``, the database, a log,
a report, or a child process environment.  :class:`Secret` redacts itself in
``str``/``repr`` so an accidental format string cannot leak it.
"""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .bounded_io import read_file_capped

_log = logging.getLogger(__name__)

__all__ = [
    "PROVIDERS",
    "CredentialError",
    "Secret",
    "delete_token",
    "normalize_provider",
    "provider_env_names",
    "resolve_token",
    "store_token",
    "token_from_stdin",
    "token_source",
]

#: The providers with token support.  Keep in step with ``[upstream_scan]
#: providers``.
PROVIDERS = ("github", "gitlab", "codeberg", "bitbucket")

SERVICE_NAME = "trustsight"
_MAX_TOKEN_BYTES = 4096


class CredentialError(RuntimeError):
    """A token source exists but cannot be used safely."""


def normalize_provider(provider: str) -> str:
    """Return the canonical provider name, refusing anything else."""
    value = str(provider or "").strip().lower()
    if value not in PROVIDERS:
        raise CredentialError(
            f"unknown provider {provider!r}; choose one of "
            + ", ".join(PROVIDERS)
        )
    return value


def _env_name(provider: str, suffix: str) -> str:
    return f"TRUSTSIGHT_{provider.upper()}_{suffix}"


def provider_env_names(provider: str) -> tuple[str, str]:
    """``(token_env, file_env)`` for one provider."""
    provider = normalize_provider(provider)
    return _env_name(provider, "TOKEN"), _env_name(provider, "TOKEN_FILE")


@dataclass(frozen=True)
class Secret:
    """A token that redacts itself in any textual rendering."""

    provider: str
    _value: str

    def reveal(self) -> str:
        """The token itself.  Call sites should use it exactly once, to send it."""
        return self._value

    @property
    def label(self) -> str:
        """A safe label: the last four characters, or ``empty``."""
        tail = self._value[-4:]
        return f"...{tail}" if tail else "empty"

    def __bool__(self) -> bool:
        return bool(self._value)

    def __str__(self) -> str:
        return f"<redacted {self.provider} token {self.label}>"

    def __repr__(self) -> str:
        return f"Secret(provider={self.provider!r}, value=<redacted>)"


def _read_secret_file(path: Path, provider: str) -> Secret | None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    if mode & 0o077:
        _log.warning(
            "%s token file is readable by group or others; restrict it to "
            "0600", provider,
        )
    try:
        value = read_file_capped(
            path, _MAX_TOKEN_BYTES, f"{provider} token"
        ).decode("utf-8", errors="replace").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return Secret(provider, value) if value else None


def _systemd_credential(provider: str, environ) -> Secret | None:
    directory = (environ.get("CREDENTIALS_DIRECTORY", "") or "").strip()
    if not directory:
        return None
    path = Path(directory) / f"{provider}-token"
    try:
        value = read_file_capped(
            path, _MAX_TOKEN_BYTES, f"{provider} credential"
        ).decode("utf-8", errors="replace").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return Secret(provider, value) if value else None


def _keyring_token(provider: str, keyring_backend) -> Secret | None:
    """The keyring token, or ``None`` when no usable backend exists.

    A backend that is present but refuses (locked, denied) raises
    :class:`CredentialError`: silently falling back would downgrade the
    security of a working desktop keyring without saying so.
    """
    backend = keyring_backend
    if backend is None:
        try:
            import keyring as backend  # type: ignore[no-redef]
        except ImportError:
            return None
        try:
            from keyring.backends.fail import Keyring as _FailKeyring

            if isinstance(backend.get_keyring(), _FailKeyring):
                return None
        except Exception:  # noqa: BLE001 - an odd install stays usable
            pass
    try:
        value = backend.get_password(SERVICE_NAME, provider)
    except Exception as exc:  # noqa: BLE001 - a refusing backend fails closed
        raise CredentialError(
            f"the OS keyring is present but could not be read for {provider} "
            f"({type(exc).__name__}); unlock it or use a 0600 token file"
        ) from exc
    return Secret(provider, value.strip()) if value else None


def token_source(
    provider: str,
    *,
    environ=None,
    keyring_backend=None,
) -> tuple[Secret | None, str]:
    """Resolve a token and say which tier supplied it (for ``auth status``)."""
    provider = normalize_provider(provider)
    environ = os.environ if environ is None else environ

    secret = _systemd_credential(provider, environ)
    if secret is not None:
        return secret, "systemd credential"

    secret = _keyring_token(provider, keyring_backend)
    if secret is not None:
        return secret, "OS keyring"

    token_env, file_env = provider_env_names(provider)
    file_path = (environ.get(file_env, "") or "").strip()
    if file_path:
        secret = _read_secret_file(Path(file_path).expanduser(), provider)
        if secret is not None:
            return secret, "0600 token file"

    value = (environ.get(token_env, "") or "").strip()
    if value:
        return Secret(provider, value), "environment"
    return None, ""


def resolve_token(
    provider: str,
    *,
    environ=None,
    keyring_backend=None,
) -> Secret | None:
    """Resolve *provider*'s token from the safest available source.

    Returns ``None`` when no source holds a token, so an unauthenticated run
    is explicit rather than an error.  A keyring that refuses raises
    :class:`CredentialError` (fail closed).
    """
    return token_source(
        provider, environ=environ, keyring_backend=keyring_backend
    )[0]


def store_token(provider: str, token: str, *, keyring_backend=None) -> None:
    """Store a token in the OS keyring; refuse rather than write a plaintext file."""
    provider = normalize_provider(provider)
    value = str(token or "").strip()
    if not value:
        raise CredentialError("refusing to store an empty token")
    backend = keyring_backend
    if backend is None:
        try:
            import keyring as backend  # type: ignore[no-redef]
        except ImportError as exc:
            raise CredentialError(
                "the optional 'keyring' package is not installed; install "
                "trustsight[credentials] or set a 0600 TRUSTSIGHT_<PROVIDER>_"
                "TOKEN_FILE"
            ) from exc
    try:
        backend.set_password(SERVICE_NAME, provider, value)
    except Exception as exc:  # noqa: BLE001 - surface, never swallow
        raise CredentialError(
            f"could not write the {provider} token to the OS keyring "
            f"({type(exc).__name__})"
        ) from exc


def delete_token(provider: str, *, keyring_backend=None) -> bool:
    """Remove a token from the OS keyring; return whether one was removed."""
    provider = normalize_provider(provider)
    backend = keyring_backend
    if backend is None:
        try:
            import keyring as backend  # type: ignore[no-redef]
        except ImportError:
            return False
    try:
        existing = backend.get_password(SERVICE_NAME, provider)
        if not existing:
            return False
        backend.delete_password(SERVICE_NAME, provider)
        return True
    except Exception:  # noqa: BLE001 - a failed delete is reported, not raised
        return False


def token_from_stdin(stream=None) -> str:
    """Read one bounded line from stdin without echoing it.

    ``trustsight auth login --stdin`` uses this so a token can be piped in
    (``read -rsp`` / a CI secret) without appearing in argv or a shell history.
    """
    import sys

    handle = sys.stdin if stream is None else stream
    raw = handle.readline(_MAX_TOKEN_BYTES + 1)
    if len(raw) > _MAX_TOKEN_BYTES:
        raise CredentialError("token on stdin is longer than the cap")
    return raw.strip()
