from trustsight.shell_words import command_starts


def _words(body):
    return [word for word, _tail in command_starts(body)]


def test_a_bare_command_is_found():
    assert _words("pip install demo") == ["pip"]


def test_wrappers_are_skipped():
    for body in (
        "env A=1 pip install demo",
        "exec pip install demo",
        "command pip install demo",
        "nice -n 10 pip install demo",
        "timeout 5 pip install demo",
        "sudo -u root pip install demo",
        "time pip install demo",
    ):
        assert _words(body) == ["pip"], body


def test_grouping_and_reserved_words_are_skipped():
    assert _words("{ pip install demo; }") == ["pip", "}"]
    assert _words("if true; then pip install demo; fi") == ["true", "pip", "fi"]
    assert _words("! pip install demo") == ["pip"]


def test_a_case_arm_body_is_a_command_position():
    assert _words("  0.1.*|0.2.*) pip install demo ;;") == ["pip"]


def test_a_printed_manager_is_not_a_command():
    assert _words('echo "then pip install demo"') == ["echo"]
    assert _words('echo "{ pip install demo }"') == ["echo"]


def test_a_command_substitution_is_scanned():
    assert _words('echo "$(pip install demo)"') == ["echo", "pip"]
    assert _words("out=$(pip install demo)") == ["pip"]
    assert _words("(( $(vercmp 1 2) >= 0 ))") == []


def test_a_redirect_and_numeric_argument_do_not_hide_the_command():
    assert _words(">out pip install demo") == ["pip"]
    assert _words("timeout 5 pip install demo") == ["pip"]


def test_the_tail_starts_at_the_command_word():
    assert list(command_starts("  time pip install demo")) == [
        ("pip", "pip install demo")
    ]
