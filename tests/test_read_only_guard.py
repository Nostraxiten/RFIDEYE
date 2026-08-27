"""The read-only guarantee, expressed as tests.

If the project's central claim ("this tool cannot write to a tag") is ever
broken, these tests fail.  They are deliberately exhaustive about the *denied*
side: the allow-list is small and reviewable, but the list of dangerous things
that must stay unreachable is what a reviewer actually cares about.
"""

from __future__ import annotations

import pytest

from rfideye import read_only_guard as guard
from rfideye.read_only_guard import GuardViolation

# --------------------------------------------------------------------------- #
# Commands that must NEVER be reachable
# --------------------------------------------------------------------------- #
WRITE_COMMANDS = [
    "hf mf wrbl --blk 4 -k FFFFFFFFFFFF -d 00112233445566778899AABBCCDDEEFF",
    "hf mf wrsc 1 A FFFFFFFFFFFF",
    "hf mfu wrbl -b 4 -d 01020304",
    "hf 15 write -b 4 -d 01020304",
    "hf iclass wrbl --blk 10 -d 0000000000000000",
    "lf t55xx write -b 0 -d 00148040",
    "lf em 4x05 write -a 1 -d 12345678",
    "hf mfdes write --aid 112233",
]

#: Arbitrary-frame commands. They carry no forbidden verb, so they are stopped
#: by the allow-list rather than the deny-list - which is exactly the point of
#: being allow-list first: an unlisted command is refused even when it looks
#: innocuous, because its payload could be any APDU, including a write.
RAW_COMMANDS = [
    "hf 14a raw -k -a 3000",
    "hf 14b raw -s -c 0006",
    "hf 15 raw -d 020B",
    "hf 14a apdu -s 00A404000E325041592E5359532E4444463031",
]

CLONE_COMMANDS = [
    "lf hid clone -r 2006ec0c86",
    "lf em 410x clone --id 0F0368568B",
    "lf indala clone --heden 888",
    "hf mf restore --1k -f dump.bin",
    "hf iclass clone -f dump.bin --first 6 --last 12",
    "lf awid clone --fmt 26 --fc 123 --cn 1337",
]

EMULATION_COMMANDS = [
    "hf mf sim -u 11223344",
    "hf 14a sim -t 1 -u 11223344",
    "hf mfu sim -t 7",
    "lf em 410x sim --id 0F0368568B",
    "hf iclass sim -t 3",
    "hf mf eload -f dump.bin",
    "hf mf esave -f dump.bin",
    "hf mf eset --blk 1 -d 000102",
    "hf legic eload -f dump.bin",
]

ATTACK_COMMANDS = [
    "hf mf nested --1k --blk 0 -a -k FFFFFFFFFFFF",
    "hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta",
    "hf mf staticnested --1k -k FFFFFFFFFFFF",
    "hf mf darkside",
    "hf mf autopwn",
    "hf iclass loclass -f iclass_mac_attack.bin",
    "lf t55xx bruteforce --r1 0 --r2 100",
    "lf t55xx recoverpw",
    "hf 14a sniff",
    "hf mf sniff",
    "lf sniff",
]

HOST_COMMANDS = [
    "script run dumptoemul",
    "mem spiffs dump -f x",
    "hw setmux -h",
    "pref set savepaths --dump /tmp",
    "sc upgrade -f sim011.bin",
    "hf mf dump && rm -rf /",
    "hw version; hf mf wrbl",
    "hw version | tee /tmp/out",
    "hw version $(whoami)",
    "hw version `id`",
    "hw version\nhf mf wrbl --blk 0",
]

ALL_FORBIDDEN = (
    WRITE_COMMANDS
    + RAW_COMMANDS
    + CLONE_COMMANDS
    + EMULATION_COMMANDS
    + ATTACK_COMMANDS
    + HOST_COMMANDS
)


@pytest.mark.parametrize("command", ALL_FORBIDDEN)
def test_forbidden_commands_are_rejected(command: str) -> None:
    """No write / clone / emulate / attack / host command may pass the guard."""
    assert guard.is_allowed(command) is False
    with pytest.raises(GuardViolation):
        guard.validate(command)


@pytest.mark.parametrize("command", WRITE_COMMANDS + CLONE_COMMANDS + EMULATION_COMMANDS)
def test_write_family_is_caught_by_the_deny_layer(command: str) -> None:
    """Writing vocabulary must be caught by the deny layer, not just the allow-list.

    This proves defence in depth: even if a bad rule were added to the
    allow-list by mistake, these commands would still be refused.
    """
    with pytest.raises(GuardViolation) as excinfo:
        guard.validate(command)
    assert excinfo.value.layer == "deny"


def test_no_allowed_rule_contains_a_forbidden_verb() -> None:
    """The allow-list itself must not smuggle in a dangerous verb."""
    for rule in guard.ALLOWED_RULES:
        for token in rule.prefix:
            assert token not in guard.FORBIDDEN_TOKENS, f"{rule.name} contains {token!r}"


def test_every_allowed_rule_validates_itself() -> None:
    """Each rule's bare prefix must be accepted (no unreachable rules)."""
    for rule in guard.ALLOWED_RULES:
        assert guard.is_allowed(rule.name), f"{rule.name} is unreachable"


# --------------------------------------------------------------------------- #
# Commands that must work
# --------------------------------------------------------------------------- #
ALLOWED = [
    "hw version",
    "hw status",
    "hw tune",
    "hf search",
    "lf search",
    "hf 14a info",
    "hf 14b info",
    "hf 15 info",
    "hf mf info",
    "hf mfu info",
    "hf mfdes info",
    "hf iclass info",
    "lf t55xx detect",
    "hf mf rdbl --blk 4 -k FFFFFFFFFFFF -a",
    "hf mf rdsc -s 0 -k A0A1A2A3A4A5 -b",
    "hf mfu rdbl -b 4",
    "hf 15 dump --ns",
    "hf mfu dump --ns",
]


@pytest.mark.parametrize("command", ALLOWED)
def test_read_commands_are_allowed(command: str) -> None:
    assert guard.validate(command) == " ".join(command.split())


def test_whitespace_is_normalised() -> None:
    assert guard.validate("  hf   14a    info ") == "hf 14a info"


def test_case_is_accepted_but_values_are_preserved() -> None:
    assert guard.validate("HF 14A INFO") == "HF 14A INFO"
    assert guard.validate("hf mf rdbl --blk 4 -k a0a1a2a3a4a5 -a").endswith("a0a1a2a3a4a5 -a")


# --------------------------------------------------------------------------- #
# Argument validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "command",
    [
        "hf mf rdbl --blk 4 -k ZZZZZZZZZZZZ -a",     # non-hex key
        "hf mf rdbl --blk 4 -k FFFF -a",             # short key
        "hf mf rdbl --blk notanumber -k FFFFFFFFFFFF",
        "hf mf rdbl --blk 4 -k FFFFFFFFFFFF --unknown-flag",
        "hf 14a info --port /dev/ttyACM0",           # flag not on this rule
        "hf mf rdbl --blk",                          # option without a value
        "hf 15 dump -f ../../etc/passwd",            # path traversal in a filename
        "hf 15 dump -f /etc/passwd",
        "hf 14a info extra-positional",
    ],
)
def test_bad_arguments_are_rejected(command: str) -> None:
    with pytest.raises(GuardViolation) as excinfo:
        guard.validate(command)
    assert excinfo.value.layer in {"allow", "lexical", "deny"}


@pytest.mark.parametrize(
    "command",
    ["", "   ", "hf 14a info; rm -rf /", "hf 14a info && whoami", "hf 14a info > /tmp/x",
     "hf 14a info 'quoted'", 'hf 14a info "quoted"', "hf 14a info\\;id", "hf 14a info*"],
)
def test_lexical_layer_rejects_shell_metacharacters(command: str) -> None:
    with pytest.raises(GuardViolation) as excinfo:
        guard.validate(command)
    assert excinfo.value.layer in {"lexical", "deny", "allow"}


def test_overlong_commands_are_rejected() -> None:
    with pytest.raises(GuardViolation) as excinfo:
        guard.validate("hf 14a info " + "-v " * 200)
    assert excinfo.value.layer == "lexical"


def test_unknown_command_is_rejected() -> None:
    with pytest.raises(GuardViolation) as excinfo:
        guard.validate("hf notarealcommand info")
    assert excinfo.value.layer == "allow"


def test_violations_are_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Every rejection must leave an audit trail."""
    with caplog.at_level("WARNING", logger="rfideye.guard"):
        with pytest.raises(GuardViolation):
            guard.validate("hf mf wrbl --blk 4 -k FFFFFFFFFFFF -d 00")
    assert any("BLOCKED" in record.message for record in caplog.records)


def test_non_string_input_is_rejected() -> None:
    with pytest.raises(GuardViolation):
        guard.validate(None)  # type: ignore[arg-type]


def test_allowed_commands_helper_is_sorted_and_complete() -> None:
    names = [rule.name for rule in guard.allowed_commands()]
    assert names == sorted(names)
    assert len(names) == len(guard.ALLOWED_RULES)
