"""Read-only command guard - the security kernel of RFIDeye.

Design contract
---------------
No string ever reaches the Proxmark3 unless :func:`validate` returned it.
Validation is *allow-list first*: a command is rejected unless it matches one
of the explicitly enumerated read/identify rules in :data:`ALLOWED_RULES`.

Three independent layers must all pass:

1. **Lexical layer** - the raw string may only contain a conservative
   character set.  Shell metacharacters, quotes, newlines and control
   characters are rejected outright, so a crafted tag name or key file can
   never smuggle a second command into ``pm3 -c``.
2. **Deny layer** - a curated blocklist of verbs associated with writing,
   cloning, emulating, simulating, sniffing or key-recovery attacks.  This is
   redundant with layer 3 by design (defence in depth) but produces far better
   audit logs: we learn *what* was attempted, not just *that* it failed.
3. **Allow layer** - longest-prefix match against :data:`ALLOWED_RULES`, then
   per-rule validation of every remaining flag, option and positional value
   against a regular expression.  Unknown flags are refused.

Every rejection is logged at ``WARNING`` with the offending command, which is
what makes the read-only claim auditable rather than aspirational.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from re import Pattern
from typing import Final

LOGGER: Final[logging.Logger] = logging.getLogger("rfideye.guard")

#: Hard cap on command length; nothing legitimate comes close.
MAX_COMMAND_LENGTH: Final[int] = 200

#: The only characters a command may contain.  Deliberately excludes every
#: shell metacharacter and every quoting character.
_SAFE_CHARS: Final[Pattern[str]] = re.compile(r"^[A-Za-z0-9 _.:,/=+-]+$")

# --------------------------------------------------------------------------- #
# Value patterns used by the rule table
# --------------------------------------------------------------------------- #
P_HEX: Final[Pattern[str]] = re.compile(r"^[0-9A-Fa-f]{2,64}$")
P_KEY6: Final[Pattern[str]] = re.compile(r"^[0-9A-Fa-f]{12}$")  # MIFARE Classic key
P_KEY_ICLASS: Final[Pattern[str]] = re.compile(r"^[0-9A-Fa-f]{16}$")
P_SMALL_INT: Final[Pattern[str]] = re.compile(r"^\d{1,4}$")
#: Filenames are restricted to a *basename* charset - no slashes and no ``..``,
#: which keeps client-side dump files inside the working directory.
P_BASENAME: Final[Pattern[str]] = re.compile(r"^(?!\.\.)[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")


# --------------------------------------------------------------------------- #
# Deny layer
# --------------------------------------------------------------------------- #
#: Tokens that must never appear anywhere in a command.  Grouped by intent so
#: the list stays reviewable.
FORBIDDEN_TOKENS: Final[frozenset[str]] = frozenset(
    {
        # --- writing to a tag ------------------------------------------------
        "write", "wr", "wrbl", "wrsc", "wrkey", "writeblk", "setblk", "restore",
        "load", "cload", "csave", "csetuid", "csetblk", "cwipe", "wipe", "format",
        "value", "incr", "decr", "gen", "setuid", "acl", "lock", "protect",
        "burn", "personalize", "commit", "createapp", "createfile", "deleteapp",
        "deletefile", "changekey", "createvalue", "createrecord",
        # --- cloning ---------------------------------------------------------
        "clone", "copy", "duplicate", "encode",
        # --- emulation / simulation ------------------------------------------
        "sim", "simulate", "eload", "esave", "eset", "eclr", "eview", "eget",
        "eattack", "emu", "emulate", "standalone",
        # --- key-recovery / brute force attacks ------------------------------
        "nested", "hardnested", "staticnested", "darkside", "autopwn", "crack",
        "brute", "bruteforce", "recoverpw", "loclass", "legrec", "nack", "fuzz",
        "dictattack", "keyrecovery",
        # --- passive interception of third-party traffic ---------------------
        "sniff", "snoop", "eavesdrop", "listen",
        # --- host / firmware / arbitrary execution ---------------------------
        "script", "exec", "run", "shell", "pref", "mem", "spiffs", "flash",
        "upgrade", "bootloader", "reboot", "dbg", "setmux", "sc", "smart",
        "trace", "usart", "wiegand", "piv", "emrtd", "vas",
    }
)

#: Substrings that are forbidden regardless of tokenisation, catching things
#: like ``--write``, ``-wrbl`` or ``hf14asim``.
FORBIDDEN_SUBSTRINGS: Final[tuple[str, ...]] = (
    "wrbl", "wrsc", "write", "clone", "restore", "sim", "eload", "esave",
    "nested", "darkside", "autopwn", "loclass", "sniff", "script", "spiffs",
    "flash", "upgrade", "csetuid", "csetblk", "cwipe",
)


class GuardViolation(RuntimeError):
    """Raised when a command is rejected by the read-only guard.

    Attributes:
        command: The offending command, verbatim.
        reason: Human-readable explanation shown in the TUI and the log.
        layer: Which validation layer rejected it (lexical / deny / allow).
    """

    def __init__(self, command: str, reason: str, layer: str) -> None:
        super().__init__(f"[{layer}] {reason}: {command!r}")
        self.command = command
        self.reason = reason
        self.layer = layer


@dataclass(frozen=True, slots=True)
class CommandRule:
    """One whitelisted, read-only Proxmark3 command family.

    Args:
        prefix: The literal command words, e.g. ``("hf", "mf", "rdbl")``.
        summary: One-line description surfaced in the in-app help.
        flags: Boolean switches accepted after the prefix (no value).
        options: Switches that take exactly one value, mapped to the regex the
            value must fully match.
        positionals: Regexes for optional bare arguments, applied in order.
    """

    prefix: tuple[str, ...]
    summary: str
    flags: frozenset[str] = frozenset()
    options: Mapping[str, Pattern[str]] = field(default_factory=dict)
    positionals: tuple[Pattern[str], ...] = ()

    @property
    def name(self) -> str:
        """The command family as a space-separated string."""
        return " ".join(self.prefix)


def _rule(
    command: str,
    summary: str,
    *,
    flags: Sequence[str] = (),
    options: Mapping[str, Pattern[str]] | None = None,
    positionals: Sequence[Pattern[str]] = (),
) -> CommandRule:
    """Small constructor helper that keeps the rule table readable."""
    return CommandRule(
        prefix=tuple(command.split()),
        summary=summary,
        flags=frozenset(flags),
        options=dict(options or {}),
        positionals=tuple(positionals),
    )


# Flags accepted by virtually every Iceman command.
_COMMON_FLAGS: Final[tuple[str, ...]] = ("-v", "--verbose", "-h", "--help")
_MF_AUTH_FLAGS: Final[tuple[str, ...]] = ("-a", "-b", *_COMMON_FLAGS)
_MF_SIZE_FLAGS: Final[tuple[str, ...]] = ("--mini", "--1k", "--2k", "--4k")


# --------------------------------------------------------------------------- #
# Allow layer - the complete list of what RFIDeye may ever do
# --------------------------------------------------------------------------- #
ALLOWED_RULES: Final[tuple[CommandRule, ...]] = (
    # ---- device / diagnostics --------------------------------------------- #
    _rule("hw version", "Report firmware, bootrom and hardware revision", flags=_COMMON_FLAGS),
    _rule("hw status", "Report device status and memory usage", flags=_COMMON_FLAGS),
    _rule("hw ping", "Liveness check", flags=_COMMON_FLAGS),
    _rule("hw tune", "Measure LF/HF antenna tuning voltages", flags=_COMMON_FLAGS),
    # ---- generic search ---------------------------------------------------- #
    _rule("lf search", "Identify any LF tag in the field", flags=("-1", "-u", *_COMMON_FLAGS)),
    _rule("hf search", "Identify any HF tag in the field", flags=_COMMON_FLAGS),
    # ---- LF readers (all passive, all read-only) --------------------------- #
    _rule("lf read", "Sample the raw LF waveform", flags=("-s", *_COMMON_FLAGS),
          options={"-d": P_SMALL_INT}),
    _rule("lf em 410x reader", "Read an EM410x tag", flags=_COMMON_FLAGS),
    _rule("lf em 4x05 info", "Read EM4x05/EM4x69 configuration blocks", flags=_COMMON_FLAGS),
    _rule("lf hid reader", "Read an HID Prox credential", flags=_COMMON_FLAGS),
    _rule("lf indala reader", "Read an Indala credential", flags=("--raw", *_COMMON_FLAGS)),
    _rule("lf awid reader", "Read an AWID credential", flags=_COMMON_FLAGS),
    _rule("lf io reader", "Read an ioProx credential", flags=_COMMON_FLAGS),
    _rule("lf paradox reader", "Read a Paradox credential", flags=_COMMON_FLAGS),
    _rule("lf pyramid reader", "Read a Farpointe/Pyramid credential", flags=_COMMON_FLAGS),
    _rule("lf viking reader", "Read a Viking tag", flags=_COMMON_FLAGS),
    _rule("lf noralsy reader", "Read a Noralsy tag", flags=_COMMON_FLAGS),
    _rule("lf jablotron reader", "Read a Jablotron tag", flags=_COMMON_FLAGS),
    _rule("lf keri reader", "Read a KERI tag", flags=_COMMON_FLAGS),
    _rule("lf nexwatch reader", "Read a NexWatch/Quadrakey tag", flags=_COMMON_FLAGS),
    _rule("lf gallagher reader", "Read a Gallagher credential", flags=_COMMON_FLAGS),
    _rule("lf securakey reader", "Read a Securakey credential", flags=_COMMON_FLAGS),
    _rule("lf visa2000 reader", "Read a Visa2000 tag", flags=_COMMON_FLAGS),
    _rule("lf motorola reader", "Read a Motorola tag", flags=_COMMON_FLAGS),
    _rule("lf fdxb reader", "Read an FDX-B animal transponder", flags=_COMMON_FLAGS),
    _rule("lf hitag info", "Read Hitag configuration", flags=_COMMON_FLAGS),
    _rule("lf t55xx detect", "Detect T55xx modulation and configuration", flags=_COMMON_FLAGS),
    _rule("lf t55xx info", "Decode the T55xx configuration block", flags=_COMMON_FLAGS),
    _rule("lf t55xx dump", "Read every T55xx block", flags=_COMMON_FLAGS),
    # ---- HF: ISO14443-A ---------------------------------------------------- #
    _rule("hf 14a info", "UID / ATQA / SAK / ATS of an ISO14443-A tag",
          flags=("-v", "--verbose")),
    _rule("hf 14a reader", "Poll for ISO14443-A tags", flags=_COMMON_FLAGS),
    # ---- HF: ISO14443-B (Calypso transport cards live here) ---------------- #
    _rule("hf 14b info", "PUPI / ATQB / protocol info of an ISO14443-B tag",
          flags=("-v", "--verbose")),
    _rule("hf 14b reader", "Poll for ISO14443-B tags", flags=_COMMON_FLAGS),
    _rule("hf 14b sriread", "Read the public blocks of an SRI/SRIX memory tag",
          flags=_COMMON_FLAGS),
    # ---- HF: ISO15693 ------------------------------------------------------ #
    _rule("hf 15 info", "Identify an ISO15693 (vicinity) tag", flags=_COMMON_FLAGS),
    _rule("hf 15 reader", "Poll for ISO15693 tags", flags=_COMMON_FLAGS),
    _rule("hf 15 dump", "Read every readable ISO15693 block",
          flags=("--ns", *_COMMON_FLAGS), options={"-f": P_BASENAME}),
    # ---- HF: MIFARE Classic ------------------------------------------------ #
    _rule("hf mf info", "Identify a MIFARE Classic family tag", flags=_COMMON_FLAGS),
    _rule(
        "hf mf rdbl",
        "Read one MIFARE Classic block with a supplied key",
        flags=_MF_AUTH_FLAGS,
        options={"--blk": P_SMALL_INT, "-k": P_KEY6},
    ),
    _rule(
        "hf mf rdsc",
        "Read one MIFARE Classic sector with a supplied key",
        flags=_MF_AUTH_FLAGS,
        options={"-s": P_SMALL_INT, "--sec": P_SMALL_INT, "-k": P_KEY6},
    ),
    _rule(
        "hf mf chk",
        "Test user-supplied keys against a tag you own (not a recovery attack)",
        flags=("-a", "-b", *_MF_SIZE_FLAGS, *_COMMON_FLAGS),
        options={"-k": P_KEY6, "-f": P_BASENAME, "--blk": P_SMALL_INT},
    ),
    # ---- HF: MIFARE Ultralight / NTAG -------------------------------------- #
    _rule("hf mfu info", "Identify a MIFARE Ultralight / NTAG tag",
          flags=("-l", *_COMMON_FLAGS), options={"-k": P_HEX}),
    _rule("hf mfu rdbl", "Read one Ultralight/NTAG page",
          flags=("-l", *_COMMON_FLAGS), options={"-b": P_SMALL_INT, "-k": P_HEX}),
    _rule("hf mfu dump", "Read every readable Ultralight/NTAG page",
          flags=("-l", "--ns", *_COMMON_FLAGS), options={"-k": P_HEX, "-f": P_BASENAME}),
    # ---- HF: MIFARE DESFire (very common on transit cards) ----------------- #
    _rule("hf mfdes info", "Identify a MIFARE DESFire tag", flags=_COMMON_FLAGS),
    _rule("hf mfdes getuid", "Read the DESFire UID", flags=_COMMON_FLAGS),
    _rule("hf mfdes lsapp", "List DESFire application IDs",
          flags=("--no-auth", *_COMMON_FLAGS)),
    _rule("hf mfdes lsfiles", "List files inside a DESFire application",
          flags=("--no-auth", *_COMMON_FLAGS), options={"--aid": P_HEX}),
    # ---- HF: MIFARE Plus ---------------------------------------------------- #
    _rule("hf mfp info", "Identify a MIFARE Plus tag", flags=_COMMON_FLAGS),
    # ---- HF: iCLASS --------------------------------------------------------- #
    _rule("hf iclass info", "Identify an iCLASS / PicoPass tag", flags=_COMMON_FLAGS),
    _rule("hf iclass reader", "Poll for iCLASS tags", flags=_COMMON_FLAGS),
    _rule("hf iclass rdbl", "Read one iCLASS block with a supplied key",
          flags=("--elite", "--raw", *_COMMON_FLAGS),
          options={"--blk": P_SMALL_INT, "-k": P_KEY_ICLASS}),
    # ---- HF: misc identification -------------------------------------------- #
    _rule("hf topaz info", "Identify a Topaz / Jewel tag", flags=_COMMON_FLAGS),
    _rule("hf felica info", "Identify a FeliCa tag", flags=_COMMON_FLAGS),
    _rule("hf legic info", "Identify a LEGIC Prime tag", flags=_COMMON_FLAGS),
)

#: Rules sorted by prefix length, longest first, so ``hf mf rdbl`` wins over a
#: hypothetical ``hf mf`` rule during matching.
_RULES_BY_LENGTH: Final[tuple[CommandRule, ...]] = tuple(
    sorted(ALLOWED_RULES, key=lambda r: len(r.prefix), reverse=True)
)


def allowed_commands() -> Iterator[CommandRule]:
    """Yield every whitelisted rule, sorted alphabetically (for help screens)."""
    yield from sorted(ALLOWED_RULES, key=lambda r: r.name)


def _check_lexical(command: str) -> None:
    """Layer 1: reject anything that is not a plain, single, printable command."""
    if not isinstance(command, str) or not command.strip():
        raise GuardViolation(str(command), "empty command", "lexical")
    if len(command) > MAX_COMMAND_LENGTH:
        raise GuardViolation(
            command, f"command exceeds {MAX_COMMAND_LENGTH} characters", "lexical"
        )
    if not _SAFE_CHARS.match(command):
        raise GuardViolation(
            command,
            "command contains characters outside the safe set "
            "(shell metacharacters and quotes are never allowed)",
            "lexical",
        )


def _check_denylist(command: str, tokens: Sequence[str]) -> None:
    """Layer 2: refuse known write / clone / emulate / attack vocabulary."""
    lowered = command.lower()
    for token in tokens:
        stripped = token.lstrip("-").lower()
        if stripped in FORBIDDEN_TOKENS:
            raise GuardViolation(command, f"'{stripped}' is a non-read-only operation", "deny")
    collapsed = lowered.replace(" ", "")
    for fragment in FORBIDDEN_SUBSTRINGS:
        if fragment in collapsed:
            raise GuardViolation(
                command, f"command contains the forbidden fragment '{fragment}'", "deny"
            )


def _match_rule(command: str, tokens: Sequence[str]) -> tuple[CommandRule, list[str]]:
    """Layer 3a: longest-prefix match against the allow-list."""
    lowered = [token.lower() for token in tokens]
    for rule in _RULES_BY_LENGTH:
        span = len(rule.prefix)
        if tuple(lowered[:span]) == rule.prefix:
            return rule, list(tokens[span:])
    raise GuardViolation(command, "command is not on the read-only allow-list", "allow")


def _check_arguments(command: str, rule: CommandRule, args: Sequence[str]) -> None:
    """Layer 3b: validate every flag, option value and positional argument."""
    index = 0
    positional_index = 0
    while index < len(args):
        arg = args[index]
        if arg.startswith("-"):
            key, separator, inline = arg.partition("=")
            value: str | None = inline if separator else None

            if key in rule.options:
                if value is None:
                    index += 1
                    if index >= len(args):
                        raise GuardViolation(command, f"option '{key}' requires a value", "allow")
                    value = args[index]
                if not rule.options[key].match(value):
                    raise GuardViolation(
                        command, f"value {value!r} is not valid for option '{key}'", "allow"
                    )
            elif key in rule.flags:
                if value is not None:
                    raise GuardViolation(command, f"flag '{key}' does not take a value", "allow")
            else:
                raise GuardViolation(
                    command, f"flag '{key}' is not accepted by '{rule.name}'", "allow"
                )
        else:
            if positional_index >= len(rule.positionals):
                raise GuardViolation(command, f"unexpected positional argument {arg!r}", "allow")
            if not rule.positionals[positional_index].match(arg):
                raise GuardViolation(command, f"invalid positional argument {arg!r}", "allow")
            positional_index += 1
        index += 1


def validate(command: str) -> str:
    """Validate a Proxmark3 command and return its normalised form.

    Args:
        command: The candidate command, e.g. ``hf mf rdbl --blk 4 -k FFFFFFFFFFFF``.

    Returns:
        The command with collapsed whitespace, safe to hand to the ``pm3`` client.

    Raises:
        GuardViolation: If any of the three validation layers rejects it.  The
            attempt is logged at ``WARNING`` before the exception propagates.
    """
    try:
        _check_lexical(command)
        tokens = command.split()
        _check_denylist(command, tokens)
        rule, args = _match_rule(command, tokens)
        _check_arguments(command, rule, args)
    except GuardViolation as exc:
        LOGGER.warning("BLOCKED (%s) %s -> %s", exc.layer, exc.command, exc.reason)
        raise

    normalised = " ".join(tokens)
    LOGGER.debug("allowed: %s (rule: %s)", normalised, rule.name)
    return normalised


def is_allowed(command: str) -> bool:
    """Return ``True`` if :func:`validate` would accept ``command``."""
    try:
        validate(command)
    except GuardViolation:
        return False
    return True
