"""Fixed last-resort review candidates over exact retained findings; no host writes."""
from dataclasses import dataclass, replace
import hashlib
from pathlib import PurePosixPath
import re

from offenders_findings import COMPATIBILITY, FindingDecision, FindingInventory
from offenders_validation import FilterValidation, validate_custom

# Fixed path fragments, never interpolated from observed log content. Percent
# signs are doubled for Fail2Ban's INI interpolation. Traversal decoding is bounded
# to literal, encoded and double-encoded dots/separators, like #31's recognizer.
_SEP = r"(?:/|\\|%%2[fF]|%%5[cC]|%%252[fF]|%%255[cC])"
_DOT = r"(?:\.|%%2[eE]|%%252[eE])"
PATHS = {
    "sensitive_dotfile": r"/(?:[^\s\"?#]*/)?(?i:\.env(?:\.[^/\s\"?#]*)?|\.(?:git|svn|hg))(?=[/?#\s\"])",
    "path_traversal": rf"/(?:[^\s\"?#]*{_SEP})?{_DOT}{_DOT}(?={_SEP}|[?#\s\"])",
}
CATALOG = {f"{family}:path_probe:{category}": (family, category,
           f"offenders-{family}-{category.replace('_', '-')}")
           for family in ("nginx", "apache") for category in PATHS}
DATEPATTERN = r"""datepattern = {^LN-BEG}%%ExY(?P<_sep>[-/.])%%m(?P=_sep)%%d[T ]%%H:%%M:%%S(?:[.,]%%f)?(?:\s*%%z)?
              ^[^\[]*\[({DATE})
              {^LN-BEG}
"""
ACCESS = r'^\s*<HOST> - \S+ (?:\[\]\s+)?"[A-Z]+ <path>[^\s"]* HTTP/\d(?:\.\d)?" 4\d\d(?:\s.*)?$'
NGINX_ERROR = (r'^\s*\[error\] \d+#\d+: \*\d+ (?:open\(\) "[^"\r\n]*" failed|"[^"\r\n]*" is not found) '
               r'\(2: No such file or directory\), client: <HOST>, server: [^,]*, '
               r'request: "[A-Z]+ <path>[^\s"]* HTTP/\d(?:\.\d)?"(?:, .*)?$')


@dataclass(frozen=True)
class CustomCandidate:
    """Withheld results retain evidence but never retain either generated snippet."""

    decision: FindingDecision
    state: str = "withheld"
    template_id: str | None = None
    name: str | None = None
    source_kind: str | None = None
    source_identity: str | None = None
    filter_text: str | None = None
    jail_text: str | None = None
    validation: FilterValidation | None = None
    filter_sha256: str | None = None
    filter_bytes: int | None = None
    reason: str = ""
    limitations: tuple[str, ...] = ()


def _line(text: str) -> str:
    """Bound evidence comments to one printable line, including terminal safety."""
    return " ".join("".join(c if c.isprintable() else " " for c in text).split())[:300]


def _source(decision):
    """Use only same-family canonical targets, retaining configured file aliases."""
    group = decision.group
    identities = set()
    for target in decision.coverage_targets:
        source = target.source
        canonical = (source.resolved_path or source.identity) if source.kind == "file" else source.identity
        if (source.kind == group.source_kind and canonical == group.source_identity
                and target.association and target.association.family == group.family):
            identities.add(source.identity)
    if len(identities) != 1:
        raise ValueError("source wiring is missing or ambiguous (configured aliases)")
    identity = identities.pop()
    if not identity or any(not c.isprintable() for c in identity):
        raise ValueError("unsafe source identity: control characters")
    if group.source_kind == "file":
        # Fail closed for INI interpolation, multi-path/glob and inline comment
        # syntax: the snippet must select the exact retained file identity.
        if (not PurePosixPath(identity).is_absolute() or any(c in identity for c in '%*?[]#;')
                or any(c.isspace() for c in identity)):
            raise ValueError("unsafe source identity: requires a literal absolute file path")
    elif group.source_kind == "journal":
        if identity != group.source_identity or not re.fullmatch(r"[A-Za-z0-9_.@:-]+", identity):
            raise ValueError("unsafe journal unit identity")
    else:
        raise ValueError("unsupported source kind")
    return group.source_kind, identity


def _filter(family, category, source_kind, identity):
    """Build only self-contained Definition/Init text selected by the fixed catalog."""
    regexes = ACCESS + ("\n            " + NGINX_ERROR if family == "nginx" else "")
    journal = f"journalmatch = _SYSTEMD_UNIT={identity}\n" if source_kind == "journal" else ""
    return ("# Fixed candidate for operator review; not installed/enabled by Offenders.\n"
            f"# Template: {family}/{category}\n[Definition]\nfailregex = {regexes}\n"
            f"ignoreregex =\n{DATEPATTERN}{journal}\n[Init]\npath = {PATHS[category]}\n")


def _counts(label, sample):
    """Render parsed counts without interpreting context as a known-clean corpus."""
    if sample is None or sample.tested_lines is None:
        return f"{label} unavailable"
    return (f"{label} tested={sample.tested_lines} matched={sample.matched_lines} "
            f"missed={sample.missed_lines} ignored={sample.ignored_lines}")


def _jail(result):
    """Disabled minimal wiring, with factual validation comments and inherited policy."""
    validation = result.validation
    comments = (f"Service: {result.decision.group.family}",
                f"Source: {result.source_kind} {result.source_identity}",
                f"Finding: {result.decision.reason}", f"Filter SHA-256: {result.filter_sha256}",
                _counts("Target", validation.target), _counts("Context", validation.context),
                f"Validation: {validation.state}",
                "fail2ban-regex validated the filter sample only; jail wiring was not activated or daemon-tested.",
                "Ban settings inherit local defaults; explicit operator review is required before future enablement.")
    wiring = (f"logpath = {result.source_identity}\n" if result.source_kind == "file" else "backend = systemd\n")
    return ("\n".join("# " + _line(line) for line in comments)
            + f"\n[{result.name}]\nenabled = false\nport = http,https\nusedns = no\n"
            + f"filter = {result.name}\n{wiring}")


def generate_candidate(inventory: FindingInventory, decision: FindingDecision) -> CustomCandidate:
    """Validate exact fixed bytes once; expose snippets only after full target matching."""
    result = CustomCandidate(decision, limitations=decision.limitations)
    if (not any(row is decision for row in inventory.findings)
            or decision.classification != "custom_gap_candidate"):
        return replace(result, reason="requires the exact retained custom-gap decision")
    group = decision.group
    template = CATALOG.get(group.signature)
    if not template or group.family != template[0] or group.pattern_kind != "path_probe":
        known = (group.pattern_kind in COMPATIBILITY or group.signature in COMPATIBILITY
                 or group.signature == f"{group.family}:path_probe:wordpress_auth")
        reason = ("known stock/partially-overlapping definition should be investigated/restored first"
                  if known else "unsupported fixed template signature")
        return replace(result, reason=reason)
    family, category, name = template
    result = replace(result, template_id=group.signature, name=name)
    static = inventory.coverage_inventory.static
    if any(row.name == name for row in (*static.jails, *static.filters)):
        return replace(result, reason="candidate name collides with a retained jail/filter definition")
    try:
        kind, identity = _source(decision)
    except ValueError as error:
        return replace(result, reason=str(error))
    result = replace(result, source_kind=kind, source_identity=identity)
    text = _filter(family, category, kind, identity)
    encoded = text.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    validation = validate_custom(inventory, decision, text)
    limits = tuple(dict.fromkeys((*decision.limitations, *validation.limitations)))
    result = replace(result, validation=validation, filter_sha256=digest,
                     filter_bytes=len(encoded), limitations=limits)
    if (validation.decision is not decision or validation.target_kind != "custom"
            or validation.custom_sha256 != digest or validation.custom_bytes != len(encoded)):
        return replace(result, reason="internal integrity failure: validation identity/fingerprint mismatch")
    target = validation.target
    if (validation.state not in ("complete", "partial") or target.tested_lines is None
            or target.tested_lines <= 0 or target.matched_lines != target.tested_lines
            or target.missed_lines != 0 or target.ignored_lines != 0):
        return replace(result, reason="fixed template did not prove complete bounded target-sample coverage; validation may be unavailable")
    return replace(result, state="reviewable", filter_text=text, jail_text=_jail(result))
