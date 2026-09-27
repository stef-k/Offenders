"""Read-only validation of exact finding targets against retained evidence only."""
from __future__ import annotations

import configparser
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import tempfile

from offenders_fail2ban import CommandFailure, run_host_command
from offenders_findings import FilterMatch, FindingDecision, FindingInventory

# Independent budgets for each pass; stdout is capped after the runner captures it.
SAMPLE_BYTES = 64 * 1024
SAMPLE_RECORDS = 40
OUTPUT_BYTES = 256 * 1024
OPTIONS_FALLBACK = "effective jail filter options were not reproduced; base filter was validated"


@dataclass(frozen=True)
class SampleResult:
    """Logical sample sizes and aggregate physical-line counts, never record matches."""

    available_records: int = 0
    selected_records: int = 0
    written_bytes: int = 0
    tested_lines: int | None = None
    ignored_lines: int | None = None
    matched_lines: int | None = None
    missed_lines: int | None = None
    examples: tuple[str, ...] = ()
    truncated: bool = False
    limitations: tuple[str, ...] = ()
    failure: CommandFailure | None = None
    detail: str = ""


@dataclass(frozen=True)
class FilterValidation:
    """Separate immutable evidence; custom temp arguments expire after this call."""

    decision: FindingDecision
    target_kind: str
    jail_name: str | None = None
    filter_stem: str | None = None
    filter_argument: str | None = None
    effective_options_reproduced: bool = False
    custom_sha256: str | None = None
    custom_bytes: int | None = None
    validated_at: datetime | None = None
    target: SampleResult = SampleResult()
    context: SampleResult | None = None
    state: str = "unavailable"
    limitations: tuple[str, ...] = ()


def _clip(text: str, size: int = 300) -> str:
    """Bound UTF-8 retention without emitting an incomplete character."""
    return text.encode("utf-8", errors="replace")[:size].decode("utf-8", errors="ignore")


def _notes(messages) -> tuple[str, ...]:
    """Retain ordered unique bounded limitations, signalling overflow."""
    notes = tuple(dict.fromkeys(_clip(message) for message in messages))
    return notes if len(notes) <= 32 else (*notes[:31], "additional limitations omitted")


def eligible_targets(inventory: FindingInventory, decision: FindingDecision) -> tuple[FilterMatch, ...]:
    """Only exact retained candidate objects expose existing validation targets."""
    if not any(row is decision for row in inventory.findings):
        return ()
    if decision.classification == "existing_disabled_candidate":
        return decision.disabled_candidates
    if decision.classification == "enabled_tuning_question":
        return decision.running_filters
    return ()


def _existing_argument(inventory, target):
    """Resolve exact jail identity; accept only simple literal filter options."""
    definitions = [row for row in inventory.coverage_inventory.static.jails if row.name == target.name]
    if len(definitions) != 1:
        raise ValueError("selected jail definition is missing or ambiguous")
    jail = definitions[0]
    stem = jail.filter_stem
    if stem != target.filter_stem or not stem or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", stem):
        raise ValueError("selected jail has no consistent safe base filter identity")
    raw = jail.filter_raw.replace("%(__name__)s", jail.name)
    # Deliberately narrow: complex quoted regex/options fall back to the base.
    option = r"[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:[A-Za-z0-9_.:/+@-]+|'[A-Za-z0-9_ .:/+@-]*'|\"[A-Za-z0-9_ .:/+@-]*\")"
    safe = (not any(char in raw for char in "\r\n\x00%")
            and re.fullmatch(re.escape(stem) + rf"(?:\[\s*{option}(?:\s*,\s*{option})*\s*\])?", raw))
    return raw if safe else stem, bool(safe), jail.limitations


def _custom_bytes(text: str) -> bytes:
    """Reject include chains, inherited defaults and non-text before any file I/O."""
    if not isinstance(text, str):
        raise ValueError("custom filter must be UTF-8 text, not a filesystem path object")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("custom filter must be valid UTF-8 text") from error
    if len(encoded) > SAMPLE_BYTES or "\x00" in text:
        raise ValueError("custom filter exceeds 64 KiB or contains NUL")
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as error:
        raise ValueError("custom filter is not valid strict INI text") from error
    if (set(parser.sections()) - {"Definition", "Init"} or parser.defaults()
            or not parser.has_section("Definition")
            or not parser.get("Definition", "failregex", fallback="").strip()):
        raise ValueError("custom filter requires Definition/failregex and only optional Init; includes/defaults are forbidden")
    return encoded


def _records(inventory, decision):
    """Join canonical analysis aliases and require every target identity to exist."""
    patterns = inventory.pattern_inventory
    group = decision.group
    analyses = [row for row in patterns.analyses if
                (row.source_kind, row.source_identity, row.family) ==
                (group.source_kind, group.source_identity, group.family)]
    if len(analyses) != 1:
        raise ValueError("matching canonical source/family analysis is missing or ambiguous")
    analysis = analyses[0]
    keys = set(analysis.source_keys)
    records = patterns.evidence_snapshot.records
    ids = set(group.record_ids)
    same_source = [row for row in records if keys.intersection(row.sources)]
    target = [row for row in same_source if row.identity in ids]
    if {row.identity for row in target} != ids:
        raise ValueError("target record identity is missing from the retained source snapshot")
    context = [row for row in same_source if row.identity not in ids]
    notes = [*decision.limitations, *group.limitations, *analysis.limitations,
             *patterns.evidence_snapshot.limitations]
    if patterns.evidence_snapshot.truncated or analysis.state != "analyzed":
        notes.append("upstream evidence is partial/truncated")
    for source in patterns.evidence_snapshot.sources:
        if (source.source.kind, source.source.identity) in keys:
            notes.extend(source.limitations)
            if source.truncated or source.state != "collected":
                notes.append("upstream source evidence is partial/truncated")
    return target, context, notes


def _sample(records):
    """Use snapshot order, omit whole unusable records, and never content-deduplicate."""
    parts, examples, notes = [], [], []
    size = 0
    for record in records:
        if len(parts) == SAMPLE_RECORDS:
            break
        if "\x00" in record.text or not record.text:
            notes.append("NUL/empty record omitted")
            continue
        try:
            data = (record.text if record.text.endswith("\n") else record.text + "\n").encode("utf-8")
        except UnicodeEncodeError:
            notes.append("non-UTF-8 record omitted")
            continue
        if size + len(data) > SAMPLE_BYTES:
            notes.append("whole record omitted by sample byte bound")
            continue
        parts.append(data)
        size += len(data)
        if len(examples) < 3:
            examples.append(_clip(record.text, 512))
        if "\n" in record.text.rstrip("\n") or "\r" in record.text or record.text.endswith("\n\n"):
            notes.append("multiline record: tested lines differ from logical records")
        if record.text_truncated:
            notes.append("upstream record text was truncated")
    truncated = len(parts) < len(records)
    if truncated:
        notes.append("sample bounded or records omitted")
    return b"".join(parts), SampleResult(len(records), len(parts), size,
        examples=tuple(examples), truncated=truncated, limitations=_notes(notes))


def _write(path: Path, data: bytes) -> None:
    """Create private files exclusively inside this operation's secure directory."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)


def _counts(stdout: str) -> tuple[int, int, int, int]:
    """Parse only the newest 256 KiB, requiring one consistent 1.0.2 Lines summary."""
    tail = stdout.encode("utf-8", errors="replace")[-OUTPUT_BYTES:].decode("utf-8", errors="ignore")
    lines = [line.strip() for line in tail.splitlines() if line.lstrip().startswith("Lines:")]
    if len(lines) != 1:
        raise ValueError("missing or duplicate Lines summary")
    match = re.fullmatch(r"Lines: ([0-9]+) lines, ([0-9]+) ignored, ([0-9]+) matched, ([0-9]+) missed", lines[0])
    if not match:
        raise ValueError("malformed Lines summary")
    counts = tuple(int(value) for value in match.groups())
    if sum(counts[1:]) != counts[0]:
        raise ValueError("inconsistent Lines summary arithmetic")
    return counts


def _run_sample(directory, name, data, sample, argument, config_root):
    """One no-DNS/no-sudo command; retain counts or bounded redacted diagnostics."""
    path = directory / name
    _write(path, data)
    result = run_host_command([
        "fail2ban-regex", "--usedns=no", "--encoding=utf-8", "--print-no-missed",
        "--print-no-ignored", "-c", str(config_root), "--", str(path), argument,
    ], timeout=8, sudo=False)
    if result.failure or result.returncode != 0:
        detail = (result.stderr or result.detail or "command failed").replace(str(directory), "<temporary>")
        return replace(sample, failure=result.failure or CommandFailure.NONZERO_EXIT, detail=_clip(detail))
    try:
        tested, ignored, matched, missed = _counts(result.stdout)
    except ValueError as error:
        return replace(sample, detail=_clip(str(error)))
    return replace(sample, tested_lines=tested, ignored_lines=ignored, matched_lines=matched, missed_lines=missed)


def _execute(result, target_records, context_records, custom, config_root):
    """Own both bounded passes and unconditional temporary-directory cleanup."""
    target_data, target = _sample(target_records)
    context_data, context = _sample(context_records)
    notes = [*result.limitations, *target.limitations, *context.limitations]
    if not target_data:
        return replace(result, target=target, limitations=_notes((*notes, "no usable target records")))
    with tempfile.TemporaryDirectory(prefix="offenders-validation-") as temporary:
        directory = Path(temporary)
        argument = result.filter_argument
        if custom is not None:
            filter_path = directory / "candidate.conf"
            _write(filter_path, custom)
            argument = str(filter_path)
        result = replace(result, filter_argument=argument)
        target = _run_sample(directory, "target.log", target_data, target, argument, config_root)
        if target.tested_lines is None:
            return replace(result, target=target, limitations=_notes((*notes, "target validation unavailable")))
        if context_data:
            context = _run_sample(directory, "context.log", context_data, context, argument, config_root)
            if context.tested_lines is None:
                notes.append("context validation unavailable")
        else:
            context = None
            notes.append("no usable context sample; context match counts are unavailable")
    return replace(result, target=target, context=context,
                   state="partial" if notes else "complete", limitations=_notes(notes))


def validate_existing(inventory: FindingInventory, decision: FindingDecision, target: FilterMatch,
                      *, config_root: Path = Path("/etc/fail2ban")) -> FilterValidation:
    """Validate one exact retained existing target; config_root is a test seam only."""
    result = FilterValidation(decision, "existing", validated_at=datetime.now(timezone.utc))
    try:
        if not any(row is target for row in eligible_targets(inventory, decision)):
            raise ValueError("existing target is not attached to the exact candidate decision")
        argument, reproduced, limits = _existing_argument(inventory, target)
        records, context, notes = _records(inventory, decision)
        notes.extend((*limits, *target.limitations))
        if not reproduced:
            notes.append(OPTIONS_FALLBACK)
        result = replace(result, jail_name=target.name, filter_stem=target.filter_stem,
                         filter_argument=argument, effective_options_reproduced=reproduced,
                         limitations=_notes(notes))
        return _execute(result, records, context, None, config_root)
    except (ValueError, OSError) as error:
        return replace(result, limitations=_notes((*result.limitations, _clip(str(error)))))


def validate_custom(inventory: FindingInventory, decision: FindingDecision, text: str,
                    *, config_root: Path = Path("/etc/fail2ban")) -> FilterValidation:
    """Backend-only prospective text validation for the later custom workflow."""
    result = FilterValidation(decision, "custom", validated_at=datetime.now(timezone.utc))
    try:
        if (decision.classification != "custom_gap_candidate"
                or not any(row is decision for row in inventory.findings)):
            raise ValueError("custom text requires the exact custom-gap candidate decision")
        custom = _custom_bytes(text)
        records, context, notes = _records(inventory, decision)
        result = replace(result, custom_sha256=hashlib.sha256(custom).hexdigest(), custom_bytes=len(custom),
                         limitations=_notes(notes))
        return _execute(result, records, context, custom, config_root)
    except (ValueError, OSError) as error:
        return replace(result, limitations=_notes((*result.limitations, _clip(str(error)))))
