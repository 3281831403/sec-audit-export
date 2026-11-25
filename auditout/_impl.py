"""Audit log export pipeline.

The public surface covers batching, masking, field selection, single batch
export, merging, digest verification, plan validation and multi-job exports.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from typing import Any

__all__ = [
    "plan_batches",
    "mask_record",
    "select_fields",
    "export_batch",
    "merge_batches",
    "verify_export",
    "validate_plan",
    "export_batch_jobs",
]

_MISSING = object()


def _coerce_record(record: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise TypeError("record 必须是映射对象")
    return dict(record)


def _policy_dict(policy: Mapping[str, Any] | None) -> dict[str, Any]:
    if policy is None:
        return {}
    if not isinstance(policy, Mapping):
        raise TypeError("policy 必须是映射对象")
    return dict(policy)


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _digest_records(records: Sequence[Mapping[str, Any]]) -> str:
    return _sha256(list(records))


def _digest_batches(batches: Sequence[Mapping[str, Any]]) -> str:
    payload = []
    for batch in batches:
        payload.append(
            {
                "index": batch.get("index"),
                "total": batch.get("total"),
                "count": batch.get("count"),
                "records": batch.get("records", []),
            }
        )
    return _sha256(payload)


def _mask_keep(value: Any, left: int, right: int, char: str = "*") -> str:
    text = str(value)
    size = len(text)
    if size == 0:
        return text
    left = max(0, min(int(left), size))
    right = max(0, min(int(right), size - left))
    if left + right >= size:
        if size == 1:
            return char
        if left >= right and left > 0:
            left -= 1
        elif right > 0:
            right -= 1
        else:
            return char * size
    middle = size - left - right
    suffix = text[size - right :] if right else ""
    return text[:left] + char * middle + suffix


def _mask_phone(value: Any) -> str:
    text = str(value)
    size = len(text)
    if size <= 1:
        return "*" * size
    left = min(3, max(0, size - 2))
    right = min(4, max(0, size - left - 1))
    middle = size - left - right
    return text[:left] + "*" * middle + text[size - right :]


def _mask_email(value: Any) -> str:
    text = str(value)
    if "@" not in text:
        return _mask_keep(text, 1, 1)
    local, domain = text.rsplit("@", 1)
    if not local:
        return "*@" + domain
    if len(local) == 1 and domain:
        return local + "@" + "*" + domain[1:]
    return local[0] + "*" * (len(local) - 1) + "@" + domain


def _mask_value(value: Any, rule: Any) -> Any:
    if rule is None:
        return copy.deepcopy(value)
    if callable(rule):
        return rule(value)
    if isinstance(rule, Mapping):
        kind = rule.get("type") or rule.get("rule") or rule.get("using")
        if kind is not None and str(kind).lower() not in {"keep", "partial", "custom"}:
            return _mask_value(value, kind)
        left = int(rule.get("keep_left", rule.get("left", 1)))
        right = int(rule.get("keep_right", rule.get("right", 1)))
        char = str(rule.get("mask_char", "*"))[:1] or "*"
        return _mask_keep(value, left, right, char)
    name = str(rule).lower()
    if name in {"phone", "mobile", "tel"}:
        return _mask_phone(value)
    if name in {"email", "mail"}:
        return _mask_email(value)
    if name in {"name", "person"}:
        return _mask_keep(value, 1, 0)
    if name in {"all", "full"}:
        return "*" * len(str(value))
    return _mask_keep(value, 1, 1)


def _mask_compact(value: Any, rule: Any) -> str:
    return "***"


def _split_path(path: Any) -> list[str]:
    if not isinstance(path, str) or not path:
        return []
    return path.split(".")


def _lookup(record: Mapping[str, Any], parts: Sequence[str]) -> Any:
    current: Any = record
    for part in parts:
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _assign(
    container: dict[str, Any],
    parts: Sequence[str],
    value: Any,
    *,
    create: bool = False,
) -> None:
    current: dict[str, Any] = container
    for part in parts[:-1]:
        if part not in current:
            if not create:
                return
            current[part] = {}
        child = current[part]
        if not isinstance(child, dict):
            if not create:
                return
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = value


def plan_batches(
    records: Sequence[Any],
    size: int | None = None,
    *,
    batch_size: int | None = None,
) -> list[dict[str, Any]]:
    """Split records into numbered batches."""
    if batch_size is not None:
        if size is not None and size != batch_size:
            raise ValueError("size 与 batch_size 必须一致")
        size = batch_size
    if size is None:
        raise TypeError("plan_batches() 缺少批大小参数")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError("size 必须为正整数")
    items = list(records)
    batch_count = (len(items) + size - 1) // size
    plan: list[dict[str, Any]] = []
    for offset in range(batch_count):
        chunk = items[offset * size : (offset + 1) * size]
        plan.append(
            {
                "index": offset + 1,
                "total": batch_count,
                "count": len(chunk),
                "records": chunk,
            }
        )
    return plan


def mask_record(record: Mapping[str, Any], policy: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a masked copy of a record according to the field policy."""
    source = _coerce_record(record)
    result = copy.deepcopy(source)
    rules = _policy_dict(policy).get("mask") or {}
    if not isinstance(rules, Mapping):
        raise TypeError("policy.mask 必须是映射对象")
    for field, rule in rules.items():
        parts = _split_path(field)
        if not parts or _lookup(result, parts) is _MISSING:
            continue
        current_value = _lookup(result, parts)
        _assign(result, parts, _mask_value(current_value, rule), create=False)
    return result


def select_fields(record: Mapping[str, Any], allowed: Sequence[str] | str | Mapping[str, Any] | None) -> dict[str, Any]:
    """Return only the field paths named by allowed."""
    source = _coerce_record(record)
    if isinstance(allowed, Mapping):
        allowed = allowed.get("allowed_fields")
    if allowed is None:
        return copy.deepcopy(source)
    if isinstance(allowed, str):
        allowed = [allowed]
    elif isinstance(allowed, (set, frozenset)):
        allowed = sorted(allowed)

    selected: dict[str, Any] = {}
    for path in allowed:
        parts = _split_path(path)
        if not parts:
            continue
        value = _lookup(source, parts)
        if value is _MISSING:
            continue
        _assign(selected, parts, copy.deepcopy(value), create=True)
    return selected


def export_batch(batch: Mapping[str, Any], policy: Mapping[str, Any] | None) -> dict[str, Any]:
    """Export one batch with its batch-wide digest."""
    if not isinstance(batch, Mapping):
        raise TypeError("batch 必须是映射对象")
    source = batch.get("records", [])
    if isinstance(source, (str, bytes)) or not isinstance(source, Sequence):
        raise TypeError("batch.records 必须是序列")
    job_policy = _policy_dict(policy)
    allowed_fields = job_policy.get("allowed_fields")
    exported: list[dict[str, Any]] = []
    for record in source:
        masked = mask_record(record, job_policy)
        exported.append(select_fields(masked, allowed_fields))

    working = batch if isinstance(batch, dict) else dict(batch)
    index = int(working.get("index", 1))
    total = int(working.get("total", 1))
    digest = _digest_records(exported)

    # ``_export_sink`` is the small in-repository write boundary.  Record the
    # digest already written for this batch/index so retrying the same batch
    # appends its records at most once.
    sink = working.setdefault("_export_sink", [])
    already_written = working.get("_exported_digest") == digest
    if isinstance(sink, list) and not already_written:
        sink.extend(copy.deepcopy(exported))
    working["_exported_digest"] = digest

    records_out = copy.deepcopy(exported)
    return {
        "index": index,
        "total": total,
        "count": len(records_out),
        "records": records_out,
        "digest": digest,
    }


def merge_batches(batches: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Merge batches into one record list after checking batch order."""
    items = list(batches)
    if not items:
        return []
    ordered = sorted(
        items,
        key=lambda item: item.get("index", 0) if isinstance(item, Mapping) else 0,
    )
    merged: list[dict[str, Any]] = []
    for position, batch in enumerate(ordered, start=1):
        if not isinstance(batch, Mapping):
            raise ValueError("批次必须是映射对象")
        if batch.get("index") != position:
            raise ValueError(f"批次序号缺失或乱序：期望 {position}，实际 {batch.get('index')}")
        merged.extend(copy.deepcopy(list(batch.get("records", []))))
    return merged


def verify_export(export: Mapping[str, Any], digest: str) -> bool:
    """Check an export against the supplied digest."""
    if not isinstance(export, Mapping) or not isinstance(digest, str):
        return False
    stored = export.get("digest")
    if not isinstance(stored, str):
        return False
    try:
        return hmac.compare_digest(stored, digest)
    except TypeError:
        return stored == digest


def validate_plan(plan: Sequence[Mapping[str, Any]], total: int) -> list[str]:
    """Return a list of problems found in a batch plan."""
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        return ["总批次数必须为非负整数"]
    if not isinstance(plan, (list, tuple)):
        return ["计划必须为批次列表"]

    problems: list[str] = []
    if len(plan) != total:
        problems.append(f"批次数不符：期望 {total}，实际 {len(plan)}")

    seen: set[int] = set()
    indexes: list[int] = []
    for position, batch in enumerate(plan, start=1):
        if not isinstance(batch, Mapping):
            problems.append(f"第 {position} 个批次不是映射对象")
            continue
        index = batch.get("index")
        if not isinstance(index, int) or isinstance(index, bool):
            problems.append(f"第 {position} 个批次缺少有效序号")
        else:
            indexes.append(index)
            if index in seen:
                problems.append(f"批次序号重复：{index}")
            seen.add(index)
            if index < 1 or index > total:
                problems.append(f"批次序号越界：{index}")
        if batch.get("total") != total:
            problems.append(
                f"第 {position} 个批次总数标注不符：期望 {total}，实际 {batch.get('total')}"
            )
        records = batch.get("records", [])
        if isinstance(records, (list, tuple)):
            count = batch.get("count", len(records))
            if count != len(records):
                problems.append(f"第 {position} 个批次记录数不符")
        else:
            problems.append(f"第 {position} 个批次缺少记录列表")

    missing = [index for index in range(1, total + 1) if index not in seen]
    if missing:
        problems.append("缺少批次：" + ",".join(str(index) for index in missing))
    if indexes and indexes != list(range(1, len(plan) + 1)):
        problems.append("批次序号不连续")
    return problems


def export_batch_jobs(
    jobs: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Export several independent jobs."""
    base = copy.deepcopy(_policy_dict(policy))
    results: dict[str, dict[str, Any]] = {}

    for job in list(jobs):
        if not isinstance(job, Mapping):
            raise TypeError("job 必须是映射对象")
        task_id = job.get("task_id")
        if task_id is None:
            raise ValueError("job 缺少 task_id")
        task_id = str(task_id)
        records = list(job.get("records") or [])

        job_policy = copy.deepcopy(base)
        base_allowed: Any = (
            job_policy["allowed_fields"]
            if "allowed_fields" in job_policy
            else _MISSING
        )

        # Build the allow-list from this job only.  In particular, never extend
        # a list that is shared with a previous or subsequent job.
        if "fields" in job:
            incoming = job.get("fields")
            if incoming is None:
                allowed: list[str] | None = None
            else:
                allowed = []
                if isinstance(base_allowed, (list, tuple, set, frozenset)):
                    allowed.extend(base_allowed)
                elif isinstance(base_allowed, str):
                    allowed.append(base_allowed)
                if isinstance(incoming, str):
                    allowed.append(incoming)
                elif isinstance(incoming, (set, frozenset)):
                    allowed.extend(sorted(incoming))
                else:
                    allowed.extend(incoming)
                # Preserve order while removing accidental duplicates.
                allowed = list(dict.fromkeys(allowed))
        elif base_allowed is _MISSING or base_allowed is None:
            allowed = None
        elif isinstance(base_allowed, str):
            allowed = [base_allowed]
        elif isinstance(base_allowed, (set, frozenset)):
            allowed = sorted(base_allowed)
        else:
            allowed = list(base_allowed)

        job_policy["allowed_fields"] = allowed
        if "mask" in job:
            merged_mask: dict[str, Any] = {}
            base_mask = job_policy.get("mask")
            if isinstance(base_mask, Mapping):
                merged_mask.update(base_mask)
            job_mask = job.get("mask")
            if isinstance(job_mask, Mapping):
                merged_mask.update(job_mask)
            job_policy["mask"] = merged_mask

        size = job.get("batch_size")
        if size is None:
            size = job.get("size")
        if size is None:
            size = base.get("batch_size", 100)
        plan = plan_batches(records, size)
        batches = [export_batch(batch, job_policy) for batch in plan]
        digest = _digest_batches(batches)
        results[task_id] = {
            "task_id": task_id,
            "fields": list(allowed) if isinstance(allowed, (list, tuple)) else allowed,
            "batches": batches,
            "count": sum(batch["count"] for batch in batches),
            "digest": digest,
        }
    return results