"""Public tests for the audit log export package."""

from auditout import (
    export_batch_jobs,
    mask_record,
    merge_batches,
    plan_batches,
    select_fields,
)


def test_plan_batches_includes_sequence_and_tail():
    records = [{"id": index} for index in range(5)]

    plan = plan_batches(records, 2)

    assert [batch["index"] for batch in plan] == [1, 2, 3]
    assert [batch["total"] for batch in plan] == [3, 3, 3]
    assert [batch["count"] for batch in plan] == [2, 2, 1]
    flattened = [record["id"] for batch in plan for record in batch["records"]]
    assert flattened == [0, 1, 2, 3, 4]


def test_mask_record_masks_phone_without_changing_length():
    source = {"id": 1, "phone": "13812345678"}

    masked = mask_record(source, {"mask": {"phone": "phone"}})

    assert masked == {"id": 1, "phone": "138****5678"}
    assert source == {"id": 1, "phone": "13812345678"}


def test_select_fields_keeps_only_authorized_paths():
    source = {
        "id": 7,
        "phone": "13812345678",
        "profile": {
            "email": "alice@example.com",
            "internal_note": "do-not-export",
        },
    }

    selected = select_fields(source, ["id", "profile.email"])

    assert selected == {"id": 7, "profile": {"email": "alice@example.com"}}


def test_merge_batches_rebuilds_complete_export():
    records = [{"id": index} for index in range(5)]

    plan = plan_batches(records, 2)
    merged = merge_batches(plan)

    assert merged == records


def test_export_batch_jobs_keeps_tasks_independent():
    jobs = [
        {
            "task_id": "alpha",
            "fields": ["id", "phone"],
            "batch_size": 2,
            "records": [
                {
                    "id": 1,
                    "phone": "13812345678",
                    "amount": 10,
                    "email": "alpha@example.com",
                },
                {
                    "id": 2,
                    "phone": "13912345678",
                    "amount": 20,
                    "email": "alpha2@example.com",
                },
            ],
        },
        {
            "task_id": "beta",
            "fields": ["id", "amount"],
            "batch_size": 2,
            "records": [
                {
                    "id": 3,
                    "phone": "13712345678",
                    "amount": 30,
                    "email": "beta@example.com",
                },
                {
                    "id": 4,
                    "phone": "13612345678",
                    "amount": 40,
                    "email": "beta2@example.com",
                },
            ],
        },
    ]

    exports = export_batch_jobs(jobs, {"mask": {"phone": "phone"}})

    alpha = exports["alpha"]["batches"][0]["records"][0]
    beta = exports["beta"]["batches"][0]["records"][0]
    assert set(alpha) == {"id", "phone"}
    assert set(beta) == {"id", "amount"}