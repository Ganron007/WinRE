from winre import remote_driver


def test_dynamic_label_distinguishes_failed_run_from_not_run():
    assert remote_driver._dynamic_status_label({
        "ok": False, "detonation_ran": True,
    }) == "failed-after-start"
    assert remote_driver._dynamic_status_label({
        "ok": False, "detonation_ran": False,
    }) == "not-run"
    assert remote_driver._dynamic_status_label(None) == "not-requested"


def test_inventory_diff_names_missing_unexpected_and_mismatched_paths():
    h1, h2 = "a" * 64, "b" * 64
    diff = remote_driver._inventory_diff(
        {"missing.bin": (1, h1), "changed.bin": (2, h1),
         "same.bin": (3, h1)},
        {"extra.bin": (1, h1), "changed.bin": (2, h2),
         "same.bin": (3, h1)},
    )

    assert diff == {
        "missing_local_count": 1,
        "unexpected_local_count": 1,
        "content_mismatch_count": 1,
        "missing_local": ["missing.bin"],
        "unexpected_local": ["extra.bin"],
        "content_mismatch": ["changed.bin"],
        "truncated": False,
    }
