from scoring.scorer import score_capture


def test_coverage_partitions_pass_fail_and_not_observable_rules():
    result = score_capture(
        {
            "ike_version": "IKEv1",
            "encryption_algorithm": None,
            "esp_encryption_algorithm": "3DES",
            "integrity_algorithm": None,
            "esp_integrity_algorithm": "HMAC-SHA1-96",
            "dh_group": None,
            "pfs_enabled": None,
            "ike_sa_established": True,
            "sa_lifetime_seconds": None,
        }
    )
    coverage = result["coverage"]

    assert coverage["observed"] == coverage["pass"] + coverage["fail"]
    assert coverage["total"] == coverage["observed"] + coverage["not_observable"]
    assert result["security_score"] <= 20
    assert all(
        rule["status"] == "NOT OBSERVABLE"
        for rule in result["rule_results"]
        if rule["observed_value"] is None
    )
    assert any(
        rule["status"] == "FAIL" and rule["source"] == "capture parsing"
        for rule in result["rule_results"]
    )
