import json
from pathlib import Path

import pandas as pd
import pytest

from features.cicflow_adapter import MODEL_TO_CIC, adapt_cicflow_row
from features.one_way_features import (
    FEATURE_CONTRACT_PATH,
    ONE_WAY_FEATURE_SCHEMA_ID,
    ORIGINATOR_ONLY,
    RESPONDER_DEPENDENT_LEGACY_FEATURES,
    get_one_way_features,
    validate_one_way_feature_names,
)


ROOT = Path(__file__).resolve().parents[1]
MAPPING_PATH = (
    ROOT
    / "data"
    / "metadata"
    / "MASTER_Feature_Mapping_Deliverable_A.csv"
)
FLOW_THREATS = ("PortScan", "DDoS", "Data_Exfiltration")


def _normalize(value):
    return " ".join(str(value).strip().split()).casefold()


def test_feature_contract_json_is_well_formed_and_unique():
    contract = json.loads(FEATURE_CONTRACT_PATH.read_text(encoding="utf-8"))
    assert contract["schema_id"] == ONE_WAY_FEATURE_SCHEMA_ID
    assert contract["version"] == 1
    assert contract["observation_model"] == "strictly_unidirectional"
    assert len(ORIGINATOR_ONLY) == len(set(ORIGINATOR_ONLY))
    assert ORIGINATOR_ONLY


@pytest.mark.parametrize("threat", FLOW_THREATS)
def test_allowlist_matches_master_mapping_for_flow_threats(threat):
    mapping = pd.read_csv(MAPPING_PATH)
    rows = mapping.loc[mapping["Threat"] == threat]
    classifications = {
        _normalize(row["Feature"]): row["Classification"]
        for _, row in rows.iterrows()
    }

    missing = [
        feature
        for feature in ORIGINATOR_ONLY
        if _normalize(feature) not in classifications
    ]
    non_observable = [
        feature
        for feature in ORIGINATOR_ONLY
        if classifications.get(_normalize(feature)) != "Observable"
    ]

    assert not missing, f"{threat}: unmapped features: {missing}"
    assert not non_observable, (
        f"{threat}: feature contract includes non-observable features: "
        f"{non_observable}"
    )


def test_responder_dependent_legacy_fields_are_excluded():
    selected = set(ORIGINATOR_ONLY)
    assert not selected.intersection(RESPONDER_DEPENDENT_LEGACY_FEATURES)

    for feature in RESPONDER_DEPENDENT_LEGACY_FEATURES:
        with pytest.raises(ValueError, match="outside"):
            validate_one_way_feature_names([feature])


def test_get_one_way_features_preserves_contract_order_and_ignores_unsafe_fields():
    columns = [
        " Flow Duration",
        ORIGINATOR_ONLY[3],
        " SYN Flag Count",
        ORIGINATOR_ONLY[0],
    ]
    assert get_one_way_features(columns) == [
        ORIGINATOR_ONLY[0],
        ORIGINATOR_ONLY[3],
    ]


def test_adapter_does_not_map_responder_dependent_legacy_features():
    for feature in RESPONDER_DEPENDENT_LEGACY_FEATURES:
        assert feature not in MODEL_TO_CIC
        with pytest.raises(KeyError, match="No CICFlowMeter mapping"):
            adapt_cicflow_row({}, [feature])


def test_adapter_model_keys_are_approved_one_way_features():
    assert set(MODEL_TO_CIC).issubset(set(ORIGINATOR_ONLY))
