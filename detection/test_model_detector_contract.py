from types import SimpleNamespace

import numpy as np
import pytest
from unittest.mock import patch

from detection.model_detector import (
    ModelFeatureContractError,
    validate_model_feature_contract,
)
from features.one_way_features import ORIGINATOR_ONLY


def test_model_with_named_one_way_features_is_accepted():
    model = SimpleNamespace(
        feature_names_in_=np.asarray(ORIGINATOR_ONLY[:4], dtype=object)
    )
    assert validate_model_feature_contract(model) == ORIGINATOR_ONLY[:4]


@pytest.mark.parametrize(
    "feature",
    [
        " Flow Duration",
        " SYN Flag Count",
        " ACK Flag Count",
    ],
)
def test_model_with_responder_dependent_feature_is_rejected(feature):
    model = SimpleNamespace(feature_names_in_=np.asarray([feature], dtype=object))
    with pytest.raises(ModelFeatureContractError, match="incompatible"):
        validate_model_feature_contract(model)


def test_inference_reports_incompatible_model_as_controlled_unavailable_error():
    from detection import inference

    with patch.object(
        inference,
        "load_model",
        side_effect=ModelFeatureContractError("unsafe legacy feature"),
    ):
        with pytest.raises(inference.ModelUnavailableError) as captured:
            inference._load_model_or_raise("PortScan")

    assert captured.value.code == "model_contract_invalid"
    assert "Retrain the model" in captured.value.message

def test_model_without_named_feature_schema_is_rejected():
    model = SimpleNamespace(n_features_in_=4)
    with pytest.raises(ModelFeatureContractError, match="no named feature schema"):
        validate_model_feature_contract(model)
