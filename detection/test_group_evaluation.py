import pandas as pd
import pytest

from detection.group_evaluation import stratified_group_holdout


def _balanced_capture_dataset(group_count=10):
    rows = []
    labels = []
    groups = []
    for group_index in range(group_count):
        # Each independent capture contributes both labels in this synthetic
        # fixture so a stratified group-disjoint holdout is possible.
        rows.extend([
            {"fwd_packets": group_index + 1, "fwd_bytes": 100 + group_index},
            {"fwd_packets": group_index + 2, "fwd_bytes": 200 + group_index},
        ])
        labels.extend(["BENIGN", "DDoS"])
        groups.extend([f"capture-{group_index}", f"capture-{group_index}"])
    return pd.DataFrame(rows), pd.Series(labels), pd.Series(groups)


def test_group_holdout_keeps_capture_groups_disjoint_and_stratified():
    X, y, groups = _balanced_capture_dataset()
    X_train, X_test, y_train, y_test, groups_train, groups_test = (
        stratified_group_holdout(X, y, groups, n_splits=5, random_state=42)
    )

    assert set(groups_train).isdisjoint(set(groups_test))
    assert set(y_train) == set(y_test) == set(y)
    assert groups_train.nunique() + groups_test.nunique() == groups.nunique()
    assert len(X_train) + len(X_test) == len(X)
    assert len(y_train) + len(y_test) == len(y)


def test_group_holdout_is_deterministic_for_a_fixed_seed():
    X, y, groups = _balanced_capture_dataset()
    first = stratified_group_holdout(X, y, groups, random_state=17)
    second = stratified_group_holdout(X, y, groups, random_state=17)

    assert first[4].tolist() == second[4].tolist()
    assert first[5].tolist() == second[5].tolist()


def test_group_holdout_rejects_missing_capture_ids():
    X, y, groups = _balanced_capture_dataset()
    groups.iloc[0] = None

    with pytest.raises(ValueError, match="contain missing values"):
        stratified_group_holdout(X, y, groups)


def test_group_holdout_rejects_too_few_independent_captures():
    X, y, groups = _balanced_capture_dataset(group_count=4)

    with pytest.raises(ValueError, match="At least 5 distinct capture groups"):
        stratified_group_holdout(X, y, groups)


def test_group_holdout_rejects_class_distribution_that_cannot_be_separated():
    X, _, groups = _balanced_capture_dataset()
    y = pd.Series(["BENIGN"] * (len(X) - 1) + ["DDoS"])

    with pytest.raises(ValueError, match="Could not create a capture-group-disjoint split"):
        stratified_group_holdout(X, y, groups)
