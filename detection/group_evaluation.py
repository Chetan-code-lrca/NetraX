"""Group-disjoint evaluation splits for flow datasets."""

from collections.abc import Sequence

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold


def stratified_group_holdout(
    features,
    labels,
    groups,
    *,
    n_splits=5,
    random_state=42,
):
    """Return one stratified fold with no capture/group overlap.

    Groups must represent independent capture/source units, not individual
    flows. The function fails closed when group provenance is missing or when
    no fold contains every class in both train and test.
    """
    if n_splits < 2:
        raise ValueError("n_splits must be at least 2.")

    if not isinstance(features, pd.DataFrame):
        raise TypeError("features must be a pandas DataFrame.")
    if not isinstance(labels, (pd.Series, Sequence)):
        raise TypeError("labels must be a pandas Series or sequence.")
    if not isinstance(groups, (pd.Series, Sequence)):
        raise TypeError("groups must be a pandas Series or sequence.")

    y = pd.Series(labels).reset_index(drop=True)
    group_values = pd.Series(groups).reset_index(drop=True)
    X = features.reset_index(drop=True)

    if len(X) == 0:
        raise ValueError("Cannot split an empty dataset.")
    if len(X) != len(y) or len(X) != len(group_values):
        raise ValueError("features, labels, and groups must have equal length.")
    if y.isna().any():
        raise ValueError("Labels contain missing values.")
    if group_values.isna().any():
        raise ValueError(
            "Capture/group identifiers contain missing values; "
            "a row-level split is not an acceptable fallback."
        )
    if group_values.astype(str).str.strip().eq("").any():
        raise ValueError("Capture/group identifiers cannot be empty.")

    unique_groups = group_values.nunique()
    if unique_groups < n_splits:
        raise ValueError(
            f"At least {n_splits} distinct capture groups are required; "
            f"found {unique_groups}."
        )

    classes = set(y.unique())
    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=random_state,
    )

    for train_indices, test_indices in splitter.split(X, y, group_values):
        y_train = y.iloc[train_indices]
        y_test = y.iloc[test_indices]
        if set(y_train.unique()) != classes or set(y_test.unique()) != classes:
            continue

        groups_train = set(group_values.iloc[train_indices])
        groups_test = set(group_values.iloc[test_indices])
        if not groups_train.isdisjoint(groups_test):
            raise RuntimeError("Internal error: train/test capture groups overlap.")

        return (
            X.iloc[train_indices].copy(),
            X.iloc[test_indices].copy(),
            y_train.copy(),
            y_test.copy(),
            group_values.iloc[train_indices].copy(),
            group_values.iloc[test_indices].copy(),
        )

    raise ValueError(
        "Could not create a capture-group-disjoint split with every label "
        "represented in both partitions. Add more independent captures or "
        "review the class distribution by capture; do not use a random "
        "row-level split as a fallback."
    )
