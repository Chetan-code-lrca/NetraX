from features.c2.behavioral_features import extract_c2_behavioral_features


class C2FeatureSource:
    """
    Convert CTU-13 flow data into streaming C2 events.
    """

    def __init__(self, path, limit=None):
        self.path = path
        self.limit = limit

    def __iter__(self):
        import pandas as pd

        df = pd.read_csv(self.path)

        features = extract_c2_behavioral_features(df)

        if self.limit:
            features = features.head(self.limit)

        for index, row in features.iterrows():
            yield {
                "type": "c2",
                "features": row.to_dict(),
                "flow_id": (
                    f"C2-{row['src']}-"
                    f"{row['window']}"
                )
            }
