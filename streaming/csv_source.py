import pandas as pd


class CSVFeatureSource:
    """
    Convert pre-extracted CIC-style flow features into
    streaming NetraX events.
    """

    def __init__(self, path, threat_class, limit=None):
        self.path = path
        self.threat_class = threat_class
        self.limit = limit

    def __iter__(self):
        df = pd.read_csv(self.path)

        if self.limit:
            df = df.head(self.limit)

        # Remove the training label before inference.
        if " Label" in df.columns:
            df = df.drop(columns=[" Label"])

        for index, row in df.iterrows():
            yield {
                "type": "model",
                "threat_class": self.threat_class,
                "features": row.to_dict(),
                "flow_id": f"{self.threat_class}-replay-{index:06d}"
            }

