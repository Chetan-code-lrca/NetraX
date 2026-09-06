from streaming.processor import NetraXProcessor


class NetraXRunner:
    """
    Continuously consume events from a streaming source
    and send them through the NetraX processor.
    """

    def __init__(self, source):
        self.source = source
        self.processor = NetraXProcessor()

    def run(self):
        """
        Process events continuously until the source ends.
        """

        for event in self.source:
            alert = self.processor.process(event)

            print(
                f"[{alert['timestamp']}] "
                f"{alert['threat_class']} | "
                f"{alert['status']} | "
                f"confidence={alert['confidence']:.3f}"
            )
