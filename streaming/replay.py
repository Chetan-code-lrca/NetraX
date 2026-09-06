import time
from pathlib import Path


class ReplaySource:
    """
    Replays captured traffic/events as a streaming source.

    Later this interface can be replaced by a live packet
    capture source without changing the detection pipeline.
    """

    def __init__(self, events, delay=0.0):
        self.events = events
        self.delay = delay

    def __iter__(self):
        for event in self.events:
            yield event

            if self.delay > 0:
                time.sleep(self.delay)


def load_lines(path):
    """
    Load a text-based event file.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(path)

    with path.open("r") as f:
        return [line.strip() for line in f if line.strip()]
