"""Original DEV fixture: nested config and profile-selected overlay."""

import tomllib


def load_settings(path, profile="dev"):
    with open(path, "rb") as stream:
        config = tomllib.load(stream)
    queue = dict(config["tool"]["queue"])
    queue.update(queue.pop("profiles", {}).get(profile, {}))
    return queue
