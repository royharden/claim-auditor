"""Original DEV fixture: class members and an unresolved dynamic export."""

SAMPLE_LIMIT = 8


class Sensor:
    def __init__(self, reader):
        self.reader = reader

    def read(self):
        return self.reader()


def __getattr__(name):
    if name == "factory":
        from importlib import import_module
        return import_module("sensor_plugin").factory
    raise AttributeError(name)
