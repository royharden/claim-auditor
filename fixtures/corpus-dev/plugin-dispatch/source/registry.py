"""This registry is source data, not a plugin installation."""

handlers = {}


def register(name, handler):
    handlers[name] = handler
