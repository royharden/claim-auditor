"""Original DEV fixture: singledispatch registrations and explicit type refusal."""

from functools import singledispatch

PREFIX = "int:"


@singledispatch
def render(value):
    raise TypeError(type(value).__name__)


@render.register(int)
def render_integer(value):
    return PREFIX + str(value)


@render.register(str)
def render_text(value):
    return value.strip()
