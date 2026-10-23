"""Original DEV fixture: higher-order decorator and closure replacement."""

from functools import wraps

BACKOFF = 0.25


def retry(*, attempts):
    def decorate(operation):
        @wraps(operation)
        def wrapped(*args, **kwargs):
            last = None
            for _ in range(attempts):
                try:
                    return operation(*args, **kwargs)
                except ConnectionError as error:
                    last = error
            raise last
        return wrapped
    return decorate


@retry(attempts=2)
def deliver(payload):
    return payload
