class Container:
    """
    This non-intuitive structure allows arbitrary attribute-based storage.

    Usage
    =====
    blob = Container()
    blob.foo = "whatever"
    blob.blah = "something"

    This is useful when you want to access fixed entities by attribute for clarity, but don't know the values beforehand
    (or the lost readability of creating and instantiating a namedtuple is prohibitive)
    """
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)