"""Null object for modules that are not part of this build (see buildcfg.py and dev/mkbuild.py).

A custom build replaces the engine modules of the sections it leaves out with generated stubs. Core code that still
holds a reference (for example worker.pipeline in a monitoring-only build) then talks to an Absent object: it is falsy,
empty, JSON-serialisable ({}), callable, and every attribute or call returns it again, so the reference is harmless.
The API methods of the missing sections are removed and blocked separately (perms.py, api.py).
"""


class NotInBuild(Exception):
    pass


class Absent(dict):
    def __init__(self, *a, **k):
        super().__init__()

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return ABSENT

    def __setattr__(self, name, value):
        pass

    def __delattr__(self, name):
        pass

    def __call__(self, *a, **k):
        return ABSENT

    def __missing__(self, key):
        return ABSENT

    def __setitem__(self, key, value):
        pass

    def update(self, *a, **k):
        pass

    def setdefault(self, key, default=None):
        return default

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __hash__(self):
        return 0

    def __repr__(self):
        return "<not in this build>"

    def __str__(self):
        return ""

    def __int__(self):
        return 0

    def __float__(self):
        return 0.0

    def __index__(self):
        return 0

    def __lt__(self, other):
        return False

    __gt__ = __le__ = __ge__ = __lt__

    def __add__(self, other):
        return other

    __radd__ = __add__

    def __sub__(self, other):
        return 0

    __rsub__ = __mul__ = __rmul__ = __sub__


ABSENT = Absent()
