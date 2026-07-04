"""clean_b91_literal_dispatch: an ordinary dynamic getattr() dispatch on a plain object with
a literal attribute name — normal plugin-style dispatch, not sink obfuscation. B91 must PASS.
"""


class Handler:
    def add(self, a, b):
        return a + b


def run(method_name, *args):
    handler = Handler()
    fn = getattr(handler, method_name)
    return fn(*args)
