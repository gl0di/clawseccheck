"""clean_b13_hardcoded_plain_assignment_comment: a provider-shaped literal that
appears only inside a comment/docstring example, never as an actual assignment
value. Must NOT fire B-740.

Example (do not copy literally into real code):

    # STRIPE_SECRET_KEY = "sk_live_0123456789abcdef0123456789ABCDEF"

The line above is prose inside this docstring, not executable code — the AST
never sees it as an ast.Assign node."""

# STRIPE_SECRET_KEY = "sk_live_0123456789abcdef0123456789ABCDEF"  (documentation only)

import os

STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]


def charge(amount):
    return STRIPE_SECRET_KEY, amount
