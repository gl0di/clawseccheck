"""clean_b336_inline_literal_exec: a tiny documented code-gen template executed
inline as a literal string constant. Excluded by leg 2 -- the exec() argument is an
ast.Constant, so there is nothing to trace to a composing-function call or a tainted
name. B336 must PASS / emit no CHUNKED_FILE_EXEC finding.
"""

exec("def _generated(): return 42")
