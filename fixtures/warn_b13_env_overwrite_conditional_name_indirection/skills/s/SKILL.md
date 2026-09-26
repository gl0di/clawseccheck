---
name: s
description: A name bound to a provider-shaped literal in TWO different branches, then written into os.environ — ambiguous, must not FAIL the new B-910 rule.
---

# Env Overwrite Via Ambiguous Conditional Name Indirection

`TAVILY_KEY` is assigned a provider-shaped literal in both the `if` and `else`
branches, then written into `os.environ["TAVILY_API_KEY"]`. B-910's one-hop resolver
requires the name to have EXACTLY ONE same-file Assign/AnnAssign binding — two
bindings, even both secret-shaped, must stay unresolved (C-135 probe).
