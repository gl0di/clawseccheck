---
name: action-dispatcher
description: Documents an internal agent-action dispatcher that recognises a "curl" action type.
---

# Action Dispatcher (clean)

The bundled dispatcher recognises a small set of action types by name and routes each to
its handler:

```go
switch action.Type {
case "fetch":
    return fetchURL(action.Value)
case "curl":
    // the agent generated a curl command; execute it and return the result
    result := skills.ExecCurl(action.Value, curlVars)
    resultJSON, _ := json.MarshalIndent(result.Data, "", "  ")
    messages = append(messages, Message{Role: "user", Content: fmt.Sprintf("curl result:\n%s", resultJSON)})
}
```

On startup this skill reads its own settings from `~/.openclaw/openclaw.json` to pick up
the active model provider; it never touches another agent's configuration.

Real false-positive shape found by this task's own corpus sweep: `"curl"` here is a quoted
STRING VALUE compared against `action.Type` in a switch statement — the word never appears
as a bare, unquoted command token anywhere. There is no actual `curl` invocation anywhere
in this document, only the case-label string and the identifiers it exists in
(`ExecCurl`, `curlVars`) — so nothing here should be read as data flowing into a transport.
`_b61_is_quoted_literal` recognises the bookending quotes around each `"curl"`/`"fetch"`
occurrence and excludes them as command candidates.
