"""The `mcp` and `mcp_detail` dimensions — connected tool servers and what they launch.

Two keys, one subject, so one module: `mcp` is the roster and `mcp_detail` is what each
entry actually runs and asks for. Splitting them would put the roster's signature builder
and the detail's diff arm in different files while a single config edit moves both.

Everything recorded here passes through the redaction helpers first — a server command line
can carry a token, and this dimension is persisted to disk.
"""

from __future__ import annotations
import json
from pathlib import Path  # noqa: F401

from ..logsafe import redact_urls_in_text, sanitize_url_host_only  # noqa: F401
from ._shared import _h  # noqa: F401


def _mcp_sig(ctx) -> dict:
    """name -> hash of each MCP server spec, so new/changed/removed servers drift."""
    from ..checks import _mcp_servers  # noqa: PLC0415 (avoid import-order coupling)
    out = {}
    for name, spec in (_mcp_servers(ctx.config) or {}).items():
        try:
            out[name] = _h(json.dumps(spec, sort_keys=True, default=str))
        except (TypeError, ValueError):
            out[name] = _h(str(spec))
    return out


# C-135/FIX3: known value-taking flags for the runner commands realistically seen in an
# MCP server spec's `command`, keyed by the command's basename. A value-taking flag's
# VALUE is never the package/image identity, so it must be skipped along with the flag
# itself rather than mistaken for the first "non-flag" token. Curated, not exhaustive —
# see the NARROWS note on ``_extract_args_pkg`` for what this deliberately does not cover.
_VALUE_FLAGS_BY_CMD: "dict[str, set[str]]" = {
    "node": {"--max-old-space-size", "--stack-size", "-r", "--require",
             "--loader", "--experimental-loader"},
    "uv": {"--with", "--python", "--index-url", "--index", "--project"},
    "uvx": {"--python", "--with", "--index-url", "--index"},
    "docker": {"-e", "--env", "--env-file", "-v", "--volume", "--mount", "-p", "--publish",
               "--name", "-w", "--workdir", "-u", "--user", "--network", "--entrypoint",
               "-m", "--memory", "--cpus", "-h", "--hostname", "--platform", "-l",
               "--label", "--add-host", "--dns", "--restart", "--log-driver", "--pull"},
}


# C-135/FIX3: a leading SUBCOMMAND names the action ("run", "exec"), not the image — the
# measured defect: `docker run -i --rm mcp/server` mis-selected "run" itself. Checked only
# at args[0] ("leading"), matching the canonical `<cmd> <subcommand> ...` shape.
_RUNNER_LEAD_SUBCOMMANDS_BY_CMD: "dict[str, set[str]]" = {
    "docker": {"run", "exec"},
    "podman": {"run", "exec"},
    "uv": {"run"},
}


# C-135/FIX3: `uvx --from <pkg> <tool>` names the package via --from's VALUE, not
# positionally — the value itself is the identity to select (unlike the SKIP_FLAG_AND_
# VALUE flags above, where the value is never the identity). Checked only at args[0].
_RUNNER_LEAD_VALUE_MARKERS_BY_CMD: "dict[str, set[str]]" = {
    "uvx": {"--from"},
}


def _extract_args_pkg(command: str, args) -> str:
    """C-135/FIX3: the first argument that identifies WHAT actually runs — the
    package/image/script — rather than the naive "first non-flag argument", which
    mis-selects in two real shapes:

    1. **A value-taking flag.** ``node --max-old-space-size 4096 server.js`` mis-selected
       "4096" (the flag's value) instead of "server.js" — measured first-hand.
    2. **A subcommand-style runner.** ``docker run -i --rm mcp/server`` mis-selected "run"
       itself (the action, not the image) — also measured first-hand.

    Fixed via ``_VALUE_FLAGS_BY_CMD`` (skip a known flag AND its value, keep scanning) and
    ``_RUNNER_LEAD_SUBCOMMANDS_BY_CMD``/``_RUNNER_LEAD_VALUE_MARKERS_BY_CMD`` (skip a
    leading subcommand/marker token, select what comes right after) — both keyed by the
    command's basename so a flag meaning in one tool (docker's ``-p``) is never applied to
    an unrelated tool.

    NARROWS, does not close: the flag tables are curated from well-known public CLI
    surfaces (Node, uv/uvx, Docker/Podman), not exhaustive. An MCP server invoked through
    an unlisted value-taking flag — most plausibly an uncommon docker flag this table
    omits, e.g. ``docker run --add-host=x:y --cap-add SYS_PTRACE myimage`` if ``--cap-add``
    were absent from the table — still mis-selects that flag's value instead of the image.
    Docker/Podman in particular have a large flag surface this table cannot claim to cover
    completely; the curated set closes the common, unflagged-image shape this was measured
    against, and closes what it can WITHOUT guessing at flags this project has not verified
    take a value. A leading marker/subcommand is only recognised at args[0] — a runner
    invoked through a wrapper that prepends its own flags before ``run``/``--from`` is not
    handled and falls back to the general scan.
    """
    if not isinstance(args, list):
        return ""
    toks = [str(a) for a in args]
    cmd = Path(str(command or "")).name

    idx = 0
    lead_subcmds = _RUNNER_LEAD_SUBCOMMANDS_BY_CMD.get(cmd)
    if lead_subcmds and toks and toks[0] in lead_subcmds:
        idx = 1

    lead_value_markers = _RUNNER_LEAD_VALUE_MARKERS_BY_CMD.get(cmd)
    if lead_value_markers and idx < len(toks) and toks[idx] in lead_value_markers:
        return toks[idx + 1] if idx + 1 < len(toks) else ""

    value_flags = _VALUE_FLAGS_BY_CMD.get(cmd, ())
    skip_next = False
    for tok in toks[idx:]:
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            if tok in value_flags:
                skip_next = True
            continue
        return tok
    return ""


def _tool_surface_hash(tool) -> str:
    """F-147 (Wave 3, rug-pull): hash a mcpsurface.ToolDef's description + param
    signature, so a description/param edit is visible even when nothing about a
    server's own name/count changed. Params are sorted by name first so key
    reordering in the source data never looks like a change.
    """
    parts = [str(getattr(tool, "description", "") or "")]
    for p in sorted(getattr(tool, "params", None) or (),
                     key=lambda x: str(getattr(x, "name", ""))):
        parts.append(str(getattr(p, "name", "") or ""))
        parts.append(str(getattr(p, "description", "") or ""))
        parts.append(str(getattr(p, "default", "") or ""))
        parts.append(str(getattr(p, "schema_type", "") or ""))
    return _h("\x1f".join(parts))


def _mcp_observed_surfaces(ctx) -> dict:
    """F-147 (Wave 3, rug-pull): name -> mcpsurface.ToolSurface, from POST-HOC
    trajectory evidence only (``mcpsurface.from_trajectory`` / B185's own source).

    This is an OPTIONAL, best-effort source — a host with no trajectory sidecar (or
    none carrying a ``context.compiled`` record) yields ``{}`` here, same as B185's own
    "no evidence" case. Absence must never itself be treated as a signal by any caller:
    see ``_mcp_detail_sig``'s ``surface_tool_sigs`` — a server present in
    ``_mcp_servers`` but ABSENT from this dict simply gets no ``surface_tool_sigs`` key
    at all, which is exactly the same "key absent = no-op for one run" idiom the
    ``args_pkg`` (B-279) and channel-dimension (B-274) guards already use.
    """
    home = getattr(ctx, "home", None)
    if not isinstance(home, Path):
        return {}
    from ..mcpsurface import from_trajectory  # noqa: PLC0415 (leaf import, no cycle)
    from ..scanbudget import limits_for  # noqa: PLC0415 (leaf import, no cycle)
    lim = limits_for(ctx)
    return {surface.server: surface for surface in
            from_trajectory(home, max_files=lim.traj_max_files,
                             max_bytes_per_file=lim.traj_max_bytes_per_file)}


def _mcp_detail_sig(ctx) -> dict:
    """name -> structured per-server snapshot for rug-pull (RP1-RP3) detection.

    Captures real MCP spec fields (command, args[0], transport, url, env key names,
    oauth.scope) — confirmed real fields per recon docs §1/§4.  Env VALUES are never
    stored; only the key names are recorded (SECRET_KEY_RE keys get a ``*``-marker so
    their presence is visible but no value leaks).

    F-147 (Wave 3, rug-pull): also folds in, per server, an OPTIONAL
    ``surface_tool_sigs`` — ``{tool_name: hash(description + params)}`` observed via
    trajectory sidecars (``_mcp_observed_surfaces``, post-hoc). This is a SEPARATE
    dimension from ``tool_sigs`` above: ``tool_sigs`` hashes what the *config itself*
    declares under ``mcp.servers.<name>.tools`` (rare in real configs); the trajectory
    source is what the host has ACTUALLY observed being sent to the model, which
    exists independently of whether the config embeds a tools list at all. It is
    entirely optional — a server with no trajectory evidence for it simply gets no
    ``surface_tool_sigs`` key, never a synthesized "missing" marker (see
    ``diff()``'s RP6/RP7 block, which requires the key on BOTH sides before comparing).
    """
    from ..checks import SECRET_KEY_RE, _mcp_servers  # noqa: PLC0415
    observed_surfaces = _mcp_observed_surfaces(ctx)
    out: dict = {}
    for name, spec in (_mcp_servers(ctx.config) or {}).items():
        if not isinstance(spec, dict):
            continue
        args = spec.get("args") or []
        args0 = str(args[0]) if isinstance(args, list) and args else ""
        # B-279: the first NON-FLAG argument — the package/script identity. `args0` is
        # positional, and the canonical MCP stdio shape is `npx -y <pkg>`, so for the
        # majority of real servers args0 is the literal constant "-y" and RP2's comparison
        # of it is structurally dead: swapping `notes-mcp` for `notes-mcp-pro` under the
        # same trusted server name produced only the generic "configuration CHANGED", and
        # the package name reached neither state.json nor events.jsonl, so the rug-pull was
        # not even forensically recoverable after the fact. Measured both ways: moving the
        # same package to a bare args[0] made the precise RP2 alert fire, proving the gap
        # was purely positional.
        #
        # Added as a NEW key rather than by redefining what args0 extracts. Reinterpreting
        # args0 in place would make every existing snapshot's stored "-y" disagree with the
        # newly-computed "<pkg>" for an entirely UNCHANGED config, firing a spurious
        # rug-pull HIGH on the first post-upgrade run for the majority server shape — and
        # `sbom.py`'s independent `detail.get("args0")` reader would silently change
        # meaning too.
        #
        # C-135/FIX3: extraction itself moved to _extract_args_pkg() — the naive "first
        # non-flag argument" mis-selected a value-taking flag's value (e.g. node's
        # `--max-old-space-size 4096`) and a runner subcommand (e.g. `docker run`) itself.
        # See that function's docstring for what is fixed and what NARROWS rather than
        # closes.
        args_pkg = _extract_args_pkg(spec.get("command"), args)
        env = spec.get("env") or {}
        env_keys: list[str] = []
        if isinstance(env, dict):
            for k in env:
                k_str = str(k)
                env_keys.append(
                    k_str + ":*" if SECRET_KEY_RE.search(k_str) else k_str
                )
        oauth = spec.get("oauth") or {}
        oauth_scope = str(oauth.get("scope") or "") if isinstance(oauth, dict) else ""
        tool_sigs: dict[str, str] = {}
        tools = spec.get("tools")
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    tool_name = str(tool.get("name") or "").strip()
                    if not tool_name:
                        continue
                    tool_desc = str(tool.get("description") or "")
                    tool_sigs[tool_name] = _h(tool_desc)
                elif isinstance(tool, (str, bytes)):
                    tool_name = str(tool).strip()
                    if tool_name:
                        tool_sigs[tool_name] = ""
        # B-105: at-rest redaction. command/args0 can embed a credential inside a URL
        # arg (npx --registry https://TOKEN@reg/ …); url can be https://user:token@host or
        # carry ?api_key=…. Sanitize BEFORE the value enters the snapshot, so state.json
        # never holds the secret and every drift alert built from these fields (RP2/RP3)
        # inherits the redaction. Host-level drift (the security signal) is preserved;
        # only the secret-bearing parts collapse.
        out[name] = {
            "command": redact_urls_in_text(str(spec.get("command") or "")),
            "args0": redact_urls_in_text(args0),
            "args_pkg": redact_urls_in_text(args_pkg),
            "transport": str(spec.get("transport") or ""),
            "url": sanitize_url_host_only(str(spec.get("url") or "")),
            "env_keys": sorted(env_keys),
            "oauth_scope": oauth_scope,
            "tool_sigs": dict(sorted(tool_sigs.items())),
        }
        # F-147 (Wave 3): OPTIONAL — only set when trajectory evidence exists for this
        # server. Never set an empty dict / sentinel here: the key's mere PRESENCE is
        # what diff() gates its RP6/RP7 comparison on, so a synthesized empty value
        # would make "no evidence" indistinguishable from "observed zero tools".
        surface = observed_surfaces.get(name)
        if surface is not None and surface.tools:
            surface_sigs = {
                str(t.name): _tool_surface_hash(t)
                for t in surface.tools if str(getattr(t, "name", "") or "").strip()
            }
            if surface_sigs:
                out[name]["surface_tool_sigs"] = dict(sorted(surface_sigs.items()))
    return out


def _diff_mcp_servers(_mcp_pair, alerts, compare_config) -> None:
    """C-433: the diff arm for the configured MCP servers.

    The statement is moved **verbatim, condition included**. The previous batch rebuilt an
    `if compare_config and _pair is not None:` as `if pair is None: return`, kept one clause
    and dropped the blind-run interlock, and reintroduced a B-269 fabrication. Moving the
    whole `if` removes that class of error entirely.

    Parameter names keep their original underscore-prefixed spelling for the same reason:
    a rename is an edit, and the contract for this move is that the body is unchanged.
    """
    if compare_config and _mcp_pair is not None:
        pm, cm = _mcp_pair
        for name in sorted(cm.keys() - pm.keys()):
            alerts.append(("CRITICAL", f"NEW MCP server connected since last check: '{name}' — "
                           "vet it before trusting (new tool/data trust surface)."))
        for name in sorted(pm.keys() & cm.keys()):
            if pm[name] != cm[name]:
                alerts.append(("HIGH", f"MCP server '{name}' configuration CHANGED — "
                               "re-review its transport, secret passthrough and scope."))
        for name in sorted(pm.keys() - cm.keys()):
            alerts.append(("INFO", f"MCP server '{name}' was removed."))


def _diff_mcp_detail(
        _detail_pair,
        _mcp_pkg_unknown,
        _mcp_surface_unknown,
        _mcp_tools_unknown,
        _trajectory_alerts,
        alerts,
        compare_config,
) -> None:
    """C-433: the `mcp_detail` dimension's diff arm — what each tool server launches and asks for.

    Seven parameters for 156 lines: nearly everything it touches is its own. The three
    `_mcp_*_unknown` sets are the caller's, mutated in place, so the notes they drive keep
    the ordering the inline code had.
    """
    if compare_config and _detail_pair is not None:
        pd, cd = _detail_pair
        for name in sorted(set(pd) & set(cd)):
            ps, cs = pd[name], cd[name]
            if not isinstance(ps, dict) or not isinstance(cs, dict):
                continue

            # RP1 — scope/privilege expansion (HIGH): oauth.scope gained a new token or
            # was broadened (e.g. read → read+write, or any → */all/admin).
            p_scope = ps.get("oauth_scope", "")
            c_scope = cs.get("oauth_scope", "")
            if p_scope != c_scope and c_scope:
                p_tokens = set(p_scope.split()) if p_scope else set()
                c_tokens = set(c_scope.split()) if c_scope else set()
                gained = c_tokens - p_tokens
                _BROAD = {"*", "all", "admin", "write", "read:write"}
                is_broad = any(t.endswith(("*", ":write", ":admin", ":all")) or t in _BROAD
                               for t in gained)
                if gained:
                    sev = "HIGH" if is_broad else "MEDIUM"
                    alerts.append((sev,
                                   f"MCP server '{name}' rug-pull RP1: oauth.scope expanded "
                                   f"'{p_scope}' -> '{c_scope}' (gained: {' '.join(sorted(gained))}) "
                                   "— server gained privilege post-approval, re-vet it."))

            # RP2 — command/transport change (HIGH): the executable, first arg, or
            # transport changed — a different thing now runs under the same trusted name.
            # C-178: command/args0 may hold a pre-cde6798 build's raw (unredacted)
            # value in ps; re-apply redact_urls_in_text (idempotent on an already-
            # redacted value) before comparing, same normalization as RP3's url.
            p_transport = ps.get("transport", "")
            c_transport = cs.get("transport", "")
            p_cmd = redact_urls_in_text(ps.get("command", ""))
            c_cmd = cs.get("command", "")
            p_args0 = redact_urls_in_text(ps.get("args0", ""))
            c_args0 = cs.get("args0", "")
            # B-279: the package identity leg, gated on the key existing on BOTH sides.
            # An old snapshot has no `args_pkg` at all, so it simply skips this one
            # comparison for one run instead of diffing a present value against a missing
            # one — the same absent-key-is-a-no-op idiom as the enclosing `"mcp_detail" in
            # prev and ... in curr` guard, and the reason this is a new key rather than a
            # redefinition of args0. Self-healing: the next snapshot carries it.
            p_pkg = redact_urls_in_text(ps.get("args_pkg", ""))
            c_pkg = cs.get("args_pkg", "")
            pkg_comparable = "args_pkg" in ps and "args_pkg" in cs
            if not pkg_comparable:
                _mcp_pkg_unknown.add(name)
            pkg_changed = pkg_comparable and p_pkg != c_pkg
            transport_changed = p_transport != c_transport
            cmd_changed = p_cmd != c_cmd
            args0_changed = p_args0 != c_args0
            # When there is no flag before the package, args0 IS the package and both legs
            # describe the identical change; report it once rather than twice.
            if pkg_changed and (p_pkg, c_pkg) == (p_args0, c_args0):
                pkg_changed = False
            if transport_changed or cmd_changed or args0_changed or pkg_changed:
                parts = []
                if cmd_changed:
                    parts.append(f"command '{p_cmd}'->'{c_cmd}'")
                if args0_changed:
                    parts.append(f"args[0] '{p_args0}'->'{c_args0}'")
                if pkg_changed:
                    parts.append(f"package '{p_pkg}'->'{c_pkg}'")
                if transport_changed:
                    parts.append(f"transport '{p_transport}'->'{c_transport}'")
                alerts.append(("HIGH",
                               f"MCP server '{name}' rug-pull RP2: "
                               + ", ".join(parts)
                               + " — a different binary/package/transport now runs under "
                               "this trusted name, re-vet it."))

            # RP3 — endpoint/default repoint (HIGH): url or env values that look like
            # endpoints changed.  We snapshot env KEY names only, so this detects an env
            # var disappearing or appearing; the url field is snapshotted directly.
            #
            # C-178: cs["url"] is always host-only sanitized at snapshot time
            # (_mcp_detail_sig), but ps["url"] may have been written by a build
            # predating the cde6798 redaction fix, in which case it is still the
            # RAW url (possibly carrying a credential). Re-sanitizing p_url here
            # (idempotent on an already-sanitized value) normalizes both sides to
            # the same form before comparing, so a version upgrade alone never
            # false-positives a rug-pull, and the stale raw credential is never
            # echoed into the alert text either.
            p_url = sanitize_url_host_only(ps.get("url", ""))
            c_url = cs.get("url", "")
            if p_url != c_url:
                # Determine severity: host change is always HIGH; adding/clearing url is HIGH.
                alerts.append(("HIGH",
                               f"MCP server '{name}' rug-pull RP3: url repointed "
                               f"'{p_url}' -> '{c_url}' "
                               "— trusted endpoint changed, verify the destination."))

            # RP4/RP5 — tool surface drift (HIGH): new tool appeared or a declared tool's
            # description changed under the same trusted server name.
            p_tools = ps.get("tool_sigs") or {}
            c_tools = cs.get("tool_sigs") or {}
            if not (isinstance(p_tools, dict) and isinstance(c_tools, dict)):
                _mcp_tools_unknown.add(name)
            if isinstance(p_tools, dict) and isinstance(c_tools, dict):
                for tool in sorted(set(c_tools) - set(p_tools)):
                    alerts.append(("HIGH",
                                   f"MCP server '{name}' rug-pull RP4: new tool '{tool}' "
                                   "appeared in the manifest — re-vet the tool surface."))
                for tool in sorted(set(p_tools) & set(c_tools)):
                    if p_tools[tool] != c_tools[tool]:
                        alerts.append(("HIGH",
                                       f"MCP server '{name}' rug-pull RP5: tool description "
                                       f"changed for '{tool}' — re-review the server's "
                                       "declared affordances."))

            # RP6/RP7 — F-147 (Wave 3): OBSERVED tool-surface drift, from trajectory
            # evidence (mcpsurface.from_trajectory), DISTINCT from RP4/RP5 above (which
            # read the config's own embedded `tools` spec — rarely present in real
            # configs). This is the actual rug-pull signature the task exists to close:
            # a server can keep a byte-identical launch spec (command/args/transport/
            # url/env-keys all unchanged, so RP1-RP3 stay silent) while the tool
            # descriptions it hands the model post-approval silently change.
            #
            # Gated on the `surface_tool_sigs` key existing on BOTH sides — same
            # absent-key-is-a-no-op idiom as `args_pkg` (B-279) and every other
            # optional-dimension guard in this module. This is not just upgrade
            # safety: it is the acceptance criterion. A server for which the key is
            # missing on EITHER side had no trajectory evidence available at that
            # snapshot, so "the source only just became visible" must never be reread
            # as "the surface changed" — comparing a real dict against a coerced {}
            # would report every tool as newly appeared the moment trajectory data
            # first showed up, which is exactly the false alarm this task forbids.
            p_surf = ps.get("surface_tool_sigs")
            c_surf = cs.get("surface_tool_sigs")
            if not (isinstance(p_surf, dict) and isinstance(c_surf, dict)):
                _mcp_surface_unknown.add(name)
            # F-170: these three loops read the tool surface OBSERVED IN TRAJECTORY
            # SIDECARS, not in the config file — so a config write did not cause them and
            # must not be stamped with its provenance. They sit inside the config-derived
            # index span, so their indices are excluded explicitly.
            _traj_from = len(alerts)
            if isinstance(p_surf, dict) and isinstance(c_surf, dict):
                for tool in sorted(set(c_surf) - set(p_surf)):
                    alerts.append(("HIGH",
                                   f"MCP server '{name}' rug-pull RP6: a new tool "
                                   f"'{tool}' was observed in the tool surface actually "
                                   "sent to the model (source: trajectory) — re-vet it."))
                for tool in sorted(set(p_surf) & set(c_surf)):
                    if p_surf[tool] != c_surf[tool]:
                        alerts.append(("HIGH",
                                       f"MCP server '{name}' rug-pull RP7: the tool "
                                       f"surface actually sent to the model for '{tool}' "
                                       "changed (source: trajectory) — the server's "
                                       "declared description/parameters changed after "
                                       "approval while its launch spec stayed identical; "
                                       "re-review it."))
                for tool in sorted(set(p_surf) - set(c_surf)):
                    alerts.append(("INFO",
                                   f"MCP server '{name}' tool '{tool}' no longer appears "
                                   "in the observed tool surface (source: trajectory)."))
            _trajectory_alerts.update(range(_traj_from, len(alerts)))
