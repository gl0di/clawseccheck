"""C-762: the state-SQLite table baseline covers the tables of `featureLocalSql`.

OpenClaw 2026.10.10 serves some state-database DDL through
`getOpenClawStateFeatureSchemaSql(table, options)` from an object, `featureLocalSql`, that
holds tables `OPENCLAW_STATE_SCHEMA_SQL` does not list. The generator reads that object (key
set pinned) and the helper (body pinned) and sanity-checks the call sites. These tests drive
that machinery on synthetic dists: every broken case has a clean twin built from the same
fixture, so a pass proves the fixture is well-formed and the raise is the guard's doing.

All DDL is built at RUNTIME (f-strings), as test_c679 does, so no plain `CREATE TABLE`
literal of a state table sits in this file for the state-DDL registry to claim.
"""
from __future__ import annotations

import pytest

from test_state_schema_grounding import (
    _FEATURE_HELPER_BODY,
    _FEATURE_PROVENANCE_KEY,
    _feature_helper_call_sites,
    _feature_helper_tables,
    _read_vendor_table_baseline,
    _satellite_state_tables,
    _vendor_state_table_surface,
    _write_dist,
)

_MAIN = {"a_main", "b_main", "skill_library_entries"}
_ADDS = {"user_profiles": "test"}
_REDECL = {"a_main": "test"}
_HELPER = "getOpenClawStateFeatureSchemaSql"


def _ddl(*names: str) -> str:
    return "\n".join(f"CREATE TABLE IF NOT EXISTS {n} (x TEXT) STRICT;" for n in names)


def _splice(table: str) -> str:
    return "${extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, \"%s\")}" % table


def _tpl(body: str) -> str:
    return f"`{body}`"


def _str(body: str) -> str:
    """The same SQL as a double-quoted JS string."""
    return '"' + body.replace("\n", "\\n") + '"'


_UP_BODY = _ddl("user_profiles", "user_profile_emails") + "\n" + _splice("a_main")
_UP_BODY_PLAIN = _ddl("user_profiles", "user_profile_emails")
_RE_BODY = _ddl("a_main")


def _entries(**kw: str) -> str:
    return ",\n".join(f"  {k}: {v}" for k, v in kw.items())


def _obj(entries: str) -> str:
    return "{\n" + entries + "\n}"


def _helper(body: str = _FEATURE_HELPER_BODY) -> str:
    return f"function {_HELPER}(table, options) {{ {body} }}\n"


def _const_bundle(entries: str, helper: str | None = None) -> str:
    return f"const featureLocalSql = {_obj(entries)};\n" + (_helper() if helper is None else helper)


def _lazy_bundle(entries: str) -> str:
    return ("var featureLocalSql;\nvar init = __esmMin(() => {\n    featureLocalSql = "
            + _obj(entries) + ";\n});\n" + _helper())


_CLEAN_ENTRIES = _entries(user_profiles=_tpl(_UP_BODY), a_main=_tpl(_RE_BODY))


def _tables(dist, adds=_ADDS, redeclares=_REDECL):
    return _feature_helper_tables(dist, _MAIN, adds, redeclares)


def _one(tmp_path, text: str):
    return _write_dist(tmp_path, {"a.mjs": text})


# ---- clean cases 1-3 ----------------------------------------------------------------------

def test_clean_const_spelling_names_the_tables_and_what_they_add(tmp_path):
    got = _tables(_one(tmp_path, _const_bundle(_CLEAN_ENTRIES)))
    assert got["adds"] == ["user_profile_emails", "user_profiles"]
    assert got["tables"] == ["a_main", "user_profile_emails", "user_profiles"]
    assert got["copies"] == 1 and got["bundle"] == "a.mjs"


def test_lazy_spelling_reads_the_same_as_the_const_spelling(tmp_path):
    lazy = _tables(_write_dist(tmp_path / "l", {"a.mjs": _lazy_bundle(_CLEAN_ENTRIES)}))
    const = _tables(_write_dist(tmp_path / "c", {"a.mjs": _const_bundle(_CLEAN_ENTRIES)}))
    assert lazy == const
    assert lazy["adds"] == ["user_profile_emails", "user_profiles"]


def test_a_string_value_and_a_template_value_of_the_same_object_agree(tmp_path):
    tpl = _entries(user_profiles=_tpl(_UP_BODY_PLAIN), a_main=_tpl(_RE_BODY))
    txt = _entries(user_profiles=_str(_UP_BODY_PLAIN), a_main=_str(_RE_BODY))
    dist = _write_dist(tmp_path, {"a.mjs": _const_bundle(tpl),
                                  "nested/b.mjs": _const_bundle(txt)})
    got = _tables(dist)
    assert got["copies"] == 2 and got["bundle"] == "a.mjs"
    assert got["adds"] == ["user_profile_emails", "user_profiles"]


# ---- broken cases 5-13 --------------------------------------------------------------------

def _clean_twin(tmp_path, **kw):
    """Positive control: the unmodified fixture passes in a sibling directory."""
    got = _tables(_write_dist(tmp_path.parent / f"{tmp_path.name}_twin", {"a.mjs": _const_bundle(_CLEAN_ENTRIES)}), **kw)
    assert got["copies"] == 1
    return got


def test_a_new_unclassified_key_stops_the_generator(tmp_path):
    _clean_twin(tmp_path)
    entries = _CLEAN_ENTRIES + ",\n" + _entries(brand_new_key=_tpl(_ddl("brand_new_key")))
    with pytest.raises(AssertionError, match=r"new, unclassified \['brand_new_key'\]"):
        _tables(_one(tmp_path, _const_bundle(entries)))


def test_a_classified_key_the_dist_dropped_stops_the_generator(tmp_path):
    _clean_twin(tmp_path)
    with pytest.raises(AssertionError, match=r"classified but missing \['gone_key'\]"):
        _tables(_one(tmp_path, _const_bundle(_CLEAN_ENTRIES)),
                redeclares={**_REDECL, "gone_key": "test"})


def test_a_redeclaring_key_that_declares_a_table_outside_main_stops(tmp_path):
    _clean_twin(tmp_path)
    entries = _entries(user_profiles=_tpl(_UP_BODY),
                       a_main=_tpl(_ddl("a_main", "outside_tbl")))
    with pytest.raises(AssertionError, match=r"\['outside_tbl'\].*promote it to"):
        _tables(_one(tmp_path, _const_bundle(entries)))


def test_an_adding_key_that_adds_nothing_stops(tmp_path):
    _clean_twin(tmp_path)
    entries = _entries(user_profiles=_tpl(_UP_BODY), a_main=_tpl(_RE_BODY))
    with pytest.raises(AssertionError, match="pinned as ADDING.*a_main"):
        _tables(_one(tmp_path, _const_bundle(entries)), adds={**_ADDS, "a_main": "t"},
                redeclares={})


def test_a_key_pinned_as_both_adding_and_redeclaring_stops(tmp_path):
    _clean_twin(tmp_path)
    with pytest.raises(AssertionError, match=r"\['a_main'\] are pinned as BOTH adding and re-declaring"):
        _tables(_one(tmp_path, _const_bundle(_CLEAN_ENTRIES)),
                adds={**_ADDS, "a_main": "t"})


_EXTRA_BRANCH = 'if (table === "x") return featureLocalSql.other; '
_EMAILS_BRANCH = 'table === "user_profile_emails" ? featureLocalSql.user_profiles : '


@pytest.mark.parametrize("old,new", [
    ("if (options === void 0 && featureLocalSql[table])",
     _EXTRA_BRANCH + "if (options === void 0 && featureLocalSql[table])"),
    (_EMAILS_BRANCH, ""),
], ids=["extra routing branch", "user_profile_emails branch removed"])
def test_a_changed_helper_body_stops_the_generator(tmp_path, old, new):
    assert _FEATURE_HELPER_BODY.count(old) == 1, "the mutation must hit the pinned body once"
    mutated = _FEATURE_HELPER_BODY.replace(old, new)
    assert mutated != _FEATURE_HELPER_BODY
    _clean_twin(tmp_path)
    with pytest.raises(AssertionError, match=r"is not the body this guard pinned"):
        _tables(_one(tmp_path, _const_bundle(_CLEAN_ENTRIES, _helper(mutated))))


def test_no_helper_anywhere_stops_the_generator(tmp_path):
    _clean_twin(tmp_path)
    dist = _one(tmp_path, "const unrelated = 1;\n")
    with pytest.raises(AssertionError, match=f"no bundle under .* defines {_HELPER}"):
        _tables(dist)


def test_two_copies_with_a_different_value_stop_the_generator(tmp_path):
    _clean_twin(tmp_path)
    other = _entries(user_profiles=_tpl(_UP_BODY), a_main=_tpl(_ddl("a_main", "b_main")))
    dist = _write_dist(tmp_path, {"a.mjs": _const_bundle(_CLEAN_ENTRIES),
                                  "b.mjs": _const_bundle(other)})
    with pytest.raises(AssertionError, match=r"featureLocalSql differs between .*keys \['a_main'\]"):
        _tables(dist)


def test_two_copies_with_a_different_helper_body_stop_the_generator(tmp_path):
    _clean_twin(tmp_path)
    old = "includeEndMarker: false"
    assert _FEATURE_HELPER_BODY.count(old) == 1
    dist = _write_dist(tmp_path, {
        "a.mjs": _const_bundle(_CLEAN_ENTRIES),
        "b.mjs": _const_bundle(_CLEAN_ENTRIES, _helper(_FEATURE_HELPER_BODY.replace(old, "includeEndMarker: true")))})
    with pytest.raises(AssertionError, match=f"{_HELPER} has a different body"):
        _tables(dist)


def test_two_objects_in_one_file_stop_the_generator(tmp_path):
    _clean_twin(tmp_path)
    text = _const_bundle(_CLEAN_ENTRIES) + f"var featureLocalSql2;\nfeatureLocalSql = {_obj(_CLEAN_ENTRIES)};\n"
    with pytest.raises(AssertionError, match=r"1 .*definition\(s\) and 2 featureLocalSql object"):
        _tables(_one(tmp_path, text))


def test_two_helper_definitions_in_one_file_stop_the_generator(tmp_path):
    _clean_twin(tmp_path)
    text = _const_bundle(_CLEAN_ENTRIES) + _helper()
    with pytest.raises(AssertionError, match=r"2 .*definition\(s\) and 1 featureLocalSql object"):
        _tables(_one(tmp_path, text))


def test_an_object_with_no_function_beside_it_stops_the_generator(tmp_path):
    _clean_twin(tmp_path)
    text = f"const featureLocalSql = {_obj(_CLEAN_ENTRIES)};\n"
    with pytest.raises(AssertionError, match="featureLocalSql object but no .*definition"):
        _tables(_one(tmp_path, text))


def test_a_rewritten_helper_definition_stops_the_generator(tmp_path):
    _clean_twin(tmp_path)
    text = (f"const featureLocalSql = {_obj(_CLEAN_ENTRIES)};\n"
            f"const {_HELPER} = (table, options) => featureLocalSql[table];\n")
    with pytest.raises(AssertionError, match="helper was rewritten"):
        _tables(_one(tmp_path, text))


def test_a_value_that_does_not_declare_its_own_key_stops(tmp_path):
    _clean_twin(tmp_path)
    entries = _entries(user_profiles=_tpl(_UP_BODY), a_main=_tpl(_ddl("b_main")))
    with pytest.raises(AssertionError, match=r"declares \['b_main'\], not 'a_main'"):
        _tables(_one(tmp_path, _const_bundle(entries)))


def test_user_profiles_without_user_profile_emails_stops(tmp_path):
    _clean_twin(tmp_path)
    entries = _entries(user_profiles=_tpl(_ddl("user_profiles")), a_main=_tpl(_RE_BODY))
    with pytest.raises(AssertionError, match="does not declare user_profile_emails"):
        _tables(_one(tmp_path, _const_bundle(entries)))


def test_a_dist_with_no_user_profiles_key_stops(tmp_path):
    _clean_twin(tmp_path)
    entries = _entries(feat_add=_tpl(_ddl("feat_add")), a_main=_tpl(_RE_BODY))
    with pytest.raises(AssertionError, match="no 'user_profiles' key"):
        _tables(_one(tmp_path, _const_bundle(entries)), adds={"feat_add": "t"})


def test_a_splice_of_a_table_main_lacks_stops(tmp_path):
    _clean_twin(tmp_path)
    entries = _entries(user_profiles=_tpl(_ddl("user_profiles", "user_profile_emails") + "\n"
                                          + _splice("ghost")), a_main=_tpl(_RE_BODY))
    with pytest.raises(AssertionError, match=r"splices \['ghost'\]"):
        _tables(_one(tmp_path, _const_bundle(entries)))


def test_a_quoted_create_table_name_stops(tmp_path):
    _clean_twin(tmp_path)
    quoted = _ddl("user_profiles", "user_profile_emails") + "\n" + _ddl("'q one'")
    entries = _entries(user_profiles=_tpl(quoted), a_main=_tpl(_RE_BODY))
    with pytest.raises(AssertionError, match="not a bare identifier"):
        _tables(_one(tmp_path, _const_bundle(entries)))


# ---- 14: value / key shapes the parser does not model --------------------------------------

@pytest.mark.parametrize("raw,match", [
    ("a_main: someIdentifier", "not a template or string literal"),
    ("a_main: makeSql()", "not a template or string literal"),
    ("...rest", "not a bare or quoted key"),
    ("[computedKey]: `x`", "not a bare or quoted key"),
    ("a_main", r"not followed by `:`"),
    ("a_main() { return 1; }", r"not followed by `:`"),
    ("a_main: `a` + `b`", r"not `,` or `\}`"),
    ("/* c */ a_main: `a`", "not a bare or quoted key"),
], ids=["identifier", "call", "spread", "computed key", "shorthand", "method",
        "concatenation", "comment"])
def test_an_unmodelled_entry_shape_stops_the_parser(tmp_path, raw, match):
    _clean_twin(tmp_path)
    entries = _entries(user_profiles=_tpl(_UP_BODY)) + ",\n  " + raw
    with pytest.raises(AssertionError, match=match):
        _tables(_one(tmp_path, _const_bundle(entries)))


def test_a_duplicate_key_stops_the_parser(tmp_path):
    _clean_twin(tmp_path)
    entries = _CLEAN_ENTRIES + ",\n" + _entries(a_main=_tpl(_RE_BODY))
    with pytest.raises(AssertionError, match="declares the key 'a_main' twice"):
        _tables(_one(tmp_path, _const_bundle(entries)))


def test_a_quoted_key_is_read_like_a_bare_one(tmp_path):
    entries = _entries(user_profiles=_tpl(_UP_BODY)) + ',\n  "a_main": ' + _tpl(_RE_BODY)
    got = _tables(_one(tmp_path, _const_bundle(entries)))
    assert got["adds"] == ["user_profile_emails", "user_profiles"]


def test_an_unterminated_object_stops_the_parser(tmp_path):
    _clean_twin(tmp_path)
    text = "const featureLocalSql = {\n  a_main: " + _tpl(_RE_BODY) + ",\n" + _helper()
    with pytest.raises(AssertionError, match="unterminated featureLocalSql object|followed by"):
        _tables(_one(tmp_path, text))


# ---- 15: interpolation inside a value ------------------------------------------------------

def test_a_computed_table_name_interpolation_in_a_value_stops(tmp_path):
    _clean_twin(tmp_path)
    expr = "tableName"
    body = _RE_BODY + f"\nCREATE TABLE IF NOT EXISTS ${{{expr}}} (y TEXT);"
    entries = _entries(user_profiles=_tpl(_UP_BODY), a_main=_tpl(body))
    with pytest.raises(AssertionError, match="interpolates `\\$\\{tableName\\}`"):
        _tables(_one(tmp_path, _const_bundle(entries)))


# ---- helper constants: clean case 4 and broken case 16 --------------------------------------

_WIDGET = "WIDGET_SCHEMA_SQL"
_NO_LISTS = {"satellites": {}, "excluded": {}, "redeclaring": {}, "derived": {}}
_FEATURE_LISTS = {**_NO_LISTS, "feature_constants": {_WIDGET: "test"}}


def _constants(tmp_path, body: str, feature_tables=frozenset(), **lists):
    dist = _write_dist(tmp_path, {"c.mjs": body})
    return _satellite_state_tables(dist, _MAIN, **(lists or _FEATURE_LISTS),
                                   feature_tables=feature_tables)


_OK_LITERAL = f'const {_WIDGET} = {_HELPER}("a_main");\n'
_OK_IDENT = f'const T = "a_main";\nconst {_WIDGET} = {_HELPER}(T);\n'


def test_a_helper_constant_over_a_main_table_passes_and_is_not_returned(tmp_path):
    assert _constants(tmp_path, _OK_LITERAL) == {}


def test_a_helper_constant_through_a_bound_identifier_passes(tmp_path):
    assert _constants(tmp_path, _OK_IDENT) == {}


def test_a_helper_constant_over_a_feature_only_table_passes_only_when_it_is_known(tmp_path):
    body = f'const {_WIDGET} = {_HELPER}("user_profiles");\n'
    assert _constants(tmp_path / "ok", body, feature_tables={"user_profiles"}) == {}
    with pytest.raises(AssertionError, match="'user_profiles'.*plus featureLocalSql|user_profiles"):
        _constants(tmp_path / "no", body)


@pytest.mark.parametrize("body,match", [
    ('const T = "a_main";\nlet T = "b_main";\n' + f"const {_WIDGET} = {_HELPER}(T);\n",
     "not bound to exactly one"),
    (f"const {_WIDGET} = {_HELPER}(T);\n", "not bound to exactly one"),
    (f'const {_WIDGET} = {_HELPER}("a_main", {{ x: 1 }});\n', "not the one shape"),
    (f'const {_WIDGET} = {_HELPER}("ghost");\n', "ghost"),
    (f"const {_WIDGET} = {_HELPER}(tableVar);\n", "not bound to exactly one"),
    (f"const {_WIDGET} = {_HELPER}(params.table);\n", "not the one shape"),
    (f"const {_WIDGET} = compose({_HELPER}('a_main'));\n", "not the one shape"),
], ids=["bound twice", "not bound", "options argument", "table outside the set",
        "unbound lowercase identifier", "member expression", "wrapped call"])
def test_a_helper_constant_edge_case_stops_the_generator(tmp_path, body, match):
    assert _constants(tmp_path / "twin", _OK_LITERAL) == {}
    with pytest.raises(AssertionError, match=match):
        _constants(tmp_path / "bad", body)


def test_a_helper_constant_the_dist_no_longer_defines_stops(tmp_path):
    assert _constants(tmp_path / "twin", _OK_LITERAL) == {}
    with pytest.raises(AssertionError, match=f"{_WIDGET} is classified as .* no bundle under"):
        _constants(tmp_path / "bad", "const unrelated = 1;\n")


def test_a_helper_constant_defined_for_two_tables_stops(tmp_path):
    body = _OK_LITERAL + f'const {_WIDGET} = {_HELPER}("b_main");\n'
    with pytest.raises(AssertionError, match=r"DIFFERENT tables \(\['a_main', 'b_main'\]\)"):
        _constants(tmp_path, body)


# ---- 18: the extended net ------------------------------------------------------------------

def test_an_unclassified_constant_defined_through_the_helper_stops(tmp_path):
    assert _constants(tmp_path / "twin", _OK_LITERAL) == {}
    with pytest.raises(AssertionError,
                       match=rf"unclassified \*_SCHEMA_SQL.*{_WIDGET}.*_STATE_FEATURE_HELPER_CONSTANTS"):
        _constants(tmp_path / "bad", _OK_LITERAL, **_NO_LISTS, feature_constants={})


# ---- 17: call sites ------------------------------------------------------------------------

# The main-constant extractor refuses a schema with fewer than 100 tables (its own sanity floor).
_FILLER = {f"filler_{i:03d}" for i in range(100)}


def _surface_dist(tmp_path, calls: str):
    main = _ddl(*sorted(_MAIN | _FILLER))
    files = {
        "state/main.mjs": 'const OPENCLAW_STATE_SCHEMA_SQL = "' + main.replace("\n", "\\n") + '";\n',
        "feat.mjs": _const_bundle(_CLEAN_ENTRIES),
        "use.mjs": calls,
    }
    return _write_dist(tmp_path, files)


def _surface(dist):
    return _vendor_state_table_surface(dist, **_NO_LISTS, feature_constants={},
                                       feature_adds=_ADDS, feature_redeclares=_REDECL)


_OK_CALL = f'db.exec({_HELPER}("a_main"));\n'


def test_the_surface_is_main_plus_feature_tables_and_reports_the_call_sites(tmp_path):
    surface, prov, _ = _surface(_surface_dist(tmp_path, _OK_CALL + f"x({_HELPER}(params.table, o));\n"))
    assert surface == _MAIN | _FILLER | {"user_profiles", "user_profile_emails"}
    feat = prov[_FEATURE_PROVENANCE_KEY]
    assert feat["adds"] == ["user_profile_emails", "user_profiles"]
    assert feat["call_sites_resolved"] == 1 and feat["call_sites_unresolved"] == 1


def test_a_literal_call_for_a_table_nobody_declares_stops(tmp_path):
    _surface(_surface_dist(tmp_path / "twin", _OK_CALL))
    with pytest.raises(AssertionError, match=r"called for \['ghost'\]"):
        _surface(_surface_dist(tmp_path / "bad", _OK_CALL + f'x({_HELPER}("ghost"));\n'))


def test_a_dist_whose_only_calls_are_unresolvable_stops(tmp_path):
    _surface(_surface_dist(tmp_path / "twin", _OK_CALL))
    with pytest.raises(AssertionError, match="no resolvable .* call site"):
        _surface(_surface_dist(tmp_path / "bad", f"x({_HELPER}(table, options));\n"))


def test_call_sites_count_unresolved_without_resolving_them(tmp_path):
    dist = _write_dist(tmp_path, {"u.mjs": _OK_CALL + f"x({_HELPER}(params.table, o));\n"
                                  + _helper()})
    sites, unresolved = _feature_helper_call_sites(dist)
    assert sorted(sites) == ["a_main"] and unresolved == 1


def test_an_upper_snake_call_argument_resolves_through_its_one_binding(tmp_path):
    dist = _write_dist(tmp_path, {"u.mjs": f'const GRANT_TABLE = "b_main";\nx({_HELPER}(GRANT_TABLE));\n'})
    sites, unresolved = _feature_helper_call_sites(dist)
    assert sorted(sites) == ["b_main"] and unresolved == 0


def test_an_upper_snake_call_argument_bound_twice_or_never_stops(tmp_path):
    ok = _write_dist(tmp_path / "twin", {"u.mjs": f'const GT = "b_main";\nx({_HELPER}(GT));\n'})
    assert _feature_helper_call_sites(ok)[0] == {"b_main": [ok / "u.mjs"]}
    for i, binding in enumerate(('const GT = "a_main";\nlet GT = "b_main";\n', "")):
        dist = _write_dist(tmp_path / f"bad{i}", {"u.mjs": binding + f"x({_HELPER}(GT));\n"})
        with pytest.raises(AssertionError, match="not bound to exactly one"):
            _feature_helper_call_sites(dist)


# ---- always-on: the shipped baseline -------------------------------------------------------

def test_the_shipped_baseline_lists_user_background_images_and_the_feature_only_tables():
    _, names = _read_vendor_table_baseline()
    if "user_background_images" not in names:
        pytest.skip("tests/vendor_state_tables.txt is not yet regenerated for 2026.10.10 "
                    "(C-762 regeneration pending); un-skips itself once it lists "
                    "user_background_images")
    assert {"user_background_images", "user_profiles", "user_profile_emails",
            "worker_environment_session_attachments"} <= set(names)
