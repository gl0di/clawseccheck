"""C-744: the structural reader of the tool catalog's ``coreTools(...)`` form.

OpenClaw 2026.10.5 rewrote ``CORE_TOOL_DEFINITIONS`` from one object literal per tool into
``...coreTools("<section>", {defaults}, [["<id>", "<description>", {overrides}?], ...])`` calls.
Every regex that assumed one literal per tool read 0 tools; this file pins the reader that
replaced them (``tests/_distgrounding.py::catalog_tool_records``) on synthetic text, so it is
checked on CI where the real dist is absent.
"""
from __future__ import annotations

import pytest
from _distgrounding import catalog_tool_records, catalog_tool_sections

_NEW = '''
const CORE_TOOL_DEFINITIONS = [
	...coreTools("agents", {
		profiles: ["coding", "messaging"],
		includeInOpenClawGroup: true
	}, [["decision_evaluate", "Evaluate [explicit] evidence, (really)"]]),
	...coreTools("fs", {
		profiles: ["coding"],
		executionLocation: "placement"
	}, [
		["ls", "List directory entries"],
		["read", "Read \\"file\\" contents, with a comma"],
		["write", "Create or overwrite files"]
	]),
	...coreTools("runtime", { profiles: ["coding"] }, [
		[
			"exec",
			EXEC_TOOL_DISPLAY_SUMMARY,
			{ executionLocation: "placement" }
		],
		["code_execution", "Run sandboxed analysis", { includeInOpenClawGroup: true, profiles: ["coding", "full"] }],
		[AUTOMATIONS_TOOL_NAME, "an imported identifier is not a literal id"]
	])
];
const CORE_TOOL_BY_ID = new Map();
'''

_OLD = '''
const CORE_TOOL_DEFINITIONS = [
	{
		id: "read",
		executionLocation: "placement",
		description: "Read file contents",
		sectionId: "fs",
		profiles: ["coding"]
	}
];
'''


def test_the_new_form_is_read_with_sections_and_merged_profiles():
    rec = catalog_tool_records(_NEW)
    assert set(rec) == {"decision_evaluate", "ls", "read", "write", "exec", "code_execution"}
    assert rec["read"] == {"sectionId": "fs", "profiles": ["coding"]}
    assert rec["decision_evaluate"]["profiles"] == ["coding", "messaging"]
    # an override REPLACES the default, as `...defaults, ...options` does in the vendor
    assert rec["code_execution"]["profiles"] == ["coding", "full"]
    assert rec["exec"]["profiles"] == ["coding"]


def test_punctuation_inside_a_description_does_not_split_or_close_anything():
    rec = catalog_tool_records(_NEW)
    assert "decision_evaluate" in rec and "read" in rec and "write" in rec


def test_an_imported_identifier_id_is_left_out_as_the_old_parser_left_it_out():
    assert not any("AUTOMATIONS" in k for k in catalog_tool_records(_NEW))


def test_section_ids_come_from_the_call_not_from_a_field():
    assert catalog_tool_sections(_NEW)["ls"] == "fs"
    assert catalog_tool_sections(_NEW)["exec"] == "runtime"


def test_the_old_one_literal_per_tool_form_still_reads_through_the_fallback():
    assert catalog_tool_records(_OLD) == {}              # the structural reader owns only the new form
    assert catalog_tool_sections(_OLD) == {"read": "fs"}  # and the regex fallback still serves the old


def test_nothing_to_read_is_empty_not_a_crash():
    assert catalog_tool_records("no catalog here") == {}


def test_a_changed_builder_arity_fails_loudly_instead_of_reading_wrong():
    broken = _NEW.replace('...coreTools("fs", {', '...coreTools("fs", 1, {', 1)
    with pytest.raises(AssertionError):
        catalog_tool_records(broken)
