# Correlation Rule Template Discovery & Deployment — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use skills:executing-plans to implement this plan task-by-task.

**Goal:** Add two new tools (`falcon_search_correlation_rule_templates`, `falcon_deploy_correlation_rule_template`) and one FQL guide resource to the existing `CorrelationRulesModule`, enabling natural-language discovery and one-click deployment of correlation rule templates.

**Architecture:** Extends the existing `CorrelationRulesModule` in `falcon_mcp/modules/correlation_rules.py`. The search tool uses the query+hydrate pattern (query IDs via `queries_templates_get_v1Mixin0` → hydrate via `entities_templates_get_v1Mixin0` → reorder → pagination envelope). The deploy tool hydrates the template first to get defaults, then merges user overrides and POSTs to `entities_templates_rules_post_v1`. A new FQL guide resource includes all 15 MITRE ATT&CK Enterprise tactics with aliases for fuzzy natural-language matching.

**Tech Stack:** Python 3, FalconPy (via `self.client.command`), FastMCP, Pydantic `Field`, unittest

## Progress

| Status | Count |
|--------|-------|
| 🔴 NOT_STARTED | 5 |
| 🟡 IN_PROGRESS | 0 |
| 🟢 COMPLETED | 0 |
| ⚪ BLOCKED | 0 |

---

### Task 1: Add Template FQL Guide Resource 🔴 NOT_STARTED
<!-- deps: [] | files: ["falcon_mcp/resources/correlation_rules.py", "tests/modules/test_correlation_rules.py"] -->

> **REQUIRED:** Follow skills:test-driven-development (RED-GREEN-REFACTOR cycle)

**Files:**
- Modify: `falcon_mcp/resources/correlation_rules.py` (add new constant)
- Modify: `tests/modules/test_correlation_rules.py` (add resource registration test)

**Context:** The resource file already exists with `SEARCH_CORRELATION_RULES_FQL_DOCUMENTATION`. Add a new constant `SEARCH_CORRELATION_RULE_TEMPLATES_FQL_DOCUMENTATION` below it, following the same structure but with template-specific filter fields and MITRE tactic aliases.

**Step 1: Write the failing test (RED)**

Update `test_register_resources` in `tests/modules/test_correlation_rules.py` to expect both resources:

```python
def test_register_resources(self):
    """Test that both FQL guide resources are registered."""
    expected_resources = [
        "falcon_search_correlation_rules_fql_guide",
        "falcon_search_correlation_rule_templates_fql_guide",
    ]
    self.assert_resources_registered(expected_resources)
```

This replaces the existing `test_register_resources` which only expects the one resource.

**Step 2: Run test to verify it fails (Verify RED)**

Run: `python -m pytest tests/modules/test_correlation_rules.py::TestCorrelationRulesModule::test_register_resources -v`
Expected: FAIL — only 1 resource registered, expected 2.

**Step 3: Write the FQL guide constant (GREEN — part 1)**

Add to `falcon_mcp/resources/correlation_rules.py`, after the existing `SEARCH_CORRELATION_RULES_FQL_DOCUMENTATION`:

```python
# List of tuples containing template filter options: (name, type, description)
SEARCH_CORRELATION_RULE_TEMPLATES_FQL_FILTERS = [
    (
        "Name",
        "Type",
        "Description",
    ),
    (
        "name",
        "String",
        """
        Template name. Exact match is case-sensitive. Use ~* with * wildcards
        for case-insensitive substring matching.
        Ex (exact): name:'Suspicious PowerShell'
        Ex (substring): name:~*'*powershell*'
        """
    ),
    (
        "description",
        "String",
        """
        Template description. Use ~* with * wildcards for case-insensitive
        substring matching. Best for natural-language keyword searches.
        Ex (substring): description:~*'*lateral movement*'
        """
    ),
    (
        "vendor",
        "String",
        """
        Vendor or source of the template.
        Ex: vendor:'CrowdStrike'
        """
    ),
    (
        "outcome",
        "String",
        """
        Rule outcome type when template is deployed. Possible values:
        - detection: Creates detections
        - case: Creates cases
        Ex: outcome:'detection'
        """
    ),
    (
        "mitre_attack.tactic_id",
        "String",
        """
        MITRE ATT&CK tactic ID. Uses ATT&CK tactic IDs, not names.
        See the tactic reference table below for IDs and aliases.
        Ex: mitre_attack.tactic_id:'TA0001'
        """
    ),
    (
        "mitre_attack.technique_id",
        "String",
        """
        MITRE ATT&CK technique ID from the mitre_attack mapping.
        Ex: mitre_attack.technique_id:'T1059'
        """
    ),
    (
        "type",
        "String",
        """
        Template type.
        Ex: type:'correlation'
        """
    ),
]

SEARCH_CORRELATION_RULE_TEMPLATES_FQL_DOCUMENTATION = r"""Falcon Query Language (FQL) - Search Correlation Rule Templates Guide

=== PURPOSE ===
Use this guide to translate natural language into FQL filters for template discovery.
Users may describe threats, tactics, or detection goals without knowing exact template
names or MITRE IDs — follow the search strategy below to map their intent.

=== BASIC SYNTAX ===
field_name:[operator]'value'

=== OPERATORS ===
• = (default): field_name:'value' (exact match, case-sensitive)
• ~*: field_name:~*'*term*' (glob/wildcard match, case-insensitive — use * as a
  wildcard; wrap the term in * for true substring/contains matching)
• >, >=, <, <=: field_name:>50 (comparison for numbers/timestamps)
• !: field_name:!'value' (not equal)

=== CHOOSING THE RIGHT STRING OPERATOR ===
• Exact match (must know precise casing): name:'Suspicious PowerShell'
• Substring/contains match (case-insensitive, anywhere in value): name:~*'*powershell*'

=== COMBINING ===
• + = AND: name:~*'*lateral*'+name:~*'*movement*'
• , = OR: mitre_attack.tactic_id:'TA0001',mitre_attack.tactic_id:'TA0002'

=== BROADENING MULTI-WORD SEARCHES ===
For multi-word searches, split each keyword into its own ~* clause joined with +.
This matches regardless of word order, extra whitespace, or intervening words —
over-fetch broadly, then pick the best matches from the results:
• name:~*'*email*'+name:~*'*phishing*'
  Matches "Phishing Email Link Clicked", "Email Phishing Alert", etc.
• description:~*'*credential*'+description:~*'*theft*'
  Matches descriptions containing both words in any order.

=== NATURAL LANGUAGE SEARCH STRATEGY ===
When the user describes a threat or detection goal in natural language:

1. CHECK MITRE TACTICS FIRST: If the user's intent maps to a known MITRE tactic
   (see the alias table below), filter by tactic ID. This is the most precise approach.
   Example: "detect lateral movement" → mitre_attack.tactic_id:'TA0008'

2. CHECK MITRE TECHNIQUES: If the user names a specific technique or sub-technique,
   filter by technique ID.
   Example: "PowerShell execution" → mitre_attack.technique_id:'T1059'

3. FALL BACK TO KEYWORD SEARCH: If no MITRE mapping fits, search the description
   and/or name fields with ~* wildcard matching. Split multi-word phrases into
   separate ~* clauses.
   Example: "ransomware detection" → description:~*'*ransomware*'

4. COMBINE APPROACHES: Use + (AND) to combine tactic filters with keyword filters
   for maximum precision.
   Example: mitre_attack.tactic_id:'TA0040'+description:~*'*ransomware*'

=== MITRE ATT&CK ENTERPRISE TACTICS (v16) — ID, NAME, AND ALIASES ===
Use the aliases to match fuzzy user intent to the correct tactic ID.
If a user says any alias term, use the corresponding tactic ID in the filter.

• TA0043: Reconnaissance
  Aliases: recon, scanning, footprinting, OSINT, information gathering,
  target selection, open-source intelligence

• TA0042: Resource Development
  Aliases: infrastructure setup, staging, acquiring infrastructure,
  developing capabilities, establishing accounts

• TA0001: Initial Access
  Aliases: entry point, intrusion, exploitation, phishing, spearphishing,
  drive-by, trusted relationship, supply chain

• TA0002: Execution
  Aliases: code execution, running malware, script execution, command execution,
  PowerShell, scripting, user execution

• TA0003: Persistence
  Aliases: backdoor, implant, foothold, maintaining access, boot or logon,
  scheduled task, registry run key, startup

• TA0004: Privilege Escalation
  Aliases: privesc, elevating privileges, admin access, root access,
  token manipulation, exploitation for privilege escalation

• TA0005: Stealth (formerly Defense Evasion)
  Aliases: defense evasion, evasion, hiding, obfuscation, masquerading,
  process injection, indicator removal, rootkit, disabling defenses

• TA0112: Defense Impairment
  Aliases: disabling security, tampering, impairing defenses, breaking security,
  disabling logging, killing security tools

• TA0006: Credential Access
  Aliases: credential theft, password stealing, credential dumping, brute force,
  keylogging, credential harvesting, Kerberoasting, pass-the-hash

• TA0007: Discovery
  Aliases: enumeration, network scanning, system discovery, account discovery,
  network share discovery, permission groups discovery

• TA0008: Lateral Movement
  Aliases: pivoting, moving laterally, spreading, remote services,
  pass-the-ticket, WMI, RDP, SMB, internal spearphishing

• TA0009: Collection
  Aliases: data gathering, data staging, harvesting, screen capture,
  clipboard data, email collection, audio capture

• TA0011: Command and Control
  Aliases: C2, C&C, beaconing, callback, remote access, encrypted channel,
  proxy, web service, DNS tunneling

• TA0010: Exfiltration
  Aliases: data theft, data exfil, stealing data, data transfer,
  exfiltration over C2, exfiltration over web service

• TA0040: Impact
  Aliases: destruction, ransomware, wiping, disruption, sabotage,
  data encryption, defacement, denial of service, resource hijacking

=== falcon_search_correlation_rule_templates FQL filter available fields ===

""" + generate_md_table(SEARCH_CORRELATION_RULE_TEMPLATES_FQL_FILTERS) + """

=== FILTER EXAMPLES ===

# Templates for detecting lateral movement (via MITRE tactic)
mitre_attack.tactic_id:'TA0008'

# Templates for credential theft (via MITRE tactic)
mitre_attack.tactic_id:'TA0006'

# Templates mentioning ransomware (keyword in description)
description:~*'*ransomware*'

# Templates for PowerShell-related detections (keyword in name)
name:~*'*powershell*'

# Templates for a specific MITRE technique
mitre_attack.technique_id:'T1059'

# Templates covering initial access OR persistence
mitre_attack.tactic_id:'TA0001',mitre_attack.tactic_id:'TA0003'

# CrowdStrike-authored templates
vendor:'CrowdStrike'

# Templates with "phishing" anywhere in name or description
name:~*'*phishing*',description:~*'*phishing*'

# Broad multi-word search (order-independent)
description:~*'*brute*'+description:~*'*force*'

# Combine tactic + keyword for precision
mitre_attack.tactic_id:'TA0040'+description:~*'*ransomware*'
"""
```

**Step 4: Register the resource in the module (GREEN — part 2)**

In `falcon_mcp/modules/correlation_rules.py`, update the import (line 13) from:

```python
from falcon_mcp.resources.correlation_rules import SEARCH_CORRELATION_RULES_FQL_DOCUMENTATION
```

to:

```python
from falcon_mcp.resources.correlation_rules import (
    SEARCH_CORRELATION_RULES_FQL_DOCUMENTATION,
    SEARCH_CORRELATION_RULE_TEMPLATES_FQL_DOCUMENTATION,
)
```

Add to `register_resources` method, after the existing `fql_resource` block (after line 71):

```python
        template_fql_resource = TextResource(
            uri=AnyUrl("falcon://correlation-rule-templates/search/fql-guide"),
            name="falcon_search_correlation_rule_templates_fql_guide",
            description="Contains the guide for the `filter` param of the `falcon_search_correlation_rule_templates` tool.",
            text=SEARCH_CORRELATION_RULE_TEMPLATES_FQL_DOCUMENTATION,
        )
        self._add_resource(server, template_fql_resource)
```

**Step 5: Run test to verify it passes (Verify GREEN)**

Run: `python -m pytest tests/modules/test_correlation_rules.py::TestCorrelationRulesModule::test_register_resources -v`
Expected: PASS

**Step 6: Run all existing tests to confirm no regressions**

Run: `python -m pytest tests/modules/test_correlation_rules.py -v`
Expected: All existing tests PASS.

**Step 7: Commit**

```bash
git add falcon_mcp/resources/correlation_rules.py falcon_mcp/modules/correlation_rules.py tests/modules/test_correlation_rules.py
git commit -m "feat(correlation-rules): add FQL guide resource for rule templates

Adds SEARCH_CORRELATION_RULE_TEMPLATES_FQL_DOCUMENTATION with all 15
MITRE ATT&CK Enterprise tactics, aliases for natural-language matching,
and a search strategy section.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

### Task 2: Add `search_correlation_rule_templates` Tool Registration and Tests 🔴 NOT_STARTED
<!-- deps: [1] | files: ["falcon_mcp/modules/correlation_rules.py", "tests/modules/test_correlation_rules.py"] -->

> **REQUIRED:** Follow skills:test-driven-development (RED-GREEN-REFACTOR cycle)

**Files:**
- Modify: `falcon_mcp/modules/correlation_rules.py` (add tool registration + method)
- Modify: `tests/modules/test_correlation_rules.py` (add registration + behavior tests)

**Context:** The existing `search_correlation_rules` uses a `combined` endpoint (single call returns full entities). Templates use a **query+hydrate** pattern: query IDs via `queries_templates_get_v1Mixin0` → hydrate full entities via `entities_templates_get_v1Mixin0` → reorder → pagination envelope.

**FalconPy operation names** (from swagger operationId → snake_case):
- Query IDs: `queries_templates_get_v1Mixin0`
- Get entities: `entities_templates_get_v1Mixin0`

**Step 1: Write the failing registration test (RED)**

Update `test_register_tools` in the test file to expect 6 tools (was 4):

```python
def test_register_tools(self):
    """Test that all 6 correlation rule tools are registered with correct prefixed names."""
    expected_tools = [
        "falcon_search_correlation_rules",
        "falcon_create_correlation_rule",
        "falcon_update_correlation_rule",
        "falcon_delete_correlation_rules",
        "falcon_search_correlation_rule_templates",
        "falcon_deploy_correlation_rule_template",
    ]
    self.assert_tools_registered(expected_tools)
```

Add a read-only annotation test:

```python
def test_search_templates_tool_annotations(self):
    """Test that search templates tool uses READ_ONLY_ANNOTATIONS."""
    self.module.register_tools(self.mock_server)
    self.assert_tool_annotations(
        "falcon_search_correlation_rule_templates", READ_ONLY_ANNOTATIONS
    )
```

**Step 2: Run tests to verify they fail (Verify RED)**

Run: `python -m pytest tests/modules/test_correlation_rules.py::TestCorrelationRulesModule::test_register_tools tests/modules/test_correlation_rules.py::TestCorrelationRulesModule::test_search_templates_tool_annotations -v`
Expected: FAIL — tools not registered yet.

**Step 3: Write the search tool method + registration (GREEN)**

Add the tool registration in `register_tools` (after the existing `delete_correlation_rules` registration):

```python
        self._add_tool(
            server=server,
            method=self.search_correlation_rule_templates,
            name="search_correlation_rule_templates",
        )
```

Add the method to the class (after `delete_correlation_rules`, before the end of the class):

```python
    def search_correlation_rule_templates(
        self,
        filter: str | None = Field(
            default=None,
            description=(
                "FQL filter expression. See `falcon://correlation-rule-templates/search/fql-guide` "
                "for syntax, MITRE ATT&CK tactic/technique ID mappings, and natural-language "
                "search strategies."
            ),
            examples={
                "mitre_attack.tactic_id:'TA0008'",
                "description:~*'*ransomware*'",
                "name:~*'*powershell*'",
            },
        ),
        limit: int = Field(
            default=20,
            ge=1,
            le=500,
            description="Maximum number of templates to return. (Max: 500)",
        ),
        offset: int | None = Field(
            default=None,
            description="Starting index for pagination.",
        ),
        sort: str | None = Field(
            default=None,
            description="Sort templates. Options: 'created_on', 'created_on|desc', 'last_updated_on', 'last_updated_on|desc'.",
            examples={"last_updated_on|desc", "created_on"},
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search pre-built Correlation Rule templates and return full template details.

        Use this to discover detection rule templates that can be deployed as live correlation
        rules. Describe what you want to detect — lateral movement, credential theft, ransomware,
        phishing, etc. — and consult falcon://correlation-rule-templates/search/fql-guide for
        MITRE ATT&CK tactic/technique ID mappings and natural-language search strategies.
        Returns full template objects; use the `id` field when passing results to the deploy tool.
        Responses include `pagination.total` (the total number of records matching the filter,
        or null when the API does not report a count) — use it to answer "how many" questions.
        """
        # Step 1: Query template IDs with pagination
        ids_result, pagination = self._base_search_with_meta(
            operation="queries_templates_get_v1Mixin0",
            search_params={
                "filter": filter,
                "limit": limit,
                "offset": offset,
                "sort": sort,
            },
            error_message="Failed to search Correlation Rule Templates",
        )

        if self._is_error(ids_result):
            return self._format_fql_error_response(
                [ids_result], filter, SEARCH_CORRELATION_RULE_TEMPLATES_FQL_DOCUMENTATION
            )

        if not ids_result:
            return self._build_pagination_envelope([], pagination, filter)

        # Step 2: Hydrate full template details by IDs
        entities = self._base_get_by_ids(
            operation="entities_templates_get_v1Mixin0",
            ids=ids_result,
            use_params=True,
        )

        if self._is_error(entities):
            return self._format_fql_error_response(
                [entities], filter, SEARCH_CORRELATION_RULE_TEMPLATES_FQL_DOCUMENTATION
            )

        # Step 3: Reorder to match query sort order
        ordered = self._reorder_by_ids(ids_result, entities, id_field="id")

        return self._build_pagination_envelope(ordered, pagination, filter)
```

**Step 4: Run registration tests to verify they pass (Verify GREEN)**

Run: `python -m pytest tests/modules/test_correlation_rules.py::TestCorrelationRulesModule::test_register_tools tests/modules/test_correlation_rules.py::TestCorrelationRulesModule::test_search_templates_tool_annotations -v`
Expected: PASS

**Step 5: Write behavior tests for search_correlation_rule_templates**

Add these tests to the test file in a new section:

```python
    # -------------------------------------------------------------------------
    # Search Templates Tests
    # -------------------------------------------------------------------------

    def test_search_templates_success(self):
        """Test searching templates uses query+hydrate pattern and returns full objects."""
        # First call: query IDs
        # Second call: hydrate entities
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {
                    "resources": ["tmpl-1", "tmpl-2"],
                    "meta": {"pagination": {"total": 2}},
                },
            },
            {
                "status_code": 200,
                "body": {"resources": [
                    {"id": "tmpl-1", "name": "Lateral Movement Detection", "severity": 70},
                    {"id": "tmpl-2", "name": "Credential Theft Alert", "severity": 90},
                ]},
            },
        ]

        result = self.module.search_correlation_rule_templates(
            filter="mitre_attack.tactic_id:'TA0008'",
            limit=10,
        )

        # Verify query call
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "queries_templates_get_v1Mixin0")
        self.assertEqual(first_call[1]["parameters"]["filter"], "mitre_attack.tactic_id:'TA0008'")
        self.assertEqual(first_call[1]["parameters"]["limit"], 10)

        # Verify hydrate call
        second_call = self.mock_client.command.call_args_list[1]
        self.assertEqual(second_call[0][0], "entities_templates_get_v1Mixin0")

        # Verify response envelope
        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["id"], "tmpl-1")
        self.assertEqual(result["results"][1]["id"], "tmpl-2")
        self.assertEqual(result["pagination"]["total"], 2)

    def test_search_templates_empty_results(self):
        """Test that empty query results return clean empty envelope."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }

        result = self.module.search_correlation_rule_templates(
            filter="name:'nonexistent'"
        )

        self.assertIsInstance(result, dict)
        self.assertEqual(result["results"], [])
        self.assertEqual(result["filter_used"], "name:'nonexistent'")
        self.assertNotIn("fql_guide", result)
        # Only one API call (query step); hydrate step is skipped
        self.mock_client.command.assert_called_once()

    def test_search_templates_query_error_returns_fql_guide(self):
        """Test that query-step API errors return a dict with fql_guide."""
        self.mock_client.command.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "Invalid filter"}]},
        }

        result = self.module.search_correlation_rule_templates(filter="bad!!!")

        self.assertIsInstance(result, dict)
        self.assertIn("fql_guide", result)
        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 1)
        self.assertIn("error", result["results"][0])

    def test_search_templates_hydrate_error_returns_fql_guide(self):
        """Test that hydrate-step API errors return a dict with fql_guide."""
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {
                    "resources": ["tmpl-1"],
                    "meta": {"pagination": {"total": 1}},
                },
            },
            {
                "status_code": 500,
                "body": {"errors": [{"message": "Internal error"}]},
            },
        ]

        result = self.module.search_correlation_rule_templates()

        self.assertIsInstance(result, dict)
        self.assertIn("fql_guide", result)

    def test_search_templates_preserves_sort_order(self):
        """Test that hydrated results are reordered to match query ID order."""
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {
                    "resources": ["tmpl-a", "tmpl-b", "tmpl-c"],
                    "meta": {"pagination": {"total": 3}},
                },
            },
            {
                "status_code": 200,
                "body": {"resources": [
                    # API returns in different order
                    {"id": "tmpl-c", "name": "C"},
                    {"id": "tmpl-a", "name": "A"},
                    {"id": "tmpl-b", "name": "B"},
                ]},
            },
        ]

        result = self.module.search_correlation_rule_templates(
            sort="last_updated_on|desc"
        )

        self.assertEqual(result["results"][0]["id"], "tmpl-a")
        self.assertEqual(result["results"][1]["id"], "tmpl-b")
        self.assertEqual(result["results"][2]["id"], "tmpl-c")
```

**Step 6: Run all template search tests (Verify GREEN)**

Run: `python -m pytest tests/modules/test_correlation_rules.py -k "template" -v`
Expected: All PASS.

**Step 7: Run full test suite for regressions**

Run: `python -m pytest tests/modules/test_correlation_rules.py -v`
Expected: All PASS.

**Step 8: Commit**

```bash
git add falcon_mcp/modules/correlation_rules.py tests/modules/test_correlation_rules.py
git commit -m "feat(correlation-rules): add search_correlation_rule_templates tool

Query+hydrate pattern: queries IDs via queries_templates_get_v1Mixin0,
hydrates via entities_templates_get_v1Mixin0, reorders to match sort,
returns pagination envelope. FQL guide resource points to MITRE tactic
aliases for natural-language search.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

### Task 3: Add `deploy_correlation_rule_template` Tool Registration and Tests 🔴 NOT_STARTED
<!-- deps: [1, 2] | files: ["falcon_mcp/modules/correlation_rules.py", "tests/modules/test_correlation_rules.py"] -->

> **REQUIRED:** Follow skills:test-driven-development (RED-GREEN-REFACTOR cycle)

**Files:**
- Modify: `falcon_mcp/modules/correlation_rules.py` (add tool registration + method)
- Modify: `tests/modules/test_correlation_rules.py` (add annotation + behavior tests)

**Context:** The deploy endpoint `entities_templates_rules_post_v1` requires a body like:
```json
[{
  "customer_id": "cid123",
  "templates": [{
    "template_id": "tmpl-1",
    "name": "Rule Name",
    "severity": 70,
    "status": "active",
    "search": {
      "filter": "...",
      "outcome": "detection",
      "lookback": "1h0m",
      "trigger_mode": "summary",
      "execution_mode": "..."
    },
    "operation": {
      "schedule": {"definition": "@every 1h0m"}
    },
    "mitre_attack": [...]
  }]
}]
```

The tool first hydrates the template to get defaults, then merges user overrides, then deploys.

**Step 1: Write annotation test (RED)**

Add to the test file:

```python
    def test_deploy_template_tool_annotations(self):
        """Test that deploy template tool has non-read-only, non-destructive, non-idempotent annotations."""
        self.module.register_tools(self.mock_server)
        self.assert_tool_annotations(
            "falcon_deploy_correlation_rule_template",
            ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
```

**Step 2: Run test to verify it fails (Verify RED)**

Run: `python -m pytest tests/modules/test_correlation_rules.py::TestCorrelationRulesModule::test_deploy_template_tool_annotations -v`
Expected: FAIL — tool not registered.

**Step 3: Write the deploy tool method + registration (GREEN)**

Add tool registration in `register_tools` (after `search_correlation_rule_templates`):

```python
        self._add_tool(
            server=server,
            method=self.deploy_correlation_rule_template,
            name="deploy_correlation_rule_template",
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=True,
            ),
        )
```

Add the method to the class:

```python
    def deploy_correlation_rule_template(
        self,
        template_id: str = Field(
            description=(
                "Template ID to deploy. Use the `id` field from "
                "`falcon_search_correlation_rule_templates` results."
            ),
        ),
        customer_id: str = Field(
            description="CID of the tenant to deploy the rule in.",
        ),
        name: str | None = Field(
            default=None,
            description="Override the template's default rule name.",
        ),
        severity: int | None = Field(
            default=None,
            description="Override severity score. Must be one of: 10, 30, 50, 70, 90.",
            examples={10, 30, 50, 70, 90},
        ),
        status: str = Field(
            default="active",
            description="Initial rule status.",
            examples={"active", "inactive"},
        ),
        schedule: str | None = Field(
            default=None,
            description="Override the schedule (e.g. '@every 1h0m'). Uses template default if omitted.",
            examples={"@every 1h0m", "@every 0h5m", "@every 24h0m"},
        ),
        lookback: str | None = Field(
            default=None,
            description="Override the lookback window (e.g. '1h0m'). Uses template default if omitted.",
            examples={"1h0m", "24h0m"},
        ),
        trigger_mode: str | None = Field(
            default=None,
            description="Override trigger mode. Uses template default if omitted.",
            examples={"summary", "verbose"},
        ),
        description: str | None = Field(
            default=None,
            description="Override the template's default description.",
        ),
        comment: str | None = Field(
            default=None,
            description="Audit comment explaining why the template is being deployed.",
        ),
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Deploy a Correlation Rule template as a live detection rule.

        First fetches the template to get its defaults (CQL query, schedule, severity,
        MITRE mappings, etc.), then deploys it with any user-provided overrides. Only
        template_id and customer_id are required — all other fields use the template's
        built-in values when omitted.

        Typical workflow:
        1. Use falcon_search_correlation_rule_templates to find a template
        2. Pass the template's `id` here along with your `customer_id`
        3. Optionally override name, severity, status, schedule, etc.
        Returns the created rule record on success.
        """
        # Step 1: Hydrate the template to get its defaults
        template_result = self._base_get_by_ids(
            operation="entities_templates_get_v1Mixin0",
            ids=[template_id],
            use_params=True,
        )

        if self._is_error(template_result):
            return [template_result]

        if not template_result:
            return [
                _format_error_response(
                    f"Template '{template_id}' not found.",
                    operation="entities_templates_get_v1Mixin0",
                )
            ]

        template = template_result[0]
        template_search = template.get("search", {})
        template_operation = template.get("operation", {})
        template_schedule = template_operation.get("schedule", {})

        # Step 2: Build deploy body, merging template defaults with overrides
        deploy_template: dict[str, Any] = {
            "template_id": template_id,
            "name": name if name is not None else template.get("name", ""),
            "severity": severity if severity is not None else template.get("severity", 50),
            "status": status,
            "search": {
                "filter": template_search.get("filter", ""),
                "outcome": template_search.get("outcome", "detection"),
                "lookback": lookback if lookback is not None else template_search.get("lookback", "1h0m"),
                "trigger_mode": trigger_mode if trigger_mode is not None else template_search.get("trigger_mode", "summary"),
                "execution_mode": template_search.get("execution_mode", ""),
            },
            "operation": {
                "schedule": {
                    "definition": schedule if schedule is not None else template_schedule.get("definition", "@every 1h0m"),
                },
            },
        }

        # Carry over template's MITRE mappings
        if template.get("mitre_attack"):
            deploy_template["mitre_attack"] = template["mitre_attack"]

        # Carry over template's anomaly config if present
        if template.get("anomaly"):
            deploy_template["anomaly"] = template["anomaly"]

        if description is not None:
            deploy_template["description"] = description
        elif template.get("description"):
            deploy_template["description"] = template["description"]

        if comment is not None:
            deploy_template["comment"] = comment

        body = [{"customer_id": customer_id, "templates": [deploy_template]}]

        # Step 3: Deploy
        response = self.client.command("entities_templates_rules_post_v1", body=body)

        result = handle_api_response(
            response,
            operation="entities_templates_rules_post_v1",
            error_message="Failed to deploy Correlation Rule Template",
            default_result=[],
        )

        if self._is_error(result):
            return [result]

        return result
```

**Step 4: Run annotation test (Verify GREEN)**

Run: `python -m pytest tests/modules/test_correlation_rules.py::TestCorrelationRulesModule::test_deploy_template_tool_annotations -v`
Expected: PASS

**Step 5: Write behavior tests for deploy**

Add these tests to the test file in a new section:

```python
    # -------------------------------------------------------------------------
    # Deploy Template Tests
    # -------------------------------------------------------------------------

    def test_deploy_template_success_with_defaults(self):
        """Test deploying a template with only required params uses template defaults."""
        self.mock_client.command.side_effect = [
            # Hydrate template
            {
                "status_code": 200,
                "body": {"resources": [{
                    "id": "tmpl-1",
                    "name": "Lateral Movement via SMB",
                    "description": "Detects SMB lateral movement",
                    "severity": 70,
                    "search": {
                        "filter": "#event_simpleName=NetworkConnect",
                        "outcome": "detection",
                        "lookback": "2h0m",
                        "trigger_mode": "summary",
                        "execution_mode": "standard",
                    },
                    "operation": {
                        "schedule": {"definition": "@every 2h0m"},
                    },
                    "mitre_attack": [
                        {"tactic_id": "TA0008", "technique_id": "T1021"},
                    ],
                }]},
            },
            # Deploy
            {
                "status_code": 200,
                "body": {"resources": [
                    {"id": "v1", "rule_id": "r1", "name": "Lateral Movement via SMB"},
                ]},
            },
        ]

        result = self.module.deploy_correlation_rule_template(
            template_id="tmpl-1",
            customer_id="cid123",
        )

        # Verify hydrate call
        first_call = self.mock_client.command.call_args_list[0]
        self.assertEqual(first_call[0][0], "entities_templates_get_v1Mixin0")

        # Verify deploy call
        second_call = self.mock_client.command.call_args_list[1]
        self.assertEqual(second_call[0][0], "entities_templates_rules_post_v1")
        body = second_call[1]["body"]
        self.assertEqual(body[0]["customer_id"], "cid123")
        tmpl = body[0]["templates"][0]
        self.assertEqual(tmpl["template_id"], "tmpl-1")
        self.assertEqual(tmpl["name"], "Lateral Movement via SMB")
        self.assertEqual(tmpl["severity"], 70)
        self.assertEqual(tmpl["status"], "active")
        self.assertEqual(tmpl["search"]["filter"], "#event_simpleName=NetworkConnect")
        self.assertEqual(tmpl["search"]["lookback"], "2h0m")
        self.assertEqual(tmpl["search"]["trigger_mode"], "summary")
        self.assertEqual(tmpl["operation"]["schedule"]["definition"], "@every 2h0m")
        self.assertEqual(tmpl["mitre_attack"], [{"tactic_id": "TA0008", "technique_id": "T1021"}])
        self.assertEqual(tmpl["description"], "Detects SMB lateral movement")

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)

    def test_deploy_template_with_overrides(self):
        """Test that user-provided overrides take precedence over template defaults."""
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {"resources": [{
                    "id": "tmpl-1",
                    "name": "Template Name",
                    "severity": 50,
                    "search": {
                        "filter": "#event=Test",
                        "outcome": "detection",
                        "lookback": "1h0m",
                        "trigger_mode": "summary",
                        "execution_mode": "standard",
                    },
                    "operation": {"schedule": {"definition": "@every 1h0m"}},
                }]},
            },
            {
                "status_code": 200,
                "body": {"resources": [{"id": "v1", "rule_id": "r1"}]},
            },
        ]

        self.module.deploy_correlation_rule_template(
            template_id="tmpl-1",
            customer_id="cid123",
            name="My Custom Name",
            severity=90,
            status="inactive",
            schedule="@every 24h0m",
            lookback="24h0m",
            trigger_mode="verbose",
            description="My custom description",
            comment="Deploying for testing",
        )

        body = self.mock_client.command.call_args_list[1][1]["body"]
        tmpl = body[0]["templates"][0]
        self.assertEqual(tmpl["name"], "My Custom Name")
        self.assertEqual(tmpl["severity"], 90)
        self.assertEqual(tmpl["status"], "inactive")
        self.assertEqual(tmpl["search"]["lookback"], "24h0m")
        self.assertEqual(tmpl["search"]["trigger_mode"], "verbose")
        self.assertEqual(tmpl["operation"]["schedule"]["definition"], "@every 24h0m")
        self.assertEqual(tmpl["description"], "My custom description")
        self.assertEqual(tmpl["comment"], "Deploying for testing")

    def test_deploy_template_not_found(self):
        """Test that a missing template returns error without calling deploy."""
        self.mock_client.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }

        result = self.module.deploy_correlation_rule_template(
            template_id="nonexistent",
            customer_id="cid123",
        )

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])
        # Only one API call (hydrate); deploy is skipped
        self.mock_client.command.assert_called_once()

    def test_deploy_template_hydrate_error(self):
        """Test that a hydrate API error is returned without calling deploy."""
        self.mock_client.command.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Internal error"}]},
        }

        result = self.module.deploy_correlation_rule_template(
            template_id="tmpl-1",
            customer_id="cid123",
        )

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])
        self.mock_client.command.assert_called_once()

    def test_deploy_template_deploy_error(self):
        """Test that a deploy API error is returned wrapped in a list."""
        self.mock_client.command.side_effect = [
            {
                "status_code": 200,
                "body": {"resources": [{
                    "id": "tmpl-1",
                    "name": "Template",
                    "severity": 50,
                    "search": {
                        "filter": "#event=Test",
                        "outcome": "detection",
                        "lookback": "1h0m",
                        "trigger_mode": "summary",
                        "execution_mode": "standard",
                    },
                    "operation": {"schedule": {"definition": "@every 1h0m"}},
                }]},
            },
            {
                "status_code": 403,
                "body": {"errors": [{"message": "Access denied"}]},
            },
        ]

        result = self.module.deploy_correlation_rule_template(
            template_id="tmpl-1",
            customer_id="cid123",
        )

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertIn("error", result[0])
```

**Step 6: Run deploy tests (Verify GREEN)**

Run: `python -m pytest tests/modules/test_correlation_rules.py -k "deploy" -v`
Expected: All PASS.

**Step 7: Run full test suite**

Run: `python -m pytest tests/modules/test_correlation_rules.py -v`
Expected: All PASS.

**Step 8: Commit**

```bash
git add falcon_mcp/modules/correlation_rules.py tests/modules/test_correlation_rules.py
git commit -m "feat(correlation-rules): add deploy_correlation_rule_template tool

Hydrates template to get defaults (CQL, schedule, severity, MITRE
mappings), merges user overrides, deploys via
entities_templates_rules_post_v1. Only template_id and customer_id
are required; everything else falls back to template defaults.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

### Task 4: Update Existing Annotation Test for Read-Only Tools 🔴 NOT_STARTED
<!-- deps: [2] | files: ["tests/modules/test_correlation_rules.py"] -->

**Files:**
- Modify: `tests/modules/test_correlation_rules.py`

**Context:** The existing `test_read_only_tools_have_default_annotations` test only checks `falcon_search_correlation_rules`. It MUST also cover `falcon_search_correlation_rule_templates`.

**Step 1: Update the test**

Replace the existing `test_read_only_tools_have_default_annotations` method:

```python
    def test_read_only_tools_have_default_annotations(self):
        """Test that search tools use READ_ONLY_ANNOTATIONS."""
        self.module.register_tools(self.mock_server)

        for tool_name in [
            "falcon_search_correlation_rules",
            "falcon_search_correlation_rule_templates",
        ]:
            self.assert_tool_annotations(tool_name, READ_ONLY_ANNOTATIONS)
```

**Step 2: Run test to verify it passes**

Run: `python -m pytest tests/modules/test_correlation_rules.py::TestCorrelationRulesModule::test_read_only_tools_have_default_annotations -v`
Expected: PASS (tool was registered in Task 2).

**Step 3: Commit**

```bash
git add tests/modules/test_correlation_rules.py
git commit -m "test(correlation-rules): add template search to read-only annotation coverage

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

### Task 5: Final Validation and Linting 🔴 NOT_STARTED
<!-- deps: [1, 2, 3, 4] | files: [] -->

**Step 1: Run all correlation rules tests**

Run: `python -m pytest tests/modules/test_correlation_rules.py -v`
Expected: All PASS. Verify the count matches expected (original tests + new template tests).

**Step 2: Run the full test suite to check for regressions**

Run: `python -m pytest tests/ -x --timeout=60`
Expected: All PASS.

**Step 3: Run linting**

Run: `ruff check falcon_mcp/modules/correlation_rules.py falcon_mcp/resources/correlation_rules.py`
Expected: No errors. If any, fix and re-run.

Run: `ruff format --check falcon_mcp/modules/correlation_rules.py falcon_mcp/resources/correlation_rules.py`
Expected: Already formatted. If not, run `ruff format` on those files.

**Step 4: Verify the module loads correctly**

Run: `python -c "from falcon_mcp.modules.correlation_rules import CorrelationRulesModule; print('Import OK')"` 
Expected: `Import OK`

**Step 5: Commit any lint fixes**

```bash
git add -A
git commit -m "chore(correlation-rules): lint and format fixes

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

(Skip if no changes.)

## Execution Handoff

To execute this plan:

```
/skills:handoff @docs/plans/2026-10-28-PLAN-correlation-rule-templates.md
```

Open a new session and paste the handoff. The session will load `skills:executing-plans` and implement the plan task-by-task.
