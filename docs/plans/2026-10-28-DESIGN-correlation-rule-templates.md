# Design: Correlation Rule Template Discovery & Deployment

## Goal

Add natural-language-friendly template discovery and one-click deployment to
the existing `CorrelationRulesModule`. Users should be able to describe what
they want to detect (e.g., "lateral movement", "credential theft",
"ransomware") without knowing the term "correlation rule template" or exact
MITRE tactic/technique IDs.

## Scope

- **Two new tools** added to `CorrelationRulesModule` (same module, same API scope)
- **One new FQL guide resource** for template-specific filters
- No changes to existing tools

## Tool 1: `falcon_search_correlation_rule_templates`

**Annotations**: `READ_ONLY_ANNOTATIONS` (default)

### Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `filter` | `str \| None` | `None` | FQL filter — points to `falcon://correlation-rule-templates/search/fql-guide` |
| `limit` | `int` | `20` | Max results (1–500) |
| `offset` | `int \| None` | `None` | Pagination offset |
| `sort` | `str \| None` | `None` | Sort field (`created_on`, `last_updated_on`, with `\|desc`) |

### Flow

1. Query template IDs via `queries_templates_get_v1Mixin0` (with filter/limit/offset/sort)
2. Hydrate full entities via `entities_templates_get_v1Mixin0` (by IDs)
3. Reorder hydrated entities to match query sort order
4. Wrap in standard pagination envelope

### Docstring emphasis

The docstring will coach the LLM that this tool is the right choice when a
user asks about detecting threats, finding detection rules, or deploying
pre-built rules — even if they don't mention "template" or "correlation rule".

## Tool 2: `falcon_deploy_correlation_rule_template`

**Annotations**: `readOnlyHint=False`, `destructiveHint=False`,
`idempotentHint=False`, `openWorldHint=True`

### Parameters

| Name | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `template_id` | `str` | — | Yes | Template ID from search results |
| `customer_id` | `str` | — | Yes | CID of the target tenant |
| `name` | `str \| None` | `None` | No | Override template's default name |
| `severity` | `int \| None` | `None` | No | Override severity (10/30/50/70/90) |
| `status` | `str` | `"active"` | No | Initial rule status |
| `schedule` | `str \| None` | `None` | No | Override schedule (e.g. `@every 1h0m`) |
| `lookback` | `str \| None` | `None` | No | Override lookback window |
| `trigger_mode` | `str \| None` | `None` | No | Override trigger mode |
| `description` | `str \| None` | `None` | No | Override description |
| `comment` | `str \| None` | `None` | No | Audit comment |

### Flow

1. Hydrate template via `entities_templates_get_v1Mixin0` to get defaults
2. Error early if template not found
3. Build deploy body: template defaults merged with user overrides
4. POST to `entities_templates_rules_post_v1`
5. Return created rule record

## Resource: Template FQL Guide

**URI**: `falcon://correlation-rule-templates/search/fql-guide`

### Template-specific filter fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Template name, supports `~*` wildcards |
| `description` | String | Template description, supports `~*` wildcards |
| `vendor` | String | Vendor/source of the template |
| `outcome` | String | Rule outcome type (detection, case) |
| `mitre_attack.tactic_id` | String | MITRE tactic ID (TA####) |
| `mitre_attack.technique_id` | String | MITRE technique ID (T####) |
| `type` | String | Template type |

### MITRE ATT&CK Enterprise Tactics (v16+) with Aliases

The guide includes all 15 current tactics with synonyms/former names so the
LLM can match fuzzy user intent:

| ID | Name | Aliases |
|----|------|---------|
| TA0043 | Reconnaissance | recon, scanning, footprinting, OSINT |
| TA0042 | Resource Development | infrastructure setup, staging |
| TA0001 | Initial Access | entry point, intrusion, exploitation, phishing |
| TA0002 | Execution | code execution, running malware, script execution |
| TA0003 | Persistence | backdoor, implant, foothold, maintaining access |
| TA0004 | Privilege Escalation | privesc, elevating privileges, admin access |
| TA0005 | Stealth (formerly Defense Evasion) | defense evasion, evasion, hiding, obfuscation |
| TA0112 | Defense Impairment | disabling security, tampering, impairing defenses |
| TA0006 | Credential Access | credential theft, password stealing, credential dumping |
| TA0007 | Discovery | enumeration, network scanning, system discovery |
| TA0008 | Lateral Movement | pivoting, moving laterally, spreading |
| TA0009 | Collection | data gathering, data staging, harvesting |
| TA0011 | Command and Control | C2, C&C, beaconing, callback |
| TA0010 | Exfiltration | data theft, data exfil, stealing data |
| TA0040 | Impact | destruction, ransomware, wiping, disruption, sabotage |

### Natural Language Search Strategy

The guide coaches the LLM with a prioritized approach:
1. Map user intent to a MITRE tactic/technique ID if it matches a known tactic
2. Fall back to `description:~*` and/or `name:~*` keyword matching
3. Split multi-word phrases into separate `~*` clauses joined with `+`

## Files to Change

1. `falcon_mcp/modules/correlation_rules.py` — add 2 tools + 1 resource registration
2. `falcon_mcp/resources/correlation_rules.py` — add template FQL docs constant
3. `tests/modules/test_correlation_rules.py` — add tests for new tools
