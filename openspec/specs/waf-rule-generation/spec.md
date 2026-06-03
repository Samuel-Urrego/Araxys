# WAF Rule Generation Specification

## Purpose

Generate AWS WAF rule JSON — IP sets, regex pattern sets, rule groups, and Web ACLs — from a FastAPI application's OpenAPI schema. Output is human-readable JSON for review; optional boto3 apply via CLI.

## Requirements

### Requirement: Schema Ingestion

The system MUST accept either a live FastAPI `app.openapi()` call or an OpenAPI JSON file path as input.

#### Scenario: Live app ingestion

- GIVEN a FastAPI app instance with mounted routes
- WHEN `WafRuleGenerator` is instantiated with `app`
- THEN the generator calls `app.openapi()` and parses paths, methods, and content-types

#### Scenario: Static file ingestion

- GIVEN a valid `openapi.json` file on disk
- WHEN the generator is instantiated with `file_path`
- THEN the file is loaded, validated as valid OpenAPI, and parsed identically

### Requirement: Rule Output

The system MUST produce AWS WAF-compatible JSON containing IP sets, regex pattern sets, rule groups, and a Web ACL.

#### Scenario: Standard app with three routes

- GIVEN an app exposing GET `/users`, POST `/users`, GET `/health`
- WHEN `generate()` is called
- THEN the output JSON includes an IP set (empty, for escalation), regex pattern sets for allowed paths and methods, a rule group combining them, and a Web ACL referencing the rule group

#### Scenario: Reviewable output

- GIVEN a generated rule set
- WHEN output is written to stdout or `--output` file
- THEN JSON is pretty-printed with 2-space indentation and all fields are human-readable

### Requirement: boto3 Apply

The system SHOULD support applying generated rules to AWS WAF via `araxys waf apply`.

#### Scenario: boto3 installed

- GIVEN `boto3>=1.34` is installed
- WHEN `araxys waf apply` is invoked with valid AWS credentials
- THEN rules are applied using `asyncio.to_thread()` to keep the event loop free

#### Scenario: boto3 absent

- GIVEN boto3 is NOT installed
- WHEN any AWS operation is attempted
- THEN a clear error message MUST be raised: "boto3 not installed. Install with: pip install araxys[aws_waf]"

### Requirement: Schema Drift Warning

The system MUST warn that generated rules are a static snapshot and may drift from live API behavior.

#### Scenario: Snapshot warning

- GIVEN rules were generated
- WHEN the output is displayed or saved
- THEN a brief comment or stdout warning states that rules represent the schema at generation time and should be regenerated on API changes
