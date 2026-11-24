/**
 * Built-in policy, shipped as data. Written to .devsec/policy/default/ before evaluation
 * and copied by `devsec init` for customisation. Conforma-style: METADATA annotations,
 * structured results with code / msg / finding_id.
 */
export const defaultPolicyFiles: Readonly<Record<string, string>> = {
  "devsec.rego": `# METADATA
# title: devsec default policy
# description: >-
#   Blocks hardcoded secrets, high-severity code findings and fixable
#   high-severity vulnerable dependencies. Warns on medium findings.
#   Exceptions come from devsec.json (data.exceptions) and must expire.
package devsec

import rego.v1

today := time.format([time.now_ns(), "UTC", "2006-01-02"])

# Secrets: anything Trivy's secret scanner reports, plus any tool finding tagged
# CWE-798 (Use of Hard-coded Credentials) - this is how semgrep's p/secrets rules
# are recognised, using semgrep's own metadata.
is_secret(f) if f.scanner == "trivy-secrets"

is_secret(f) if {
	some c in f.cwe
	startswith(c, "CWE-798")
}

high(f) if f.severity in {"critical", "high"}

fixable(f) if f.package.fixedVersion != ""

applies(e, f) if e.finding == f.id

applies(e, f) if {
	e.rule == f.rule
	not e.path
}

applies(e, f) if {
	e.rule == f.rule
	e.path == f.location.path
}

waived(f) if {
	some e in data.exceptions
	applies(e, f)
	e.expires >= today
}

# METADATA
# title: Hardcoded secret
# description: Secrets must never be committed; rotate and load them from the environment.
# custom:
#   short_name: secret
deny contains result if {
	some f in input.findings
	is_secret(f)
	not waived(f)
	result := {"code": "devsec.secret", "msg": sprintf("hardcoded secret (%s)", [f.rule]), "finding_id": f.id}
}

# METADATA
# title: High severity code finding
# custom:
#   short_name: sast_high
deny contains result if {
	some f in input.findings
	f.scanner == "semgrep"
	high(f)
	not is_secret(f)
	not waived(f)
	result := {"code": "devsec.sast_high", "msg": sprintf("%s severity code finding", [f.severity]), "finding_id": f.id}
}

# METADATA
# title: Fixable high severity vulnerable dependency
# custom:
#   short_name: sca_fixable
deny contains result if {
	some f in input.findings
	f.scanner == "trivy-sca"
	high(f)
	fixable(f)
	not waived(f)
	result := {
		"code": "devsec.sca_fixable",
		"msg": sprintf("%s %s@%s, fixed in %s", [f.rule, f.package.name, f.package.version, f.package.fixedVersion]),
		"finding_id": f.id,
	}
}

# METADATA
# title: High severity vulnerable dependency without a fix
# custom:
#   short_name: sca_unfixable
warn contains result if {
	some f in input.findings
	f.scanner == "trivy-sca"
	high(f)
	not fixable(f)
	not waived(f)
	result := {"code": "devsec.sca_unfixable", "msg": sprintf("%s %s@%s, no fix available", [f.rule, f.package.name, f.package.version]), "finding_id": f.id}
}

# METADATA
# title: Medium severity finding
# custom:
#   short_name: medium
warn contains result if {
	some f in input.findings
	f.severity == "medium"
	not is_secret(f)
	not waived(f)
	result := {"code": "devsec.medium", "msg": "medium severity finding", "finding_id": f.id}
}

# METADATA
# title: Unused exception
# description: >-
#   An exception that matches no finding is stale (fixed code, renamed file, or a
#   finding id from an older devsec). Only checked on full scans.
# custom:
#   short_name: exception_unused
warn contains result if {
	not input.partial
	some e in data.exceptions
	not exception_used(e)
	result := {"code": "devsec.exception_unused", "msg": sprintf("exception matches no finding: %s (%s)", [exception_label(e), e.reason])}
}

exception_used(e) if {
	some f in input.findings
	applies(e, f)
}

exception_label(e) := sprintf("finding %s", [e.finding]) if e.finding

exception_label(e) := sprintf("rule %s", [e.rule]) if {
	not e.finding
	e.rule
}

# METADATA
# title: Expired exception
# custom:
#   short_name: exception_expired
warn contains result if {
	some e in data.exceptions
	e.expires < today
	some f in input.findings
	applies(e, f)
	result := {"code": "devsec.exception_expired", "msg": sprintf("exception expired on %s: %s", [e.expires, e.reason]), "finding_id": f.id}
}
`,
};
