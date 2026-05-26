# METADATA
# title: Actions must be pinned to commit SHA
# description: Unpinned actions can be silently replaced by a compromised tag.
# scope: package
# custom:
#   id: TEST-001
#   severity: HIGH
#   provider: github
#   recommendation: Pin every uses reference to a full 40-character commit SHA.
#   cwe: ["CWE-829"]
#   owasp: ["CICD-SEC-3"]
package pipeline_check.github.test_001

import rego.v1

deny contains result if {
	job := input.doc.jobs[job_name]
	step := job.steps[_]
	uses := step.uses
	not startswith(uses, "./")
	not regex.match(`@[0-9a-f]{40}$`, uses)
	result := {
		"msg": sprintf("Job '%s' uses unpinned action: %s", [job_name, uses]),
		"resource": input.path,
	}
}
