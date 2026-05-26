# METADATA
# title: GitLab job must not run with privileged tag
# description: Privileged runners can escape the container boundary.
# scope: package
# custom:
#   id: TEST-002
#   severity: CRITICAL
#   provider: gitlab
#   recommendation: Remove the privileged tag from the job configuration.
package pipeline_check.gitlab.test_002

import rego.v1

deny contains result if {
	job := input.doc[job_name]
	job_name != "stages"
	job_name != "variables"
	job_name != "default"
	job_name != "include"
	tags := job.tags
	tags[_] == "privileged"
	result := {
		"msg": sprintf("Job '%s' uses a privileged runner tag", [job_name]),
		"resource": input.path,
	}
}
