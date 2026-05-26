# METADATA
# title: Missing severity and provider
# scope: package
# custom:
#   id: BAD-001
package pipeline_check.github.bad_001

import rego.v1

deny contains result if {
	result := {"msg": "bad"}
}
