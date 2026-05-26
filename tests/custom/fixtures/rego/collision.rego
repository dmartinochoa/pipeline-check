# METADATA
# title: Rule that collides with built-in GHA-001
# scope: package
# custom:
#   id: GHA-001
#   severity: HIGH
#   provider: github
package pipeline_check.github.collision

import rego.v1

deny contains result if {
	result := {"msg": "collision test"}
}
