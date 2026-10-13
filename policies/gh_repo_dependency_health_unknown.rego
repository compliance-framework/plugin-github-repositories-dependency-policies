package compliance_framework.dependency_health_unknown

import data.ccf_libs.dependency_helpers

dependencies := dependency_helpers.selected_dependencies(input)

default dependency_health_input := {}

dependency_health_input := dependency_helpers.object_or_empty(data.dependency_health) if { # regal ignore:unresolved-reference
	is_object(data.dependency_health) # regal ignore:unresolved-reference
}

unknown_health_is_violation := object.get(dependency_health_input, "unknown_health_is_violation", false)

title := "Direct dependency health is observable"

description := "Direct dependency health should be observable enough to support third-party component due diligence. Unresolved or inaccessible dependencies create visibility gaps that may require manual review."

skip_reason := "Unknown dependency health is informational because policy data does not treat unknown health as a violation." if {
	unknown_health_is_violation == false
	dep := dependencies[_]
	direct_dependency(dep)
	not repository_resolved(dep)
}

skip_reason := "Unknown dependency health is informational because policy data does not treat unknown health as a violation." if {
	unknown_health_is_violation == false
	dep := dependencies[_]
	direct_dependency(dep)
	repository_resolved(dep)
	not health_collected(dep)
}

risk_templates := [{
	"name": "Direct dependency health could not be determined",
	"title": "Unknown Third Party Component Health Creates Supply Chain Visibility Gap",
	"statement": "When the source repository or maintenance health of a direct dependency cannot be determined, the organization cannot demonstrate complete due diligence over that third-party component. This may delay vulnerability response and complicate replacement planning when the component becomes risky.",
	"likelihood_hint": "moderate",
	"impact_hint": "moderate",
	"violation_ids": ["dependency_repository_unresolved", "dependency_health_not_collected"],
	"dedupe_label_keys": ["dependency"],
	"label_schema": [{"key": "dependency", "description": "Dependency module path or package name being evaluated"}],
	"threat_refs": [
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-1059",
			"title": "Incomplete Documentation",
			"url": "https://cwe.mitre.org/data/definitions/1059.html",
		},
		{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-1104",
			"title": "Use of Unmaintained Third Party Components",
			"url": "https://cwe.mitre.org/data/definitions/1104.html",
		},
	],
	"remediation": {
		"title": "Resolve dependency source and maintenance evidence",
		"description": "Determine the upstream source and maintenance status for the dependency, or document why the dependency cannot be evaluated automatically.",
		"tasks": [
			{"title": "Confirm the dependency source repository or package registry metadata"},
			{"title": "Record a manual maintenance review when automatic collection is unavailable"},
			{"title": "Replace dependencies whose source cannot be trusted or verified"},
			{"title": "Document any accepted visibility gap with a review date"},
		],
	},
}]

violation[{"id": "dependency_repository_unresolved", "remarks": remarks}] if {
	unknown_health_is_violation == true
	dep := dependencies[_]
	direct_dependency(dep)
	not repository_resolved(dep)
	remarks := sprintf("Direct dependency %q at version %q could not be resolved to an observable upstream GitHub repository.", [dependency_name(dep), dependency_version(dep)])
}

violation[{"id": "dependency_health_not_collected", "remarks": remarks}] if {
	unknown_health_is_violation == true
	dep := dependencies[_]
	direct_dependency(dep)
	repository_resolved(dep)
	not health_collected(dep)
	remarks := sprintf("Direct dependency %q at version %q has unresolved health collection status for upstream repository %q: %s.", [dependency_name(dep), dependency_version(dep), dependency_url(dep), collection_error_summary(dep)])
}

health_collected(dep) if {
	object.get(dependency_collection_status(dep), "health_collected", false) == true
}

collection_error_summary(dep) := summary if {
	errors := dependency_helpers.array_or_empty(object.get(dependency_collection_status(dep), "errors", []))
	count(errors) > 0
	summary := concat("; ", [error_message(error) | error := errors[_]])
}

collection_error_summary(dep) := "no collection error detail was provided" if {
	errors := dependency_helpers.array_or_empty(object.get(dependency_collection_status(dep), "errors", []))
	count(errors) == 0
}

error_message(error) := msg if {
	scope := object.get(error, "scope", "health")
	message := object.get(error, "message", "unavailable")
	msg := sprintf("%s: %s", [scope, message])
}

direct_dependency(dep) if {
	dependency_helpers.direct_dependency(input, dep)
}

repository_resolved(dep) if {
	dependency_helpers.repository_resolved(dep)
}

dependency_repository(dep) := dependency_helpers.dependency_repository(dep)

dependency_collection_status(dep) := dependency_helpers.dependency_collection_status(dep)

dependency_name(dep) := dependency_helpers.dependency_name(dep)

dependency_version(dep) := dependency_helpers.dependency_version(dep)

dependency_url(dep) := dependency_helpers.dependency_url(dep)
