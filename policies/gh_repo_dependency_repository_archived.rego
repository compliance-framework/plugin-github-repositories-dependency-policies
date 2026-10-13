package compliance_framework.dependency_repository_archived

import data.ccf_libs.dependency_helpers

dependencies := dependency_helpers.selected_dependencies(input)

title := "Direct dependency repository is archived"

description := "Direct dependencies should not rely on archived upstream repositories unless the dependency has been reviewed and accepted. Archived repositories no longer receive normal maintenance signals and may stop receiving security fixes."

skip_reason := "Dependency health is not observable, so archived repository status cannot be evaluated. The dependency_health_unknown policy reports this visibility gap." if {
	unobservable_dependency_health
}

risk_templates := [{
	"name": "Direct dependency uses archived upstream repository",
	"title": "Archived Dependency {{ .dependency }} Stops Receiving Security Maintenance",
	"statement": "Dependency {{ .dependency }} is archived and may no longer receive bug fixes, security patches, or maintainer review. Continued use increases the risk that known or future vulnerabilities remain unresolved in the product's dependency chain.",
	"likelihood_hint": "moderate",
	"impact_hint": "high",
	"violation_ids": ["dependency_repository_archived"],
	"dedupe_label_keys": ["dependency"],
	"label_schema": [{"key": "dependency", "description": "Dependency module path or package name being evaluated"}],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-1104",
		"title": "Use of Unmaintained Third Party Components",
		"url": "https://cwe.mitre.org/data/definitions/1104.html",
	}],
	"remediation": {
		"title": "Review or replace the archived dependency",
		"description": "Assess whether the archived dependency is still safe to use. Replace it with a maintained alternative, fork and maintain it internally, or document a time-bound risk acceptance.",
		"tasks": [
			{"title": "Identify code paths that use the archived dependency"},
			{"title": "Check whether a maintained replacement exists"},
			{"title": "Plan dependency replacement or internal maintenance ownership"},
			{"title": "Document any temporary risk acceptance with an expiry date"},
		],
	},
}]

violation[{"id": "dependency_repository_archived", "remarks": remarks}] if {
	dep := dependencies[_]
	dependency_health_observable(dep)
	object.get(dependency_health(dep), "repository_archived", false) == true
	remarks := sprintf("Direct dependency %q at version %q uses archived upstream repository %q.", [dependency_name(dep), dependency_version(dep), dependency_url(dep)])
}

dependency_health_observable(dep) if {
	direct_dependency(dep)
	repository_resolved(dep)
	health_collected(dep)
}

observable_dependency_health if {
	dep := dependencies[_]
	dependency_health_observable(dep)
}

unobservable_dependency_health if {
	not observable_dependency_health
	dep := dependencies[_]
	direct_dependency(dep)
	not dependency_health_observable(dep)
}

direct_dependency(dep) if {
	dependency_helpers.direct_dependency(input, dep)
}

repository_resolved(dep) if {
	dependency_helpers.repository_resolved(dep)
}

health_collected(dep) if {
	dependency_helpers.health_collected(dep)
}

dependency_repository(dep) := dependency_helpers.dependency_repository(dep)

dependency_collection_status(dep) := dependency_helpers.dependency_collection_status(dep)

dependency_health(dep) := dependency_helpers.dependency_health(dep)

dependency_name(dep) := dependency_helpers.dependency_name(dep)

dependency_version(dep) := dependency_helpers.dependency_version(dep)

dependency_url(dep) := dependency_helpers.dependency_url(dep)
