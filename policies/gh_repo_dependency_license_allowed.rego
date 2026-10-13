package compliance_framework.dependency_license_allowed

import data.ccf_libs.dependency_helpers

dependencies := dependency_helpers.selected_dependencies(input)

default dependency_health_input := {}

dependency_health_input := dependency_helpers.object_or_empty(data.dependency_health) if { # regal ignore:unresolved-reference
	is_object(data.dependency_health) # regal ignore:unresolved-reference
}

default_banned_licenses := ["BUSL-1.1", "SSPL-1.0", "PolyForm-Noncommercial-1.0.0"]
banned_licenses := object.get(dependency_health_input, "banned_licenses", default_banned_licenses)
allowed_licenses := object.get(dependency_health_input, "allowed_licenses", [])

title := "Direct dependency license is allowed"

description := "Direct dependencies should use licenses that are acceptable for the repository's distribution and compliance requirements. Banned, unknown, or non-allow-listed licenses require review."

skip_reason := "Dependency health is not observable, so dependency license acceptability cannot be evaluated. The dependency_health_unknown policy reports this visibility gap." if {
	unobservable_dependency_health
}

risk_templates := [{
	"name": "Direct dependency has unacceptable or unknown license",
	"title": "Dependency License Creates Legal or Distribution Risk",
	"statement": "Dependency {{ .dependency }} that contains a banned, unknown, or non-allow-listed license can create legal, commercial, or redistribution risk for the product. License uncertainty also weakens the evidence needed to demonstrate third-party component due diligence.",
	"likelihood_hint": "moderate",
	"impact_hint": "high",
	"violation_ids": ["dependency_banned_license", "dependency_license_not_allowed", "dependency_license_unknown"],
	"dedupe_label_keys": ["dependency"],
	"label_schema": [{"key": "dependency", "description": "Dependency module path or package name being evaluated"}],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-1059",
		"title": "Incomplete Documentation",
		"url": "https://cwe.mitre.org/data/definitions/1059.html",
	}],
	"remediation": {
		"title": "Review or replace dependency with unacceptable license",
		"description": "Confirm whether the dependency license is compatible with the repository's use case. Replace the dependency, obtain legal approval, or document an accepted exception where appropriate.",
		"tasks": [
			{"title": "Review the dependency's upstream license file and package metadata"},
			{"title": "Confirm compatibility with product distribution and customer obligations"},
			{"title": "Replace dependencies with unacceptable licenses"},
			{"title": "Document legal approval or risk acceptance for exceptions"},
			{"title": "Add license scanning to prevent recurrence"},
		],
	},
}]

violation[{"id": "dependency_banned_license", "remarks": remarks}] if {
	dep := dependencies[_]
	evaluable_dependency(dep)
	spdx := dependency_license_spdx(dep)
	not unknown_license_spdx(spdx)
	license_in_list(spdx, banned_licenses)
	remarks := sprintf("Direct dependency %q at version %q uses banned license %q for upstream repository %q. Configured banned licenses: %s.", [dependency_name(dep), dependency_version(dep), spdx, dependency_url(dep), concat(", ", banned_licenses)])
}

violation[{"id": "dependency_license_not_allowed", "remarks": remarks}] if {
	dep := dependencies[_]
	evaluable_dependency(dep)
	spdx := dependency_license_spdx(dep)
	not unknown_license_spdx(spdx)
	not license_in_list(spdx, banned_licenses)
	count(allowed_licenses) > 0
	not license_in_list(spdx, allowed_licenses)
	remarks := sprintf("Direct dependency %q at version %q uses license %q for upstream repository %q, which is not in the configured allowed license list: %s.", [dependency_name(dep), dependency_version(dep), spdx, dependency_url(dep), concat(", ", allowed_licenses)])
}

violation[{"id": "dependency_license_unknown", "remarks": remarks}] if {
	dep := dependencies[_]
	evaluable_dependency(dep)
	license_collected(dep)
	spdx := dependency_license_spdx(dep)
	unknown_license_spdx(spdx)
	remarks := sprintf("Direct dependency %q at version %q has unknown collected license metadata for upstream repository %q.", [dependency_name(dep), dependency_version(dep), dependency_url(dep)])
}

evaluable_dependency(dep) if {
	dependency_health_observable(dep)
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

license_collected(dep) if {
	object.get(dependency_license(dep), "collected", false) == true
}

unknown_license_spdx(spdx) if {
	spdx == ""
}

unknown_license_spdx(spdx) if {
	lower(spdx) == "unknown"
}

unknown_license_spdx(spdx) if {
	lower(spdx) == "noassertion"
}

license_in_list(spdx, licenses) if {
	some license in licenses
	lower(spdx) == lower(license)
}

dependency_license_spdx(dep) := spdx if {
	spdx := object.get(dependency_license(dep), "spdx_id", "")
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

dependency_supply_chain(dep) := supply_chain if {
	supply_chain := dependency_helpers.object_or_empty(object.get(dep, "supply_chain", {}))
}

dependency_license(dep) := license if {
	license := dependency_helpers.object_or_empty(object.get(dependency_supply_chain(dep), "license", {}))
}

dependency_name(dep) := dependency_helpers.dependency_name(dep)

dependency_version(dep) := dependency_helpers.dependency_version(dep)

dependency_url(dep) := dependency_helpers.dependency_url(dep)
