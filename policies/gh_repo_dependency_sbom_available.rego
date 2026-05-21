package compliance_framework.dependency_sbom_available

dependencies := [dep] if {
	dep := object.get(input, "dependency", null)
	is_object(dep)
}

dependencies := deps if {
	dep := object.get(input, "dependency", null)
	not is_object(dep)
	deps := array_or_empty(object.get(input, "dependencies", []))
}

default dependency_health_input := {}

dependency_health_input := object_or_empty(data.dependency_health) if {
	is_object(data.dependency_health)
}
require_dependency_sbom := object.get(dependency_health_input, "require_dependency_sbom", false)

title := "Direct dependency repository exposes SBOM evidence"

description := "Direct dependencies should expose SBOM evidence when dependency SBOM visibility is required by policy. Dependency SBOMs improve third-party component visibility and support downstream vulnerability response."

skip_reason := "Dependency SBOM availability is not required by policy data." if {
	require_dependency_sbom == false
}

skip_reason := "Dependency health is not observable, so dependency SBOM availability cannot be evaluated. The dependency_health_unknown policy reports this visibility gap." if {
	require_dependency_sbom == true
	unobservable_dependency_health
}

risk_templates := [{
	"name": "Direct dependency SBOM is absent",
	"title": "Missing Dependency SBOM Limits Third Party Component Visibility",
	"statement": "When a direct dependency does not expose SBOM evidence, downstream users have less visibility into that component's own dependency chain. This can slow vulnerability impact analysis and weaken supply chain due diligence for products that rely on the component.",
	"likelihood_hint": "moderate",
	"impact_hint": "moderate",
	"violation_ids": ["dependency_sbom_absent", "dependency_sbom_empty"],
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
		"title": "Review dependency SBOM visibility",
		"description": "Record whether the dependency provides SBOM information or whether alternative component visibility is available through package metadata, internal scanning, or manual review.",
		"tasks": [
			{"title": "Check whether the upstream dependency publishes an SBOM in releases or repository artifacts"},
			{"title": "Scan the consumed dependency version with an internal SBOM generation tool where feasible"},
			{"title": "Document the dependency SBOM visibility result"},
			{"title": "Prefer dependencies with stronger component transparency for high-risk use cases"},
		],
	},
}]

violation[{"id": "dependency_sbom_absent", "remarks": remarks}] if {
	require_dependency_sbom == true
	dep := dependencies[_]
	dependency_health_observable(dep)
	object.get(dependency_sbom(dep), "available", false) != true
	remarks := sprintf("Direct dependency %q at version %q does not expose required SBOM evidence for upstream repository %q; require_dependency_sbom is true and observed availability is %v.", [dependency_name(dep), dependency_version(dep), dependency_url(dep), object.get(dependency_sbom(dep), "available", false)])
}

violation[{"id": "dependency_sbom_empty", "remarks": remarks}] if {
	require_dependency_sbom == true
	dep := dependencies[_]
	dependency_health_observable(dep)
	object.get(dependency_sbom(dep), "available", false) == true
	object.get(dependency_sbom(dep), "package_count", 0) == 0
	remarks := sprintf("Direct dependency %q at version %q exposes an empty SBOM for upstream repository %q; require_dependency_sbom is true and observed package count is 0.", [dependency_name(dep), dependency_version(dep), dependency_url(dep)])
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
	input_dependency_provided
}

direct_dependency(dep) if {
	not input_dependency_provided
	object.get(dep, "direct", false) == true
}

input_dependency_provided if {
	is_object(object.get(input, "dependency", null))
}

repository_resolved(dep) if {
	object.get(dependency_repository(dep), "resolved", false) == true
}

health_collected(dep) if {
	object.get(dependency_collection_status(dep), "health_collected", false) == true
}

dependency_repository(dep) := repo if {
	repo := object_or_empty(object.get(dep, "repository", {}))
}

dependency_collection_status(dep) := status if {
	status := object_or_empty(object.get(dep, "collection_status", {}))
}

dependency_supply_chain(dep) := supply_chain if {
	supply_chain := object_or_empty(object.get(dep, "supply_chain", {}))
}

dependency_sbom(dep) := sbom if {
	sbom := object_or_empty(object.get(dependency_supply_chain(dep), "sbom", {}))
}

object_or_empty(value) := value if {
	is_object(value)
}

object_or_empty(value) := {} if {
	not is_object(value)
}

array_or_empty(value) := value if {
	is_array(value)
}

array_or_empty(value) := [] if {
	not is_array(value)
}

dependency_name(dep) := object.get(dep, "name", "unknown")

dependency_version(dep) := object.get(dep, "declared_version", "unknown")

dependency_url(dep) := object.get(dependency_repository(dep), "url", "unknown")
