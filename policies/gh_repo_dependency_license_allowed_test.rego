package compliance_framework.dependency_license_allowed

base_dependency := {
	"name": "github.com/example/lib",
	"declared_version": "v1.2.3",
	"direct": true,
	"repository": {"resolved": true, "url": "https://github.com/example/lib"},
	"collection_status": {"health_collected": true},
}

mit_dependency := object.union(base_dependency, {"supply_chain": {"license": {"spdx_id": "MIT", "name": "MIT License", "collected": true}}})

banned_dependency := object.union(base_dependency, {"supply_chain": {"license": {"spdx_id": "BUSL-1.1", "name": "Business Source License", "collected": true}}})

unknown_license_dependency := object.union(base_dependency, {"supply_chain": {"license": {"spdx_id": "", "name": "Other", "collected": true}}})
unknown_license_upper_dependency := object.union(base_dependency, {"supply_chain": {"license": {"spdx_id": "UNKNOWN", "name": "Other", "collected": true}}})
unknown_license_noassertion_dependency := object.union(base_dependency, {"supply_chain": {"license": {"spdx_id": "NOASSERTION", "name": "Other", "collected": true}}})

failed_license_collection_dependency := object.union(base_dependency, {"supply_chain": {"license": {"collected": false}}})

test_passes_when_license_is_not_banned_and_no_allow_list_is_configured if {
	inp := {"dependencies": [mit_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_flags_banned_license if {
	inp := {"dependencies": [banned_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_banned_license"
}

test_flags_granular_dependency_without_direct_flag if {
	dep := object.remove(banned_dependency, {"direct"})
	inp := {
		"repository": {"organization": "ccf", "name": "api", "full_name": "ccf/api"},
		"dependency": dep,
	}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_banned_license"
}

test_flags_banned_license_when_resolved_is_legacy_alias if {
	dep := object.union(banned_dependency, {"repository": {}, "collection_status": {"repository_resolved": true, "health_collected": true}})
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_banned_license"
}

test_flags_license_not_in_configured_allow_list if {
	inp := {"dependencies": [mit_dependency]}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"allowed_licenses": ["Apache-2.0"]}} # regal ignore:unresolved-reference
	count(violations) == 1
	some v in violations
	v.id == "dependency_license_not_allowed"
}

test_flags_unknown_collected_license if {
	inp := {"dependencies": [unknown_license_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_license_unknown"
}

test_flags_unknown_uppercase_collected_license if {
	inp := {"dependencies": [unknown_license_upper_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_license_unknown"
}

test_flags_noassertion_collected_license if {
	inp := {"dependencies": [unknown_license_noassertion_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_license_unknown"
}

test_license_collection_failure_stays_silent if {
	inp := {"dependencies": [failed_license_collection_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_ignores_non_direct_dependency if {
	dep := object.union(banned_dependency, {"direct": false})
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_ignores_unresolved_dependency if {
	dep := object.union(banned_dependency, {"repository": {"resolved": false}})
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_skips_when_dependency_health_is_not_observable if {
	dep := object.union(banned_dependency, {"collection_status": {"health_collected": false}})
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
	skip_reason != "" with input as inp
}
