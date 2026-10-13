package compliance_framework.dependency_health_unknown

resolved_dependency := {
	"name": "github.com/example/lib",
	"declared_version": "v1.2.3",
	"direct": true,
	"repository": {"resolved": true, "url": "https://github.com/example/lib"},
	"collection_status": {"health_collected": true, "errors": []},
}

unresolved_dependency := {
	"name": "example.com/private/lib",
	"declared_version": "v1.2.3",
	"direct": true,
	"repository": {"resolved": false},
	"collection_status": {"repository_resolved": false, "health_collected": false},
}

partial_collection_dependency := {
	"name": "github.com/example/lib",
	"declared_version": "v1.2.3",
	"direct": true,
	"repository": {"resolved": true, "url": "https://github.com/example/lib"},
	"collection_status": {
		"health_collected": false,
		"errors": [{"scope": "workflows", "message": "actions metadata unavailable"}],
	},
}

test_unknown_health_is_informational_by_default if {
	inp := {"dependencies": [unresolved_dependency, partial_collection_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
	skip_reason != "" with input as inp
}

test_skip_reason_is_only_when_dependency_health_is_unobservable if {
	inp := {"dependencies": [resolved_dependency]}
	count({reason | reason := skip_reason with input as inp}) == 0
}

test_passes_when_health_is_collected_and_unknowns_are_violations if {
	inp := {"dependencies": [resolved_dependency]}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"unknown_health_is_violation": true}} # regal ignore:unresolved-reference
	count(violations) == 0
}

test_flags_unresolved_dependency_when_configured if {
	inp := {"dependencies": [unresolved_dependency]}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"unknown_health_is_violation": true}} # regal ignore:unresolved-reference
	count(violations) == 1
	some v in violations
	v.id == "dependency_repository_unresolved"
}

test_flags_granular_dependency_without_direct_flag if {
	dep := object.remove(unresolved_dependency, {"direct"})
	inp := {
		"repository": {"organization": "ccf", "name": "api", "full_name": "ccf/api"},
		"dependency": dep,
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"unknown_health_is_violation": true}} # regal ignore:unresolved-reference
	count(violations) == 1
	some v in violations
	v.id == "dependency_repository_unresolved"
}

test_flags_uncollected_health_when_configured if {
	inp := {"dependencies": [partial_collection_dependency]}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"unknown_health_is_violation": true}} # regal ignore:unresolved-reference
	count(violations) == 1
	some v in violations
	v.id == "dependency_health_not_collected"
	contains(v.remarks, "workflows: actions metadata unavailable")
}

test_flags_uncollected_health_when_collection_status_uses_legacy_repository_resolved if {
	dep := {
		"name": "github.com/example/lib",
		"declared_version": "v1.2.3",
		"direct": true,
		"repository": {},
		"collection_status": {"repository_resolved": true, "health_collected": false, "errors": [{"scope": "workflows", "message": "actions metadata unavailable"}]},
	}
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"unknown_health_is_violation": true}} # regal ignore:unresolved-reference
	count(violations) == 1
	some v in violations
	v.id == "dependency_health_not_collected"
}

test_ignores_non_direct_dependency if {
	dep := object.union(unresolved_dependency, {"direct": false})
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"unknown_health_is_violation": true}} # regal ignore:unresolved-reference
	count(violations) == 0
}
