package compliance_framework.dependency_repository_archived

healthy_dependency := {
	"name": "github.com/example/lib",
	"declared_version": "v1.2.3",
	"direct": true,
	"repository": {"resolved": true, "url": "https://github.com/example/lib"},
	"collection_status": {"health_collected": true},
	"health": {"repository_archived": false},
}

archived_dependency := {
	"name": "github.com/example/old",
	"declared_version": "v0.9.0",
	"direct": true,
	"repository": {"resolved": true, "url": "https://github.com/example/old"},
	"collection_status": {"health_collected": true},
	"health": {"repository_archived": true},
}

test_passes_when_direct_dependency_repository_is_not_archived if {
	inp := {"dependencies": [healthy_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_flags_archived_direct_dependency_repository if {
	inp := {"dependencies": [archived_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	violations[{"id": "dependency_repository_archived", "remarks": "Direct dependency \"github.com/example/old\" at version \"v0.9.0\" uses archived upstream repository \"https://github.com/example/old\"."}]
}

test_flags_granular_dependency_without_direct_flag if {
	dep := object.remove(archived_dependency, {"direct"})
	inp := {
		"repository": {"organization": "ccf", "name": "api", "full_name": "ccf/api"},
		"dependency": dep,
	}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_repository_archived"
}

test_ignores_non_direct_dependency if {
	dep := object.union(archived_dependency, {"direct": false})
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_ignores_unresolved_dependency if {
	dep := object.union(archived_dependency, {"repository": {"resolved": false}})
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_flags_archived_dependency_when_resolved_is_legacy_alias if {
	dep := object.union(archived_dependency, {"repository": {}, "collection_status": {"repository_resolved": true, "health_collected": true}})
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_repository_archived"
}

test_skips_when_dependency_health_is_not_observable if {
	dep := object.union(archived_dependency, {"collection_status": {"health_collected": false}})
	inp := {"dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
	skip_reason != "" with input as inp
}
