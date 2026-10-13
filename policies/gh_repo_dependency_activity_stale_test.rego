package compliance_framework.dependency_activity_stale

fixed_now_ns := time.parse_rfc3339_ns("2026-05-19T00:00:00Z")

base_dependency := {
	"name": "github.com/example/lib",
	"declared_version": "v1.2.3",
	"direct": true,
	"repository": {"resolved": true, "url": "https://github.com/example/lib"},
	"collection_status": {"health_collected": true},
}

recent_activity_dependency := object.union(base_dependency, {"health": {
	"latest_release": {"published_at": "2026-05-01T00:00:00Z"},
	"latest_commit": {"committed_at": "2026-05-15T00:00:00Z"},
}})

stale_activity_dependency := object.union(base_dependency, {"health": {
	"latest_release": {"published_at": "2024-01-01T00:00:00Z"},
	"latest_commit": {"committed_at": "2024-12-01T00:00:00Z"},
}})

test_passes_when_release_or_commit_activity_is_recent if {
	inp := {"__now_ns": fixed_now_ns, "dependencies": [recent_activity_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_flags_dependency_when_release_and_commit_are_stale if {
	inp := {"__now_ns": fixed_now_ns, "dependencies": [stale_activity_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_activity_stale"
	contains(v.remarks, "exceeds 365 days")
	contains(v.remarks, "exceeds 180 days")
}

test_flags_granular_dependency_without_direct_flag if {
	dep := object.remove(stale_activity_dependency, {"direct"})
	inp := {
		"__now_ns": fixed_now_ns,
		"repository": {"organization": "ccf", "name": "api", "full_name": "ccf/api"},
		"dependency": dep,
	}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_activity_stale"
}

test_flags_dependency_with_no_activity_signal if {
	dep := object.union(base_dependency, {"health": {}})
	inp := {"__now_ns": fixed_now_ns, "dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_has_no_activity_signal"
}

test_ignores_non_direct_dependency if {
	dep := object.union(stale_activity_dependency, {"direct": false})
	inp := {"__now_ns": fixed_now_ns, "dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_ignores_unresolved_dependency if {
	dep := object.union(stale_activity_dependency, {"repository": {"resolved": false}})
	inp := {"__now_ns": fixed_now_ns, "dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_flags_stale_activity_when_resolved_is_legacy_alias if {
	dep := object.union(stale_activity_dependency, {"repository": {}, "collection_status": {"repository_resolved": true, "health_collected": true}})
	inp := {"__now_ns": fixed_now_ns, "dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_activity_stale"
}

test_skips_when_dependency_health_is_not_observable if {
	dep := object.union(stale_activity_dependency, {"collection_status": {"health_collected": false}})
	inp := {"__now_ns": fixed_now_ns, "dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
	skip_reason != "" with input as inp
}

test_threshold_override_can_make_recent_activity_stale if {
	dep := object.union(base_dependency, {"health": {
		"latest_release": {"published_at": "2026-05-17T00:00:00Z"},
		"latest_commit": {"committed_at": "2026-05-17T00:00:00Z"},
	}})
	inp := {
		"__now_ns": fixed_now_ns,
		"dependencies": [dep],
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"max_days_since_release": 1, "max_days_since_commit": 1}} # regal ignore:unresolved-reference
	count(violations) == 1
	some v in violations
	v.id == "dependency_activity_stale"
}
