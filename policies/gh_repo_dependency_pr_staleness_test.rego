package compliance_framework.dependency_pr_staleness

fixed_now_ns := time.parse_rfc3339_ns("2026-05-19T00:00:00Z")

base_dependency := {
	"name": "github.com/example/lib",
	"declared_version": "v1.2.3",
	"direct": true,
	"repository": {"resolved": true, "url": "https://github.com/example/lib"},
	"collection_status": {"health_collected": true},
}

healthy_pr_dependency := object.union(base_dependency, {"health": {"pull_requests": {"open_count": 5, "oldest_open_created_at": "2026-05-01T00:00:00Z", "median_days_to_close": 4}}})

backlog_dependency := object.union(base_dependency, {"health": {"pull_requests": {"open_count": 84, "oldest_open_created_at": "2025-08-01T00:00:00Z", "median_days_to_close": 4}}})

slow_close_dependency := object.union(base_dependency, {"health": {"pull_requests": {"open_count": 5, "oldest_open_created_at": "2026-05-01T00:00:00Z", "median_days_to_close": 45}}})

test_passes_when_pr_metrics_are_within_thresholds if {
	inp := {"__now_ns": fixed_now_ns, "dependencies": [healthy_pr_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_flags_stale_open_pr_backlog if {
	inp := {"__now_ns": fixed_now_ns, "dependencies": [backlog_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_open_pr_backlog_stale"
	contains(v.remarks, "84 open pull requests")
}

test_flags_granular_dependency_without_direct_flag if {
	dep := object.remove(backlog_dependency, {"direct"})
	inp := {
		"__now_ns": fixed_now_ns,
		"repository": {"organization": "ccf", "name": "api", "full_name": "ccf/api"},
		"dependency": dep,
	}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_open_pr_backlog_stale"
}

test_flags_slow_median_pr_close_time if {
	inp := {"__now_ns": fixed_now_ns, "dependencies": [slow_close_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_pr_close_time_stale"
}

test_ignores_non_direct_dependency if {
	dep := object.union(backlog_dependency, {"direct": false})
	inp := {"__now_ns": fixed_now_ns, "dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_partial_pr_data_stays_silent if {
	dep := object.union(base_dependency, {"health": {"pull_requests": {"open_count": 84}}})
	inp := {"__now_ns": fixed_now_ns, "dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
}

test_skips_when_dependency_health_is_not_observable if {
	dep := object.union(backlog_dependency, {"collection_status": {"health_collected": false}})
	inp := {"__now_ns": fixed_now_ns, "dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
	skip_reason != "" with input as inp
}

test_flags_stale_pr_backlog_when_resolved_is_legacy_alias if {
	dep := object.union(backlog_dependency, {"repository": {}, "collection_status": {"repository_resolved": true, "health_collected": true}})
	inp := {"__now_ns": fixed_now_ns, "dependencies": [dep]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 1
	some v in violations
	v.id == "dependency_open_pr_backlog_stale"
}

test_threshold_override_flags_smaller_backlog if {
	dep := object.union(base_dependency, {"health": {"pull_requests": {"open_count": 6, "oldest_open_created_at": "2026-05-01T00:00:00Z", "median_days_to_close": 4}}})
	inp := {
		"__now_ns": fixed_now_ns,
		"dependencies": [dep],
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"max_open_prs": 5, "max_oldest_open_pr_age_days": 10}}
	count(violations) == 1
	some v in violations
	v.id == "dependency_open_pr_backlog_stale"
}
