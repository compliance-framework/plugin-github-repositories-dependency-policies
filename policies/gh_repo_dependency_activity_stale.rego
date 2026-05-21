package compliance_framework.dependency_activity_stale

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

max_days_since_release := object.get(dependency_health_input, "max_days_since_release", 365)
max_days_since_commit := object.get(dependency_health_input, "max_days_since_commit", 180)
nano_per_day := ((24 * 60) * 60) * 1000000000
current_time_ns := object.get(input, "__now_ns", time.now_ns())

title := "Direct dependency has recent upstream activity"

description := "Direct dependency repositories should show recent release or commit activity. A dependency with no recent upstream activity may require review to confirm it is still maintained and safe to rely on."

skip_reason := "Dependency health is not observable, so upstream activity cannot be evaluated. The dependency_health_unknown policy reports this visibility gap." if {
	unobservable_dependency_health
}

risk_templates := [
	{
		"name": "Direct dependency has stale upstream activity",
		"title": "Dependency {{ .dependency }} contribution seems stale and may delay security fixes",
		"statement": "Dependency {{ .dependency }} has no recent release and no recent default-branch commit, which may indicate reduced upstream maintenance. Reduced maintenance can delay security fixes, compatibility updates, and review of reported defects.",
		"likelihood_hint": "moderate",
		"impact_hint": "moderate",
		"violation_ids": ["dependency_activity_stale"],
		"dedupe_label_keys": ["dependency"],
		"label_schema": [{"key": "dependency", "description": "Dependency module path or package name being evaluated"}],
		"threat_refs": [{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-1104",
			"title": "Use of Unmaintained Third Party Components",
			"url": "https://cwe.mitre.org/data/definitions/1104.html",
		}],
		"remediation": {
			"title": "Review stale dependency maintenance status",
			"description": "Confirm whether the dependency remains maintained and appropriate for production use. If not, plan replacement or internal maintenance ownership.",
			"tasks": [
				{"title": "Review upstream repository activity and maintainer communications"},
				{"title": "Check whether newer maintained alternatives exist"},
				{"title": "Create a remediation issue for replacement or upgrade"},
				{"title": "Document acceptance rationale if the dependency is intentionally stable"},
			],
		},
	},
	{
		"name": "Direct dependency has no collected activity signal",
		"title": "Missing upstream activity evidence limits dependency due diligence",
		"statement": "When no release or commit activity can be collected for a direct dependency, the organization lacks evidence to determine whether the upstream component is actively maintained. This creates a visibility gap in third-party component risk management.",
		"likelihood_hint": "moderate",
		"impact_hint": "moderate",
		"violation_ids": ["dependency_has_no_activity_signal"],
		"dedupe_label_keys": ["dependency"],
		"label_schema": [{"key": "dependency", "description": "Dependency module path or package name being evaluated"}],
		"threat_refs": [{
			"system": "https://cwe.mitre.org",
			"external_id": "CWE-1059",
			"title": "Incomplete Documentation",
			"url": "https://cwe.mitre.org/data/definitions/1059.html",
		}],
		"remediation": {
			"title": "Record dependency maintenance evidence",
			"description": "Investigate why upstream activity could not be collected and record an alternative maintenance signal or replacement plan.",
			"tasks": [
				{"title": "Verify the dependency source repository"},
				{"title": "Collect an alternative maintenance signal if GitHub data is unavailable"},
				{"title": "Document the dependency review result"},
			],
		},
	},
]

violation[{"id": "dependency_activity_stale", "remarks": remarks}] if {
	dep := dependencies[_]
	dependency_health_observable(dep)
	release_is_stale(dep)
	commit_is_stale(dep)
	remarks := sprintf("Direct dependency %q at version %q has stale upstream activity at %q: latest release %q exceeds %d days and latest commit %q exceeds %d days.", [dependency_name(dep), dependency_version(dep), dependency_url(dep), release_published_at(dep), max_days_since_release, commit_committed_at(dep), max_days_since_commit])
}

violation[{"id": "dependency_has_no_activity_signal", "remarks": remarks}] if {
	dep := dependencies[_]
	dependency_health_observable(dep)
	not has_release_signal(dep)
	not has_commit_signal(dep)
	remarks := sprintf("Direct dependency %q at version %q has no collected release or commit activity signal for upstream repository %q.", [dependency_name(dep), dependency_version(dep), dependency_url(dep)])
}

release_is_stale(dep) if {
	ts := release_published_at(dep)
	ts != ""
	age_days(ts) > max_days_since_release
}

commit_is_stale(dep) if {
	ts := commit_committed_at(dep)
	ts != ""
	age_days(ts) > max_days_since_commit
}

has_release_signal(dep) if {
	release_published_at(dep) != ""
}

has_commit_signal(dep) if {
	commit_committed_at(dep) != ""
}

release_published_at(dep) := ts if {
	latest_release := object_or_empty(object.get(dependency_health(dep), "latest_release", {}))
	ts := object.get(latest_release, "published_at", "")
}

commit_committed_at(dep) := ts if {
	latest_commit := object_or_empty(object.get(dependency_health(dep), "latest_commit", {}))
	ts := object.get(latest_commit, "committed_at", "")
}

age_days(ts) := floor((current_time_ns - time.parse_rfc3339_ns(ts)) / nano_per_day)

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

dependency_health(dep) := health if {
	health := object_or_empty(object.get(dep, "health", {}))
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
