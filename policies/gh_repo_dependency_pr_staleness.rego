package compliance_framework.dependency_pr_staleness

import data.ccf_libs.dependency_helpers as dependency_helpers

dependencies := dependency_helpers.selected_dependencies(input)

default dependency_health_input := {}

dependency_health_input := dependency_helpers.object_or_empty(data.dependency_health) if {
	is_object(data.dependency_health)
}

max_open_prs := object.get(dependency_health_input, "max_open_prs", 50)
max_oldest_open_pr_age_days := object.get(dependency_health_input, "max_oldest_open_pr_age_days", 180)
max_median_days_to_close_pr := object.get(dependency_health_input, "max_median_days_to_close_pr", 30)
nano_per_day := ((24 * 60) * 60) * 1000000000
current_time_ns := object.get(input, "__now_ns", time.now_ns())

title := "Direct dependency pull requests are maintained within expected thresholds"

description := sprintf("Direct dependency repositories should not show excessive stale pull request backlog or slow pull request closure because those signals may indicate reduced maintainer responsiveness. Policy data: dependency_health.max_open_prs=%d, dependency_health.max_oldest_open_pr_age_days=%d, dependency_health.max_median_days_to_close_pr=%d.", [max_open_prs, max_oldest_open_pr_age_days, max_median_days_to_close_pr])

skip_reason := "Dependency health is not observable, so pull request maintenance cannot be evaluated. The dependency_health_unknown policy reports this visibility gap." if {
	unobservable_dependency_health
}

risk_templates := [{
	"name": "Direct dependency has stale pull request maintenance",
	"title": "Low Upstream Maintainer Responsiveness May Delay {{ .dependency }} Fixes",
	"statement": "A dependency repository with a large stale pull request backlog or slow pull request closure may have reduced maintainer responsiveness. This can delay bug fixes, security patches, and compatibility updates needed by downstream products.",
	"likelihood_hint": "moderate",
	"impact_hint": "moderate",
	"violation_ids": ["dependency_open_pr_backlog_stale", "dependency_pr_close_time_stale"],
	"dedupe_label_keys": ["dependency"],
	"label_schema": [{"key": "dependency", "description": "Dependency module path or package name being evaluated"}],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-1104",
		"title": "Use of Unmaintained Third Party Components",
		"url": "https://cwe.mitre.org/data/definitions/1104.html",
	}],
	"remediation": {
		"title": "Review dependency maintainer responsiveness",
		"description": "Assess whether the dependency is still suitable based on upstream maintainer responsiveness and create a tracked remediation or replacement plan where needed.",
		"tasks": [
			{"title": "Review open pull request backlog and maintainer responses"},
			{"title": "Check whether critical fixes are delayed upstream"},
			{"title": "Evaluate maintained alternatives or internal fork ownership"},
			{"title": "Create a remediation issue for dependencies with unacceptable responsiveness"},
		],
	},
}]

violation[{"id": "dependency_open_pr_backlog_stale", "remarks": remarks}] if {
	dep := dependencies[_]
	dependency_health_observable(dep)
	pr_open_count(dep) > max_open_prs
	oldest_age := oldest_open_pr_age_days(dep)
	oldest_age > max_oldest_open_pr_age_days
	remarks := sprintf("Direct dependency %q at version %q has %d open pull requests and the oldest open pull request is %d days old for upstream repository %q, exceeding thresholds of %d open PRs and %d days. Failure values: expected_max_open_prs:%d, dependency_open_prs:%d, expected_max_oldest_open_pr_age_days:%d, dependency_oldest_open_pr_age_days:%d.", [dependency_name(dep), dependency_version(dep), pr_open_count(dep), oldest_age, dependency_url(dep), max_open_prs, max_oldest_open_pr_age_days, max_open_prs, pr_open_count(dep), max_oldest_open_pr_age_days, oldest_age])
}

violation[{"id": "dependency_pr_close_time_stale", "remarks": remarks}] if {
	dep := dependencies[_]
	dependency_health_observable(dep)
	median_days := pr_median_days_to_close(dep)
	median_days > max_median_days_to_close_pr
	remarks := sprintf("Direct dependency %q at version %q has median pull request close time of %d days for upstream repository %q, exceeding threshold of %d days.", [dependency_name(dep), dependency_version(dep), median_days, dependency_url(dep), max_median_days_to_close_pr])
}

pr_open_count(dep) := object.get(dependency_pull_requests(dep), "open_count", 0)

oldest_open_pr_age_days(dep) := floor((current_time_ns - time.parse_rfc3339_ns(ts)) / nano_per_day) if {
	ts := object.get(dependency_pull_requests(dep), "oldest_open_created_at", "")
	valid_rfc3339(ts)
}

valid_rfc3339(ts) if {
	regex.match(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`, ts)
}

pr_median_days_to_close(dep) := object.get(dependency_pull_requests(dep), "median_days_to_close", 0)

dependency_pull_requests(dep) := prs if {
	prs := dependency_helpers.object_or_empty(object.get(dependency_health(dep), "pull_requests", {}))
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
