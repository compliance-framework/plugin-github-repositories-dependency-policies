package compliance_framework.dependency_sbom_available

base_dependency := {
	"name": "github.com/example/lib",
	"declared_version": "v1.2.3",
	"direct": true,
	"repository": {"resolved": true, "url": "https://github.com/example/lib"},
	"collection_status": {"health_collected": true},
}

sbom_dependency := object.union(base_dependency, {"supply_chain": {"sbom": {"available": true, "package_count": 12}}})

absent_sbom_dependency := object.union(base_dependency, {"supply_chain": {"sbom": {"available": false, "collected": true}}})

empty_sbom_dependency := object.union(base_dependency, {"supply_chain": {"sbom": {"available": true, "package_count": 0}}})

test_passes_by_default_when_sbom_is_not_required if {
	inp := {"dependencies": [absent_sbom_dependency]}
	violations := {v | violation[v] with input as inp}
	count(violations) == 0
	skip_reason != "" with input as inp
}

test_passes_when_required_sbom_is_available_with_packages if {
	inp := {
		"dependencies": [sbom_dependency],
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"require_dependency_sbom": true}}
	count(violations) == 0
}

test_flags_absent_required_sbom if {
	inp := {
		"dependencies": [absent_sbom_dependency],
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"require_dependency_sbom": true}}
	count(violations) == 1
	some v in violations
	v.id == "dependency_sbom_absent"
}

test_flags_granular_dependency_without_direct_flag if {
	dep := object.remove(absent_sbom_dependency, {"direct"})
	inp := {
		"repository": {"organization": "ccf", "name": "api", "full_name": "ccf/api"},
		"dependency": dep,
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"require_dependency_sbom": true}}
	count(violations) == 1
	some v in violations
	v.id == "dependency_sbom_absent"
}

test_flags_empty_required_sbom if {
	inp := {
		"dependencies": [empty_sbom_dependency],
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"require_dependency_sbom": true}}
	count(violations) == 1
	some v in violations
	v.id == "dependency_sbom_empty"
}

test_ignores_non_direct_dependency if {
	dep := object.union(absent_sbom_dependency, {"direct": false})
	inp := {
		"dependencies": [dep],
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"require_dependency_sbom": true}}
	count(violations) == 0
}

test_ignores_unresolved_dependency if {
	dep := object.union(absent_sbom_dependency, {"repository": {"resolved": false}})
	inp := {
		"dependencies": [dep],
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"require_dependency_sbom": true}}
	count(violations) == 0
}

test_skips_when_dependency_health_is_not_observable if {
	dep := object.union(absent_sbom_dependency, {"collection_status": {"health_collected": false}})
	inp := {
		"dependencies": [dep],
	}
	violations := {v | violation[v] with input as inp with data.dependency_health as {"require_dependency_sbom": true}}
	count(violations) == 0
	skip_reason != "" with input as inp
}
