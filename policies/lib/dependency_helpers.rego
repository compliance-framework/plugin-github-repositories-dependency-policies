package ccf_libs.dependency_helpers

array_or_empty(value) := value if {
	is_array(value)
}

array_or_empty(value) := [] if {
	not is_array(value)
}

object_or_empty(value) := value if {
	is_object(value)
}

object_or_empty(value) := {} if {
	not is_object(value)
}

selected_dependencies(input_data) := [dep] if {
	dep := object.get(input_data, "dependency", null)
	is_object(dep)
}

selected_dependencies(input_data) := deps if {
	dep := object.get(input_data, "dependency", null)
	not is_object(dep)
	deps := array_or_empty(object.get(input_data, "dependencies", []))
}

input_dependency_provided(input_data) if {
	is_object(object.get(input_data, "dependency", null))
}

direct_dependency(input_data, _) if {
	input_dependency_provided(input_data)
}

direct_dependency(input_data, dep) if {
	not input_dependency_provided(input_data)
	object.get(dep, "direct", false) == true
}

repository_resolved(dep) if {
	repository := dependency_repository(dep)
	object.get(repository, "resolved", "__repository_resolved_missing__") == true
}

repository_resolved(dep) if {
	repository := dependency_repository(dep)
	object.get(repository, "resolved", "__repository_resolved_missing__") == "__repository_resolved_missing__"
	object.get(dependency_collection_status(dep), "repository_resolved", false) == true
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

dependency_name(dep) := object.get(dep, "name", "unknown")

dependency_version(dep) := object.get(dep, "declared_version", "unknown")

dependency_url(dep) := object.get(dependency_repository(dep), "url", "unknown")
