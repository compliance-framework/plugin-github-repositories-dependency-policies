# GitHub Repository Dependency Policies

Opt-in CCF policy bundle for dependency health evidence collected by `plugin-github-repositories`.

These policies evaluate direct dependency facts exposed on `input.dependency`. They do not collect dependency data themselves and do not decide whether an upstream project is controlled by the assessed organization.

For granular risk acceptance, evaluate one dependency at a time and attach evidence to that dependency subject. The legacy `input.dependencies[]` collection shape is still supported as a compatibility fallback, but granular evaluation is preferred when dependency-specific risk acceptance matters.

## Expected Input

The preferred input shape is:

```json
{
  "repository": {
    "organization": "ccf",
    "name": "api",
    "full_name": "ccf/api"
  },
  "dependency": {
    "name": "github.com/example/lib",
    "ecosystem": "go",
    "source_file": "go.mod",
    "declared_version": "v1.2.3",
    "repository": {
      "provider": "github",
      "owner": "example",
      "name": "lib",
      "url": "https://github.com/example/lib",
      "resolved": true
    },
    "health": {
      "repository_archived": false,
      "latest_release": {"tag": "v1.3.0", "published_at": "2026-01-10T00:00:00Z"},
      "latest_commit": {"sha": "abc123", "committed_at": "2026-04-15T00:00:00Z"},
      "pull_requests": {
        "open_count": 12,
        "oldest_open_created_at": "2025-09-01T00:00:00Z",
        "median_days_to_close": 8
      }
    },
    "supply_chain": {
      "license": {"spdx_id": "MIT", "name": "MIT License", "collected": true},
      "sbom": {"available": true, "package_count": 42, "collected": true}
    },
    "collection_status": {
      "repository_resolved": true,
      "health_collected": true,
      "errors": []
    }
  }
}
```

When `input.dependency` is present, it is treated as the dependency being evaluated and does not need `direct: true`.

Generated evidence for granular dependency evaluation should include a `dependency` label whose value is the dependency name or stable dependency identifier, for example `dependency=github.com/example/lib`. Every risk template in this bundle declares `dedupe_label_keys: ["dependency"]`, so risks are tracked separately per dependency instead of one shared risk per policy.

Specific dependency health policies only evaluate a dependency when `dependency.repository.resolved` is `true` and `dependency.collection_status.health_collected` is `true`. If dependency health is not observable, those policies return `skip_reason` instead of failing evidence, and the `dependency_health_unknown` policy is responsible for reporting the visibility gap.

The compatibility collection shape is:

```json
{
  "dependencies": [
    {
      "name": "github.com/example/lib",
      "direct": true,
      "declared_version": "v1.2.3",
      "repository": {"resolved": true, "url": "https://github.com/example/lib"}
    }
  ]
}
```

When using `input.dependencies[]`, only dependencies with `direct: true` are evaluated.

## Policies

- `dependency_repository_archived`: flags direct dependencies whose resolved upstream repository is archived.
- `dependency_activity_stale`: flags dependencies with both stale release and commit activity, or no collected activity signal.
- `dependency_pr_staleness`: flags stale open PR backlog or slow median PR close time.
- `dependency_sbom_available`: flags absent or empty dependency SBOM evidence when required by policy data.
- `dependency_license_allowed`: flags banned, non-allow-listed, or unknown collected dependency licenses.
- `dependency_health_unknown`: optionally flags unresolved repositories or uncollected health facts.

## Policy Data

Thresholds are read from `data.dependency_health`.

```json
{
  "dependency_health": {
    "max_days_since_release": 365,
    "max_days_since_commit": 180,
    "max_open_prs": 50,
    "max_oldest_open_pr_age_days": 180,
    "max_median_days_to_close_pr": 30,
    "require_dependency_sbom": false,
    "banned_licenses": ["BUSL-1.1", "SSPL-1.0", "PolyForm-Noncommercial-1.0.0"],
    "allowed_licenses": [],
    "unknown_health_is_violation": false
  }
}
```

## Testing

```shell
opa test policies
opa check policies
```

## Bundling

Policies are built into a bundle for distribution:

```shell
make build
```
