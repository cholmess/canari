from __future__ import annotations

from typing import Annotated

from canari import __version__
from canari.registry import CanaryRegistry
from canari.reporting import ForensicReporter
from canari.threat_intel import ThreatIntelBuilder


def create_app(db_path: str = "canari.db", api_key: str | None = None):
    from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query

    app = FastAPI(title="Canari API", version=__version__)
    registry = CanaryRegistry(db_path)
    reporter = ForensicReporter(registry)
    intel = ThreatIntelBuilder(registry)

    def _auth(x_api_key: Annotated[str | None, Header()] = None):
        if api_key is not None:
            if x_api_key != api_key:
                raise HTTPException(status_code=401, detail="unauthorized")
            return {"role": "admin", "tenant_id": None, "application_id": None, "source": "static"}

        active_keys = registry.list_api_keys(include_inactive=False)
        if not active_keys:
            return {"role": "admin", "tenant_id": None, "application_id": None, "source": "open"}
        if not x_api_key:
            raise HTTPException(status_code=401, detail="unauthorized")
        verified = registry.verify_api_key(x_api_key)
        if not verified:
            raise HTTPException(status_code=401, detail="unauthorized")
        return {
            "role": verified.get("role", "reader"),
            "tenant_id": verified.get("tenant_id"),
            "application_id": verified.get("application_id"),
            "source": "registry",
        }

    def _require_role(principal: dict, minimum: str) -> None:
        order = {"reader": 0, "admin": 1}
        if order.get(principal.get("role", "reader"), -1) < order.get(minimum, 0):
            raise HTTPException(status_code=403, detail="forbidden")

    @app.get("/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.get("/v1/summary")
    def summary(
        limit: Annotated[int, Query(ge=1, le=20000)] = 5000,
        app: str | None = None,
        principal: dict = Depends(_auth),
    ):
        tenant_id = principal.get("tenant_id")
        app_scope = principal.get("application_id")
        payload = reporter.forensic_summary(
            limit=limit,
            tenant_id=tenant_id,
            application_id=app_scope or app,
        )
        payload["version"] = __version__
        return payload

    @app.get("/v1/alerts")
    def alerts(
        limit: Annotated[int, Query(ge=1, le=5000)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
        severity: str | None = None,
        surface: str | None = None,
        conversation: str | None = None,
        incident: str | None = None,
        tenant: str | None = None,
        app: str | None = None,
        since: str | None = None,
        until: str | None = None,
        principal: dict = Depends(_auth),
    ):
        tenant_scope = principal.get("tenant_id")
        app_scope = principal.get("application_id")
        rows = registry.list_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            detection_surface=surface,
            conversation_id=conversation,
            incident_id=incident,
            tenant_id=tenant_scope or tenant,
            application_id=app_scope or app,
            since=since,
            until=until,
        )
        return [r.model_dump(mode="json") for r in rows]

    @app.get("/v1/alert-stats")
    def alert_stats(
        tenant: str | None = None,
        app: str | None = None,
        principal: dict = Depends(_auth),
    ):
        tenant_scope = principal.get("tenant_id")
        app_scope = principal.get("application_id")
        return registry.alert_stats(
            tenant_id=tenant_scope or tenant,
            application_id=app_scope or app,
        )

    @app.get("/v1/incidents")
    def incidents(
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        app: str | None = None,
        principal: dict = Depends(_auth),
    ):
        tenant_scope = principal.get("tenant_id")
        app_scope = principal.get("application_id")
        incidents = registry.list_alerts(limit=10000, tenant_id=tenant_scope, application_id=app_scope or app)
        grouped = {}
        for a in incidents:
            if not a.incident_id:
                continue
            grouped.setdefault(a.incident_id, []).append(a)

        out = []
        for inc_id, events in grouped.items():
            events.sort(key=lambda e: e.triggered_at)
            out.append(
                {
                    "incident_id": inc_id,
                    "conversation_id": events[0].conversation_id,
                    "tenant_id": events[0].tenant_id,
                    "application_id": events[0].application_id,
                    "event_count": len(events),
                    "max_severity": max(events, key=lambda e: _sev_rank(e.severity.value)).severity.value,
                    "surfaces": sorted({e.detection_surface for e in events}),
                    "last_seen": events[-1].triggered_at.isoformat(),
                }
            )
        out.sort(key=lambda x: x["last_seen"], reverse=True)
        return out[:limit]

    @app.get("/v1/incidents/{incident_id}")
    def incident_detail(
        incident_id: str,
        app: str | None = None,
        tenant: str | None = None,
        principal: dict = Depends(_auth),
    ):
        tenant_scope = principal.get("tenant_id")
        app_scope = principal.get("application_id")
        return reporter.incident_report(
            incident_id,
            tenant_id=tenant_scope or tenant,
            application_id=app_scope or app,
        )

    @app.get("/v1/siem/events")
    def siem_events(
        limit: Annotated[int, Query(ge=1, le=50000)] = 1000,
        app: str | None = None,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        tenant_scope = principal.get("tenant_id")
        app_scope = principal.get("application_id")
        return reporter.siem_events(limit=limit, tenant_id=tenant_scope, application_id=app_scope or app)

    @app.get("/v1/siem/cef")
    def siem_cef(
        limit: Annotated[int, Query(ge=1, le=50000)] = 1000,
        app: str | None = None,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        tenant_scope = principal.get("tenant_id")
        app_scope = principal.get("application_id")
        return reporter.siem_cef_events(limit=limit, tenant_id=tenant_scope, application_id=app_scope or app)

    @app.post("/v1/siem/ingest")
    def siem_ingest(payload: dict = Body(...), principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        source = payload.get("source", "siem")
        events = payload.get("events", [])
        if not isinstance(events, list):
            raise HTTPException(status_code=400, detail="events must be a list")
        out = intel.ingest_external_events(events, source=source)
        registry.record_audit("siem_ingest_api", out)
        return out

    @app.get("/v1/siem/external")
    def siem_external(
        limit: Annotated[int, Query(ge=1, le=5000)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        return registry.list_external_events(limit=limit, offset=offset)

    @app.get("/v1/audit")
    def audit(
        limit: Annotated[int, Query(ge=1, le=5000)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        return registry.list_audit(limit=limit, offset=offset)

    @app.get("/v1/threat-feed")
    def threat_feed(
        limit: Annotated[int, Query(ge=1, le=50000)] = 5000,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        return intel.local_feed(limit=limit)

    @app.get("/v1/threat-sharing")
    def threat_sharing_status(principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        return {"opt_in_enabled": registry.threat_sharing_opt_in()}

    @app.post("/v1/threat-sharing")
    def threat_sharing_set(payload: dict = Body(...), principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        enabled = bool(payload.get("opt_in_enabled"))
        registry.set_threat_sharing_opt_in(enabled)
        registry.record_audit("set_threat_sharing_opt_in_api", {"enabled": enabled})
        return {"opt_in_enabled": enabled}

    @app.get("/v1/network-signatures")
    def network_signatures(
        limit: Annotated[int, Query(ge=1, le=5000)] = 200,
        offset: Annotated[int, Query(ge=0)] = 0,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        return registry.list_network_signatures(limit=limit, offset=offset)

    @app.post("/v1/network-signatures/import")
    def network_signatures_import(payload: dict = Body(...), principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        source = payload.get("source", "community")
        out = intel.import_share_bundle(payload, source=source)
        registry.record_audit("import_network_signatures_api", out)
        return out

    @app.get("/v1/threat-matches")
    def threat_matches(
        local_limit: Annotated[int, Query(ge=1, le=50000)] = 5000,
        network_limit: Annotated[int, Query(ge=1, le=50000)] = 5000,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        return intel.network_matches(local_limit=local_limit, network_limit=network_limit)

    @app.get("/v1/threat-transparency")
    def threat_transparency(
        local_limit: Annotated[int, Query(ge=1, le=50000)] = 5000,
        network_limit: Annotated[int, Query(ge=1, le=50000)] = 5000,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        return intel.transparency_report(local_limit=local_limit, network_limit=network_limit)

    @app.get("/v1/attack-patterns")
    def attack_patterns(
        local_limit: Annotated[int, Query(ge=1, le=50000)] = 5000,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        return intel.attack_pattern_library(local_limit=local_limit)

    @app.get("/v1/api-keys")
    def api_keys_list(
        include_inactive: bool = True,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        return registry.list_api_keys(include_inactive=include_inactive)

    @app.post("/v1/api-keys")
    def api_keys_add(
        payload: dict = Body(...),
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        name = payload.get("name")
        key = payload.get("key")
        role = payload.get("role", "reader")
        tenant_id = payload.get("tenant_id")
        application_id = payload.get("application_id")
        if not name or not key:
            raise HTTPException(status_code=400, detail="name and key are required")
        return registry.create_api_key(
            name=name,
            key=key,
            role=role,
            tenant_id=tenant_id,
            application_id=application_id,
        )

    @app.post("/v1/api-keys/{key_id}/revoke")
    def api_keys_revoke(
        key_id: int,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        return {"id": key_id, "revoked": registry.revoke_api_key(key_id)}

    @app.post("/v1/api-keys/{key_id}/rotate")
    def api_keys_rotate(
        key_id: int,
        payload: dict = Body(...),
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        new_key = payload.get("new_key")
        if not new_key:
            raise HTTPException(status_code=400, detail="new_key is required")
        out = registry.rotate_api_key(key_id=key_id, new_key=new_key)
        if out is None:
            raise HTTPException(status_code=404, detail="key not found")
        return out

    @app.get("/v1/policy")
    def policy_get(principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        min_sev = registry.get_setting("policy.min_dispatch_severity") or None
        win = registry.get_setting("policy.rate_window_seconds")
        mx = registry.get_setting("policy.rate_max_dispatches")
        retention = registry.get_setting("policy.retention_days")
        rate = None
        if win and mx:
            rate = {"window_seconds": int(win), "max_dispatches": int(mx)}
        return {
            "min_dispatch_severity": min_sev,
            "rate_limit": rate,
            "retention_days": int(retention) if retention else None,
        }

    @app.post("/v1/policy")
    def policy_set(payload: dict = Body(...), principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        min_sev = payload.get("min_dispatch_severity")
        rate_win = payload.get("rate_window_seconds")
        rate_max = payload.get("rate_max_dispatches")
        retention_days = payload.get("retention_days")

        if min_sev is not None:
            if min_sev not in {"low", "medium", "high", "critical"}:
                raise HTTPException(status_code=400, detail="invalid min_dispatch_severity")
            registry.set_setting("policy.min_dispatch_severity", min_sev)
        if rate_win is not None:
            registry.set_setting("policy.rate_window_seconds", str(int(rate_win)))
        if rate_max is not None:
            registry.set_setting("policy.rate_max_dispatches", str(int(rate_max)))
        if retention_days is not None:
            n = int(retention_days)
            if n <= 0:
                raise HTTPException(status_code=400, detail="retention_days must be > 0")
            registry.set_setting("policy.retention_days", str(n))

        registry.record_audit("policy_set_api", payload)
        return {"saved": True, "policy": policy_get(principal)}

    @app.get("/v1/retention-policies")
    def retention_policies(principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        return registry.list_retention_policies()

    @app.post("/v1/retention-policies")
    def retention_policy_set(payload: dict = Body(...), principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        days = int(payload.get("retention_days", 0))
        if days <= 0:
            raise HTTPException(status_code=400, detail="retention_days must be > 0")
        tenant_id = payload.get("tenant_id")
        application_id = payload.get("application_id")
        out = registry.upsert_retention_policy(
            retention_days=days,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        registry.record_audit("retention_policy_set_api", out)
        return out

    @app.post("/v1/retention-policies/apply")
    def retention_policy_apply(principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        policies = registry.list_retention_policies()
        results = []
        total_removed = 0
        for p in policies:
            removed = registry.purge_alerts_older_than(
                days=int(p["retention_days"]),
                tenant_id=p.get("tenant_id"),
                application_id=p.get("application_id"),
            )
            results.append(
                {
                    "tenant_id": p.get("tenant_id"),
                    "application_id": p.get("application_id"),
                    "retention_days": int(p["retention_days"]),
                    "removed": removed,
                }
            )
            total_removed += removed
        out = {"policies_applied": len(policies), "total_removed": total_removed, "results": results}
        registry.record_audit("retention_policies_apply_api", out)
        return out

    @app.get("/v1/control-plane/export")
    def control_plane_export(principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        return {
            "schema": "canari-control-plane-v1",
            "schema_version": 1,
            "settings": registry.settings(),
            "retention_policies": registry.list_retention_policies(),
            "network_signatures": registry.list_network_signatures(limit=100000, offset=0),
            "api_keys_metadata": registry.list_api_keys(include_inactive=True),
        }

    @app.post("/v1/control-plane/import")
    def control_plane_import(
        payload: dict = Body(...),
        dry_run: bool = False,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        source = payload.get("source", "control_plane_import_api")
        settings = payload.get("settings", {}) or {}
        if not dry_run:
            for k, v in settings.items():
                registry.set_setting(str(k), str(v))

        ret_rows = payload.get("retention_policies", []) or []
        ret_applied = 0
        for row in ret_rows:
            if not isinstance(row, dict):
                continue
            days = int(row.get("retention_days", 0))
            if days <= 0:
                continue
            if not dry_run:
                registry.upsert_retention_policy(
                    retention_days=days,
                    tenant_id=row.get("tenant_id"),
                    application_id=row.get("application_id"),
                )
            ret_applied += 1

        sig_rows = payload.get("network_signatures", []) or []
        sig_imported = len(sig_rows) if dry_run else registry.upsert_network_signatures(sig_rows, source=source)
        out = {
            "settings_applied": len(settings),
            "retention_policies_applied": ret_applied,
            "network_signatures_imported": sig_imported,
            "api_keys_metadata_seen": len(payload.get("api_keys_metadata", []) or []),
            "dry_run": dry_run,
        }
        if not dry_run:
            registry.record_audit("control_plane_import_api", out | {"source": source})
        return out

    @app.post("/v1/control-plane/validate")
    def control_plane_validate(payload: dict = Body(...), principal: dict = Depends(_auth)):
        _require_role(principal, "admin")
        errors: list[str] = []
        warnings: list[str] = []
        if not isinstance(payload, dict):
            return {"ok": False, "errors": ["payload must be an object"], "warnings": [], "counts": {}}
        schema = payload.get("schema")
        if schema not in (None, "canari-control-plane-v1"):
            warnings.append(f"unexpected schema '{schema}'")
        if payload.get("schema_version") not in (None, 1):
            warnings.append(f"unexpected schema_version '{payload.get('schema_version')}'")
        settings = payload.get("settings", {})
        if settings is not None and not isinstance(settings, dict):
            errors.append("settings must be an object")
            settings = {}
        ret = payload.get("retention_policies", [])
        if ret is not None and not isinstance(ret, list):
            errors.append("retention_policies must be a list")
            ret = []
        sig = payload.get("network_signatures", [])
        if sig is not None and not isinstance(sig, list):
            errors.append("network_signatures must be a list")
            sig = []
        keys = payload.get("api_keys_metadata", [])
        if keys is not None and not isinstance(keys, list):
            errors.append("api_keys_metadata must be a list")
            keys = []
        return {
            "ok": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "counts": {
                "settings": len(settings),
                "retention_policies": len(ret),
                "network_signatures": len(sig),
                "api_keys_metadata": len(keys),
            },
        }

    @app.get("/v1/compliance/evidence")
    def compliance_evidence(
        limit: Annotated[int, Query(ge=1, le=50000)] = 5000,
        tenant: str | None = None,
        app: str | None = None,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        tenant_scope = principal.get("tenant_id")
        app_scope = principal.get("application_id")
        return reporter.compliance_evidence_pack(
            limit=limit,
            tenant_id=tenant_scope or tenant,
            application_id=app_scope or app,
        )

    @app.get("/v1/compliance/incidents/{incident_id}")
    def compliance_incident_dossier(
        incident_id: str,
        tenant: str | None = None,
        app: str | None = None,
        principal: dict = Depends(_auth),
    ):
        _require_role(principal, "admin")
        tenant_scope = principal.get("tenant_id")
        app_scope = principal.get("application_id")
        return reporter.incident_dossier(
            incident_id,
            tenant_id=tenant_scope or tenant,
            application_id=app_scope or app,
        )

    return app


def _sev_rank(sev: str) -> int:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return order.get(sev, -1)
