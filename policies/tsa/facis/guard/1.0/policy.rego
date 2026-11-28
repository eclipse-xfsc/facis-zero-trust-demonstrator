# The guard's IF-05 policy, evaluated by the XFSC TSA policy service. Input is the IF-05 policy
# input (docs/contracts/if05-policy-input.v1.schema.json); "decision" is the IF-05 decision
# (if05-policy-decision.v1.schema.json). Every decision names its rule and the bundle revision, which
# the publisher writes into data.bundle.revision. data.config is the zone's configuration.
# OPA v0.58 (the TSA's), hence the future keywords.
package facis.guard

import future.keywords.if
import future.keywords.in

revision := data.bundle.revision

scopes := split(input.token.scope, " ")

# The first entitled scope the token carries selects the acquisition tenant; a summary identity can
# never select the full-report one.
selected := "report:read" if {
	"report:read" in scopes
} else := "report:summary" if {
	"report:summary" in scopes
}

# The routes the rule set covers, as the built-in evaluator's: the REST route, or a gRPC method the
# zone's data lists (data.config.grpc_methods, full method paths) whose service the guard named.
grpc_service := object.get(input.request, "grpc_service", "")

route_ok if {
	grpc_service == ""
	input.request.path == "/demo"
}

route_ok if {
	grpc_service != ""
	input.request.path in object.get(data.config, "grpc_methods", [])
	startswith(input.request.path, concat("", ["/", grpc_service, "/"]))
}

shape_ok if {
	input.source.spiffe_id in data.config.participant_callers
	input.request.method == "POST"
	route_ok
	input.request.host == data.config.host
	input.token.present == true
	input.token.proof_valid == true
	input.token.aud == data.config.audience
	input.token.sub != ""
	input.token.client_id != ""
	input.token.jkt != ""
}

# Tenant membership, as the built-in evaluator's m3-tenant-membership: the guard names the tenant of
# its route (target_tenant), this policy's data names who belongs to it (data.config.tenant_members,
# tenant -> member SPIFFE IDs). With a target tenant, or with members configured, the caller must be
# a member of the target tenant; a policy that serves no tenant refuses a target tenant.
target_tenant := object.get(input, "target_tenant", "")

tenant_members := object.get(data.config, "tenant_members", {})

member_ok if {
	target_tenant == ""
	count(tenant_members) == 0
}

member_ok if {
	input.source.spiffe_id in object.get(tenant_members, target_tenant, [])
}

# A scope that needs a credential presentation first (data.config.presentation: its scopes and the
# OID4VP link the caller is answered with), as the built-in evaluator's m3-presentation-required.
presentation := object.get(data.config, "presentation", {"scopes": [], "oid4vp_link": ""})

presentation_required if {
	some scope in scopes
	scope in presentation.scopes
}

request_ok if {
	shape_ok
	member_ok
	input.tenant == data.config.scope_tenants[selected]
}

decision := {
	"allow": false,
	"reason_code": "POL-RULE-DENY",
	"rule_id": "m3-tenant-membership",
	"bundle_revision": revision,
	"deny_body": {"error": "access_denied"},
} if {
	shape_ok
	not member_ok
} else := {
	"allow": false,
	"reason_code": "POL-PRESENTATION-REQUIRED",
	"rule_id": "m3-presentation-required",
	"bundle_revision": revision,
	"deny_body": {"error": "presentation_required", "oid4vp_link": presentation.oid4vp_link},
} if {
	shape_ok
	presentation_required
} else := {
	"allow": false,
	"reason_code": "POL-RULE-DENY",
	"rule_id": "m3-scope-withdrawn",
	"bundle_revision": revision,
	"deny_body": {"error": "access_denied"},
} if {
	request_ok
	selected in data.config.withdrawn_scopes
} else := {
	"allow": true,
	"rule_id": sprintf("m3-%s", [replace(selected, ":", "-")]),
	"bundle_revision": revision,
	"obligations": ["substitute_upstream_token"],
} if {
	request_ok
} else := {
	"allow": false,
	"reason_code": "POL-RULE-DENY",
	"rule_id": "m3-default-deny",
	"bundle_revision": revision,
	"deny_body": {"error": "access_denied"},
}
