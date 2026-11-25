# Tests of policy.rego in OPA (scripts/verify-tsa-policy/rego-test.sh), the cases of the built-in
# evaluator's TestTenantMembership (services/policyevaluator/policy_test.go). Not packed into a bundle:
# the bundle carries policy.rego and data.json only.
package facis.guard

import future.keywords.if

member_a := "spiffe://zone-a.test/ns/tenant-a/sa/ztd-participant"

member_b := "spiffe://zone-a.test/ns/tenant-b/sa/ztd-participant"

untenanted := {
	"audience": "https://guard.facis.invalid",
	"host": "ztd-guard:8080",
	"participant_callers": [member_a, member_b],
	"scope_tenants": {"report:read": "report-read", "report:summary": "report-summary"},
	"withdrawn_scopes": [],
}

tenant_a := object.union(untenanted, {
	"scope_tenants": {"report:read": "tenant-a-read", "report:summary": "tenant-a-summary"},
	"tenant_members": {"tenant-a": [member_a]},
})

request(caller, target, route) := r if {
	base := {
		"correlation_id": "c",
		"source": {"spiffe_id": caller},
		"request": {"method": "POST", "path": "/demo", "host": "ztd-guard:8080"},
		"token": {"present": true, "sub": "s", "client_id": "c", "jkt": "j", "scope": "report:summary", "aud": "https://guard.facis.invalid", "proof_valid": true},
		"tenant": route,
	}
	r := object.union(base, {"target_tenant": target})
}

untargeted(caller, route) := object.remove(request(caller, "", route), ["target_tenant"])

decide(cfg, in) := d if {
	d := decision with input as in with data.config as cfg with data.bundle.revision as "t"
}

membership_denied(d) if {
	d.allow == false
	d.rule_id == "m3-tenant-membership"
	d.reason_code == "POL-RULE-DENY"
}

test_member_allowed if {
	d := decide(tenant_a, request(member_a, "tenant-a", "tenant-a-summary"))
	d.allow == true
	d.rule_id == "m3-report-summary"
}

test_other_tenants_caller_denied if {
	membership_denied(decide(tenant_a, request(member_b, "tenant-a", "tenant-a-summary")))
}

test_no_target_tenant_denied if {
	membership_denied(decide(tenant_a, untargeted(member_a, "tenant-a-summary")))
}

test_route_of_a_tenant_not_served_denied if {
	membership_denied(decide(tenant_a, request(member_a, "tenant-c", "tenant-a-summary")))
}

test_untenanted_policy_refuses_a_target_tenant if {
	membership_denied(decide(untenanted, request(member_a, "tenant-a", "report-summary")))
}

test_untenanted_policy_without_target_unchanged if {
	d := decide(untenanted, untargeted(member_a, "report-summary"))
	d.allow == true
	d.rule_id == "m3-report-summary"
}

test_member_on_the_full_route_not_allowed if {
	d := decide(tenant_a, request(member_a, "tenant-a", "tenant-a-read"))
	d.allow == false
	d.rule_id == "m3-default-deny"
}

test_unlisted_caller_is_default_deny if {
	d := decide(tenant_a, request("spiffe://zone-a.test/ns/x/sa/y", "tenant-a", "tenant-a-summary"))
	d.rule_id == "m3-default-deny"
}

# The cases of the built-in evaluator's TestPolicyDecidesAConfiguredGRPCMethodLikeTheRESTRoute and
# its presentation-required denial.
grpc_method := "/grpc.health.v1.Health/Check"

link := "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.test%2Frequest"

with_grpc := object.union(untenanted, {"grpc_methods": [grpc_method], "presentation": {"scopes": ["report:full"], "oid4vp_link": link}})

grpc_call(path, service) := object.union(untargeted(member_a, "report-summary"), {"request": {"path": path, "grpc_service": service}})

test_grpc_method_decided_like_the_rest_route if {
	rest := decide(with_grpc, untargeted(member_a, "report-summary"))
	grpc := decide(with_grpc, grpc_call(grpc_method, "grpc.health.v1.Health"))
	rest.allow
	grpc == rest
}

test_grpc_denied_when_not_a_configured_route if {
	decide(with_grpc, grpc_call("/grpc.health.v1.Health/Watch", "grpc.health.v1.Health")).rule_id == "m3-default-deny"
	decide(with_grpc, grpc_call(grpc_method, "other.Service")).rule_id == "m3-default-deny"
	decide(with_grpc, grpc_call(grpc_method, "")).rule_id == "m3-default-deny"
	decide(with_grpc, grpc_call("/demo", "grpc.health.v1.Health")).rule_id == "m3-default-deny"
	decide(untenanted, grpc_call(grpc_method, "grpc.health.v1.Health")).rule_id == "m3-default-deny"
}

full := {"token": {"scope": "report:full report:summary"}}

presentation_denial := {"allow": false, "reason_code": "POL-PRESENTATION-REQUIRED", "rule_id": "m3-presentation-required", "bundle_revision": "t", "deny_body": {"error": "presentation_required", "oid4vp_link": link}}

test_presentation_required_carries_the_link if {
	decide(with_grpc, object.union(untargeted(member_a, "report-summary"), full)) == presentation_denial
	decide(with_grpc, object.union(grpc_call(grpc_method, "grpc.health.v1.Health"), full)) == presentation_denial
	decide(untenanted, object.union(untargeted(member_a, "report-summary"), {"token": {"scope": "report:full"}})).rule_id == "m3-default-deny"
}
