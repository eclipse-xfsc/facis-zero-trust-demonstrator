(() => {
  // Keep identity and Journey routes beneath the reverse-proxy UI mount.
  const facisMount = window.location.pathname.match(/^(.*)\/facis-demo(?:\/|$)/);
  const facisRoute = (path) => (facisMount ? facisMount[1] : "") + path;

  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __esm = (fn, res, err) => function __init() {
    if (err) throw err[0];
    try {
      return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
    } catch (e) {
      throw err = [e], e;
    }
  };
  var __commonJS = (cb, mod) => function __require() {
    try {
      return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
    } catch (e) {
      throw mod = 0, e;
    }
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));

  // src/vendor/vue.js
  var Vue, createApp, reactive, computed, ref, watch, defineComponent, onMounted, onBeforeUnmount, onUnmounted, nextTick, h;
  var init_vue = __esm({
    "src/vendor/vue.js"() {
      Vue = window.Vue;
      if (!Vue) {
        throw new Error("[vendor/vue] window.Vue not found; load ./vendor/vue.global.js (copied by build.js from the vue package) before index.js");
      }
      ({
        createApp,
        reactive,
        computed,
        ref,
        watch,
        defineComponent,
        onMounted,
        onBeforeUnmount,
        onUnmounted,
        nextTick,
        h
      } = Vue);
    }
  });

  // src/services/identity.service.js
  function publish(value) {
    identity = value;
    for (const listener of listeners) listener(value);
  }
  function onIdentity(listener) {
    listeners.add(listener);
    listener(identity);
    return () => listeners.delete(listener);
  }
  async function refreshIdentity() {
    if (!identityEnabled) return identity;
    const epoch = identityEpoch;
    try {
      const res = await fetch(facisRoute("/ztd/api/session"), { credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(1e4) });
      const result = await res.json();
      if (epoch !== identityEpoch) return identity;
      if (!res.ok) {
        publish({ mode: "oidc", state: result.state || "unavailable", canOperate: false });
        return identity;
      }
      if (result.mode !== "oidc" || !["authenticated", "denied"].includes(result.state) || typeof result.csrf !== "string") throw fail("IDENTITY_INVALID_RESPONSE");
      publish(result);
      return identity;
    } catch {
      if (epoch === identityEpoch) publish({ mode: "oidc", state: "unavailable", canOperate: false });
      return identity;
    }
  }
  async function identityCommand(type, data = {}) {
    var _a3, _b;
    if (identity.state !== "authenticated") throw fail(identity.state === "expired" ? "EXPIRED" : "LOGGED_OUT");
    const res = await fetch(facisRoute("/ztd/api/journey"), { method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(35e3), headers: { "Content-Type": "application/json", "X-FACIS-CSRF": identity.csrf }, body: JSON.stringify({ type, data }) });
    const text = await res.text();
    if (text.length > 131072) throw fail("IDENTITY_INVALID_RESPONSE");
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw fail("IDENTITY_INVALID_RESPONSE");
    }
    if (!res.ok || body.ok !== true) {
      const code = ((_a3 = body.error) == null ? void 0 : _a3.code) || "MODULE_OPERATION_FAILED";
      if (res.status === 401) publish({ mode: "oidc", state: body.state || "expired", canOperate: false });
      throw fail(code, body.state || ((_b = body.error) == null ? void 0 : _b.detail));
    }
    return body.data;
  }
  async function passwordLogin(username, password) {
    var _a3;
    if (!identityEnabled || !passwordLoginMode) throw fail("PASSWORD_LOGIN_NOT_ENABLED");
    const epoch = ++identityEpoch;
    const res = await fetch(facisRoute("/ztd/api/login"), { method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(25e3), headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
    let result;
    try {
      result = await res.json();
    } catch {
      throw fail("LOGIN_SERVICE_UNAVAILABLE");
    }
    if (!res.ok || result.ok !== true) throw fail(((_a3 = result.error) == null ? void 0 : _a3.code) || "LOGIN_REJECTED");
    if (result.mode !== "oidc" || !["authenticated", "denied"].includes(result.state) || typeof result.csrf !== "string") throw fail("INVALID_LOGIN_RESPONSE");
    if (epoch !== identityEpoch) throw fail("STALE_LOGIN");
    publish(result);
    return result;
  }
  function login() {
    window.location.assign(facisRoute("/ztd/oidc/login"));
  }
  async function logout() {
    var _a3;
    identityEpoch++;
    if (passwordLoginMode) {
      const res = await fetch(facisRoute("/ztd/oidc/logout"), { method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(15e3), headers: { "Content-Type": "application/json", "X-FACIS-CSRF": identity.csrf }, body: "{}" });
      const result = await res.json();
      if (result.state === "logged out") publish({ mode: "oidc", state: "logged out", canOperate: false });
      if (!res.ok || result.ok !== true) throw fail(((_a3 = result.error) == null ? void 0 : _a3.code) || "LOGOUT_FAILED");
      return;
    }
    const form = document.createElement("form");
    form.method = "POST";
    form.action = facisRoute("/ztd/oidc/logout");
    const field = document.createElement("input");
    field.type = "hidden";
    field.name = "csrf";
    field.value = identity.csrf;
    form.appendChild(field);
    document.body.appendChild(form);
    form.submit();
  }
  var _a, identityEnabled, _a2, passwordLoginMode, identity, listeners, identityEpoch, fail;
  var init_identity_service = __esm({
    "src/services/identity.service.js"() {
      identityEnabled = ((_a = document.querySelector('meta[name="facis-auth-mode"]')) == null ? void 0 : _a.content) === "oidc";
      passwordLoginMode = ((_a2 = document.querySelector('meta[name="facis-login-mode"]')) == null ? void 0 : _a2.content) === "password";
      identity = { mode: identityEnabled ? "oidc" : "fixture", state: identityEnabled ? "connecting" : "fixture", canOperate: !identityEnabled };
      listeners = /* @__PURE__ */ new Set();
      identityEpoch = 0;
      fail = (code, detail) => Object.assign(new Error(code), { code, detail });
    }
  });

  // src/services/uibuilder.service.js
  function state(value) {
    for (const fn of states) {
      try {
        fn(value);
      } catch {
      }
    }
  }
  function receive(msg) {
    var _a3, _b;
    const message = msg && msg.payload;
    if (!message || message.kind !== "response") return;
    const p = pending.get(message.requestId);
    if (!p) return;
    pending.delete(message.requestId);
    clearTimeout(p.timer);
    if (message.ok === true) p.resolve(message.data);
    else p.reject(fail2(((_a3 = message.error) == null ? void 0 : _a3.code) || "MODULE_OPERATION_FAILED", (_b = message.error) == null ? void 0 : _b.detail));
  }
  async function connect() {
    if (!window.uibuilder) throw fail2("MODULE_CLIENT_UNAVAILABLE");
    if (!bound) {
      bound = true;
      uibuilder.onChange("msg", receive);
      uibuilder.onChange("ioConnected", (value) => {
        state(value ? "connected" : "disconnected");
        if (!value) {
          for (const p of pending.values()) {
            clearTimeout(p.timer);
            p.reject(fail2("MODULE_CONNECTION_LOST"));
          }
          pending.clear();
        }
      });
    }
    if (uibuilder.get("ioConnected")) {
      state("connected");
      return;
    }
    state("connecting");
    await new Promise((resolve, reject) => {
      const start = Date.now();
      const timer = setInterval(() => {
        if (uibuilder.get("ioConnected")) {
          clearInterval(timer);
          state("connected");
          resolve();
        } else if (Date.now() - start > 15e3) {
          clearInterval(timer);
          state("unavailable");
          reject(fail2("MODULE_CONNECTION_FAILED"));
        }
      }, 100);
    });
  }
  async function send({ route, type, data = {} }) {
    await connect();
    if (!uibuilder.get("ioConnected")) throw fail2("MODULE_CONNECTION_LOST");
    if (pending.size >= 32) throw fail2("MODULE_BUSY");
    const requestId = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(requestId);
        reject(fail2("MODULE_TIMEOUT"));
      }, 35e3);
      pending.set(requestId, { resolve, reject, timer });
      uibuilder.send({ payload: { route, type, data, requestId } });
    });
  }
  function onConnection(fn) {
    states.add(fn);
    return () => states.delete(fn);
  }
  function retryConnection() {
    return connect();
  }
  var pending, states, bound, fail2;
  var init_uibuilder_service = __esm({
    "src/services/uibuilder.service.js"() {
      pending = /* @__PURE__ */ new Map();
      states = /* @__PURE__ */ new Set();
      bound = false;
      fail2 = (code, detail) => Object.assign(new Error(code), { code, detail });
    }
  });

  // src/app/registry.js
  function registerComponent(descriptor) {
    if (!(descriptor == null ? void 0 : descriptor.tag) || !(descriptor == null ? void 0 : descriptor.component)) {
      throw new Error("[registry] registerComponent requires { tag, component }");
    }
    if (components.some((entry) => entry.tag === descriptor.tag)) return;
    components.push({ enabled: true, ...descriptor });
  }
  function getComponents() {
    return components.filter((entry) => entry.enabled !== false);
  }
  function registerModule(descriptor) {
    if (!(descriptor == null ? void 0 : descriptor.name) || !(descriptor == null ? void 0 : descriptor.route)) {
      throw new Error("[registry] registerModule requires { name, route }");
    }
    modules.set(descriptor.name, {
      reads: [],
      actions: [],
      ...descriptor
    });
  }
  function callModule(name, type, data = {}) {
    const module = modules.get(name);
    if (!module) throw new Error(`[registry] Unknown module: ${name}`);
    const allowed = [...module.reads, ...module.actions];
    if (!allowed.includes(type)) throw new Error(`[registry] Unsupported operation: ${name}.${type}`);
    if (identityEnabled) {
      if (name !== "journey") return Promise.reject(Object.assign(new Error("UNSUPPORTED_AUTH_MODULE"), { code: "UNSUPPORTED_AUTH_MODULE" }));
      return identityCommand(type, data);
    }
    return send({ route: module.route, type, data });
  }
  function onModuleConnection(listener) {
    if (identityEnabled) {
      listener("connected");
      return () => {
      };
    }
    return onConnection(listener);
  }
  function retryModuleConnection() {
    if (identityEnabled) return Promise.resolve();
    return retryConnection();
  }
  var components, modules;
  var init_registry = __esm({
    "src/app/registry.js"() {
      init_identity_service();
      init_uibuilder_service();
      components = [];
      modules = /* @__PURE__ */ new Map();
    }
  });

  // src/components/welcome-card.js
  var require_welcome_card = __commonJS({
    "src/components/welcome-card.js"() {
      init_identity_service();
      init_vue();
      init_registry();
      var ShellIcon = defineComponent({
        props: { name: { type: String, required: true } },
        template: `<svg class="ui-icon" aria-hidden="true"><use :href="'#icon-' + name" /></svg>`
      });
      registerModule({
        name: "journey",
        route: "journey",
        reads: ["status"],
        actions: ["start", "next", "reset"]
      });
      var scenarioCatalog = [
        { id: "atlas-successful-call", label: "Successful call" },
        { id: "atlas-revoked-credential", label: "Revoked credential" },
        { id: "atlas-wrong-scope", label: "Wrong scope" }
      ];
      var serviceScenarioCatalog = [
        { id: "success", label: "Service success" },
        { id: "denied", label: "Service denied" },
        { id: "unavailable", label: "Resource unavailable" },
        { id: "error", label: "Service error" },
        { id: "slow", label: "Slow response" }
      ];
      var RESYNC_CODES = /* @__PURE__ */ new Set(["STALE_RUN", "DUPLICATE_COMMAND", "RUN_IN_PROGRESS", "NO_ACTIVE_RUN", "INVALID_TRANSITION"]);
      var TRANSPORT_CODES = /* @__PURE__ */ new Set(["MODULE_CONNECTION_LOST", "MODULE_CONNECTION_FAILED", "MODULE_TIMEOUT", "MODULE_CLIENT_UNAVAILABLE", "MODULE_RUNTIME_BRIDGE_MISSING", "MODULE_CLIENT_CLOSED"]);
      var WelcomeCard = defineComponent({
        name: "FacisZeroTrustDemo",
        components: { ShellIcon },
        data: () => ({
          identityMode: identityEnabled,
          passwordMode: passwordLoginMode,
          loginUsername: "",
          loginPassword: "",
          loginBusy: false,
          loginError: "",
          loginFormOpen: true,
          identity: { state: identityEnabled ? "connecting" : "fixture", canOperate: !identityEnabled },
          identityPoll: null,
          stopIdentityObserver: null,
          scenarioOptions: scenarioCatalog,
          serviceScenarioOptions: serviceScenarioCatalog,
          activeView: "journey",
          flowAvailable: false,
          epoch: 0,
          lastSyncedAt: "",
          selectedScenarioId: "atlas-successful-call",
          selectedVariant: "rule-deny",
          atlasCatalog: [],
          selectedServiceScenario: "success",
          adapterMode: "fixture",
          transport: "fixture",
          pendingPoll: null,
          runState: null,
          connectionState: "connecting",
          loading: false,
          errorMessage: "",
          showSampleMetadata: true,
          draftConfig: { kind: "trust-zone", target: "zone-a", bundle: "", revision: "", digest: "", adapter: "mock" },
          draftPreview: null,
          stopConnectionObserver: null
        }),
        computed: {
          canOperate() {
            return !this.identityMode || this.identity.canOperate === true;
          },
          isAuthenticated() {
            return !this.identityMode || this.identity.state === "authenticated";
          },
          selectedSpec() {
            return this.atlasCatalog.find((s) => s.id === this.selectedScenarioId);
          },
          profile() {
            var _a3, _b;
            return ((_a3 = this.runState) == null ? void 0 : _a3.profile) || (this.selectedScenarioId === "atlas-wrong-scope" && this.selectedVariant === "presentation-required" ? "participant-unpresented" : ((_b = this.selectedSpec) == null ? void 0 : _b.profile) || "Awaiting fixture catalogue");
          },
          steps() {
            var _a3, _b;
            return (((_a3 = this.runState) == null ? void 0 : _a3.checks) || ((_b = this.selectedSpec) == null ? void 0 : _b.steps) || []).map((step, index) => [String(index + 1).padStart(2, "0"), step.name, step.detail]);
          },
          currentCheck() {
            var _a3, _b;
            return (_b = (_a3 = this.runState) == null ? void 0 : _a3.checks) == null ? void 0 : _b[this.activeStep - 1];
          },
          activeStep() {
            var _a3;
            return ((_a3 = this.runState) == null ? void 0 : _a3.activeStep) || 0;
          },
          scenario() {
            var _a3;
            if (this.runState) return { ...this.runState, checks: this.runState.policyChecks || [] };
            const option = this.scenarioOptions.find((entry) => entry.id === this.selectedScenarioId) || this.scenarioOptions[0];
            return {
              ...option,
              summary: ((_a3 = this.selectedSpec) == null ? void 0 : _a3.summary) || "Flow-owned fixture scenario. Run the journey to retrieve its evidence.",
              tone: "neutral",
              outcome: "Decision pending",
              reason: "Not evaluated",
              credential: { type: "Not evaluated", issuer: "\u2014", validity: "\u2014", status: "Not evaluated" },
              trust: { zone: "Not evaluated", confidence: "\u2014", attestation: "\u2014", status: "Not evaluated" },
              attestation: { method: "Not evaluated", result: "Not evaluated", timestamp: "\u2014" },
              connection: { protocol: "Not evaluated", encryption: "\u2014", endpoint: "\u2014", status: "Not evaluated" },
              measurements: [],
              checks: []
            };
          },
          isStarted() {
            var _a3;
            return Boolean((_a3 = this.runState) == null ? void 0 : _a3.runId);
          },
          isComplete() {
            var _a3;
            return Boolean((_a3 = this.runState) == null ? void 0 : _a3.terminal);
          },
          isServicePending() {
            var _a3, _b;
            return ((_b = (_a3 = this.runState) == null ? void 0 : _a3.serviceRequest) == null ? void 0 : _b.status) === "pending";
          },
          isHttpSampleMode() {
            return this.adapterMode === "http-sample";
          },
          serviceScenarioDisabled() {
            return !this.canOperate || !this.isHttpSampleMode || this.selectedScenarioId !== "atlas-successful-call" || this.isStarted || this.loading;
          },
          serviceScenarioEvidence() {
            var _a3;
            return this.isHttpSampleMode && this.selectedScenarioId === "atlas-successful-call" ? ((_a3 = this.runState) == null ? void 0 : _a3.serviceScenario) || this.selectedServiceScenario : "Not applicable \u2014 fixture mode";
          },
          isUnavailable() {
            return !this.flowAvailable || this.connectionState !== "connected";
          },
          runLabel() {
            if (this.identityMode && !this.isAuthenticated) return "Login required";
            if (!this.canOperate) return "Observer \xB7 Read only";
            if (this.isServicePending) return "Awaiting Participant\u2026";
            if (this.loading) return "Sending\u2026";
            if (this.isUnavailable) return this.connectionState === "connecting" ? "Connecting to flow\u2026" : "Flow unavailable";
            if (!this.isStarted) return "Run journey";
            if (this.isComplete) return "Run complete";
            return `Continue to step ${this.activeStep + 1}`;
          },
          decisionStatus() {
            if (!this.isComplete) return "Pending";
            return this.runState.terminalStatus || (this.runState.result === "success" ? "Granted" : this.scenario.tone === "warning" ? "Unavailable" : "Refused");
          },
          eventMessages() {
            var _a3;
            return (((_a3 = this.runState) == null ? void 0 : _a3.evidence) || []).map((item) => {
              var _a4, _b, _c, _d, _e;
              return {
                at: new Date(item.timestamp).toISOString().slice(11, 23),
                direction: ((_a4 = item.data) == null ? void 0 : _a4.unavailable) ? "Unavailable" : ((_b = item.data) == null ? void 0 : _b.blocked) ? "Blocked" : "Fixture",
                text: ((_c = item.data) == null ? void 0 : _c.contractEvent) ? `${item.data.source} \xB7 ${item.data.kind} \xB7 ${item.data.state}${item.data.reasonCode ? " \xB7 " + item.data.reasonCode : ""}${item.data.ruleId ? " \xB7 " + item.data.ruleId : ""} \u2014 ${item.detail}` : item.detail,
                status: ((_d = item.data) == null ? void 0 : _d.unavailable) ? "Unavailable" : ((_e = item.data) == null ? void 0 : _e.blocked) ? "Blocked" : "Sent"
              };
            });
          }
        },
        mounted() {
          if (this.identityMode) {
            this.stopIdentityObserver = onIdentity((value) => {
              this.identity = value;
              if (value.state !== "authenticated") {
                this.epoch += 1;
                this.runState = null;
                this.flowAvailable = false;
                this.draftPreview = null;
              }
            });
            void this.pollIdentity();
            return;
          }
          this.stopConnectionObserver = onModuleConnection((state2) => {
            const wasConnected = this.connectionState === "connected";
            this.connectionState = state2;
            if (state2 !== "connected") {
              this.flowAvailable = false;
              return;
            }
            if (!wasConnected) void this.syncStatus();
          });
          void this.syncStatus();
        },
        beforeUnmount() {
          var _a3, _b;
          (_a3 = this.stopIdentityObserver) == null ? void 0 : _a3.call(this);
          clearTimeout(this.identityPoll);
          (_b = this.stopConnectionObserver) == null ? void 0 : _b.call(this);
          clearTimeout(this.pendingPoll);
          this.epoch += 1;
        },
        methods: {
          async pollIdentity() {
            if (this.loginBusy) {
              this.identityPoll = setTimeout(() => void this.pollIdentity(), 2e3);
              return;
            }
            const value = await refreshIdentity();
            if (value.state === "authenticated" && !this.loading) await this.syncStatus();
            this.identityPoll = setTimeout(() => void this.pollIdentity(), 2e3);
          },
          loginViewer() {
            if (this.passwordMode) {
              this.loginFormOpen = true;
              return;
            }
            login();
          },
          async submitPasswordLogin() {
            if (this.loginBusy) return;
            this.loginBusy = true;
            this.loginError = "";
            const password = this.loginPassword;
            this.loginPassword = "";
            try {
              await passwordLogin(this.loginUsername, password);
              this.loginFormOpen = false;
              this.errorMessage = "";
              await this.syncStatus();
            } catch (error) {
              const messages = { DIRECT_GRANT_DISABLED: "Keycloak has not enabled username/password login for ztd-ui yet.", INVALID_CREDENTIALS: "Login rejected. Check your credentials; the account may also require setup in Keycloak.", CLIENT_NOT_ALLOWED: "Keycloak rejected the UI client.", LOGIN_RATE_LIMIT: "Too many login attempts. Please wait a minute.", IDENTITY_PROVIDER_UNAVAILABLE: "Keycloak is unavailable. Try again.", INVALID_LOGIN_RESPONSE: "Keycloak returned an invalid identity response.", LOGIN_SERVICE_UNAVAILABLE: "The login endpoint is not available." };
              this.loginError = messages[error.code] || "Login failed (" + (error.code || "CONNECTION_FAILED") + ").";
            } finally {
              this.loginPassword = "";
              this.loginBusy = false;
            }
          },
          async logoutViewer() {
            try {
              await logout();
            } catch (error) {
              this.errorMessage = "Logout failed (" + (error.code || "IDENTITY_UNAVAILABLE") + ").";
            }
          },
          applyFlowState(state2, response = null) {
            this.runState = state2 || null;
            if (Array.isArray(response == null ? void 0 : response.atlasCatalog)) this.atlasCatalog = response.atlasCatalog;
            if (state2 == null ? void 0 : state2.variant) this.selectedVariant = state2.variant;
            if (response == null ? void 0 : response.adapterMode) this.adapterMode = response.adapterMode;
            if (response == null ? void 0 : response.transport) this.transport = response.transport;
            if (state2 == null ? void 0 : state2.adapterMode) this.adapterMode = state2.adapterMode;
            if (state2 == null ? void 0 : state2.transport) this.transport = state2.transport;
            if (state2 == null ? void 0 : state2.scenario) this.selectedScenarioId = state2.scenario;
            if (state2 == null ? void 0 : state2.serviceScenario) this.selectedServiceScenario = state2.serviceScenario;
            this.flowAvailable = true;
            this.connectionState = "connected";
            this.lastSyncedAt = (/* @__PURE__ */ new Date()).toISOString();
            clearTimeout(this.pendingPoll);
            this.pendingPoll = this.isServicePending ? setTimeout(() => void this.syncStatus(), 500) : null;
          },
          describeError(error, action) {
            const code = (error == null ? void 0 : error.code) || "UNKNOWN";
            if (TRANSPORT_CODES.has(code)) {
              this.flowAvailable = false;
              return code === "MODULE_CONNECTION_LOST" || code === "MODULE_TIMEOUT" ? `${action} result unknown: the Journey flow connection was lost (${code}). The command was not retried; state will be re-read from the flow.` : `Journey flow unavailable (${code}). No local result is shown.`;
            }
            return `${action} rejected by the Journey flow (${code})${(error == null ? void 0 : error.detail) ? `: ${error.detail}` : "."}`;
          },
          async syncStatus() {
            const epoch = ++this.epoch;
            try {
              const response = await callModule("journey", "status");
              if (epoch !== this.epoch) return;
              this.applyFlowState(response == null ? void 0 : response.state, response);
            } catch (error) {
              if (epoch !== this.epoch) return;
              this.flowAvailable = false;
              this.errorMessage = this.describeError(error, "Status");
            }
          },
          async dispatch(type, data, action) {
            var _a3, _b;
            if (!this.canOperate) {
              this.errorMessage = "denied \u2014 UI-NOT-AUTHORISED";
              return;
            }
            if (this.loading || this.isUnavailable) return;
            const epoch = ++this.epoch;
            const expectedRunId = ((_a3 = this.runState) == null ? void 0 : _a3.runId) || null;
            this.loading = true;
            this.errorMessage = "";
            try {
              const response = await callModule("journey", type, { commandId: crypto.randomUUID(), ...data });
              if (epoch !== this.epoch) return;
              const nextRunId = ((_b = response == null ? void 0 : response.state) == null ? void 0 : _b.runId) || null;
              if (type === "next" && nextRunId !== expectedRunId) {
                await this.resyncAfter(epoch);
                return;
              }
              if (type === "reset" && !(response == null ? void 0 : response.reset)) {
                await this.resyncAfter(epoch);
                return;
              }
              this.applyFlowState(response == null ? void 0 : response.state, response);
            } catch (error) {
              if (epoch !== this.epoch) return;
              this.errorMessage = this.describeError(error, action);
              if (RESYNC_CODES.has(error == null ? void 0 : error.code) || (error == null ? void 0 : error.code) === "MODULE_TIMEOUT") await this.resyncAfter(epoch);
            } finally {
              this.loading = false;
            }
          },
          async resyncAfter(epoch) {
            if (epoch !== this.epoch) return;
            this.loading = false;
            const message = this.errorMessage;
            await this.syncStatus();
            if (message && !this.errorMessage) this.errorMessage = message;
          },
          runNext() {
            if (this.isComplete) return;
            return this.isStarted ? this.dispatch("next", { runId: this.runState.runId }, "Continue") : this.dispatch("start", {
              scenario: this.selectedScenarioId,
              profile: this.profile,
              ...this.selectedScenarioId === "atlas-wrong-scope" ? { variant: this.selectedVariant } : {},
              ...this.isHttpSampleMode ? { serviceScenario: this.selectedServiceScenario } : {}
            }, "Run");
          },
          resetJourney() {
            if (!this.isStarted) return;
            return this.dispatch("reset", { runId: this.runState.runId }, "Reset");
          },
          async retryFlow() {
            this.errorMessage = "";
            try {
              await retryModuleConnection();
            } catch (error) {
              this.errorMessage = this.describeError(error, "Reconnect");
              return;
            }
            await this.syncStatus();
          },
          selectScenario(event) {
            var _a3;
            const value = (_a3 = event == null ? void 0 : event.target) == null ? void 0 : _a3.value;
            if (this.canOperate && !this.isStarted && this.scenarioOptions.some((entry) => entry.id === value)) {
              this.selectedScenarioId = value;
              this.selectedVariant = "rule-deny";
            }
            this.errorMessage = "";
          },
          selectServiceScenario(event) {
            var _a3;
            const value = (_a3 = event == null ? void 0 : event.target) == null ? void 0 : _a3.value;
            if (!this.serviceScenarioDisabled && this.serviceScenarioOptions.some((entry) => entry.id === value)) this.selectedServiceScenario = value;
            this.errorMessage = "";
          },
          statusClass(value) {
            const normalized = String(value).toLowerCase();
            if (["pass", "valid", "trusted", "verified", "granted", "sent", "protected"].some((token) => normalized.includes(token))) return "status-success";
            if (["fail", "revoked", "refused", "denied", "blocked", "mismatch"].some((token) => normalized.includes(token))) return "status-danger";
            if (["unavailable", "unknown", "conditional"].some((token) => normalized.includes(token))) return "status-warning";
            return "status-neutral";
          },
          showObserved(value) {
            return !["", "\u2014", "not evaluated", "skipped", "unavailable"].includes(String(value || "").trim().toLowerCase());
          },
          changeConfigKind() {
            const targets = {"trust-zone":"zone-a", "policy-ref":"guard-a", measurement:"zone-a-gateway", "mock-replacement":"participant-backend"};
            this.draftConfig.target = targets[this.draftConfig.kind]; this.draftPreview = null;
          },
          async previewDraft() {
            this.draftPreview = null; this.errorMessage = "";
            if (!this.canOperate) { this.errorMessage = "denied — CFG-NOT-AUTHORISED"; return; }
            const d = this.draftConfig;
            const payload = d.kind === "trust-zone" ? {zone:d.target} : d.kind === "policy-ref" ? {bundle:d.bundle.trim(), revision:d.revision.trim()} : d.kind === "measurement" ? {digest:d.digest.trim()} : {adapter:d.adapter};
            if (d.kind === "measurement" && !/^sha256:[0-9a-fA-F]{64}$/.test(payload.digest)) { this.errorMessage = "CFG-SCHEMA-INVALID: enter sha256 followed by a colon and 64 hexadecimal characters."; return; }
            if (d.kind === "policy-ref" && (!payload.bundle || !payload.revision)) { this.errorMessage = "CFG-SCHEMA-INVALID: bundle and revision are required."; return; }
            const change = {kind:d.kind, target:d.target, payload};
            if (this.identityMode) {
              try { const response = await identityCommand("config-preview", change); this.draftPreview = response.preview; }
              catch (error) { this.errorMessage = "Configuration preview rejected (" + error.code + ")."; }
              return;
            }
            this.draftPreview = {...change, phase:"preview", validation:d.kind === "policy-ref" ? "awaiting-registry" : "local-schema-valid"};
          },
          setActiveView(view) {
            if (!["journey", "evidence", "configuration"].includes(view)) return;
            this.activeView = view;
            this.$nextTick(() => {
              if (!this.$refs.mainContent) return;
              this.$refs.mainContent.scrollTop = 0;
              this.$refs.mainContent.focus({ preventScroll: true });
            });
          }
        },
        template: `
    <div class="app-shell">
      <svg class="icon-sprite" aria-hidden="true">
        <symbol id="icon-route" viewBox="0 0 24 24"><circle cx="6" cy="18" r="2"/><circle cx="18" cy="6" r="2"/><path d="M8 18h3a3 3 0 0 0 3-3v-6a3 3 0 0 1 3-3"/></symbol>
        <symbol id="icon-evidence" viewBox="0 0 24 24"><path d="M7 3h10v18H7z"/><path d="M9 8h6M9 12h6M9 16h4"/></symbol>
        <symbol id="icon-settings" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.4 1a8 8 0 0 0-1.8-1L14.4 3h-4.8l-.3 3.1a8 8 0 0 0-1.8 1l-2.4-1-2 3.4 2 1.5a7 7 0 0 0 0 2l-2 1.5 2 3.4 2.4-1a8 8 0 0 0 1.8 1l.3 3.1h4.8l.3-3.1a8 8 0 0 0 1.8-1l2.4 1 2-3.4-2-1.5a7 7 0 0 0 .1-1Z"/></symbol>
        <symbol id="icon-shield" viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 4.6 2.8 8.2 7 10 4.2-1.8 7-5.4 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-5"/></symbol>
        <symbol id="icon-lock" viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></symbol>
      </svg>

      <aside class="sidebar">
        <button class="brand" type="button" @click="setActiveView('journey')" aria-label="FACIS Zero Trust home"><span class="brand-mark"><shell-icon name="shield" /></span><span><strong>FACIS</strong><small>Zero Trust Demonstrator</small></span></button>
        <nav class="primary-nav" aria-label="Primary navigation">
          <p class="nav-label">Demonstrator</p>
          <button class="nav-item" :class="{ active: activeView === 'journey' }" type="button" aria-label="Journey" @click="setActiveView('journey')" :aria-current="activeView === 'journey' ? 'page' : null"><shell-icon name="route" /><span>Journey</span></button>
          <button class="nav-item" :class="{ active: activeView === 'evidence' }" type="button" aria-label="Evidence" @click="setActiveView('evidence')" :aria-current="activeView === 'evidence' ? 'page' : null"><shell-icon name="evidence" /><span>Evidence</span></button>
          <button class="nav-item" :class="{ active: activeView === 'configuration' }" type="button" aria-label="Configuration" @click="setActiveView('configuration')" :aria-current="activeView === 'configuration' ? 'page' : null"><shell-icon name="settings" /><span>Configuration</span><span class="soon">Preview only</span></button>
        </nav>
        <div class="environment-card"><span class="status-dot"></span><div><strong>Demonstration mode</strong><small>{{ isHttpSampleMode ? 'Fixture security · Participant sample' : 'Fixture security' }}</small></div></div>
      </aside>

      <div class="workspace">
        <header class="topbar"><div><span class="eyebrow">Security journey workspace</span><h1>Zero Trust access decision</h1></div><div class="header-actions"><span v-if="identityMode && isAuthenticated" class="identity-label">{{ identity.username }} \xB7 {{ identity.role }}</span><button v-if="identityMode && isAuthenticated" type="button" class="login-button" @click="logoutViewer">Log out</button><button v-else-if="identityMode" type="button" class="login-button" @click="loginViewer"><shell-icon name="lock" /> Log in</button><button v-else type="button" class="login-button" disabled><shell-icon name="lock" /> Live login unavailable</button></div></header>

        <main id="main-content" ref="mainContent" class="main-content" tabindex="-1">
          <section v-if="identityMode" class="notice" role="status"><div class="notice-icon">i</div><div><strong>{{ identity.state === "authenticated" ? (canOperate ? "Operator session" : "Observer \xB7 Read only") : identity.state }}</strong><p v-if="!isAuthenticated">Log in to continue. An expired session requires re-authentication.</p><p v-if="errorMessage" class="danger-text" role="alert">{{ errorMessage }}</p></div></section>
          <section v-if="identityMode && passwordMode && !isAuthenticated && loginFormOpen" class="login-panel stage-panel" aria-labelledby="login-title">
            <form @submit.prevent="submitPasswordLogin" class="login-form">
              <span class="section-kicker">Viewer identity</span><h2 id="login-title">Log in</h2><p>Your identity is checked by Keycloak. Journey results remain fixture-only.</p>
              <label class="config-field"><span>Username</span><input v-model="loginUsername" name="username" type="text" autocomplete="username" required maxlength="254" :disabled="loginBusy" /></label>
              <label class="config-field"><span>Password</span><input v-model="loginPassword" name="password" type="password" autocomplete="current-password" required maxlength="4096" :disabled="loginBusy" /></label>
              <p v-if="loginError" class="danger-text" role="alert">{{ loginError }}</p>
              <button class="primary-button interactive" type="submit" :disabled="loginBusy" :aria-busy="loginBusy">{{ loginBusy ? 'Checking identity\u2026' : 'Log in' }}</button>
            </form>
          </section>
          <div v-if="isAuthenticated">

          <section v-show="activeView === 'journey'" class="hero-grid compact-hero">
            <div class="hero-copy"><span class="section-kicker">Request \xB7 Prove \xB7 Verify \xB7 Decide</span><h2>Inspect every decision,<br />not just the outcome.</h2><p>Run the three priority fixture journeys: Successful call, Revoked credential and Wrong scope. Inspect each step, its source and the precise cause of any refusal.</p></div>
            <div class="assurance-panel"><div class="assurance-head"><span>Current run</span><strong>{{ isUnavailable ? (connectionState === 'connecting' ? 'Connecting' : 'Unavailable') : (isComplete ? decisionStatus : (isStarted ? 'In progress' : 'Ready')) }}</strong></div><dl><div><dt>Scenario</dt><dd>{{ scenario.scenarioLabel || scenario.label }}</dd></div><div><dt>Run</dt><dd>{{ runState?.runId || (lastSyncedAt ? 'Not started' : 'Awaiting flow status') }}</dd></div><div><dt>Adapter</dt><dd>{{ adapterMode }}</dd></div><div><dt>Transport</dt><dd>{{ transport }}</dd></div></dl></div>
          </section>

          <section v-show="activeView === 'journey'" class="journey-section" aria-labelledby="journey-heading">
            <div class="section-heading"><div><span class="section-kicker">Interactive journey</span><h2 id="journey-heading">The decision path</h2></div></div>
            <div class="scenario-toolbar">
              <label class="scenario-field"><span>Security fixture scenario</span><select :value="selectedScenarioId" @input="selectScenario" @change="selectScenario" :disabled="!canOperate || isStarted || loading" aria-label="Security fixture scenario"><option v-for="item in scenarioOptions" :key="item.id" :value="item.id">{{ item.label }}</option></select></label>
              <label class="scenario-field"><span>Final service scenario</span><select :value="selectedServiceScenario" @input="selectServiceScenario" @change="selectServiceScenario" :disabled="serviceScenarioDisabled" :aria-describedby="!isHttpSampleMode ? 'service-scenario-hint' : null" aria-label="Final service scenario"><option v-for="item in serviceScenarioOptions" :key="item.id" :value="item.id">{{ item.label }}</option></select><small v-if="!isHttpSampleMode" id="service-scenario-hint" class="scenario-hint">Available for Successful call in HTTP sample mode only.</small></label>
              <div class="scenario-copy"><strong>{{ scenario.scenarioLabel || scenario.label }}</strong><p>{{ scenario.summary }}</p><p v-if="isUnavailable && connectionState !== 'connecting'" class="danger-text" role="status">Journey flow unavailable. Results shown are not refreshed and no local outcome is produced.</p><p v-if="errorMessage" class="danger-text" role="alert">{{ errorMessage }}</p></div>
              <div class="journey-actions"><button v-if="isUnavailable && connectionState !== 'connecting'" class="secondary-button" type="button" @click="retryFlow" :disabled="loading">Retry connection</button><button class="secondary-button" type="button" @click="resetJourney" :disabled="!canOperate || !isStarted || loading || isUnavailable">Reset</button><button class="primary-button interactive" type="button" @click="runNext" :disabled="!canOperate || isComplete || isServicePending || loading || isUnavailable" :aria-busy="(loading || isServicePending) ? 'true' : 'false'">{{ runLabel }}</button></div>
            </div>
            <div class="fixture-inputs sample-metadata">
              <span><strong>Participant profile:</strong> {{ profile }}</span>
              <label v-if="selectedScenarioId === 'atlas-wrong-scope'" class="variant-field"><span>Wrong scope variant</span><select v-model="selectedVariant" :disabled="!canOperate || isStarted || loading" aria-label="Wrong scope variant"><option value="rule-deny">rule-deny</option><option value="presentation-required">presentation-required</option></select></label>
              <span v-if="selectedScenarioId === 'atlas-revoked-credential'"><strong>Credential to revoke:</strong> profile's own fixture credential \xB7 status-list bit 42 is seeded revoked</span>
              
            </div>
            <ol class="trust-path interactive-path" :style="{ '--journey-step-count': steps.length || 6 }" aria-label="Zero Trust journey progress">
              <li v-for="(step, index) in steps" :key="step[0]" :class="{ current: activeStep === index + 1, complete: runState?.checks?.[index]?.status === 'Pass', failed: runState?.checks?.[index]?.status === 'Fail', skipped: runState?.checks?.[index]?.status === 'Skipped' }" :aria-current="activeStep === index + 1 ? 'step' : null"><span class="step-index">{{ step[0] }}</span><div><strong>{{ step[1] }}</strong><p>{{ step[2] }}</p></div></li>
            </ol>
            <div class="stage-panel" :class="{ 'terminal-panel': isComplete }" aria-live="polite">
              <div class="stage-index">{{ isComplete ? decisionStatus.slice(0, 1) : String(activeStep || 1).padStart(2, '0') }}</div>
              <div v-if="isComplete" class="final-stage" :class="'outcome-' + scenario.tone">
                <span class="status-pill" :class="statusClass(decisionStatus)">{{ decisionStatus }}</span>
                <h3>{{ scenario.outcome }}</h3>
                <p>{{ scenario.reason }}</p>
                <dl class="terminal-details">
                  <div><dt>Reason code</dt><dd><code>{{ runState.reasonCode }}</code></dd></div>
                  <div><dt>{{ runState.failedCheck ? 'Failed or unavailable check' : 'Final check' }}</dt><dd>{{ runState.failedCheck?.name || 'All sample checks completed' }}</dd></div>
                  <div><dt>Transport</dt><dd>{{ runState.transport }}</dd></div>
                  <div v-if="runState.ruleId"><dt>Rule ID</dt><dd><code>{{ runState.ruleId }}</code></dd></div>
                  <div v-if="runState.presentationLink"><dt>OID4VP link (fixture)</dt><dd><code>{{ runState.presentationLink }}</code></dd></div>
                  <div v-if="runState.notExecuted?.length"><dt>Not executed</dt><dd>{{ runState.notExecuted.join(" \xB7 ") }}</dd></div>
                  <div v-if="runState.serviceRequest"><dt>Request ID</dt><dd><code>{{ runState.serviceRequest.requestId }}</code></dd></div>
                  <div v-if="runState.serviceRequest"><dt>Correlation ID</dt><dd><code>{{ runState.serviceRequest.correlationId }}</code></dd></div>
                  <div v-if="runState.serviceRequest?.respondedAt"><dt>Response observed</dt><dd>{{ runState.serviceRequest.respondedAt }}</dd></div><div v-if="runState.serviceRequest?.httpStatus"><dt>HTTP status</dt><dd>{{ runState.serviceRequest.httpStatus }}</dd></div><div v-if="runState.serviceRequest"><dt>Certificate validation</dt><dd>{{ runState.serviceRequest.tlsVerification }}</dd></div>
                </dl>
              </div>
              <div v-else-if="activeStep === 0"><span class="card-tag">Fixture-only \xB7 Ready</span><h3>Select a priority fixture journey</h3><p>Start evaluates the first step. Continue reveals the remaining stages, including refusal propagation. No live security component is invoked.</p></div>
              <div v-else-if="isServicePending"><span class="card-tag">Participant sample HTTPS pending</span><h3>Waiting for Participant</h3><p>The final resource call is pending. Earlier security results remain fixture-only.</p></div>
              <div v-else><span class="card-tag">Fixture-only \xB7 {{ currentCheck?.source }}</span><h3>{{ currentCheck?.name }}</h3><p>{{ currentCheck?.detail }}</p><span class="status-pill" :class="statusClass(currentCheck?.status)">{{ currentCheck?.status }}</span><p v-if="currentCheck?.reasonCode"><code>{{ currentCheck.reasonCode }}</code></p></div>
            </div>
            <div v-if="isStarted" class="fixture-step-results" aria-label="Fixture step results">
              <div class="section-heading small-heading"><div><span class="section-kicker">Fixture-only</span><h3>Each step's result</h3></div></div>
              <ul class="check-list"><li v-for="check in runState.checks" :key="check.id"><span class="check-marker" :class="statusClass(check.status)"></span><div><strong>{{ check.number }} \xB7 {{ check.name }}</strong><p>{{ check.source }} \xB7 {{ check.kind }} \xB7 {{ check.status === 'Not evaluated' ? 'Not evaluated' : check.detail }}</p><p v-if="check.reasonCode && check.evaluatedAt"><code>{{ check.reasonCode }}</code></p><p v-if="check.ruleId && check.evaluatedAt"><code>{{ check.ruleId }}</code></p></div><span class="status-pill" :class="statusClass(check.status)">{{ check.status }}</span></li></ul>
            </div>
          </section>

          <section v-if="isStarted" v-show="activeView === 'evidence'" class="detail-grid" aria-label="Credential and trust evidence details">
            <article class="data-card"><div class="card-head"><span class="card-tag">Credential</span><span class="status-pill" :class="statusClass(scenario.credential.status)">{{ scenario.credential.status }}</span></div><h3>{{ scenario.credential.type }}</h3><dl><div><dt>Issuer</dt><dd>{{ scenario.credential.issuer }}</dd></div><div><dt>Validity</dt><dd>{{ scenario.credential.validity }}</dd></div><div><dt>Identifier</dt><dd>{{ scenario.credential.id || "\u2014" }}</dd></div></dl></article>
            <article class="data-card"><div class="card-head"><span class="card-tag">Trust zone</span><span class="status-pill" :class="statusClass(scenario.trust.status)">{{ scenario.trust.status }}</span></div><h3>{{ scenario.trust.zone }}</h3><dl><div><dt>Membership</dt><dd>{{ scenario.trust.membershipStatus || 'Not evaluated' }}</dd></div><div><dt>Confidence</dt><dd>{{ showObserved(scenario.trust.confidence) ? scenario.trust.confidence : (scenario.trust.confidence || 'Not evaluated') }}</dd></div><div><dt>Last attestation</dt><dd>{{ showObserved(scenario.trust.attestation) ? scenario.trust.attestation : (scenario.trust.attestation || 'Not evaluated') }}</dd></div></dl></article>
            <article class="data-card"><div class="card-head"><span class="card-tag">Attestation</span><span class="status-pill" :class="statusClass(scenario.attestation.result)">{{ scenario.attestation.result }}</span></div><h3>{{ scenario.attestation.method }}</h3><dl><div><dt>Evidence signature</dt><dd>{{ scenario.attestation.signatureStatus || 'Not evaluated' }}</dd></div><div><dt>Measurement appraisal</dt><dd>{{ scenario.attestation.measurementStatus || 'Not evaluated' }}</dd></div><div><dt>Observed</dt><dd>{{ showObserved(scenario.attestation.timestamp) ? scenario.attestation.timestamp : (scenario.attestation.timestamp || 'Not evaluated') }}</dd></div><div><dt>Freshness</dt><dd>{{ showObserved(scenario.attestation.timestamp) ? '\u2264 60 seconds \xB7 Sample value' : 'Not evaluated' }}</dd></div></dl></article>
            <article class="data-card"><div class="card-head"><span class="card-tag">Fixture connection metadata</span><span class="status-pill" :class="statusClass(scenario.connection.status)">{{ scenario.connection.status }}</span></div><h3>{{ scenario.connection.protocol }}</h3><dl><div><dt>Encryption</dt><dd>{{ scenario.connection.encryption }}</dd></div><div><dt>Endpoint</dt><dd>{{ scenario.connection.endpoint }}</dd></div><div><dt>Observed transport</dt><dd>{{ runState?.transport || 'fixture' }}</dd></div><div><dt>Claim</dt><dd>Fixture information only</dd></div></dl></article>
          </section>

          <section v-if="isStarted" v-show="activeView === 'journey'" class="inspection-grid" aria-label="Policy inspection">
            <article class="inspection-card"><div class="section-heading small-heading"><div><span class="section-kicker">Policy checks</span><h2>Control decisions</h2></div><span class="sample-chip">Sample</span></div><ul class="check-list"><li v-for="check in scenario.checks" :key="check.label"><span class="check-marker" :class="statusClass(check.status)"></span><div><strong>{{ check.label }}</strong><p>{{ check.detail }}</p></div><span class="status-pill" :class="statusClass(check.status)">{{ check.status }}</span></li></ul></article>
            <article class="inspection-card"><div class="section-heading small-heading"><div><span class="section-kicker">Measurements</span><h2>Expected vs observed</h2></div></div><div class="measurement-table" role="table" aria-label="Sample runtime measurements"><div class="measurement-row measurement-header" role="row"><span>Control</span><span>Expected</span><span>Observed</span><span>Result</span></div><div v-for="item in scenario.measurements" :key="item.label" class="measurement-row" role="row"><strong>{{ item.label }}</strong><span>{{ item.expected }}</span><span>{{ item.actual }}</span><span class="status-pill" :class="statusClass(item.status)">{{ item.status }}</span></div></div></article>
          </section>

          <section v-show="activeView === 'configuration'" id="configuration-heading" class="configuration-section" aria-labelledby="configuration-title">
            <div class="section-heading"><div><span class="section-kicker">Demonstrator configuration</span><h2 id="configuration-title">Draft \u2013 Preview Only</h2></div></div>
            <div class="configuration-layout">
              <div class="configuration-grid">
                <div class="config-field"><span>Participant backend</span><p>Participant sample service</p><small>Read-only in this phase</small></div>
                <div class="config-field"><span>Protected resource</span><p>sample-report</p><small>Read-only in this phase</small></div>
                <div class="config-field"><span>DNS</span><p>Not supplied</p><small>Read-only in this phase</small></div>
                <label class="config-field"><span>Change type</span><select style="width:100%;min-height:38px;padding:0 10px;border:1px solid #c7d1de;border-radius:7px;background:#fff;color:inherit" v-model="draftConfig.kind" @change="changeConfigKind" :disabled="!canOperate"><option value="trust-zone">Trust zone</option><option value="policy-ref">Policy reference</option><option value="measurement">Measurement</option><option value="mock-replacement">Mock replacement</option></select></label>
                <label class="config-field"><span>Target</span><select style="width:100%;min-height:38px;padding:0 10px;border:1px solid #c7d1de;border-radius:7px;background:#fff;color:inherit" v-model="draftConfig.target" :disabled="!canOperate" @change="draftPreview = null"><template v-if="draftConfig.kind === 'trust-zone'"><option value="zone-a">zone-a</option><option value="zone-b">zone-b</option></template><template v-else-if="draftConfig.kind === 'policy-ref'"><option value="guard-a">guard-a</option><option value="guard-b">guard-b</option></template><template v-else-if="draftConfig.kind === 'measurement'"><option value="zone-a-gateway">zone-a-gateway</option><option value="zone-b-gateway">zone-b-gateway</option></template><template v-else><option value="participant-backend">participant-backend</option><option value="protected-resource">protected-resource</option></template></select></label>
                <template v-if="draftConfig.kind === 'policy-ref'"><label class="config-field"><span>Policy bundle</span><input v-model="draftConfig.bundle" @input="draftPreview = null" type="text" maxlength="200" :disabled="!canOperate" /></label><label class="config-field"><span>Policy revision</span><input v-model="draftConfig.revision" @input="draftPreview = null" type="text" maxlength="200" :disabled="!canOperate" /></label><p>Registry verification is unavailable. A preview does not confirm that this bundle and revision exist.</p></template>
                <label v-if="draftConfig.kind === 'measurement'" class="config-field"><span>Measurement digest</span><input v-model="draftConfig.digest" @input="draftPreview = null" type="text" placeholder="sha256:&lt;64 hex characters&gt;" maxlength="71" :disabled="!canOperate" /><small>sha256 followed by a colon and 64 hexadecimal characters</small></label>
                <label v-if="draftConfig.kind === 'mock-replacement'" class="config-field"><span>Adapter</span><select style="width:100%;min-height:38px;padding:0 10px;border:1px solid #c7d1de;border-radius:7px;background:#fff;color:inherit" v-model="draftConfig.adapter" @change="draftPreview = null" :disabled="!canOperate"><option value="mock">mock</option><option value="real" disabled>real — awaiting approved API</option></select></label>
              </div>
              <aside class="configuration-safety">
                <span class="card-tag">Local draft control</span>
                <p class="draft-note">Choose an allowed change and preview its payload. Apply requires the approved validation and pull request pipeline.</p>
                <div class="draft-actions"><button class="secondary-button" type="button" @click="previewDraft" :disabled="!canOperate">Preview draft</button><button class="primary-button interactive" type="button" disabled>Apply live</button></div>
                <dl v-if="draftPreview" class="draft-preview" aria-live="polite"><div v-for="(value, key) in draftPreview" :key="key"><dt>{{ key }}</dt><dd>{{ typeof value === 'object' ? JSON.stringify(value) : value || 'Not set' }}</dd></div></dl>
                <label class="sample-toggle"><input v-model="showSampleMetadata" type="checkbox" aria-label="Show sample metadata" /><span><strong>Show sample metadata</strong><small>Displays local run identifiers and source labels. This does not change policy or security behavior.</small></span></label>
                <div id="config-lock-note" class="lock-note"><shell-icon name="lock" /><p><strong>Live apply is unavailable.</strong> Draft editing and preview are local presentation features only. They do not change real services, policy, DNS, infrastructure or Atlas lifecycle controls.</p></div>
              </aside>
            </div>
          </section>

          <section v-show="activeView === 'evidence'" id="evidence-heading" class="evidence-section" aria-labelledby="evidence-title">
            <div class="section-heading"><div><span class="section-kicker">Run evidence</span><h2 id="evidence-title">Messages and decision record</h2></div></div>
            <div class="evidence-grid">
              <article class="message-log"><div v-if="!eventMessages.length" class="empty-state"><strong>No run evidence yet</strong><p>Start the journey to reveal sent and blocked sample messages.</p></div><ol v-else><li v-for="message in eventMessages" :key="message.at + message.text"><time>{{ message.at }}</time><span class="message-direction" :class="statusClass(message.status)">{{ message.direction }}</span><p>{{ message.text }}</p></li></ol></article>
              <aside class="decision-record"><span class="card-tag">Decision record</span><h3>{{ isComplete ? scenario.outcome : (isServicePending ? 'Participant sample HTTPS pending' : 'Decision pending') }}</h3><dl><div><dt>Run ID</dt><dd>{{ runState?.runId || '\u2014' }}</dd></div><div><dt>Adapter</dt><dd>{{ adapterMode }}</dd></div><div><dt>Transport</dt><dd>{{ transport }}</dd></div><div><dt>Security evidence</dt><dd>Fixture-only</dd></div><div v-if="runState?.serviceRequest"><dt>Application response</dt><dd>Participant sample</dd></div><div><dt>Participant profile</dt><dd>{{ profile }}</dd></div><div><dt>Correlation ID</dt><dd>{{ runState?.correlationId || "\u2014" }}</dd></div><div v-if="runState?.variant"><dt>Variant</dt><dd>{{ runState.variant }}</dd></div><div><dt>Security scenario</dt><dd>{{ scenario.scenarioLabel || scenario.label }}</dd></div><div><dt>Service scenario</dt><dd>{{ serviceScenarioEvidence }}</dd></div><div><dt>Evidence artifacts</dt><dd>{{ runState?.evidence?.length || 0 }}</dd></div><div><dt>Live audit storage</dt><dd>Unavailable</dd></div></dl><div v-if="runState?.fixtureResource?.report" class="service-report"><span>Fixture-only resource payload</span><strong>{{ runState.fixtureResource.report.title }}</strong><p>{{ runState.fixtureResource.report.content }}</p><code>{{ runState.fixtureResource.report.id }}</code></div><div v-if="runState?.serviceRequest?.safeData?.report" class="service-report"><span>Participant sample report · Not live authorization</span><strong>{{ runState.serviceRequest.safeData.report.title }}</strong><p>{{ runState.serviceRequest.safeData.report.content }}</p><code>{{ runState.serviceRequest.safeData.report.id }}</code></div><p v-if="isComplete" class="decision-reason">{{ scenario.reason }}</p></aside>
            </div>
          </section>
          </div>
        </main>
        <footer><span>FACIS Zero Trust Demonstrator</span></footer>
      </div>
    </div>
  `
      });
      registerComponent({ tag: "welcome-card", component: WelcomeCard });
    }
  });

  // src/components/index.js
  var require_components = __commonJS({
    "src/components/index.js"() {
      var import_welcome_card = __toESM(require_welcome_card());
    }
  });

  // src/main.js
  var require_main = __commonJS({
    "src/main.js"() {
      init_vue();
      init_registry();
      var import_components = __toESM(require_components());
      var root = document.querySelector("#app");
      if (!root) throw new Error("facis mount element #app is missing from src/index.html");
      var app = createApp({ template: "<welcome-card />" });
      for (const entry of getComponents()) app.component(entry.tag, entry.component);
      app.mount(root);
    }
  });
  require_main();
})();
