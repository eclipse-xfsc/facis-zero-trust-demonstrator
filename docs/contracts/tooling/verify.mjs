// Validates the interface contracts in docs/contracts: every JSON Schema compiles, every valid
// fixture passes and every invalid one fails, reason codes used anywhere are registered, and every
// OpenAPI 3.1 document validates against the official OpenAPI 3.1 schema, with all its references
// resolving and every embedded Schema Object compiling as strict JSON Schema 2020-12. (The official
// schema-base variant would check Schema Objects through $dynamicRef, which Ajv 8 does not resolve
// correctly; compiling them directly is the stricter check.)
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import YAML from 'yaml';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const contracts = path.join(root, 'docs/contracts');
const oasDir = path.join(here, 'oas-3.1');

// Schemas outside docs/contracts that are part of the registry (IF-08, delivered before v1).
const extraSchemas = ['docs/lifecycle-result.schema.json'];
const extraOpenAPI = ['docs/lifecycle.openapi.yaml'];
// Documents whose text is scanned for reason codes.
const prose = ['docs/api-docs.md'];

const failures = [];
const fail = (msg) => failures.push(msg);
const readJSON = (file) => JSON.parse(readFileSync(file, 'utf8'));
const rel = (file) => path.relative(root, file);
const escapePointer = (key) => String(key).replace(/~/g, '~0').replace(/\//g, '~1');
const unescapePointer = (seg) => seg.replace(/~1/g, '/').replace(/~0/g, '~');

// Strict mode rejects unknown keywords and formats. Its type and required heuristics are off: they
// flag the conditional (if/then) constraints the contracts rely on.
function newAjv(strict = true) {
  const ajv = new Ajv2020({ strict, strictTypes: false, strictRequired: false, allErrors: true, allowUnionTypes: true });
  addFormats(ajv);
  // The OpenAPI base vocabulary, so embedded Schema Objects compile.
  for (const keyword of ['discriminator', 'example', 'externalDocs', 'xml']) ajv.addKeyword(keyword);
  return ajv;
}

// 1. The vendored OpenAPI schemas are the pinned ones.
for (const line of readFileSync(path.join(oasDir, 'SHA256SUMS'), 'utf8').trim().split('\n')) {
  const [sum, name] = line.split(/\s+/);
  const actual = createHash('sha256').update(readFileSync(path.join(oasDir, name))).digest('hex');
  if (actual !== sum) fail(`oas-3.1/${name}: checksum ${actual}, pinned ${sum}`);
}

// 2. Every schema compiles.
const ajv = newAjv();
const schemaFiles = [
  ...readdirSync(contracts).filter((f) => f.endsWith('.schema.json')).map((f) => path.join(contracts, f)),
  ...extraSchemas.map((f) => path.join(root, f)),
];
const schemas = new Map(); // stem -> { file, id }
for (const file of schemaFiles) {
  const schema = readJSON(file);
  if (file.startsWith(contracts) && !/\/v1\//.test(schema.$id ?? '') && !/\.v1\.schema\.json$/.test(schema.$id ?? '')) {
    fail(`${rel(file)}: $id must carry v1`);
  }
  ajv.addSchema(schema);
  schemas.set(path.basename(file, '.schema.json'), { file, id: schema.$id });
}
// Every $defs member too: Ajv compiles only what the root references.
function defsPointers(node, at = '', out = []) {
  if (Array.isArray(node)) node.forEach((n, i) => defsPointers(n, `${at}/${i}`, out));
  else if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      const here = `${at}/${escapePointer(key)}`;
      if (key === '$defs' && value && typeof value === 'object') {
        for (const name of Object.keys(value)) out.push(`${here}/${escapePointer(name)}`);
      }
      defsPointers(value, here, out);
    }
  }
  return out;
}
for (const [stem, { file, id }] of schemas) {
  try {
    ajv.getSchema(id);
    for (const at of defsPointers(readJSON(file))) ajv.compile({ $ref: `${id}#${at}` });
  } catch (err) {
    fail(`${rel(file)}: does not compile: ${err.message}`);
    schemas.delete(stem);
  }
}

// 3. The reason-code registry.
const registry = readJSON(path.join(contracts, 'reason-codes.json'));
const registered = new Set();
const validateRegistry = ajv.getSchema(schemas.get('reason-codes.v1')?.id);
if (!validateRegistry || !validateRegistry(registry)) {
  fail(`reason-codes.json: ${ajv.errorsText(validateRegistry?.errors)}`);
} else {
  for (const [family, { codes }] of Object.entries(registry.families)) {
    for (const code of Object.keys(codes)) {
      if (!code.startsWith(`${family}-`)) fail(`reason-codes.json: ${code} is not in family ${family}`);
      if (registered.has(code)) fail(`reason-codes.json: ${code} registered twice`);
      registered.add(code);
    }
  }
}
const families = new Set(Object.keys(registry.families ?? {}));
const codePattern = /\b([A-Z]{2,5})-[A-Z0-9]+(?:-[A-Z0-9]+)*\b/g;
function checkCodesInText(text, where) {
  for (const match of text.matchAll(codePattern)) {
    if (families.has(match[1]) && !registered.has(match[0])) fail(`${where}: ${match[0]} is not a registered reason code`);
  }
}
// A reason_code member's value, or the const/enum/default/examples of a reason_code property schema,
// must be registered - in fixtures, OpenAPI examples and schemas alike.
// The codes a reason_code member names: its value, or every string under const, enum, default,
// example or examples anywhere in its schema - through anyOf/oneOf/allOf/not/if/then/else and
// through $ref to this document or a contract schema file.
function namedCodes(node, doc, docKey, out = new Set(), seen = new Set()) {
  if (typeof node === 'string') out.add(node);
  else if (Array.isArray(node)) node.forEach((n) => namedCodes(n, doc, docKey, out, seen));
  else if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      if (['const', 'enum', 'default', 'example', 'examples'].includes(key)) {
        for (const v of [value].flat()) if (typeof v === 'string') out.add(v);
      } else if (key === '$ref' && typeof value === 'string') {
        // Visited targets are keyed by document and pointer: the same relative $ref means different
        // things in different documents.
        const [file, fragment = ''] = value.split('#');
        const targetKey = file === '' ? docKey : file;
        if (seen.has(`${targetKey}#${fragment}`)) continue;
        seen.add(`${targetKey}#${fragment}`);
        const target = file === '' ? doc : existsSync(path.join(contracts, file)) ? readJSON(path.join(contracts, file)) : undefined;
        if (target !== undefined) namedCodes(resolveFragment(target, fragment), target, targetKey, out, seen);
      } else if (typeof value === 'object') {
        namedCodes(value, doc, docKey, out, seen);
      }
    }
  }
  return out;
}
function checkReasonCodeMembers(value, where, root = value) {
  if (Array.isArray(value)) return value.forEach((v) => checkReasonCodeMembers(v, where, root));
  if (value && typeof value === 'object') {
    for (const [key, v] of Object.entries(value)) {
      if (key === 'reason_code') {
        for (const code of namedCodes(v, root, where)) {
          if (!registered.has(code)) fail(`${where}: reason_code ${code} is not registered`);
        }
      }
      checkReasonCodeMembers(v, where, root);
    }
  }
}
for (const [, { file }] of schemas) {
  checkCodesInText(readFileSync(file, 'utf8'), rel(file));
  checkReasonCodeMembers(readJSON(file), rel(file));
}

// 4. Fixtures: fixtures/<schema stem>/{valid,invalid}-*.json.
const fixtureRoot = path.join(contracts, 'fixtures');
const fixtureDirs = new Set(readdirSync(fixtureRoot));
for (const dir of fixtureDirs) if (!schemas.has(dir)) fail(`fixtures/${dir}: no schema with this name`);
let fixtureCount = 0;
for (const [stem, { id }] of schemas) {
  if (stem === 'reason-codes.v1') continue; // validated against the registry itself above
  if (!fixtureDirs.has(stem)) {
    fail(`fixtures/${stem}: missing`);
    continue;
  }
  const validate = ajv.getSchema(id);
  const files = readdirSync(path.join(fixtureRoot, stem));
  for (const kind of ['valid', 'invalid']) {
    if (!files.some((f) => f.startsWith(`${kind}-`))) fail(`fixtures/${stem}: no ${kind} fixture`);
  }
  for (const name of files) {
    const where = `fixtures/${stem}/${name}`;
    if (!/^(valid|invalid)-[a-z0-9-]+\.json$/.test(name)) {
      fail(`${where}: name must be valid-*.json or invalid-*.json`);
      continue;
    }
    fixtureCount++;
    const data = readJSON(path.join(fixtureRoot, stem, name));
    const ok = validate(data);
    if (name.startsWith('valid-')) {
      if (!ok) fail(`${where}: should pass: ${ajv.errorsText(validate.errors)}`);
      checkReasonCodeMembers(data, where);
    } else if (ok) {
      fail(`${where}: should fail but passes`);
    }
  }
}

// 5. OpenAPI documents. The official OpenAPI schema is not written for Ajv's strict mode, and Ajv 8
// resolves its `$dynamicRef: #meta` to the wrong schema. In this (non-base) variant the only `meta`
// anchor is $defs/schema, so the equivalent static $ref is substituted in memory; the file on disk
// stays byte-identical to the pinned one.
const oas = newAjv(false);
oas.addFormat('media-range', true); // an annotation in the OpenAPI schema, not checked
const oasSchema = JSON.parse(
  readFileSync(path.join(oasDir, 'schema_2025-09-15.json'), 'utf8').replaceAll('"$dynamicRef": "#meta"', '"$ref": "#/$defs/schema"'),
);
const validateOAS = oas.compile(oasSchema);

// JSON pointers of the Schema Objects in an OpenAPI document: components.schemas members and every
// `schema` member of a parameter, header or media type. Schema Objects are not descended into.
function schemaPointers(node, at = '', out = []) {
  if (!node || typeof node !== 'object') return out;
  for (const [key, value] of Object.entries(node)) {
    const here = `${at}/${escapePointer(key)}`;
    if (at === '/components/schemas' || key === 'schema') out.push(here);
    else schemaPointers(value, here, out);
  }
  return out;
}

// Resolves a plain JSON pointer exactly (an empty segment is a key, not skipped); undefined if absent.
function resolve(doc, pointer) {
  if (pointer === '') return doc;
  if (!pointer.startsWith('/')) return undefined;
  let node = doc;
  for (const seg of pointer.slice(1).split('/')) {
    const key = unescapePointer(seg);
    if (node === null || typeof node !== 'object' || !Object.hasOwn(node, key)) return undefined;
    node = node[key];
  }
  return node;
}
// A $ref fragment is a URI fragment: percent-decoded first, then a JSON pointer.
function resolveFragment(doc, fragment) {
  let pointer;
  try {
    pointer = decodeURIComponent(fragment);
  } catch {
    return undefined;
  }
  return resolve(doc, pointer);
}

// The component kind a $ref at this position must name, from the keys leading to it.
function expectedKind(keys) {
  const last = keys.at(-1);
  const prev = keys.at(-2);
  if (last === 'requestBody') return 'requestBodies';
  const byParent = { responses: 'responses', parameters: 'parameters', requestBodies: 'requestBodies', headers: 'headers',
    examples: 'examples', links: 'links', callbacks: 'callbacks', paths: 'pathItems', pathItems: 'pathItems',
    securitySchemes: 'securitySchemes' };
  return byParent[prev];
}

// A $ref inside a Schema Object: #/components/schemas/<name> of this document, or a contract schema
// file next to it (optionally with a fragment that resolves).
function checkSchemaRef(value, doc, dir, where) {
  const [file, fragment = ''] = value.split('#');
  if (file === '') {
    const m = /^\/components\/schemas\/([^/]+)$/.exec(fragment);
    if (!m || resolveFragment(doc, fragment) === undefined) fail(`${where}: schema $ref ${value} is not an existing #/components/schemas/* entry`);
  } else if (!/^[a-z0-9.-]+\.schema\.json$/.test(file) || !existsSync(path.join(dir, file))) {
    fail(`${where}: schema $ref ${value} is not an existing contract schema file`);
  } else if (fragment && resolveFragment(readJSON(path.join(dir, file)), fragment) === undefined) {
    fail(`${where}: schema $ref ${value}: fragment does not resolve`);
  }
}
function checkSchemaRefs(node, doc, dir, where) {
  if (Array.isArray(node)) return node.forEach((n) => checkSchemaRefs(n, doc, dir, where));
  if (!node || typeof node !== 'object') return;
  for (const [key, value] of Object.entries(node)) {
    if (key === '$ref' && typeof value === 'string') checkSchemaRef(value, doc, dir, where);
    else if (key === '$defs') fail(`${where}: use components.schemas instead of $defs in an embedded Schema Object`);
    else checkSchemaRefs(value, doc, dir, where);
  }
}

// Walks an OpenAPI document. Outside Schema Objects a $ref must name an existing component of the
// kind its position requires; inside, see checkSchemaRef.
function checkRefs(node, doc, dir, where, keys = []) {
  if (Array.isArray(node)) return node.forEach((n, i) => checkRefs(n, doc, dir, where, [...keys, i]));
  if (!node || typeof node !== 'object') return;
  const inComponentSchemas = keys.length === 3 && keys[0] === 'components' && keys[1] === 'schemas';
  if (keys.at(-1) === 'schema' || inComponentSchemas) return checkSchemaRefs(node, doc, dir, `${where}#/${keys.map(escapePointer).join('/')}`);
  for (const [key, value] of Object.entries(node)) {
    if (key === '$ref') {
      const kind = expectedKind(keys);
      const m = typeof value === 'string' ? /^#\/components\/([A-Za-z]+)\/([^/]+)$/.exec(value) : null;
      const at = `/${keys.map(escapePointer).join('/')}`;
      if (!kind) fail(`${where}: $ref not allowed at ${at}`);
      else if (!m || m[1] !== kind || resolveFragment(doc, value.slice(1)) === undefined) {
        fail(`${where}: $ref ${value} at ${at} must name an existing #/components/${kind}/* entry`);
      } else {
        // Follow the chain to a concrete object; a cycle never reaches one.
        const seen = new Set([value]);
        let target = resolveFragment(doc, value.slice(1));
        while (target && typeof target === 'object' && typeof target.$ref === 'string') {
          const next = /^#\/components\/([A-Za-z]+)\/([^/]+)$/.exec(target.$ref);
          if (seen.has(target.$ref) || !next || next[1] !== kind) {
            fail(`${where}: $ref ${value} at ${at} does not resolve to a ${kind} object (${seen.has(target.$ref) ? 'cycle' : target.$ref})`);
            break;
          }
          seen.add(target.$ref);
          target = resolveFragment(doc, target.$ref.slice(1));
        }
        if (target === undefined) fail(`${where}: $ref ${value} at ${at}: chain ends at a missing entry`);
      }
    } else if (key === 'x-facis-message-schema') {
      checkSchemaRef(String(value), doc, dir, `${where}#/${[...keys, key].map(escapePointer).join('/')}`);
    } else {
      checkRefs(value, doc, dir, where, [...keys, key]);
    }
  }
}
const openapiFiles = [
  ...readdirSync(contracts).filter((f) => f.endsWith('.openapi.yaml')).map((f) => path.join(contracts, f)),
  ...extraOpenAPI.map((f) => path.join(root, f)),
];
for (const file of openapiFiles) {
  const where = rel(file);
  const text = readFileSync(file, 'utf8');
  const parsed = YAML.parseDocument(text, { uniqueKeys: true, prettyErrors: true });
  if (parsed.errors.length > 0) {
    fail(`${where}: ${parsed.errors.map((e) => e.message).join('; ')}`);
    continue;
  }
  const doc = parsed.toJS();
  checkRefs(doc, doc, path.dirname(file), where);
  checkCodesInText(text, where);
  checkReasonCodeMembers(doc, where);
  if (!/^3\.1\./.test(doc.openapi ?? '')) {
    if (file.startsWith(contracts)) fail(`${where}: contracts must be OpenAPI 3.1`);
    continue; // IF-08 predates v1 and is OpenAPI 3.0: parsed and reference-checked only
  }
  if (!validateOAS(doc)) fail(`${where}: not valid OpenAPI 3.1: ${oas.errorsText(validateOAS.errors)}`);
  // Each Schema Object is compiled on its own, with an $id next to the contract schemas so a relative
  // $ref such as if01-event.v1.schema.json resolves to the contract, and #/components/schemas/X
  // rewritten to a companion schema holding the document's components.schemas.
  const docId = `${path.dirname(schemas.get('reason-codes.v1').id)}/${path.basename(file)}`;
  const rewrite = (node) => {
    if (Array.isArray(node)) return node.map(rewrite);
    if (!node || typeof node !== 'object') return node;
    const out = {};
    for (const [key, value] of Object.entries(node)) {
      if (key === '$ref' && typeof value === 'string' && value.startsWith('#')) {
        const m = /^#\/components\/schemas\/([^/]+)$/.exec(value);
        out[key] = m ? `${docId}.components.json#/$defs/${m[1]}` : value; // other forms fail in checkSchemaRef
      } else {
        out[key] = rewrite(value);
      }
    }
    return out;
  };
  ajv.addSchema({ $id: `${docId}.components.json`, $defs: rewrite(doc.components?.schemas ?? {}) });
  schemaPointers(doc).forEach((at, n) => {
    const node = resolve(doc, at);
    if (node === undefined || (typeof node !== 'boolean' && (node === null || typeof node !== 'object'))) {
      fail(`${where}#${at}: Schema Object cannot be retrieved`);
      return;
    }
    try {
      ajv.compile(typeof node === 'boolean' ? node : { ...rewrite(node), $id: `${docId}.${n}.json` });
    } catch (err) {
      fail(`${where}#${at}: Schema Object does not compile: ${err.message}`);
    }
  });
}

for (const file of prose) checkCodesInText(readFileSync(path.join(root, file), 'utf8'), file);

if (failures.length > 0) {
  for (const f of failures) console.error(`FAIL ${f}`);
  console.error(`${failures.length} contract check(s) failed`);
  process.exit(1);
}
console.log(`contracts ok: ${schemas.size} schemas, ${fixtureCount} fixtures, ${openapiFiles.length} OpenAPI documents, ${registered.size} reason codes`);
