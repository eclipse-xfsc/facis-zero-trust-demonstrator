const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'../..');
test('installer reproduces all supplied UI assets byte for byte including Vue licence',()=>{
 const flow=JSON.parse(fs.readFileSync(path.join(root,'flows/demonstrator/ui-install.json')));
 const messages=[];
 const installer = new Function('msg','node','env','nodeFS',flow.find(n=>n.id==='facis-native-ui-files').func);
 // Model the Linux runtime path while reading the real assets on any test host.
 const stagedRoot = '/release/ui/demonstrator/src';
 installer({}, {send:m=>messages.push(m), status() {}, error:message=>assert.fail(message)},
  {get:()=>stagedRoot}, {readFileSync:name=>{
   assert.ok(name.startsWith(stagedRoot + '/'));
   return fs.readFileSync(path.join(root,'ui/demonstrator/src',name.slice(stagedRoot.length + 1)));
  }});
 const names=['index.html','index.css','index.js','vendor/vue.global.js','vendor/LICENSE.vue','assets/Facis-logo.svg','assets/favicon-32x32.png','assets/favicon-192x192.png','assets/apple-touch-icon-180x180.png'];
 assert.equal(messages.length,names.length);
 for(const [i,m] of messages.entries()){
  assert.equal(m.filename,'/data/uibuilder/facis-demo/src/'+names[i]);
  assert.deepEqual(m.payload,fs.readFileSync(path.join(root,'ui/demonstrator/src',names[i])));
  assert.equal(m.installFiles,names.length);
 }
 const file=flow.find(n=>n.id==='facis-native-ui-write');assert.equal(file.createDir,true);assert.equal(file.overwriteFile,'true');assert.equal(file.appendNewline,false);
 const html=messages[0].payload.toString();assert.match(html,/src="\.\/vendor\/vue.global.js"/);
});
test('installer reports completion only after all nine file-node acknowledgements',()=>{
 const flow=JSON.parse(fs.readFileSync(path.join(root,'flows/demonstrator/ui-install.json')));
 const state=new Map(),statuses=[];
 const fn=new Function('msg','node','context',flow.find(n=>n.id==='facis-native-ui-complete').func);
 for(let i=0;i<9;i++)fn({installId:'test',installFiles:9},{status:s=>statuses.push(s)},{get:k=>state.get(k),set:(k,v)=>state.set(k,v)});
 assert.equal(statuses.filter(s=>s.fill==='green').length,1);assert.equal(statuses[8].text,'All 9 UI files installed');
});
test('standalone identity and installer exports match their combined import',()=>{
 const read=name=>JSON.parse(fs.readFileSync(path.join(root,'flows/demonstrator',name)));
 const combined=read('current-facis-flows.json');
 for(const filename of ['identity_flow.json','ui-install.json'])for(const n of read(filename))assert.deepEqual(combined.find(c=>c.id===n.id),n);
 const engine=combined.find(n=>n.id==='facis-native-identity-engine');assert.equal(engine.initialize,fs.readFileSync(path.join(root,'flows/demonstrator/identity-on-start.js'),'utf8'));
});


test('missing or empty staged assets cannot trigger a partial installation', () => {
 const flow = JSON.parse(fs.readFileSync(path.join(root, 'flows/demonstrator/ui-install.json')));
 const installer = new Function('msg', 'node', 'env', 'nodeFS', flow.find(n => n.id === 'facis-native-ui-files').func);
 for (const mode of ['missing', 'empty', 'oversized']) {
  const writes = [], errors = [];
  const fakeFS = { readFileSync(name) {
   if (name.endsWith('vendor/LICENSE.vue')) {
    if (mode === 'missing') throw new Error('Missing staged licence');
    return Buffer.alloc(mode === 'empty' ? 0 : 2 * 1024 * 1024 + 1);
   }
   return Buffer.from('asset');
  }};
  installer({}, {send: m => writes.push(m), status() {}, error: e => errors.push(e)}, {get: () => '/release/src'}, fakeFS);
  assert.equal(writes.length, 0);
  assert.equal(errors.length, 1);
 }
});

test('installer and flow exports stay reviewable without embedded asset blobs', () => {
 const source = fs.readFileSync(path.join(root, 'flows/demonstrator/ui-installer.js'), 'utf8');
 assert.ok(Buffer.byteLength(source) < 16384, 'Keep installer logic below 16 KiB; use real asset files');
 assert.doesNotMatch(source, /base64/);
 for (const name of ['ui-installer.js', 'ui-install.json', 'current-facis-flows.json', 'identity_flow.json', 'journey_flow.json']) {
  const text = fs.readFileSync(path.join(root, 'flows/demonstrator', name), 'utf8');
  for (const line of text.split('\n')) assert.ok(Buffer.byteLength(line) <= 65536, name + ': line exceeds 64 KiB');
 }
 const flow = JSON.parse(fs.readFileSync(path.join(root, 'flows/demonstrator/ui-install.json')));
 assert.deepEqual(flow.find(n => n.id === 'facis-native-ui-files').libs, [{var: 'nodeFS', module: 'fs'}]);
});
