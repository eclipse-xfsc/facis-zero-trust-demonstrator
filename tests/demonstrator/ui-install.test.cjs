const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'../..');
test('installer reproduces all supplied UI assets byte for byte including Vue licence',()=>{
 const flow=JSON.parse(fs.readFileSync(path.join(root,'flows/demonstrator/ui-install.json')));
 const messages=[];
 new Function('node','Buffer',flow.find(n=>n.id==='facis-native-ui-files').func)({send:m=>messages.push(m)},Buffer);
 assert.equal(messages.length,5);
 const names=['index.html','index.css','index.js','vendor/vue.global.js','vendor/LICENSE.vue'];
 for(const [i,m] of messages.entries()){
  assert.equal(m.filename,'/data/uibuilder/facis-demo/src/'+names[i]);
  assert.deepEqual(m.payload,fs.readFileSync(path.join(root,'ui/demonstrator/src',names[i])));
  assert.equal(m.installFiles,5);
 }
 const file=flow.find(n=>n.id==='facis-native-ui-write');assert.equal(file.createDir,true);assert.equal(file.overwriteFile,'true');assert.equal(file.appendNewline,false);
 const html=messages[0].payload.toString();assert.match(html,/src="\.\/vendor\/vue.global.js"/);
});
test('installer reports completion only after all five file-node acknowledgements',()=>{
 const flow=JSON.parse(fs.readFileSync(path.join(root,'flows/demonstrator/ui-install.json')));
 const state=new Map(),statuses=[];
 const fn=new Function('msg','node','context',flow.find(n=>n.id==='facis-native-ui-complete').func);
 for(let i=0;i<5;i++)fn({installId:'test',installFiles:5},{status:s=>statuses.push(s)},{get:k=>state.get(k),set:(k,v)=>state.set(k,v)});
 assert.equal(statuses.filter(s=>s.fill==='green').length,1);assert.equal(statuses[4].text,'All 5 UI files installed');
});
test('standalone identity and installer exports match their combined import',()=>{
 const read=name=>JSON.parse(fs.readFileSync(path.join(root,'flows/demonstrator',name)));
 const combined=read('current-facis-flows.json');
 for(const filename of ['identity_flow.json','ui-install.json'])for(const n of read(filename))assert.deepEqual(combined.find(c=>c.id===n.id),n);
 const engine=combined.find(n=>n.id==='facis-native-identity-engine');assert.equal(engine.initialize,fs.readFileSync(path.join(root,'flows/demonstrator/identity-on-start.js'),'utf8'));
});
