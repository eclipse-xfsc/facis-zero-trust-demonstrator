'use strict';
// Take the Helm-rendered realm, resolve only password placeholders into a private file.
const fs=require('node:fs');
const source=fs.readFileSync(process.argv[2],'utf8');
let raw=source.split('  facis-ztd.json: |-\n')[1]?.split('\n---')[0];
if(!raw) throw new Error('Rendered realm missing');
raw=raw.split('\n').map(line=>line.replace(/^    /,'')).join('\n');
raw=raw.replace(/\$\(env:([A-Z_]+)_JSON\)/g,(_,name)=> {
 const password=process.env[name] || (name.startsWith('DEMO_') ? require('node:crypto').randomBytes(24).toString('hex') : null);
 if(!password) throw new Error('Missing persona credential');
 return JSON.stringify(password);
});
const realm=JSON.parse(raw);
// The chart applies the realm with keycloak-config-cli, whose `userProfile` key the server's own
// import does not read: carry the same profile as the component a stock realm export holds.
realm.components={'org.keycloak.userprofile.UserProfileProvider':[{providerId:'declarative-user-profile',config:{'kc.user.profile.config':[JSON.stringify(realm.userProfile)]}}]};
delete realm.userProfile;
// The public client's production code/PKCE flow is retained; never enable direct grants.
if(realm.clients[0].directAccessGrantsEnabled || realm.clients[0].attributes['pkce.code.challenge.method']!=='S256') throw new Error('Realm flow contract differs');
fs.writeFileSync(process.argv[3],JSON.stringify(realm),{mode:0o600});
