const auth=context._facisAuth;
if(!auth){msg.statusCode=503;msg.payload={ok:false,error:{code:'IDENTITY_UNAVAILABLE'}};return [msg,null];}
const req=msg.req; const headers={'Cache-Control':'no-store','Pragma':'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'};
let status=200,finished=false; const res={headersSent:false,set(k,v){headers[k]=v;return this;},append(k,v){headers[k]=headers[k]?[].concat(headers[k],v):v;return this;},status(v){status=v;return this;},json(v){this.set('Content-Type','application/json');this.end(JSON.stringify(v));},redirect(s,url){this.set('Location',url);this.status(s);this.end('');},end(v=''){if(finished)return;finished=true;this.headersSent=true;msg.statusCode=status;msg.headers=headers;msg.payload=v;delete msg._facisRoute;node.send([msg,null],false);}};
(async()=>{
 try{
  const route=req.route?.path||req.url.split('?')[0];
  if(['POST'].includes(req.method)){const ct=String(req.headers['content-type']||'').split(';')[0];if(!['application/json','application/x-www-form-urlencoded'].includes(ct))return res.status(415).end();if(Number(req.headers['content-length'])>16384||JSON.stringify(req.body||{}).length>16384)return res.status(413).end();}
  switch(route){
   case '/ztd/oidc/login': await auth.login(req,res);break;
   case '/ztd/oidc/callback': await auth.callbackHandler(req,res);break;
   case '/ztd/api/session': await auth.status(req,res);break;
   case '/ztd/oidc/logout': await auth.logout(req,res);break;
   case '/ztd/oidc/frontchannel-logout': auth.frontchannel(req,res);break;
   case '/ztd/oidc/backchannel-logout': await auth.backchannel(req,res);break;
   case '/ztd/api/journey': await auth.command(req,res,command=>{const nativeResponse=msg.res._res||msg.res;const timer=setTimeout(()=>{if(!nativeResponse.headersSent&&!nativeResponse.writableEnded)res.status(504).json({ok:false,error:{code:'MODULE_TIMEOUT'}});},35000);nativeResponse.once('finish',()=>clearTimeout(timer));nativeResponse.once('close',()=>clearTimeout(timer));command.req=msg.req;command.res=msg.res;node.send([null,command],false);});break;
   default:res.status(404).end();
  }
 }catch{if(!finished)res.status(503).json({ok:false,error:{code:'IDENTITY_UNAVAILABLE'}});}finally{node.done();}
})();return;
