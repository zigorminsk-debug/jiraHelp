const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const android = 'helpdesk-apk/assets';
function scripts(file) {
  return [...fs.readFileSync(file, 'utf8').matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)]
    .map(([,attrs,body]) => {
      const src = attrs.match(/src="([^"]+)"/);
      return src ? fs.readFileSync(path.join(path.dirname(file),src[1]), 'utf8') : body;
    });
}
function app() {
  const elements = new Map(), storage = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {value:'', textContent:'', innerHTML:'', style:{},
      classList:{add(){},remove(){}},addEventListener(){}});
    return elements.get(id);
  };
  const ctx = vm.createContext({console:{log(){},error(){}}, URL, location:{protocol:'file:'},
    window:{AndroidBridge:{}}, navigator:{}, setTimeout(){}, setInterval(){},
    localStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    document:{getElementById:element,addEventListener(){}, querySelectorAll:()=>[], querySelector:()=>null}});
  scripts(android+'/index.html').forEach(s=>vm.runInContext(s,ctx));
  return {ctx,storage,element,run:s=>vm.runInContext(s,ctx)};
}
test('all active JavaScript parses; shared safety helpers stay in sync',()=>{
  for(const dir of [android,'helpdesk-app']) {
    scripts(dir+'/index.html').forEach(s=>new vm.Script(s));
    new vm.Script(fs.readFileSync(dir+'/sw.js','utf8'));
    const manifest=JSON.parse(fs.readFileSync(dir+'/manifest.json','utf8'));
    assert.equal(manifest.start_url,'./index.html');
  }
  assert.equal(fs.readFileSync(android+'/safety.js','utf8'),fs.readFileSync('helpdesk-app/safety.js','utf8'));
});
test('server URL accepts HTTPS context paths, rejects HTTP, credentials and malformed values',()=>{
  const {run}=app();
  assert.equal(run("normalizeServerUrl('jira.example.com/jira/')"),'https://jira.example.com/jira');
  for(const value of ['http://jira.example.com','https://user:pass@jira.example.com','https://','javascript:alert(1)'])
    assert.equal(run(`normalizeServerUrl(${JSON.stringify(value)})`),'');
});
test('HTML escaping and inline ID validation defeat markup and handler injection',()=>{
  const {run}=app();
  assert.equal(run(`escapeHtml('<img src=x onerror="alert(1)">')`),'&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
  assert.equal(run(`safeId("HD-1');alert(1)//")`),'');
  assert.equal(run(`normalizePhone("+375');alert(1)//")`),null);
  assert.equal(run(`normalizePhone('8 (029) 123-45-67')`),'+375291234567');
  const card=run(`renderTicketCard({id:"HD-1');alert(1)//", subject:'<img src=x onerror=alert(1)>', priority:'high',status:'open',created:'2026-10-22T12:00'})`);
  assert.ok(!card.includes('<img'));
  assert.ok(!card.includes('alert(1)//'));
});
test('missing native Jira methods do not crash and report unavailable operation',()=>{
  const {run,element}=app();
  assert.doesNotThrow(()=>run('refreshTickets()'));
  assert.match(element('toast').textContent,/не реализован/);
  assert.equal(run("hasNative('fetchTickets')"),false);
});
test('login does not save password or crash when Jira methods are absent',()=>{
  const {run,element,storage}=app();
  element('login-server').value='jira.example.com';
  element('login-username').value='user'; element('login-password').value='secret';
  run('doLogin(); enterApp()');
  assert.ok(!storage.has('csl_hd_password'));
  assert.equal(element('server-name-label').textContent,'Локальный режим');
});
test('logout removes account cache and clears password in memory',()=>{
  const {run,storage}=app();
  storage.set('csl_hd_tickets','secret');storage.set('csl_hd_notifications','secret');
  run("state.password='secret';doLogout()");
  assert.equal(run('state.password'),'');
  assert.ok(!storage.has('csl_hd_tickets'));assert.ok(!storage.has('csl_hd_notifications'));
});
test('old plaintext password is removed without restoring authenticated state',()=>{
  const {run,storage}=app();storage.set('csl_hd_password','old-secret');
  run('loadSaved()');assert.ok(!storage.has('csl_hd_password'));
  assert.equal(run('state.isLoggedIn'),false);
});
test('manifest contains no missing resources/services and disables backup/cleartext',()=>{
  const manifest=fs.readFileSync('helpdesk-apk/AndroidManifest.xml','utf8');
  assert.ok(!manifest.includes('network_security_config'));assert.ok(!manifest.includes('PollJobService'));
  assert.match(manifest,/allowBackup="false"/);assert.match(manifest,/usesCleartextTraffic="false"/);
});
test('comment and assignee markup is escaped in Android detail view',()=>{
  const {run,element}=app();
  run(`state.tickets=[{id:'HD-1',subject:'test',client:'client',description:'text',category:'other',priority:'high',status:'open',assignee:'<img src=x>',created:'today',sla:100,comments:[{author:'<b>author</b>',text:'<img src=x onerror=alert(1)>',time:'now'}]}];renderTicketDetail('HD-1')`);
  assert.ok(!element('dt-info').innerHTML.includes('<img'));
  assert.ok(!element('dt-comments').innerHTML.includes('<img'));
  assert.ok(element('dt-comments').innerHTML.includes('&lt;img'));
});
test('different local account does not inherit previous account tickets',()=>{
  const {run,element,storage}=app();
  storage.set('csl_hd_server','https://jira.example.com');storage.set('csl_hd_username','old-user');
  run("state.tickets=[{id:'HD-1'}];state.notifications=[{title:'secret'}]");
  element('login-server').value='jira.example.com';element('login-username').value='new-user';
  run('doLogin()');assert.equal(run('state.tickets.length'),0);assert.equal(run('state.notifications.length'),0);
});
test('logout clears hidden detail view, credentials and comment draft',()=>{
  const {run,element}=app();
  element('dt-desc').textContent='private description';element('set-password').value='secret';
  element('cm-input').value='private draft';
  run("state.currentTicketId='HD-1';doLogout()");
  assert.equal(element('dt-desc').textContent,'');assert.equal(element('set-password').value,'');
  assert.equal(element('cm-input').value,'');assert.equal(run('state.currentTicketId'),null);
});
