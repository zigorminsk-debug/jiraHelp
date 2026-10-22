const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
function publish(mode='ok') {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'helpdesk-publish-'));
  try {
    for (const dir of ['scripts','build/android','bin']) fs.mkdirSync(path.join(root,dir),{recursive:true});
    fs.copyFileSync('scripts/publish-apk.sh',path.join(root,'scripts/publish-apk.sh'));
    fs.writeFileSync(path.join(root,'build/android/CSL-HelpDesk-debug.apk'),'fake APK fixture, not installable');
    fs.writeFileSync(path.join(root,'build/android/signature.txt'),'fixture');
    fs.writeFileSync(path.join(root,'bin/gh'),`#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == 'release create' ]]; then
  [[ "$MODE" != 'denied' ]] || exit 1
  printf '%s\\n' "$@" > create-args
elif [[ "$1 $2" == 'release download' ]]; then
  cp build/android/{CSL-HelpDesk-debug.apk,SHA256SUMS} build/android/download-check/
  if [[ "$MODE" == 'corrupt' ]]; then echo broken >> build/android/download-check/CSL-HelpDesk-debug.apk; fi
else exit 2
fi
`,{mode:0o755});
    const r=spawnSync('bash',['scripts/publish-apk.sh'],{cwd:root,encoding:'utf8',env:{...process.env,
      PATH:path.join(root,'bin')+':'+process.env.PATH,MODE:mode,GH_REPO:'owner/repo',
      GITHUB_SHA:'abc123',GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'2',GITHUB_STEP_SUMMARY:path.join(root,'summary')}});
    return {status:r.status,stdout:r.stdout,stderr:r.stderr,
      summary:fs.existsSync(path.join(root,'summary'))?fs.readFileSync(path.join(root,'summary'),'utf8'):'',
      args:fs.existsSync(path.join(root,'create-args'))?fs.readFileSync(path.join(root,'create-args'),'utf8'):''};
  } finally {fs.rmSync(root,{recursive:true,force:true});}
}
test('publication requires matching downloaded bytes and links unique prerelease',()=>{
  const r=publish();assert.equal(r.status,0,r.stderr);
  assert.match(r.args,/apk-123-2/);assert.match(r.args,/--prerelease/);assert.match(r.args,/--latest=false/);
  assert.match(r.summary,/releases\/download\/apk-123-2\/CSL-HelpDesk-debug.apk/);
});
test('corrupted release download fails without claiming APK ready',()=>{
  const r=publish('corrupt');assert.notEqual(r.status,0);assert.equal(r.summary,'');
});
test('release API denial fails without claiming APK ready',()=>{
  const r=publish('denied');assert.notEqual(r.status,0);assert.equal(r.summary,'');
});
