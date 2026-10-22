'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const path = require('node:path');
const {extract,redact,score} = require('../website/tool-core.js');

test('IOC candidates deduplicate, reject invalid IPs and filter secrets', () => {
  const found = extract('203.0.113.42 203.0.113.42 999.1.1.1 hxxps://example[.]com/path\napi_key=203.0.113.99\nAuthorization: Bearer 01234567890123456789012345678901');
  assert.deepEqual(found, [{type:'url',value:'https://example.com/path'},{type:'ipv4',value:'203.0.113.42'}]);
});
test('redaction handles nested JSON, credentials, headers and optional PII', () => {
  const result = JSON.parse(redact('{"password":"demo","nested":[{"api_key":"value"}],"contact":"test@example.com"}',true));
  assert.equal(result.password,'[REDACTED:SECRET]');
  assert.equal(result.nested[0].api_key,'[REDACTED:SECRET]');
  assert.equal(result.contact,'[REDACTED:EMAIL]');
  const plain = redact('Authorization: Bearer demo_token\nCookie: a=demo; b=secret\nhttps://user:password@example.com/\n192.168.1.1',true);
  for (const value of ['demo_token','a=demo','b=secret','user:password','192.168.1.1']) assert.ok(!plain.includes(value));
});
test('risk inputs must be known, finite and in range', () => {
  const input = {cvss:'9.8',epss:'0.72',confidence:'0.9',kev:true,exposed:true,sensitive:false};
  assert.equal(score(input).priority,'P0');
  for (const bad of ['', 'NaN', 'Infinity', '-1', '10.1']) assert.throws(() => score({...input,cvss:bad}));
  assert.throws(() => score({...input,kev:null}));
});
test('browser risk calculation agrees with the repository Python CLI formula and thresholds', () => {
  const root = path.resolve(__dirname,'..');
  const cases = [
    {cvss:'9.8',epss:'0.72',confidence:'0.9',kev:true,exposed:true,sensitive:false},
    {cvss:'9.0',epss:'0',confidence:'0.6',kev:true,exposed:true,sensitive:false},
    {cvss:'7.1',epss:'0.005',confidence:'0.9',kev:false,exposed:false,sensitive:true},
    {cvss:'0',epss:'0',confidence:'1',kev:false,exposed:false,sensitive:false},
    {cvss:'9.0',epss:'0',confidence:'0.7',kev:false,exposed:false,sensitive:false},
  ];
  const script = 'import sys,json,importlib.util; s=importlib.util.spec_from_file_location("secops",sys.argv[1]); m=importlib.util.module_from_spec(s); sys.modules["secops"]=m; s.loader.exec_module(m); c=json.loads(sys.argv[2]); v=[m.normalize_finding({"id":"test","title":"synthetic","asset":"example.com","severity":"info","cvss":x["cvss"],"epss":x["epss"],"confidence":x["confidence"],"kev":x["kev"],"internet_exposed":x["exposed"],"data_sensitive":x["sensitive"]},0,"synthetic") for x in c]; print(json.dumps(v))';
  // Only known repository CLI functions run here, with synthetic data and no network.
  const command = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
  const raw = execFileSync(command,['-c',script,path.join(root,'.dsh/skills/cybersecurity-ops/scripts/secops.py'),JSON.stringify(cases)],{encoding:'utf8'});
  const expected = JSON.parse(raw);
  cases.forEach((input,index) => { const actual = score(input); assert.equal(actual.score,expected[index].score); assert.equal(actual.priority,expected[index].priority); });
});
