import json,hashlib,pathlib
root=pathlib.Path(__file__).resolve().parents[1]
advisory=json.loads((root/'evidence'/'osv-snapshot.json').read_text())
raw=(root/'evidence'/'osv-snapshot.json').read_text()
def doc(text,source='submitter-attestation'):
    return {'text':text,'source':source,'bytes':len(text.encode()),'sha256':hashlib.sha256(text.encode()).hexdigest()}
for name,version,config in [
('exposed','4.17.20','Synthetic integration fixture; not a production deployment. Complete scope: this service has a single route /render. It passes attacker-controlled template strings to lodash.template and then executes the compiled function on the Node.js server. There are no alternate routes or mitigations. The installed lodash version is exactly 4.17.20.'),
('patched','4.17.21','Synthetic integration fixture; not a production deployment. Complete scope: this service has a single route /render using lodash.template on the Node.js server. The installed lodash version is exactly 4.17.21.'),
('uncertain','4.17.20','Synthetic integration fixture; not a production deployment. The deployment configuration, template usage, and input trust boundaries have not been documented.')]:
    lock={'name':'vulnreach-fixture','lockfileVersion':3,'packages':{'':{'name':'vulnreach-fixture','dependencies':{'lodash':version}},'node_modules/lodash':{'version':version,'resolved':f'https://registry.npmjs.org/lodash/-/lodash-{version}.tgz'}}}
    data={'id':{'exposed':'VR-LODASH-001','patched':'VR-PATCHED-001','uncertain':'VR-UNKNOWN-001'}[name],'title':{'exposed':'Template rendering service','patched':'Patched template service','uncertain':'Undocumented deployment'}[name],'package':'lodash','dependency_path':'node_modules/lodash','advisory_id':advisory['id'],'advisory_sha256':hashlib.sha256(json.dumps(advisory,sort_keys=True,separators=(',', ':'),ensure_ascii=True).encode()).hexdigest(),'manifest':doc(json.dumps(lock,indent=2)),'configuration':doc(config)}
    (root/'fixtures'/f'{name}.json').write_text(json.dumps(data,indent=2)+'\n')
(root/'evidence'/'osv-snapshot.json').write_text(raw)
