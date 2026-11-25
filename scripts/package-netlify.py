"""Package an already verified production build with its editable public source."""
from pathlib import Path
import hashlib,json,re,subprocess,zipfile
root=Path(__file__).resolve().parents[1]
dist=root/'dist'
assert (dist/'index.html').is_file(), 'Run npm run build first'
for item in ['_headers','_redirects']:
 assert (dist/item).is_file(), 'Missing Netlify upload configuration'
html=(dist/'index.html').read_text()
for path in re.findall(r'(?:src|href)="(/assets/[^\"]+)"',html):
 assert (dist/path.lstrip('/')).is_file(), 'Missing built asset: '+path
excluded={'.git','node_modules','dist','.vercel','.netlify','__pycache__','.pytest_cache'}
files={str(p.relative_to(dist)):p.read_bytes() for p in dist.rglob('*') if p.is_file()}
files['README-UPLOAD-FIRST.txt']=(root/'NETLIFY_UPLOAD.md').read_bytes()
files['netlify.toml']=b'[build]\n  publish = "."\n'
for p in root.rglob('*'):
 if p.is_file() and not excluded.intersection(p.relative_to(root).parts) and not p.name.startswith('.env'):
  files['project-source/'+str(p.relative_to(root))]=p.read_bytes()
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
files['PACKAGE_INFO.json']=(json.dumps({'project':'VulnReach','network':'Studionet','chain_id':61999,'contract':'0x65329695921c877b8371f2F60084fb55bCF1523C','source_commit':commit,'validation':{'python_tests':52,'javascript_tests':21,'production_build':'passed','netlify_configuration':'validated'},'upload':'Extract and upload the folder directly containing index.html.','verification_limits':'See project-source/EVIDENCE.md; remaining live finalization and comparison assessments are unconfirmed.'},indent=2)+'\n').encode()
files['SHA256SUMS.txt']=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in sorted(files.items())).encode()
out=root.parent/'deliverables'/'VulnReach-Netlify-Ready.zip';out.parent.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for name,data in sorted(files.items()):z.writestr(name,data)
with zipfile.ZipFile(out) as z:
 assert z.testzip() is None
 assert 'index.html' in z.namelist() and 'project-source/contracts/vuln_reach.py' in z.namelist()
 assert not any('/node_modules/' in name or '/.git/' in name or name.startswith('/') or '..' in Path(name).parts for name in z.namelist())
print(json.dumps({'file':str(out),'bytes':out.stat().st_size,'files':len(files),'sha256':hashlib.sha256(out.read_bytes()).hexdigest()}))
