import sys
import types
import importlib.util
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
import pytest

class UserError(Exception): pass
class Return:
    def __init__(self, value): self.calldata = value
class Decorator:
    def __call__(self, fn): return fn
class Contract:
    def __new__(cls):
        obj = object.__new__(cls)
        obj.cases, obj.receipts = {}, {}
        return obj
class TreeMap:
    def __class_getitem__(cls, args): return dict

state = {'body': '', 'prompt': None, 'calls': 0}
gl = types.SimpleNamespace(Contract=Contract, public=types.SimpleNamespace(write=Decorator(), view=Decorator()), message=types.SimpleNamespace(sender_address='0x'+'1'*40), message_raw={'datetime':'2026-11-24T00:00:00Z'})
def strict(fn):
    a, b = fn(), fn()
    assert a == b
    return a
def run(fn, validator):
    result = fn()
    assert validator(Return(result)), 'Validator disagreed'
    return result
def prompt(*args, **kwargs):
    state['calls'] += 1
    return state['prompt'] if kwargs.get('response_format') == 'json' else json.dumps(state['prompt'])
gl.vm = types.SimpleNamespace(UserError=UserError, Return=Return, run_nondet_unsafe=run)
gl.eq_principle = types.SimpleNamespace(strict_eq=strict)
gl.nondet = types.SimpleNamespace(web=types.SimpleNamespace(get=lambda url: types.SimpleNamespace(status=200,body=state['body'].encode())),exec_prompt=prompt)
module = types.ModuleType('genlayer')
module.gl, module.TreeMap, module.u256 = gl, TreeMap, int
sys.modules['genlayer'] = module
spec = importlib.util.spec_from_file_location('contract',Path(__file__).parents[1]/'contracts/vuln_reach.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

def doc(text): return {'text':text,'source':'submitter-attestation','bytes':len(text.encode()),'sha256':c.sha(text)}
def advisory():
    return {'id':'GHSA-35jh-r3h4-6jhm','modified':'2024-01-01T00:00:00Z','details':'Lodash before 4.17.21 is vulnerable via the template function.','affected':[{'package':{'name':'lodash','ecosystem':'npm'},'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'4.17.21'}]}]}]}
def sample(version='4.17.20'):
    return {'id':'CASE-001','title':'Template review','package':'lodash','dependency_path':'node_modules/lodash','advisory_id':advisory()['id'],'advisory_sha256':c.sha(c.canonical(json.loads(state['body']))),'manifest':doc(json.dumps({'lockfileVersion':3,'packages':{'node_modules/lodash':{'version':version,'resolved':f'https://registry.npmjs.org/lodash/-/lodash-{version}.tgz'}}})),'configuration':doc('The service passes untrusted user input to the lodash template function.')}
@pytest.fixture(autouse=True)
def reset():
    state.update(body=json.dumps(advisory()),prompt={'status':'CONDITIONS_MET','advisory_quote':'vulnerable via the template function','configuration_quote':'passes untrusted user input to the lodash template function'},calls=0)
    gl.message.sender_address='0x'+'1'*40
    gl.message_raw['datetime']='2026-11-24T00:00:00Z'
def created(version='4.17.20'):
    obj=c.VulnReach();obj.create_case(json.dumps(sample(version)));return obj
def locked(version='4.17.20'):
    obj=created(version);obj.lock_case('CASE-001');return obj

@pytest.mark.parametrize('value,expected',[('4.17.20',(4,17,20)),('0.0.0',(0,0,0)),('04.1.0',None),('1.2',None),('1.2.3-beta',None),('v1.2.3',None),('1.2.3+sha',None),(True,None)])
def test_semver(value,expected): assert c.semver(value)==expected
@pytest.mark.parametrize('v,wanted',[('0.0.0','IN_RANGE'),('4.17.20','IN_RANGE'),('4.17.21','OUTSIDE_RANGE'),('5.0.0','OUTSIDE_RANGE'),('4.17.21-beta','UNKNOWN')])
def test_range_boundaries(v,wanted): assert c.version_status(advisory(),'lodash',v)==wanted
@pytest.mark.parametrize('events,version,wanted',[
([{'introduced':'1.0.0'},{'fixed':'2.0.0'},{'introduced':'3.0.0'}],(2,5,0),False),
([{'introduced':'1.0.0'},{'fixed':'2.0.0'},{'introduced':'3.0.0'}],(3,0,0),True),
([{'introduced':'0'},{'last_affected':'1.0.0'}],(1,0,0),True),
([{'introduced':'0'},{'last_affected':'1.0.0'}],(1,0,1),False),
([{'introduced':'0'},{'limit':'2.0.0'}],(2,0,0),None),
([{'fixed':'2.0.0'}],(1,0,0),None),
([{'introduced':'2.0.0'},{'fixed':'1.0.0'}],(1,0,0),None),
([{'introduced':'0'},{'fixed':'2.0.0-beta'}],(1,0,0),None),
([{'introduced':'0'},{'introduced':'1.0.0'}],(1,0,0),None),
([], (1,0,0),None)])
def test_intervals(events,version,wanted): assert c.range_hit(version,events) is wanted

def test_multiple_records_are_union():
    a=advisory();a['affected'].append({'package':{'name':'lodash','ecosystem':'npm'},'ranges':[{'type':'SEMVER','events':[{'introduced':'5.0.0'}]}]})
    assert c.version_status(a,'lodash','5.0.0')=='IN_RANGE'
def test_unsupported_prevents_exclusion():
    a=advisory();a['affected'][0]['ranges'].append({'type':'GIT','events':[]})
    assert c.version_status(a,'lodash','5.0.0')=='UNKNOWN'
def test_withdrawn():
    a=advisory();a['withdrawn']='2024-01-02';assert c.version_status(a,'lodash','4.17.20')=='UNKNOWN'
def test_wrong_package(): assert c.version_status(advisory(),'other','4.17.20')=='UNKNOWN'
def test_only_version_list_not_exhaustive():
    a=advisory();a['affected'][0].pop('ranges');a['affected'][0]['versions']=['4.17.20']
    assert c.version_status(a,'lodash','4.17.20')=='IN_RANGE'
    assert c.version_status(a,'lodash','4.17.21')=='UNKNOWN'

@pytest.mark.parametrize('mutation',[
 lambda x:x['manifest'].update(sha256='0'*64),
 lambda x:x['configuration'].update(bytes=1),
 lambda x:x.update(package='other'),
 lambda x:x.update(advisory_id='../../secret'),
 lambda x:x.update(extra='field'),
 lambda x:x.update(id='bad/id'),
 lambda x:x.update(dependency_path='lodash'),
 lambda x:x.update(advisory_sha256='bad'),
])
def test_invalid_inputs(mutation):
    data=sample();mutation(data)
    with pytest.raises(UserError): c.validate_case(data)
def test_alias_rejected():
    data=sample();lock=json.loads(data['manifest']['text']);lock['packages']['node_modules/lodash']['resolved']='https://registry.npmjs.org/other/-/other-4.17.20.tgz';data['manifest']=doc(json.dumps(lock))
    with pytest.raises(UserError): c.validate_case(data)
def test_duplicate_keys_rejected():
    with pytest.raises(UserError): c.parse('{"a":1,"a":2}')
def test_unicode_binding():
    d=doc('café λ');c.document(d,100);assert d['bytes']>len(d['text'])
def test_no_overwrite():
    obj=created()
    with pytest.raises(UserError):obj.create_case(json.dumps(sample()))
def test_owner_enforced():
    obj=created();gl.message.sender_address='0x'+'2'*40
    with pytest.raises(UserError):obj.lock_case('CASE-001')
def test_snapshot_change_rejected():
    obj=created();data=json.loads(state['body']);data['details']+=' Changed.';state['body']=json.dumps(data)
    with pytest.raises(UserError):obj.lock_case('CASE-001')
def test_cannot_skip_lock():
    obj=created()
    with pytest.raises(UserError):obj.assess('CASE-001')
def test_live_semantic_path_and_independent_validator():
    obj=locked();obj.assess('CASE-001');a=json.loads(obj.get_case('CASE-001'))
    assert a['assessment']['outcome']=='AFFECTED';assert state['calls']==2
@pytest.mark.parametrize('status,expected',[('UNKNOWN','INCONCLUSIVE'),('CONDITION_ABSENT','NOT_AFFECTED')])
def test_other_outcomes(status,expected):
    state['prompt']['status']=status
    if status=='UNKNOWN':state['prompt'].update(advisory_quote='',configuration_quote='')
    obj=locked();obj.assess('CASE-001');assert json.loads(obj.get_case('CASE-001'))['assessment']['outcome']==expected

def test_ungrounded_fails_closed():
    state['prompt']['advisory_quote']='invented quote';obj=locked();obj.assess('CASE-001')
    assert json.loads(obj.get_case('CASE-001'))['assessment']['outcome']=='INCONCLUSIVE'
def test_fixed_version_skips_ai():
    obj=locked('4.17.21');obj.assess('CASE-001')
    assert json.loads(obj.get_case('CASE-001'))['assessment']['outcome']=='NOT_AFFECTED';assert state['calls']==0

def test_full_lifecycle_receipt_chain():
    obj=locked();obj.assess('CASE-001');first=json.loads(obj.get_case('CASE-001'))['assessment_receipt']
    obj.challenge('CASE-001','Recheck the template condition against the entire service scope.')
    assert json.loads(obj.get_case('CASE-001'))['state']=='CHALLENGED'
    with pytest.raises(UserError):obj.finalize('CASE-001')
    obj.assess('CASE-001')
    with pytest.raises(UserError):obj.challenge('CASE-001','Again')
    with pytest.raises(UserError):obj.finalize('CASE-001')
    gl.message_raw['datetime']='2026-11-24T00:05:00Z';obj.finalize('CASE-001')
    assert json.loads(obj.get_case('CASE-001'))['state']=='FINALIZED'
    previous='0'*64
    for i in range(1,int(obj.receipt_count)+1):
        r=json.loads(obj.get_receipt(i));h=r.pop('hash');assert r['previous']==previous;assert c.sha(c.canonical(r))==h;previous=h
    assert previous==obj.head
    assert json.loads(obj.get_receipt(3))['hash']==first
    with pytest.raises(UserError):obj.assess('CASE-001')
def test_expired_challenge():
    obj=locked();obj.assess('CASE-001');gl.message_raw['datetime']='2026-11-24T00:05:00Z'
    with pytest.raises(UserError):obj.challenge('CASE-001','Late challenge')
def test_unknown_case_read(): assert c.VulnReach().get_case('missing')=='{}'

def test_advisory_transport_whitespace_is_irrelevant():
    obj=created();state['body']=json.dumps(json.loads(state['body']),indent=4);obj.lock_case('CASE-001');assert json.loads(obj.get_case('CASE-001'))['state']=='LOCKED'
