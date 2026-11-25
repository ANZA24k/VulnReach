import {canonical} from '../web/canonical.mjs';
import fs from 'node:fs';import crypto from 'node:crypto';
import {createClient} from 'genlayer-js';import{studionet}from'genlayer-js/chains';import{TransactionHashVariant}from'genlayer-js/types';
import{transactionState}from'../web/wallet.mjs';import{makeReadQueue}from'../web/rpc.mjs';
const d=JSON.parse(fs.readFileSync('evidence/deployment.json'));
const client=createClient({chain:studionet});
const queue=makeReadQueue();
const delay=()=>new Promise(r=>setTimeout(r,2300));
const read=async(fn,args=[])=>{await delay();return JSON.parse(await queue(()=>client.readContract({address:d.address,functionName:fn,args,transactionHashVariant:TransactionHashVariant.LATEST_FINAL})))};
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const code=await queue(()=>client.getContractCode(d.address));const remote=typeof code==='string'&&code.startsWith('0x')?Buffer.from(code.slice(2),'hex'):Buffer.from(code);const local=fs.readFileSync('contracts/vuln_reach.py');if(!remote.equals(local))throw Error('Deployed source differs from local source');
const transactions=[];
for(const t of d.transactions){await delay();const tx=await queue(()=>client.getTransaction({hash:t.hash}));const s=transactionState(tx);if(!s.success||tx.leader_only!==false)throw Error('Unverified full-consensus execution: '+t.action+' '+JSON.stringify(s));const summary={...t,status:tx.statusName,result:tx.result_name,leader_only:tx.leader_only,from:tx.from_address,votes:tx.consensus_data?.votes,executions:tx.consensus_data?.leader_receipt?.map(r=>r.execution_result)};transactions.push(summary);fs.writeFileSync('evidence/tx-'+t.action+'.json',JSON.stringify(summary,null,2)+'\n');}
const status=await read('get_status');const receipts=[];let previous='0'.repeat(64);
for(let i=1;i<=status.receipts;i++){const r=await read('get_receipt',[i]);const {hash,...body}=r;if(r.sequence!==i||r.previous!==previous||sha(canonical(body))!==hash)throw Error('Receipt chain invalid at '+i);previous=hash;receipts.push(r)}
if(previous!==status.head)throw Error('Head mismatch');
const records={};for(const id of d.case_ids||['VR-LODASH-001']){const record=await read('get_case',[id]);if(!record.input)throw Error('Missing case '+id);for(const name of ['manifest','configuration']){const doc=record.input[name];if(sha(doc.text)!==doc.sha256||Buffer.byteLength(doc.text)!==doc.bytes)throw Error('Evidence binding mismatch')}records[id]=record;}
const result={verified_at:new Date().toISOString(),chain_id:61999,contract:d.address,source_matches:true,source_sha256:sha(local),receipt_chain_valid:true,receipt_count:receipts.length,transactions,records:Object.fromEntries(Object.entries(records).map(([id,r])=>[id,{state:r.state,outcome:r.assessment?.outcome,range_status:r.range_status,attempts:r.attempts}]))};
fs.writeFileSync('evidence/receipts-live.json',JSON.stringify(receipts,null,2)+'\n');fs.writeFileSync('evidence/records-live.json',JSON.stringify(records,null,2)+'\n');fs.writeFileSync('evidence/verified-live.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
