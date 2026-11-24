import fs from 'node:fs';import{createClient}from'genlayer-js';import{studionet}from'genlayer-js/chains';import{TransactionHashVariant}from'genlayer-js/types';
const c=createClient({chain:studionet}),d=JSON.parse(fs.readFileSync('evidence/deployment.json'));
console.log(await c.readContract({address:d.address,functionName:'get_case',args:['VR-LODASH-001'],transactionHashVariant:TransactionHashVariant.LATEST_FINAL}));
