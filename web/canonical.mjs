// Matches the contract's sorted, compact, ASCII-escaped JSON for OSV snapshots.
const compare=(a,b)=>{const x=Array.from(a,c=>c.codePointAt(0)),y=Array.from(b,c=>c.codePointAt(0));for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]-y[i];return x.length-y.length};
const ordered=v=>Array.isArray(v)?v.map(ordered):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort(compare).map(k=>[k,ordered(v[k])])):v;
export function canonical(value){return Array.from(JSON.stringify(ordered(value)),c=>c.charCodeAt(0)<127?c:c.split('').map(unit=>String.fromCharCode(92)+'u'+unit.charCodeAt(0).toString(16).padStart(4,'0')).join('')).join('')}
