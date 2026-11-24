// Serialize public reads so mounting the ledger cannot burst through Studionet's
// shared 30-per-minute allowance. Never retry a state-changing transaction here.
export function makeReadQueue({spacing=2200,wait=ms=>new Promise(r=>setTimeout(r,ms)),clock=()=>Date.now()}={}) {
  let tail=Promise.resolve(),last=0;
  return function queue(operation){
    const task=tail.then(async()=>{
      for(let attempt=0;attempt<3;attempt++){
        const delay=last+spacing-clock();if(delay>0)await wait(delay);
        last=clock();
        try{return await operation();}
        catch(e){const message=String(e.details||e.message||e);if(!/rate limit|429|server busy|execution slots/i.test(message)||attempt===2)throw e;
          const retry=e.cause?.data?.retry_after_seconds||e.data?.retry_after_seconds||35;
          await wait(Math.min(65000,Math.max(3000,Number(retry)*1000)));}
      }
    });
    tail=task.catch(()=>{});return task;
  };
}
