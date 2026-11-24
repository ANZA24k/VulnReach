export async function connectWallet(provider) {
  if (!provider?.request) throw Error('No browser wallet found. Install MetaMask or use the Studio workflow.');
  const accounts = await provider.request({ method: 'eth_requestAccounts' });
  if (!Array.isArray(accounts) || !/^0x[0-9a-fA-F]{40}$/.test(accounts[0] || '')) throw Error('The wallet did not return an account.');
  const target = '0xf22f';
  if (String(await provider.request({ method: 'eth_chainId' })).toLowerCase() !== target) {
    try { await provider.request({method:'wallet_switchEthereumChain',params:[{chainId:target}]}); }
    catch (e) {
      if (e.code !== 4902) throw e;
      await provider.request({method:'wallet_addEthereumChain',params:[{chainId:target,chainName:'GenLayer Studionet',nativeCurrency:{name:'GEN',symbol:'GEN',decimals:18},rpcUrls:['https://studio.genlayer.com/api'],blockExplorerUrls:['https://explorer-studio.genlayer.com']}]});
      await provider.request({method:'wallet_switchEthereumChain',params:[{chainId:target}]});
    }
  }
  if (String(await provider.request({method:'eth_chainId'})).toLowerCase() !== target) throw Error('Wallet must be connected to Studionet (61999).');
  return accounts[0];
}
export function transactionState(tx) {
  const status = String(tx.statusName || tx.status || '').toUpperCase();
  const receipts = tx.consensus_data?.leader_receipt || [];
  const failed = tx.result_name === 'FAILURE' || tx.result_name === 'ERROR' || receipts.some(r => ['ERROR','CONTRACT_ERROR'].includes(r.execution_result) || r.result?.status === 'rollback');
  const success = status === 'FINALIZED' && !failed && (tx.result_name === 'SUCCESS' || receipts.some(r => r.execution_result === 'SUCCESS'));
  return {status: status || 'PENDING',success,terminal:success || failed || ['CANCELED','CANCELLED','UNDETERMINED'].includes(status),failed};
}
