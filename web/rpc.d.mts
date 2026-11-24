export function makeReadQueue(options?:{spacing?:number;wait?:(ms:number)=>Promise<void>;clock?:()=>number}):<T>(operation:()=>Promise<T>)=>Promise<T>;
