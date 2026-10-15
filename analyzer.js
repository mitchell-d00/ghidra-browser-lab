/* Browser byte analysis is deliberately a limited inspector, not Ghidra decompilation. */
(function(root){'use strict';
 const REG32=['eax','ecx','edx','ebx','esp','ebp','esi','edi'];
 const fmt = (n,w=2) => '0x'+(Number(n)>>>0).toString(16).padStart(w,'0');
 const signed8=x=>x>127?x-256:x;
 const dv32=(b,i)=> (i+3<b.length)?((b[i]|(b[i+1]<<8)|(b[i+2]<<16)|(b[i+3]<<24))>>>0):0;
 function readASCII(b,p,n){return Array.from(b.subarray(p,p+n)).map(x=>String.fromCharCode(x)).join('')}
 function info(bytes){
   const b=bytes, r={format:'Raw binary',architecture:'Unknown',entry:0,details:'Raw bytes (no executable header)'};
   if(b.length>=64&&readASCII(b,0,4)==='\x7fELF'){
     const bit=b[4]===2?64:32,le=b[5]===1;
     r.format='ELF';r.architecture=le&&b[18]===62&&b[19]===0?'x86-64':le&&b[18]===3&&b[19]===0?'x86':`machine ${b[18]||0}`;
     if(le){let phoff=bit===64?Number(BigInt(dv32(b,32))+(BigInt(dv32(b,36))<<32n)):dv32(b,28);
       const entry=bit===64?Number(BigInt(dv32(b,24))+(BigInt(dv32(b,28))<<32n)):dv32(b,24);
       const pentsize=bit===64?(b[54]|b[55]<<8):(b[42]|b[43]<<8),pcnt=bit===64?(b[56]|b[57]<<8):(b[44]|b[45]<<8);
       if(phoff<b.length&&pentsize>=32){for(let i=0;i<Math.min(pcnt,128);i++){
         const p=phoff+i*pentsize;if(p+pentsize>b.length)break;
         if(dv32(b,p)!==1)continue;
         const offset=bit===64?Number(BigInt(dv32(b,p+8))+(BigInt(dv32(b,p+12))<<32n)):dv32(b,p+4);
         const vaddr=bit===64?Number(BigInt(dv32(b,p+16))+(BigInt(dv32(b,p+20))<<32n)):dv32(b,p+8);
         const mem=bit===64?Number(BigInt(dv32(b,p+40))+(BigInt(dv32(b,p+44))<<32n)):dv32(b,p+20);
         if(entry>=vaddr&&entry<vaddr+mem&&offset+entry-vaddr<b.length){r.entry=Math.floor(offset+entry-vaddr);break}
       }}
     }
     r.details=`${bit}-bit ${le?'little':'big'}-endian ELF`;return r;
   }
   if(b.length>=128&&readASCII(b,0,2)==='MZ'){
     r.format='PE';const pe=dv32(b,0x3c);
     if(pe+0x28<b.length&&readASCII(b,pe,4)==='PE\x00\x00'){
       const machine=b[pe+4]|b[pe+5]<<8;r.architecture=machine===0x8664?'x86-64':machine===0x14c?'x86':`machine ${fmt(machine,4)}`;
       const nsec=b[pe+6]|b[pe+7]<<8, optsize=b[pe+20]|b[pe+21]<<8,entryRVA=dv32(b,pe+40);
       const secstart=pe+24+optsize;
       for(let i=0;i<Math.min(nsec,96);i++){
         const p=secstart+40*i;if(p+40>b.length)break;
         const vsize=dv32(b,p+8),vaddr=dv32(b,p+12),rawsize=dv32(b,p+16),rawptr=dv32(b,p+20);
         if(entryRVA>=vaddr&&entryRVA<vaddr+Math.max(vsize,rawsize)&&rawptr+entryRVA-vaddr<b.length){r.entry=rawptr+entryRVA-vaddr;break}
       }
       r.details=`Windows PE, entry RVA ${fmt(entryRVA,8)}`;
     }return r;
   }
   if(b.length>=4&&['cffaedfe','cefaedfe','feedfacf','feedface','cafebabe'].includes(Array.from(b.subarray(0,4)).map(x=>x.toString(16).padStart(2,'0')).join(''))){r.format='Mach-O / Fat';r.details='Mach-O header; entry mapping is not implemented';}
   return r;
 }
 function strings(b,min=4,limit=200){const out=[];let from=-1;for(let i=0;i<=b.length;i++){
   const ok=i<b.length&&b[i]>=32&&b[i]<=126;
   if(ok&&from<0)from=i;
   if((!ok||i===b.length)&&from>=0){if(i-from>=min)out.push({offset:from,text:readASCII(b,from,Math.min(i-from,140))});from=-1;if(out.length>=limit)break;}
 }return out}
 function decode(bytes,start=0,count=100){const b=bytes, out=[];let p=Math.max(0,Math.min(bytes.length,Math.floor(start)));
   const add=(len,mn,op='',target=null)=>{len=Math.max(1,Math.min(len,b.length-p));out.push({offset:p,len,hex:Array.from(b.subarray(p,p+len)).map(x=>x.toString(16).padStart(2,'0')).join(' '),mnemonic:mn,operands:op,target});p+=len};
   while(p<b.length&&out.length<count){const a=b[p],c=b[p+1],d=b[p+2],e=b[p+3],f=b[p+4];const has=(n)=>p+n<=b.length;
     if(a===0x55){add(1,'push','rbp');continue}if(a===0x5d){add(1,'pop','rbp');continue}if(a===0xc3){add(1,'ret');continue}if(a===0x90){add(1,'nop');continue}
     if(a===0xcc){add(1,'int3');continue}if(a===0x48&&c===0x89&&d===0xe5&&has(3)){add(3,'mov','rbp, rsp');continue}
     if(a===0x48&&c===0x83&&d===0xec&&has(4)){add(4,'sub','rsp, '+fmt(e));continue}
     if(a===0x48&&c===0x83&&d===0xc4&&has(4)){add(4,'add','rsp, '+fmt(e));continue}
     if(a===0x89&&c===0x7d&&has(3)){add(3,'mov',`dword [rbp${signed8(d)<0?'':'+'}${signed8(d)}], edi`);continue}
     if(a===0x83&&c===0x7d&&has(4)){add(4,'cmp',`dword [rbp${signed8(d)<0?'':'+'}${signed8(d)}], ${fmt(e)}`);continue}
     if(a===0x83&&(c===0xff||c===0xf8)&&has(3)){add(3,'cmp',`${c===0xff?'edi':'eax'}, ${fmt(d)}`);continue}
     if(a===0x81&&c===0xff&&has(6)){add(6,'cmp',`edi, ${fmt(dv32(b,p+2),8)}`);continue}
     if(a===0x3d&&has(5)){add(5,'cmp',`eax, ${fmt(dv32(b,p+1),8)}`);continue}
     if(a===0x85&&c===0xc0&&has(2)){add(2,'test','eax, eax');continue}
     if(a===0x31&&c===0xc0&&has(2)){add(2,'xor','eax, eax');continue}
     if(a===0x01&&c===0xd8&&has(2)){add(2,'add','eax, ebx');continue}
     if(a===0x83&&c===0xc0&&has(3)){add(3,'add',`eax, ${fmt(d)}`);continue}
     if(a>=0xb8&&a<=0xbf&&has(5)){add(5,'mov',`${REG32[a-0xb8]}, ${fmt(dv32(b,p+1),8)}`);continue}
     if((a===0x75||a===0x74||a===0xeb||a===0x7f||a===0x7c)&&has(2)){const target=p+2+signed8(c);add(2,({117:'jne',116:'je',235:'jmp',127:'jg',124:'jl'})[a],fmt(target,4),target);continue}
     if(a===0x0f&&(c===0x85||c===0x84)&&has(6)){const rel=dv32(b,p+2)|0,target=p+6+rel;add(6,c===0x85?'jne':'je',fmt(target,4),target);continue}
     if((a===0xe8||a===0xe9)&&has(5)){const rel=dv32(b,p+1)|0,target=p+5+rel;add(5,a===0xe8?'call':'jmp',fmt(target,4),target);continue}
     if(a===0x48&&c===0x8d&&d===0x05&&has(7)){const rel=dv32(b,p+3)|0;add(7,'lea',`rax, [rip${rel<0?'':'+'}${rel}]`,p+7+rel);continue}
     if(a===0x48&&c===0x89&&d===0xc7&&has(3)){add(3,'mov','rdi, rax');continue}
     if(a===0x48&&c===0x31&&d===0xc0&&has(3)){add(3,'xor','rax, rax');continue}
     add(1,'db',fmt(a));
   }return out;
 }
 function pseudo(instructions){const ins=instructions;let lines=['// Lightweight browser interpretation (not Ghidra)'];
  let cmp=ins.find(x=>x.mnemonic==='cmp');let branch=ins.find(x=>['je','jne'].includes(x.mnemonic));
  if(cmp&&branch){const p=cmp.operands.split(',').pop().trim();lines.push('int check(int input) {');lines.push(`  // compare input against ${p}`);lines.push(`  if (input ${branch.mnemonic==='jne'?'!=':'=='} ${p}) goto loc_${branch.operands.slice(2)};`);lines.push('  // Follow the highlighted branches below for return values.');lines.push('}');}
  else if(ins.length){lines.push('void entry() {');ins.slice(0,16).filter(x=>x.mnemonic!=='db').forEach(i=>lines.push(`  // ${fmt(i.offset,4)}  ${i.mnemonic} ${i.operands}`));lines.push('}');}
  else lines.push('// No bytes selected');return lines.join('\n');
 }
 function hexdump(b,around=0){const start=Math.max(0,Math.floor(around/16)*16-64),end=Math.min(b.length,start+512),rows=[];for(let p=start;p<end;p+=16){let data=Array.from(b.subarray(p,Math.min(p+16,b.length)));rows.push({offset:p,bytes:data,ascii:data.map(x=>x>=32&&x<=126?String.fromCharCode(x):'.').join('')})}return rows}
 const challenges=[
  {id:'vault',name:'The Vault',tier:'01',type:'Crack the comparison',desc:'Locate the immediate value that opens the vault. Enter it in decimal or hexadecimal.',goal:'What number passes the vault check?',answer:'0x2a',points:100,bytes:'55 48 89 e5 89 7d fc 83 7d fc 2a 75 07 b8 01 00 00 00 5d c3 31 c0 5d c3',hint:'Find CMP and read the value on its right.'},
  {id:'signal',name:'Signal Gate',tier:'02',type:'Decode a hex constant',desc:'The access check contains a 32-bit magic constant. Decode the comparison and recover it.',goal:'What hexadecimal constant is compared with EDI?',answer:'0x1337',points:150,bytes:'55 48 89 e5 81 ff 37 13 00 00 0f 85 06 00 00 00 b8 01 00 00 00 c3 31 c0 c3',hint:'Look for the CMP EDI instruction and inspect its operand.'},
  {id:'patch',name:'Branch Flip',tier:'03',type:'Patch the byte',desc:'Change the conditional jump opcode at offset 0x03 from JNE into JE, then verify your patch.',goal:'Edit offset 0x03 from 75 to 74.',answer:'patch',points:200,bytes:'83 ff 07 75 06 b8 01 00 00 00 c3 31 c0 c3',hint:'Choose address 0x0003 in the hex panel; set the byte to 74.'},
  {id:'strings',name:'Hidden Marker',tier:'04',type:'Read the strings',desc:'An analyst left a plaintext maintenance key after the code. Find it in the Strings tab.',goal:'What is the value of MAINT_KEY?',answer:'ORBIT',points:125,bytes:'31 c0 c3 00 41 43 43 45 53 53 5f 47 52 41 4e 54 00 4d 41 49 4e 54 5f 4b 45 59 3d 4f 52 42 49 54 00',hint:'Check Strings. The value appears after MAINT_KEY=.'}
 ];
 const parseHex=s=>new Uint8Array((s.match(/[\da-fA-F]{2}/g)||[]).map(x=>parseInt(x,16)));
 const validate=(challenge,answer,b)=>{
  if(challenge.answer==='patch')return b.length>3&&b[3]===0x74;
  if(challenge.id==='strings')return answer.trim().toUpperCase()==='ORBIT';
  const n=/^0x[\da-f]+$/i.test(answer.trim())?parseInt(answer,16):/^\d+$/.test(answer.trim())?parseInt(answer,10):NaN;
  return n===parseInt(challenge.answer,16)
 };
 const api={fmt,info,strings,decode,pseudo,hexdump,challenges,parseHex,validate};
 if(typeof module==='object'&&module.exports)module.exports=api;root.GhidraLensCore=api;
})(typeof globalThis!=='undefined'?globalThis:this);
