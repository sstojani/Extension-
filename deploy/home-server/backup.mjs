import { mkdir, readdir, lstat, copyFile, open, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DatabaseSync, backup } from 'node:sqlite';
process.umask(0o077);
const source=process.env.APP_STATE_DIR;
const destination=join('/backups',new Date().toISOString().replaceAll(':','-')+'-'+process.pid);
await mkdir(destination,{recursive:true,mode:0o700});
async function copy(dir,target) {
  for(const item of await readdir(dir,{withFileTypes:true})) {
    const file=join(dir,item.name), dest=join(target,item.name);
    if(item.isSymbolicLink()) throw new Error('State backup refuses symbolic links');
    if(item.isDirectory()) {await mkdir(dest,{mode:0o700}); await copy(file,dest);}
    else if(item.isFile() && !item.name.endsWith('-wal') && !item.name.endsWith('-shm')) {
      const fd=await open(file,'r'); const header=Buffer.alloc(16); await fd.read(header,0,16,0); await fd.close();
      if(header.toString()==='SQLite format 3\0') {
        const db=new DatabaseSync(file,{readOnly:true});
        try { await backup(db,dest); } finally {db.close();}
      } else await copyFile(file,dest);
    }
  }
}
await copy(source,destination);
await writeFile(join(destination,'BACKUP-COMPLETE.json'),JSON.stringify({created:new Date().toISOString(),source}));
console.log('Pre-start state backup completed:',destination);
