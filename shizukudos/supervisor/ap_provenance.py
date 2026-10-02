# SPDX-License-Identifier: GPL-2.0-only
"""Pre-consumption source/include/tool pins for bounded AP component commands."""
import hashlib,json,re,shlex,shutil,subprocess
from pathlib import Path

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

class CommandGuard:
    def __init__(self,out):
        self.out=Path(out);self.out.mkdir(parents=True,exist_ok=True)
        self.events=[];self.tool_pins={};self.dependency_groups=[];self.dependency_pins={};self.retained_paths={}

    def retain_temporary(self,path,value):
        if not str(path).startswith('/tmp/'):return
        # selfcheck intentionally removes its own temporary C/probe files.
        # Keep exactly those consumed bytes, captured before execution.
        target=self.out/'temporary-inputs'/value
        target.parent.mkdir(exist_ok=True)
        data=Path(path).read_bytes();assert hashlib.sha256(data).hexdigest()==value
        if not target.exists():target.write_bytes(data)
        assert digest(target)==value
        self.retained_paths[str(path)]={'path':str(target.resolve()),'sha256':value}

    def stable(self,path,value):
        if Path(path).exists():return digest(path)==value
        retained=self.retained_paths.get(path)
        return retained and retained['sha256']==value and digest(retained['path'])==value

    def pin(self,path):
        path=str(Path(path).resolve());value=digest(path)
        if path in self.tool_pins:assert self.tool_pins[path]==value,'tool changed: '+path
        self.tool_pins[path]=value
        self.retain_temporary(path,value)
        return path,value

    def tools(self,command):
        driver=shutil.which(str(command[0])) or str(command[0])
        paths=[driver,shutil.which('strace')]
        assert all(paths),'strace and actual command driver required'
        self.pin(driver)  # before driver discovery queries
        gcc=Path(driver).name in ('gcc','x86_64-w64-mingw32-gcc')
        clang=Path(driver).name.startswith('clang')
        if gcc or clang:
            names=('cc1','as','collect2','ld','lto-wrapper','liblto_plugin.so') if gcc else ('as','ld')
            for name in names:
                result=subprocess.run([driver,'-print-prog-name='+name],check=True,capture_output=True,text=True)
                assert digest(Path(driver).resolve())==self.tool_pins[str(Path(driver).resolve())]
                answer=result.stdout.strip()
                path=answer if '/' in answer else shutil.which(answer)
                assert path and Path(path).is_file(),'missing selected compiler subtool '+name
                paths.append(path)
        return {p:h for p,h in (self.pin(path) for path in paths)}

    def writes(self,command):
        name=Path(command[0]).name;paths=[]
        for i,value in enumerate(command[:-1]):
            if value=='-o' or (name=='nasm' and value=='-l'):paths.append(command[i+1])
        if name=='objcopy':paths.append(command[-1])
        if name in ('mkfs.vfat','qemu-io') or (name=='qemu-img' and 'create' in command):paths.append(command[-1])
        if name in ('mcopy','mmd') and '-i' in command:paths.append(command[command.index('-i')+1])
        return {str(Path(p).resolve()) for p in paths}

    def inputs(self,command,tools,writes):
        pins={};groups=[]
        # Includes newly generated images/trampoline headers before their
        # first C object consumer. -M uses the same preprocessing flags.
        units=[x for x in command if str(x).endswith('.c')]
        if units and (Path(command[0]).name in ('gcc','x86_64-w64-mingw32-gcc') or Path(command[0]).name.startswith('clang')):
            prefix=command[1:command.index(units[0])]
            prefix=[str(x) for x in prefix if x not in ('-c','-nostdlib') and not str(x).startswith('-Wl,')]
            for unit in units:
                cmd=[str(command[0]),*prefix,'-M','-MT','unit',str(unit)]
                # The driver/subtools are pinned before this discovery, too.
                assert all(digest(p)==h for p,h in tools.items())
                result=subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=30)
                assert all(digest(p)==h for p,h in tools.items())
                paths=shlex.split(result.stdout.replace('\\\n',' ').split(':',1)[1])
                group={str(Path(p).resolve()):digest(p) for p in paths}
                pins.update(group);groups.append({'source':str(unit),'command':cmd,'dependencies_pre':group})
        for value in command[1:]:
            p=Path(str(value))
            if p.is_file() and str(p.resolve()) not in writes:pins[str(p.resolve())]=digest(p)
        if Path(command[0]).name=='qemu-io':
            for i,value in enumerate(command[:-1]):
                if value!='-c':continue
                words=shlex.split(command[i+1])
                if '-s' in words:
                    p=Path(words[words.index('-s')+1]).resolve();pins[str(p)]=digest(p)
        for path,value in pins.items():self.retain_temporary(path,value)
        return pins,groups

    def _execute(self,command,**kwargs):return subprocess.run(command,**kwargs)

    def run(self,command,**kwargs):
        command=[str(x) for x in command]
        # Preserve multicall argv0 (mtype/mcopy); pin resolved bytes separately.
        command[0]=shutil.which(command[0]) or command[0]
        tools=self.tools(command);writes=self.writes(command);inputs,groups=self.inputs(command,tools,writes)
        number=len(self.events);stem=self.out/f'{number:03d}'
        trace=Path(str(stem)+'-execve.log')
        event={'command':command,'tools_pre':tools,'inputs_pre':inputs,
               'dependency_groups_pre':groups,'declared_writes':sorted(writes),
               'retained_temporary_inputs':dict(self.retained_paths),
               'write_pre':{p:digest(p) if Path(p).exists() else None for p in writes},'pass':False}
        Path(str(stem)+'-pre.json').write_text(json.dumps(event,indent=2)+'\n')
        self.events.append(event)
        # Verify pins immediately before the actual command, not only when
        # the final producer receipt is assembled.
        assert all(digest(p)==h for p,h in tools.items())
        assert all(digest(p)==h for p,h in inputs.items())
        traced=[shutil.which('strace'),'-f','-qq','-e','trace=execve','-o',str(trace),'--',*command]
        try:
            result=self._execute(traced,**kwargs)
            event['returncode']=result.returncode
        finally:
            event['inputs_post_equal']=all(Path(p).exists() and digest(p)==h for p,h in inputs.items())
            event['tools_post_equal']=all(Path(p).exists() and digest(p)==h for p,h in tools.items())
            event['write_post']={p:digest(p) if Path(p).exists() else None for p in writes}
            actual=[]
            if trace.exists():
                for line in trace.read_text().splitlines():
                    m=re.search(r'execve\("([^"]+)".*= 0$',line)
                    if m:actual.append(str(Path(m.group(1)).resolve()))
            event['executed_subprograms']=sorted(set(actual))
            event['all_executed_tools_pinned_pre']=bool(actual) and all(p in tools for p in actual)
            event['pass']=event.get('returncode')==0 and event['inputs_post_equal'] and event['tools_post_equal'] and event['all_executed_tools_pinned_pre']
            Path(str(stem)+'-post.json').write_text(json.dumps(event,indent=2)+'\n')
        assert event['inputs_post_equal'],'consumed input changed'
        assert event['tools_post_equal'] and event['all_executed_tools_pinned_pre'],'unbound consumed tool'
        self.dependency_groups+=groups;self.dependency_pins.update({p:h for group in groups for p,h in group['dependencies_pre'].items()})
        return result

    def verify(self):
        assert all(self.stable(p,h) for p,h in self.tool_pins.items())
        assert all(self.stable(p,h) for p,h in self.dependency_pins.items())
        assert all(event['pass'] for event in self.events)
