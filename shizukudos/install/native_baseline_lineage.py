# SPDX-License-Identifier: GPL-2.0-only
"""Root bootstrap's live private lineage connector, never request authority.

This module trusts independently reviewed root code selecting the decision pin.
It does not sandbox root Python. A literal decision is configured provenance;
only its retained FD/leases AND the fixed live Windows service can admit source.
"""
import ast, copy, fcntl, hashlib, json, os, stat, threading, time
from pathlib import Path
import importlib.util

ROOT=Path(__file__).resolve().parents[2]
_spec=importlib.util.spec_from_file_location('lineage_fixed_provider',ROOT/'shizukudos/install/native_baseline_provider.py')
provider=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(provider)
need=provider.need
replacement=provider.replacement
SCOPE='WINDOWS_ORIGINAL_DOS_INSTALLED_SOURCE'
_FIELDS={'SCHEMA','SCOPE','ORIGINAL_SOURCE','ARCHIVE','SNAPSHOT','REDERIVATION','PRODUCERS'}


def literal_decision(raw):
    need(0<len(raw)<=65536,'bounded literal private decision required')
    tree=ast.parse(raw);values={}
    for item in tree.body:
        need(type(item) is ast.Assign and len(item.targets)==1 and type(item.targets[0]) is ast.Name,
             'private decision must contain literal assignments only')
        name=item.targets[0].id
        need(name in _FIELDS and name not in values,'exact unique private decision fields required')
        values[name]=ast.literal_eval(item.value)
    need(set(values)==_FIELDS and values['SCHEMA']=='shizukuos.private-root-original-installed-lineage.v1'
         and values['SCOPE']==SCOPE,'original installed-source decision scope required')
    for key in ('ORIGINAL_SOURCE','ARCHIVE','REDERIVATION'):replacement.pin_fields(values[key])
    need(values['SNAPSHOT']=={'id':'7','name':'windows98-clean-installed'},'exact disk-only snapshot lineage required')
    need(type(values['PRODUCERS']) is list and len(values['PRODUCERS'])==3,'actual review/export/tool closure required')
    for pin in values['PRODUCERS']:replacement.pin_fields(pin)
    need(len({p['path'] for p in values['PRODUCERS']})==3,'distinct producer closure required')
    return values


class RootLineageOwner:
    """Process-local root approval; never construct from installer JSON.

    `from_admitted_root` is a TRUSTED BOOTSTRAP interface, not a CLI. The pin
    must be independently source-admitted by root's reviewed private factory.
    The same ingester Union owns SIGIO/FDs until compilation ends. Close this
    owner before Union exit; final checks do not release borrowed descriptors.
    """
    @classmethod
    def from_admitted_root(cls,decision_pin,held_union):
        need(os.geteuid()==0,'independent root bootstrap required')
        need(type(held_union).__name__=='Union' and held_union.add.__code__.co_filename==
             str(ROOT/'shizukudos/install/native_payload_ingest.py'),'actual source-admitted Union required')
        held_union.check();replacement.pin_fields(decision_pin)
        need(decision_pin['bytes']<=65536,'bounded root decision extent required')
        # Root bootstrap independently admits the reviewed connector source
        # before selecting a private decision. Never self-add authority code.
        code=held_union.entries.get(Path(__file__))
        need(code is not None and code['pin']==replacement.local_pin(Path(__file__)),
             'independently source-admitted connector implementation required')
        path=Path(decision_pin['path']);replacement.safe_path(path)
        st=path.lstat();parent=path.parent.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o400 and st.st_nlink==1
             and stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and stat.S_IMODE(parent.st_mode)==0o700,
             'owned root-private0400 decision in0700 namespace required')
        self=cls();self._pid=os.getpid();self._thread=threading.get_ident();self._pidfd=os.pidfd_open(self._pid)
        self._active=True;self._cancelled=False;self._deadline=time.monotonic()+5400
        self._union=held_union;self._entries=[code];self._client=None
        try:
            self._pidfd_identity=provider.control.pidfd_identity(self._pidfd)
            decision_entry=self._add(decision_pin)
            raw=os.pread(decision_entry['fd'],decision_pin['bytes']+1,0)
            need(len(raw)==decision_pin['bytes'] and hashlib.sha256(raw).hexdigest()==decision_pin['sha256'],
                 'held decision exact bytes differ')
            self._decision=literal_decision(raw)
            need(self._decision['REDERIVATION']['bytes']<=65536,'bounded root provenance extent required')
            for pin in (self._decision['ORIGINAL_SOURCE'],self._decision['ARCHIVE'],self._decision['REDERIVATION'],*self._decision['PRODUCERS']):self._add(pin)
            original=Path(self._decision['ORIGINAL_SOURCE']['path']).lstat()
            need(stat.S_IMODE(original.st_mode)==0o400 and original.st_uid==0,'root-owned0400 original required')
            record=self._union.entries[Path(self._decision['REDERIVATION']['path'])]
            need(record['pin']['bytes']<=65536,'bounded private rederivation provenance required')
            fact=json.loads(os.pread(record['fd'],record['pin']['bytes'],0),object_pairs_hook=provider.control.unique)
            self._check_provenance(fact);self.check();return self
        except BaseException:
            self._active=False;os.close(self._pidfd);raise
    def __reduce__(self):raise TypeError('live root lineage authority cannot be serialized')
    def _add(self,pin):
        entry=self._union.add(copy.deepcopy(pin));self._entries.append(entry);return entry
    def _check_provenance(self,fact):
        d=self._decision
        need(fact['schema']=='shizukuos.independent-root-snapshot-rederivation.v1' and
             fact['scope']=='ARCHIVE_SNAPSHOT7_ORIGINAL_DOS_CONTROL_SOURCE_EQUALITY' and
             fact['status']=='PASS_ACTUAL_ARCHIVE_SNAPSHOT7_RAW_EQUALITY' and fact['snapshot']==d['SNAPSHOT'],
             'configured actual snapshot rederivation provenance differs')
        inputs=fact['original_inputs']
        need(set(inputs)=={'archive','original_raw','current_review_source','historical_export_source','qemu_img'} and
             inputs['archive']==d['ARCHIVE'] and inputs['original_raw']==d['ORIGINAL_SOURCE'] and
             {p['path']:p for p in (inputs[k] for k in ('current_review_source','historical_export_source','qemu_img'))}==
             {p['path']:p for p in d['PRODUCERS']},
             'actual archive/raw/export producer closure differs')
        exported=fact['actual_export'];source=d['ORIGINAL_SOURCE']
        need(exported['bytes']==exported['byte_compared']==source['bytes'] and exported['sha256']==source['sha256'] and
             exported['sealed'] is True and exported['persisted_raw'] is False and
             fact['original_inputs_final_readback_passed'] is True and fact['all_original_fds_closed'] is True and
             fact['cleanup_errors']==[],'configured whole raw equality/cleanup differs')
        for field in ('OEM_media_is_archive_ancestor','RAM_checkpoint_restored','SE_license_approval',
                      'VM_started','Windows98_on_ShizukuDOS','key_application_verified'):
            need(fact[field] is False,'configured lineage exceeds original-DOS-only scope')
    def check(self):
        need(self._active and not self._cancelled and os.getpid()==self._pid and threading.get_ident()==self._thread
             and time.monotonic()<self._deadline and not provider.control.pidfd_ready(self._pidfd,self._pidfd_identity),
             'live root lineage owner cancelled/dead/stale')
        need(not self._union.broken,'private input lease break observed')
        # No Union.check here: this method may itself be a Union guard.
        for entry in self._entries:
            path=Path(entry['pin']['path']);replacement.safe_path(path)
            need(self._union.entries.get(path) is entry and
                 replacement.identity(os.fstat(entry['fd']))==entry['identity']==replacement.identity(path.stat()) and
                 fcntl.fcntl(entry['fd'],fcntl.F_GETLEASE)==fcntl.F_RDLCK,'private live source/producer alias or lease differs')
        if self._client is not None:self._client.owner_check()
    def bind(self,client):
        self.check();need(self._client is None,'lineage owner binding is single-use')
        need(type(client) is provider.Client and client.borrowed is self._union and client.control_request is not None,
             'exact fixed Windows owned service on same admitted Union required')
        client.query();summary=client.summary
        need(summary['grade']=='SOURCE_AND_OBSERVATION_CUSTODY_ONLY' and summary['source']==self._decision['ORIGINAL_SOURCE']
             and summary['source_approval'] is False and summary['Windows98_on_ShizukuDOS'] is False,
             'fresh fixed Windows observation source/scope required')
        version=summary['observed_version']
        need(version['platform_id']==1 and version['major']==4 and version['minor']==10 and
             type(version['display_count']) is int and version['display_count']>=1,
             'actual Windows98 read-only observer version/Display required')
        need(type(summary['observation_sha256']) is str and len(summary['observation_sha256'])==64,
             'actual nonce-bound observer digest required')
        self._client=client;self.check()
    def verify(self,source_pin,held_entry):
        self.check();need(self._client is not None,'fresh Windows service not bound; SOURCE_CUSTODY_ONLY')
        need(source_pin==self._decision['ORIGINAL_SOURCE'] and held_entry is
             self._union.entries[Path(source_pin['path'])],'exact admitted original held FD required')
        self._client.match_held_source(held_entry);self.check()
        return {'schema':'shizukuos.private-live-installed-source-custody.v1','grade':SCOPE,
                'source':copy.deepcopy(source_pin),'observation_sha256':self._client.summary['observation_sha256'],
                'service_pid':self._client.child.pid,'challenge_sequence':self._client.sequence,
                'Windows98_on_ShizukuDOS':False,'SE_license_approval':False,'key_application_verified':False}
    def cancel(self):self._cancelled=True
    def close(self):
        if self._active:
            try:
                self.check()
                for entry in self._entries:
                    need(replacement.hash_fd(entry['fd'],entry['pin']['bytes'],self.check)==entry['pin']['sha256'],
                         'retained private input final SHA differs')
                self.check()
            finally:self._active=False;os.close(self._pidfd)
    def __enter__(self):self.check();return self
    def __exit__(self,*_):self.close()
