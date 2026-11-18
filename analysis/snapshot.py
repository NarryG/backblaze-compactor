"""Capture a VSS catalog/ledger snapshot and explicit deployment preconditions.

No live Backblaze files or service state are changed. Pending directories are
inventoried, not copied: nonempty/unknown work blocks compaction. Exact-ID
cleanup and a durable ownership journal protect only this helper's shadow copy.
"""
from __future__ import annotations
import argparse
import base64
import ctypes
import hashlib
import json
import subprocess
import os
import re
import stat
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from writer_watch import WriterWatch


def powershell(script):
    command = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-EncodedCommand', command],
                            capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def present(path):
    try:
        path.stat(follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def entries(path, allow_reparse=False):
    try:
        with os.scandir(path) as scan:
            result = list(scan)
    except FileNotFoundError:
        return []
    for item in result:
        if not allow_reparse and item.stat(follow_symlinks=False).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError('Reparse point in snapshot metadata or pending state')
    return result


def inventory(path):
    result = []
    def visit(directory):
        for item in entries(directory):
            child = Path(item.path)
            result.append(child.relative_to(path).as_posix())
            if item.is_dir(follow_symlinks=False):
                visit(child)
    visit(path)
    return sorted(result)


def reject_reparse_ancestors(path, root):
    current = root
    for part in (None, *path.relative_to(root).parts):
        if part is not None:
            current = current / part
        try:
            info = current.stat(follow_symlinks=False)
        except FileNotFoundError:
            if current == root:
                raise RuntimeError(f'Inventory root is unavailable: {root}')
            return
        if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError(f'Reparse point in pending path: {current}')
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f'Non-directory in pending path: {current}')


def external_inventory(mount, path):
    """Prove the local volume and reject reparse ancestors before inventorying."""
    proof = {'available': False, 'volumeId': ''}
    try:
        if not mount or not path:
            raise RuntimeError('Invalid scratch mount')
        mount = mount.replace('/', '\\')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        kernel.GetDriveTypeW.restype = ctypes.c_uint
        kernel.GetVolumeNameForVolumeMountPointW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        kernel.GetVolumeInformationW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p, ctypes.c_uint]
        def volume_id():
            if kernel.GetDriveTypeW(mount) not in (2, 3):
                raise RuntimeError('Scratch mount is not an available local volume')
            volume_name = ctypes.create_unicode_buffer(1024)
            if not kernel.GetVolumeNameForVolumeMountPointW(mount, volume_name, len(volume_name)):
                raise ctypes.WinError(ctypes.get_last_error())
            serial = ctypes.c_uint32()
            if not kernel.GetVolumeInformationW(mount, None, 0, ctypes.byref(serial), None, None, None, 0):
                raise ctypes.WinError(ctypes.get_last_error())
            return f'{volume_name.value.lower()}:{serial.value:08x}'
        initial_id = volume_id()
        proof.update(available=True, volumeId=initial_id)
        reject_reparse_ancestors(path, Path(mount))
        result = inventory(path)
        proof.update(available=False, volumeId='')
        final_id = volume_id()
        proof.update(available=True, volumeId=final_id)
        if initial_id != final_id:
            raise RuntimeError('Scratch volume changed during inventory')
        return proof, result, True
    except (OSError, RuntimeError) as error:
        proof['error'] = str(error)
        return proof, [], False


def journal_id(path):
    try:
        value = path.read_text(encoding='ascii').strip()
        if not re.fullmatch(r'(?:\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})', value):
            raise ValueError('Invalid shadow ownership journal')
        return '{' + str(uuid.UUID(value.strip('{}'))) + '}'
    except FileNotFoundError:
        return None


def writer_state():
    state = powershell("$ErrorActionPreference='Stop'; $p=@(Get-CimInstance Win32_Process | Where-Object {$_.Name -match '^bz(serv|transmit|filelist|fclean|doinstall|restore|downloader|cli|bui|buitray)\\.exe$'} | ForEach-Object {$_.Name+':'+$_.ProcessId}); @{writers=$p} | ConvertTo-Json -Compress")
    state['repairMarker'] = present(Path('C:/ProgramData/Backblaze/bzdata/bzreports/bzstat_ibsModifiedBzDoneFile.dat'))
    return state


def sha256(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def save_manifest(path, manifest):
    with path.open('w', encoding='utf-8') as output:
        json.dump(manifest, output, indent=2)
        output.flush()
        os.fsync(output.fileno())


def guard_offline(path):
    for root in (Path('C:/ProgramData/Backblaze'), Path('C:/Program Files/Backblaze')):
        if path.is_relative_to(root.resolve()):
            raise RuntimeError('Snapshot output/reuse must not be live Backblaze state')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--reuse', type=Path, help='Reuse byte-verified unchanged files by hard link, never live files.')
    args = parser.parse_args()
    args.output = args.output.resolve()
    guard_offline(args.output)
    if args.reuse:
        args.reuse = args.reuse.resolve()
        guard_offline(args.reuse)
        if args.output.is_relative_to(args.reuse):
            raise RuntimeError('Snapshot output must be outside the reused snapshot')
    args.output.mkdir(parents=True, exist_ok=False)
    reuse = {}
    if args.reuse:
        args.reuse = args.reuse.resolve()
        previous = json.loads((args.reuse / 'snapshot.json').read_text())
        if not previous.get('complete'):
            raise RuntimeError('Cannot reuse an incomplete snapshot')
        reuse = {e['path']: e for e in previous['files']}
    journal = args.output / 'shadow-ownership.txt'
    shadow_id = None
    manifest = {'kind': 'VSS point-in-time catalog/ledger snapshot', 'files': [], 'complete': False}
    capture = {}
    watch = WriterWatch()
    try:
        watch.start()
        before = writer_state()
        journal_literal = str(journal).replace("'", "''")
        powershell("$ErrorActionPreference='Stop'; "
                   "$r=Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume='C:\\';Context='ClientAccessible'}; "
                   "if($r.ReturnValue -ne 0){throw ('VSS creation failed '+$r.ReturnValue)}; "
                   "$id=[string]$r.ShadowID; "
                   "try { $bytes=[Text.Encoding]::ASCII.GetBytes($id); "
                   "$f=[IO.FileStream]::new('" + journal_literal + "',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read); "
                   "try { $f.Write($bytes,0,$bytes.Length); $f.Flush($true) } finally { $f.Dispose() } "
                   "} catch { $failure=$_; try { Get-CimInstance Win32_ShadowCopy | Where-Object {$_.ID -eq $id} | Remove-CimInstance } "
                   "catch { throw ('Shadow journal failed; exact-ID cleanup also failed for '+$id+': '+$_) }; throw $failure }; "
                   "@{ID=$id} | ConvertTo-Json -Compress")
        shadow_id = journal_id(journal)
        if not shadow_id:
            raise RuntimeError('VSS did not persist a shadow-copy identity')
        manifest['shadow_id'] = shadow_id
        save_manifest(args.output / 'snapshot.json', manifest)
        shadow = powershell("$ErrorActionPreference='Stop'; $s=Get-CimInstance Win32_ShadowCopy | Where-Object {$_.ID -eq '" + shadow_id + "'}; "
                            "if(-not $s){throw 'Owned shadow copy not found'}; $s | Select-Object ID,DeviceObject | ConvertTo-Json -Compress")
        if not shadow or not shadow.get('DeviceObject'):
            raise RuntimeError('VSS did not return a shadow-copy device')
        volume = Path(shadow['DeviceObject'])
        data = volume / 'ProgramData/Backblaze/bzdata'
        source = data / 'bzbackup'
        config = ET.parse(data / 'bzinfo.xml').getroot()
        scratch = config.find('scratch_drive')
        mount = scratch.get('scratch_mountpoint') if scratch is not None else None
        valid_mount = bool(mount and len(mount) == 3 and mount[0].isascii() and mount[0].isalpha()
                           and mount[1] == ':' and mount[2] in '\\/')
        external = Path(mount) / '.bzvol/bzscratch/bzcurrentlargefile' if valid_mount else None
        volume_before, external_before, external_before_ok = external_inventory(mount if valid_mount else None, external)
        for pending in (data / 'bzthread', source / 'bzdatacenter/bzcurrentlargefile',
                        source / 'bzdatacenter/bz_tofix'):
            reject_reparse_ancestors(pending, data)
        capture = {
            'clientSha256': sha256(volume / 'Program Files/Backblaze/bztransmit.exe'),
            'writersBefore': before['writers'],
            'pendingDirectories': {
                'thread': inventory(data / 'bzthread'),
                'mainLarge': inventory(source / 'bzdatacenter/bzcurrentlargefile'),
                'externalLargeBefore': external_before,
            },
            'externalScratchVolumeBefore': volume_before,
            'excludedDirectories': [e.get('dir') for e in config.iter('bzdirfilter') if e.get('whichfiles') == 'none'],
            'includedDirectories': [e.get('dir') for e in config.iter('bzdirfilter') if e.get('whichfiles') != 'none' and e.get('dir')],
            'repairMarkers': [],
            'catalogSidecars': [p.name for p in entries(source) if p.is_file(follow_symlinks=False) and (
                p.name.lower() == 'tmp_bzlastassignedfileid.dat' or re.match(r'^(bzfileids|bzlastassignedfileid)\.dat\.(tmp|future|new)$', p.name, re.I))],
            'pendingCoverageComplete': valid_mount and external_before_ok and all(e.get('dir') and e.get('whichfiles') in ('none', 'all') for e in config.iter('bzdirfilter')),
        }
        marker = data / 'bzreports/bzstat_ibsModifiedBzDoneFile.dat'
        if present(marker):
            capture['repairMarkers'].append('VSS:bzstat_ibsModifiedBzDoneFile.dat')
        if before['repairMarker']:
            capture['repairMarkers'].append('before:bzstat_ibsModifiedBzDoneFile.dat')
        paths = [source / 'bzfileids.dat', source / 'bzlastassignedfileid.dat']
        center = entries(source / 'bzdatacenter', allow_reparse=True)
        def regular(item):
            return (not item.stat(follow_symlinks=False).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
                    and item.is_file(follow_symlinks=False))
        done_pattern = r'bz_done_[0-9]{8}_[0-9]\.dat'
        todo_pattern = r'bz_todo_[0-9]{8}_[0-9]+\.dat'
        unsupported = sorted(p.name for p in center
                             if (('bz_done' in p.name.lower() and not (regular(p) and re.fullmatch(done_pattern, p.name)))
                                 or ('bz_todo' in p.name.lower() and not (regular(p) and re.fullmatch(todo_pattern, p.name)))))
        capture['unsupportedLedgerNames'] = unsupported
        capture['historyCoverageComplete'] = not any('bz_done' in name.lower() for name in unsupported)
        if any('bz_todo' in name.lower() for name in unsupported):
            capture['pendingCoverageComplete'] = False
        paths.extend(sorted(Path(p.path) for p in center if regular(p) and re.fullmatch(done_pattern, p.name)))
        paths.extend(sorted(Path(p.path) for p in center if regular(p) and re.fullmatch(todo_pattern, p.name)))
        fix_entries = entries(source / 'bzdatacenter/bz_tofix')
        paths.extend(sorted(Path(p.path) for p in fix_entries if p.is_file(follow_symlinks=False) and re.fullmatch(r'bz_tofix_[0-9]{14}\.dat', p.name)))
        if any(not p.is_file(follow_symlinks=False) or not re.fullmatch(r'bz_tofix_[0-9]{14}\.dat', p.name) for p in fix_entries):
            capture['pendingCoverageComplete'] = False
        for index, path in enumerate(paths):
            relative = path.relative_to(source)
            destination = args.output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = sha256(path)
            count = path.stat().st_size
            old = reuse.get(relative.as_posix())
            old_path = args.reuse / relative if args.reuse else None
            if old and old['bytes'] == count and old['sha256'] == digest and sha256(old_path) == digest:
                os.link(old_path, destination)
            else:
                with path.open('rb') as reader, destination.open('xb') as writer:
                    while block := reader.read(8 * 1024 * 1024):
                        writer.write(block)
            manifest['files'].append({'path': relative.as_posix(), 'bytes': count, 'sha256': digest})
            if index % 50 == 0:
                print(json.dumps({'captured': index + 1, 'of': len(paths)}), flush=True)
        after = writer_state()
        capture['writersAfter'] = after['writers']
        volume_after, external_after, external_after_ok = external_inventory(mount if valid_mount else None, external)
        capture['externalScratchVolumeAfter'] = volume_after
        capture['pendingDirectories']['externalLargeAfter'] = external_after
        if not (external_before_ok and external_after_ok and volume_before['available'] and volume_after['available']
                and volume_before['volumeId'] and volume_before['volumeId'] == volume_after['volumeId']):
            capture['pendingCoverageComplete'] = False
        if after['repairMarker']:
            capture['repairMarkers'].append('after:bzstat_ibsModifiedBzDoneFile.dat')
        manifest['capture'] = capture
        manifest['complete'] = True
    finally:
        active_error = sys.exc_info()[0] is not None
        final_error = None
        try:
            observed = watch.stop()
            capture['writerObservationComplete'] = observed.get('complete') is True
            capture['writerDrainComplete'] = observed.get('drained') is True
            capture['writersStarted'] = observed.get('started', [])
            if not capture['writerObservationComplete'] or not capture['writerDrainComplete']:
                manifest['complete'] = False
                final_error = RuntimeError('Writer observation or drain incomplete: ' + observed.get('error', 'unknown failure'))
        except Exception as error:
            manifest['complete'] = False
            capture['writerObservationComplete'] = False
            capture['writerDrainComplete'] = False
            final_error = error
        manifest['capture'] = capture
        try:
            shadow_id = shadow_id or journal_id(journal)
            if shadow_id:
                manifest['shadow_id'] = shadow_id
                deletion = powershell("$ErrorActionPreference='Stop'; $s=Get-CimInstance Win32_ShadowCopy | Where-Object {$_.ID -eq '" + shadow_id + "'}; if($s){$s | Remove-CimInstance}; @{deleted=$true} | ConvertTo-Json -Compress")
                manifest['temporary_shadow_deleted'] = deletion['deleted'] is True
                if not manifest['temporary_shadow_deleted']:
                    raise RuntimeError('Owned shadow deletion was not confirmed')
        except Exception as error:
            manifest['complete'] = False
            manifest['temporary_shadow_deleted'] = False
            manifest['shadow_cleanup_error'] = str(error)
            if final_error is None:
                final_error = error
        try:
            save_manifest(args.output / 'snapshot.json', manifest)
        except Exception:
            if not active_error:
                raise
        if final_error is not None and not active_error:
            raise final_error
    print(json.dumps({'snapshot': str(args.output), 'complete': manifest['complete'],
                      'files': len(manifest['files']), 'bytes': sum(r['bytes'] for r in manifest['files'])}), flush=True)


if __name__ == '__main__':
    main()
