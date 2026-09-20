"""Exercise real helper/owner/job failures with retained process handles on Windows."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
import uuid

k = c.WinDLL('kernel32', use_last_error=True)
for name, restype, args in [
    ('OpenProcess', w.HANDLE, [w.DWORD, w.BOOL, w.DWORD]),
    ('CloseHandle', w.BOOL, [w.HANDLE]),
    ('WaitForSingleObject', w.DWORD, [w.HANDLE, w.DWORD]),
    ('TerminateProcess', w.BOOL, [w.HANDLE, w.UINT]),
    ('GetProcessTimes', w.BOOL, [w.HANDLE, c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p]),
    ('CreateToolhelp32Snapshot', w.HANDLE, [w.DWORD, w.DWORD]),
    ('CreateEventW', w.HANDLE, [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]),
    ('OpenEventW', w.HANDLE, [w.DWORD, w.BOOL, w.LPCWSTR]),
    ('SetEvent', w.BOOL, [w.HANDLE]),
    ('CreateJobObjectW', w.HANDLE, [c.c_void_p, w.LPCWSTR]),
    ('AssignProcessToJobObject', w.BOOL, [w.HANDLE, w.HANDLE]),
    ('GetCurrentProcess', w.HANDLE, []),
]:
    fn = getattr(k, name)
    fn.restype, fn.argtypes = restype, args

class Entry(c.Structure):
    _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('pid', w.DWORD), ('heap', c.c_size_t), ('module', w.DWORD),
                ('threads', w.DWORD), ('parent', w.DWORD), ('priority', w.LONG), ('flags', w.DWORD), ('exe', w.WCHAR * 260)]

k.Process32FirstW.argtypes = k.Process32NextW.argtypes = [w.HANDLE, c.POINTER(Entry)]

def creation(handle):
    values = [c.c_uint64() for _ in range(4)]
    assert k.GetProcessTimes(handle, *(c.byref(v) for v in values)), c.get_last_error()
    return values[0].value

def children(parent):
    snapshot = k.CreateToolhelp32Snapshot(2, 0)
    assert snapshot not in (None, c.c_void_p(-1).value)
    result = []
    try:
        entry = Entry()
        entry.size = c.sizeof(entry)
        valid = k.Process32FirstW(snapshot, c.byref(entry))
        while valid:
            if entry.parent == parent:
                result.append(entry.pid)
            valid = k.Process32NextW(snapshot, c.byref(entry))
    finally:
        k.CloseHandle(snapshot)
    return result

def wait_until(predicate, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(.05)
    raise AssertionError('Timed out waiting for process evidence')

def scenario(helper, action):
    operation = 'own-' + uuid.uuid4().hex
    sample = helper.parent / 'knmon-sample-fileio.exe'
    owner = subprocess.Popen([str(Path(os.environ['SystemRoot']) / 'System32/ping.exe'), '127.0.0.1', '-n', '90'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    command = [str(helper), 'launch-session', '--target', str(sample), '--args',
               '--spawn-child-loop --children 2 --child-iterations 3000 --delay-ms 25', '--stream-batches',
               '--operation-id', operation, '--session-id', 'session-' + operation, '--own-launch-job',
               '--api-selection', 'kernel32.dll!CreateFileW;kernel32.dll!CloseHandle',
               '--owner-pid', str(owner.pid), '--owner-created', str(creation(owner._handle))]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8',
                               creationflags=subprocess.CREATE_NO_WINDOW)
    frames = queue.Queue()
    errors = []
    def read_frames():
        try:
            for line in process.stdout:
                frames.put(json.loads(line))
        except Exception as error:
            errors.append(str(error))
    reader = threading.Thread(target=read_frames, daemon=True)
    reader.start()
    handles = []
    observed = []
    try:
        def target_started():
            while not frames.empty():
                frame = frames.get()
                observed.append(frame)
                session = frame.get('session', {})
                if session.get('targetProcessId'):
                    return session
            assert process.poll() is None, (process.returncode, observed, process.stderr.read())
            return None
        session = wait_until(target_started)
        root = session['targetProcessId']
        root_handle = k.OpenProcess(0x1000 | 0x100000 | 1, False, root)
        assert root_handle and creation(root_handle) == int(session['targetProcessCreationTime'])
        handles.append(root_handle)
        child_ids = wait_until(lambda: (pids if len(pids := children(root)) >= 2 else None))
        for pid in child_ids:
            handle = k.OpenProcess(0x1000 | 0x100000 | 1, False, pid)
            assert handle and creation(handle) >= creation(root_handle)
            handles.append(handle)
        if action == 'helper-crash':
            process.kill()
        elif action == 'owner-exit':
            owner.kill()
        else:
            event = k.OpenEventW(2, False, 'Local\\KNMonCancel_' + operation)
            assert event and k.SetEvent(event)
            k.CloseHandle(event)
        process.wait(timeout=30)
        reader.join(timeout=2)
        assert not reader.is_alive() and not errors, errors
        while not frames.empty():
            observed.append(frames.get())
        if action == 'normal-detach':
            result = next(frame['captureResult'] for frame in observed if frame.get('frameType') == 'capture_result')
            assert result['operationState'] == 'cancelled' and result['agentCleanupSucceeded'], result.get('message')
            assert all(k.WaitForSingleObject(h, 0) == 258 for h in handles), 'Normal detach terminated the owned target tree'
        else:
            assert all(k.WaitForSingleObject(h, 5000) == 0 for h in handles), 'Owned job leaked a live target or child'
        print(f'{action}: root and {len(child_ids)} children verified using retained handles')
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for handle in handles:
            if k.WaitForSingleObject(handle, 0) == 258:
                k.TerminateProcess(handle, 1)
                k.WaitForSingleObject(handle, 5000)
            k.CloseHandle(handle)
        if owner.poll() is None:
            owner.kill()
        owner.wait(timeout=5)

def collision(helper):
    operation = 'collision-' + uuid.uuid4().hex
    event = k.CreateEventW(None, True, True, 'Local\\KNMonCancel_' + operation)
    assert event
    try:
        result = subprocess.run([str(helper), 'launch-session', '--target', str(helper.parent / 'knmon-sample-fileio.exe'),
                                 '--operation-id', operation, '--stream-batches'], capture_output=True, text=True,
                                encoding='utf-8', timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        frames = [json.loads(line) for line in result.stdout.splitlines()]
        capture = next(frame['captureResult'] for frame in frames if frame.get('frameType') == 'capture_result')
        assert not capture['success'] and capture['targetProcessId'] == 0 and capture['win32ErrorCode'] == 183, capture
        assert k.WaitForSingleObject(event, 0) == 0, 'Foreign event was reset'
        print('event-collision: rejected existing object without resetting it or starting a target')
    finally:
        k.CloseHandle(event)

def invalid_configuration(helper):
    for operation in ['x' * 64, 'invalid/path']:
        result = subprocess.run([str(helper), 'launch-session', '--target', str(helper.parent / 'knmon-sample-fileio.exe'),
                                 '--operation-id', operation, '--stream-batches'], capture_output=True, text=True,
                                encoding='utf-8', timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        frames = [json.loads(line) for line in result.stdout.splitlines()]
        capture = next(frame['captureResult'] for frame in frames if frame.get('frameType') == 'capture_result')
        assert not capture['success'] and capture['targetProcessId'] == 0 and capture['operation'] == 'invalid_operation_id', capture
    result = subprocess.run([str(helper), 'launch-session', '--target', str(helper.parent / 'knmon-sample-fileio.exe'),
                             '--owner-pid', str(os.getpid()), '--owner-created', '1', '--own-launch-job', '--stream-batches'],
                            capture_output=True, text=True, encoding='utf-8', timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
    frames = [json.loads(line) for line in result.stdout.splitlines()]
    capture = next(frame['captureResult'] for frame in frames if frame.get('frameType') == 'capture_result')
    assert not capture['success'] and capture['operation'] == 'owner_identity_invalid', capture
    assert all(event['eventType'] != 'primary_thread_resumed' for event in capture['auditEvents'])
    print('invalid-config: long/unsafe IDs rejected; wrong owner creation time rejected before target resume')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--helper', required=True, type=Path)
    args = parser.parse_args()
    helper = args.helper.resolve(strict=True)
    # The launched helper and target already inherit this job, exercising nested-job compatibility.
    outer = k.CreateJobObjectW(None, None)
    assert outer and k.AssignProcessToJobObject(outer, k.GetCurrentProcess()), c.get_last_error()
    try:
        for action in ['helper-crash', 'owner-exit', 'normal-detach']:
            scenario(helper, action)
        collision(helper)
        invalid_configuration(helper)
    finally:
        k.CloseHandle(outer)
