"""Run a fixture in a Windows job with one process and bounded cleanup.

The child starts suspended, joins the job, then resumes. The one-process limit
rejects recursive host relaunches; closing the job kills any remaining member.
This is process containment for benign fixtures, not a security sandbox.
Use running(command, **Popen_kwargs) as a context manager, or run() like
subprocess.run() with explicit stdout/stderr and timeout arguments.
"""
from contextlib import contextmanager
import ctypes as c
from ctypes import wintypes as w
import subprocess

k = c.WinDLL('kernel32', use_last_error=True)
n = c.WinDLL('ntdll')
class BasicLimits(c.Structure):
    _fields_ = [('process_time', c.c_int64), ('job_time', c.c_int64),
                ('flags', w.DWORD), ('min_working_set', c.c_size_t),
                ('max_working_set', c.c_size_t), ('process_limit', w.DWORD),
                ('affinity', c.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]
class IoCounters(c.Structure):
    _fields_ = [(name, c.c_uint64) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
class Limits(c.Structure):
    _fields_ = [('basic', BasicLimits), ('io', IoCounters),
                ('process_memory', c.c_size_t), ('job_memory', c.c_size_t),
                ('peak_process_memory', c.c_size_t), ('peak_job_memory', c.c_size_t)]
for name, args, result in (
    ('CreateJobObjectW', [c.c_void_p,w.LPCWSTR],w.HANDLE),
    ('SetInformationJobObject',[w.HANDLE,c.c_int,c.c_void_p,w.DWORD],w.BOOL),
    ('AssignProcessToJobObject',[w.HANDLE,w.HANDLE],w.BOOL),
    ('CloseHandle',[w.HANDLE],w.BOOL),
    ('SetErrorMode',[w.UINT],w.UINT),
):
    fn=getattr(k,name);fn.argtypes=args;fn.restype=result
n.NtResumeProcess.argtypes=[w.HANDLE]
n.NtResumeProcess.restype=w.LONG

@contextmanager
def running(command, max_processes=1, **kwargs):
    job=k.CreateJobObjectW(None,None)
    if not job:
        raise c.WinError(c.get_last_error())
    process=None
    try:
        limits=Limits()
        limits.basic.flags=0x2008  # KILL_ON_JOB_CLOSE | ACTIVE_PROCESS
        if not 1 <= max_processes <= 16:
            raise ValueError("Invalid process limit.")
        limits.basic.process_limit=max_processes
        if not k.SetInformationJobObject(job,9,c.byref(limits),c.sizeof(limits)):
            raise c.WinError(c.get_last_error())
        kwargs['creationflags']=kwargs.get('creationflags',0)|0x4  # CREATE_SUSPENDED
        old_mode=k.SetErrorMode(0x8003)
        try:
            process=subprocess.Popen(command,**kwargs)
        finally:
            k.SetErrorMode(old_mode)
        if not k.AssignProcessToJobObject(job,int(process._handle)):
            raise c.WinError(c.get_last_error())
        status=n.NtResumeProcess(int(process._handle))
        if status:
            raise OSError(f'Cannot resume fixture: NTSTATUS {status & 0xffffffff:#x}')
        yield process
    finally:
        k.CloseHandle(job)
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


def run(command, timeout=None, **kwargs):
    with running(command, **kwargs) as process:
        out, err=process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command,process.returncode,out,err)
