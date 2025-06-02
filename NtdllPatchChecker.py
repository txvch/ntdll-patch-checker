import ctypes
from ctypes import wintypes
import psutil
import win32service, win32serviceutil
import win32con
import win32api
import struct
import time
import os
import sys
#
# Some constants I threw in here
chunkSz = 64  # how much we read at once
procRead = 0x0010  # PROCESS_VM_READ
QUERY_FULL = 0x0400  # full query perms
queryLite = 0x1000  # limited query
MAXPATH = 260  # max path length, classic Windows

# Load Windows DLLs - kernel32 is the big dog
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
nt = ctypes.WinDLL("ntdll", use_last_error=True)

# shoutout to chatgpt for giving these to me
open_proc = k32.OpenProcess
open_proc.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
open_proc.restype = ctypes.wintypes.HANDLE

readMem = k32.ReadProcessMemory
readMem.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
readMem.restype = ctypes.wintypes.BOOL

close_h = k32.CloseHandle
close_h.argtypes = [ctypes.wintypes.HANDLE]
close_h.restype = ctypes.wintypes.BOOL

getProcAddr = k32.GetProcAddress
getProcAddr.argtypes = [ctypes.wintypes.HMODULE, ctypes.c_char_p]
getProcAddr.restype = ctypes.c_void_p

getModHandle = k32.GetModuleHandleA
getModHandle.argtypes = [ctypes.c_char_p]
getModHandle.restype = ctypes.wintypes.HMODULE

virtQuery = k32.VirtualQueryEx
virtQuery.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
virtQuery.restype = ctypes.c_size_t

enumModsEx = psapi.EnumProcessModulesEx
enumModsEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.HMODULE), ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.wintypes.DWORD]
enumModsEx.restype = ctypes.wintypes.BOOL

getmoduleinfo = psapi.GetModuleInformation
getModFileName = psapi.GetModuleFileNameExA
getModFileName.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HMODULE, ctypes.c_char_p, ctypes.wintypes.DWORD]
getModFileName.restype = ctypes.wintypes.DWORD

class memoryinfo(ctypes.Structure):
    _fields_ = [
        ("baseAddr", ctypes.c_void_p),
        ("allocBase", ctypes.c_void_p),
        ("allocProt", ctypes.wintypes.DWORD),
        ("regionSz", ctypes.c_size_t),
        ("state", ctypes.wintypes.DWORD),
        ("protect", ctypes.wintypes.DWORD),
        ("type", ctypes.wintypes.DWORD),
    ]

class moduleinfo(ctypes.Structure):
    _fields_ = [
        ("base", ctypes.c_void_p),
        ("size", ctypes.wintypes.DWORD),
        ("entry", ctypes.c_void_p),
    ]

getmoduleinfo.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HMODULE, ctypes.POINTER(moduleinfo), ctypes.wintypes.DWORD]
getmoduleinfo.restype = ctypes.wintypes.BOOL

class patchchecker:
    def __init__(self):
        self.debug = True
        self.funcs = [  # some APIs i needed to check
            b"NtCreateFile",
            b"NtOpenFile", 
            b"NtReadFile",
            b"NtWriteFile",
            b"NtQueryInformationFile",
            b"NtSetInformationFile",
            b"NtCreateProcess",
            b"NtCreateProcessEx",
            b"NtOpenProcess",
            b"NtTerminateProcess"
        ]

    def log(self, msg):
        if self.debug:
            print(f"[LOG] {msg}")  # quick debug print

    def err(self, code=None):
        if code is None:
            code = ctypes.get_last_error()
        return f"Error {code}: {ctypes.FormatError(code)}"

    def find_sysmainn(self):
        self.log("Looking for SysMain PID")
        try:
            svcMgr = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
            svc = win32service.OpenService(svcMgr, "SysMain", win32service.SERVICE_QUERY_STATUS)
            status = win32service.QueryServiceStatusEx(svc)
            pid = status.get("ProcessId", 0)
            if pid:
                self.log(f"Got SysMain at PID {pid}")
                win32service.CloseServiceHandle(svc)
                win32service.CloseServiceHandle(svcMgr)
                return pid
            win32service.CloseServiceHandle(svc)
            win32service.CloseServiceHandle(svcMgr)
        except Exception as e:
            self.log(f"SysMain lookup failed: {e}")
        return None

    def getmodules(self, pid):
        self.log(f"listing modules for PID {pid}")
        mods = {}
        perms = [QUERY_FULL | procRead, queryLite | procRead, procRead, 0x1000 | 0x0010]
        
        for p in perms:  # trying different access levels
            self.log(f"trying perms 0x{p:x}")
            try:
                h = open_proc(p, False, pid)
                if not h:
                    self.log(f"OpenProcess failed: {self.err()}")
                    continue
                self.log(f"Handle grabbed: 0x{h:x}")
                
                # basic module enum
                try:
                    enumMods = psapi.EnumProcessModules
                    enumMods.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.HMODULE), ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
                    enumMods.restype = ctypes.wintypes.BOOL
                    
                    modArr = (ctypes.wintypes.HMODULE * 1024)()
                    needed = ctypes.wintypes.DWORD()
                    
                    if enumMods(h, modArr, ctypes.sizeof(modArr), ctypes.byref(needed)) and needed.value > 0:
                        n = needed.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
                        self.log(f"Found {n} modules")
                        
                        for i in range(min(n, 1024)):
                            mod = modArr[i]
                            if not mod:
                                continue
                            buf = ctypes.create_string_buffer(MAXPATH)
                            if getModFileName(h, mod, buf, MAXPATH):
                                path = buf.value.decode("ascii", errors="ignore")
                                info = moduleinfo()
                                if getmoduleinfo(h, mod, ctypes.byref(info), ctypes.sizeof(info)):
                                    name = os.path.basename(path).lower()
                                    mods[name] = {"base": info.base, "sz": info.size, "path": path, "h": mod}
                                    self.log(f"Module {name} at 0x{info.base:x}")
                        if mods:
                            close_h(h)
                            return mods
                    else:
                        self.log(f"EnumMods failed: {self.err()}")
                except:
                    self.log("Basic enum crashed, trying extended...")
                
                # fallback to extended enum
                for flag in [0x03, 0x01, 0x02]:
                    try:
                        modArr = (ctypes.wintypes.HMODULE * 1024)()
                        needed = ctypes.wintypes.DWORD()
                        if enumModsEx(h, modArr, ctypes.sizeof(modArr), ctypes.byref(needed), flag) and needed.value > 0:
                            n = needed.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
                            self.log(f"Extended enum found {n} modules (flag={flag})")
                            for i in range(min(n, 1024)):
                                mod = modArr[i]
                                if not mod:
                                    continue
                                buf = ctypes.create_string_buffer(MAXPATH)
                                if getModFileName(h, mod, buf, MAXPATH):
                                    path = buf.value.decode("ascii", errors="ignore")
                                    info = moduleinfo()
                                    if getmoduleinfo(h, mod, ctypes.byref(info), ctypes.sizeof(info)):
                                        name = os.path.basename(path).lower()
                                        mods[name] = {"base": info.base, "sz": info.size, "path": path, "h": mod}
                            if mods:
                                close_h(h)
                                return mods
                    except Exception as e:
                        self.log(f"Extended enum flag {flag} failed: {e}")
                
                # last resort: manual scan
                self.log("Going manual...")
                mods = self.memscan(h, pid)
                close_h(h)
                if mods:
                    return mods
                close_h(h)
                
            except Exception as e:
                self.log(f"Attempt failed: {e}")
        
        self.log(f"Got {len(mods)} modules")
        return mods

    def memscan(self, h, pid):
        mods = {}
        addr = 0x10000
        maxAddr = 0x7FFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 4 else 0x7FFFFFFFFFFF
        i = 0
        
        while addr < maxAddr and i < 10000:
            i += 1
            mem = memoryinfo()
            if virtQuery(h, ctypes.c_void_p(addr), ctypes.byref(mem), ctypes.sizeof(mem)):
                if mem.state == 0x1000 and mem.type == 0x1000000 and mem.regionSz > 0x1000:
                    try:
                        buf = (ctypes.c_ubyte * 0x1000)()
                        n = ctypes.c_size_t(0)
                        if readMem(h, ctypes.c_void_p(mem.baseAddr), ctypes.byref(buf), 0x1000, ctypes.byref(n)):
                            if n.value >= 0x40 and buf[0] == 0x4D and buf[1] == 0x5A:  # MZ header
                                data = bytes(buf[:n.value])
                                if b"ntdll.dll" in data or b"NtCreateFile" in data:
                                    mods["ntdll.dll"] = {
                                        "base": mem.baseAddr,
                                        "sz": mem.regionSz,
                                        "path": "C:\\Windows\\System32\\ntdll.dll",
                                        "h": mem.baseAddr
                                    }
                                    self.log(f"Manual scan found ntdll.dll at 0x{mem.baseAddr:x}")
                                    break
                    except:
                        pass
                addr = mem.baseAddr + mem.regionSz
                if addr <= mem.baseAddr:
                    break
            else:
                addr += 0x10000
        return mods

    def readfunc(self, base, fname, h=None):
        if h is None:
            ntdll = getModHandle(b"ntdll.dll")
            if not ntdll:
                raise RuntimeError("No local ntdll handle")
            addr = getProcAddr(ntdll, fname)
            if not addr:
                raise RuntimeError(f"Cant find {fname.decode()}")
            buf = (ctypes.c_ubyte * chunkSz)()
            ctypes.memmove(buf, addr, chunkSz)
            return bytes(buf), addr
        else:
            ntdll = getModHandle(b"ntdll.dll")
            localAddr = getProcAddr(ntdll, fname)
            offset = localAddr - ntdll
            remoteAddr = base + offset
            buf = (ctypes.c_ubyte * chunkSz)()
            n = ctypes.c_size_t(0)
            if not readMem(h, ctypes.c_void_p(remoteAddr), ctypes.byref(buf), chunkSz, ctypes.byref(n)):
                raise RuntimeError(f"Read failed: {self.err()}")
            return bytes(buf), remoteAddr

    def checkpatch(self, clean, dirty, fname):
        res = {"patched": False, "info": []}
        if clean == dirty:
            res["info"].append("No patches found")
            return res
        
        # checking the first 16 bytes for differences, from my testing it only changed 9 bytes, so we're doing 16
        x = clean[:16]
        y = dirty[:16]
        diff = 0
        for i in range(16):
            if x[i] != y[i]:
                diff += 1
        if diff > 0:
            res["patched"] = True
            res["info"].append(f"Patch detected: {diff}/16 bytes changed")
            res["info"].append(f"Clean: {x.hex().upper()}")
            res["info"].append(f"Dirty: {y.hex().upper()}")
        return res

    def run(self):
        print("starting patch check...")
        print("-" * 40)
        
        pid = self.find_sysmainn()
        if not pid:
            print("SysMain not found :(")
            return "Failed to find SysMain"
        
        print(f"Found SysMain at PID {pid}")
        mods = self.getmodules(pid)
        if "ntdll.dll" not in mods:
            print("ntdll.dll missing!")
            return "No ntdll.dll found"
        
        ntdll = mods["ntdll.dll"]
        print(f"ntdll at 0x{ntdll['base']:x}, size {ntdll['sz']}")
        
        print("\nChecking functions:")
        cnt = 0
        h = open_proc(QUERY_FULL | procRead, False, pid)
        if not h:
            print(f"Can't open process: {self.err()}")
            return "Process open failed" 
        try:
            for f in self.funcs:
                try:
                    clean, c_addr = self.readfunc(ntdll["base"], f)
                    dirty, d_addr = self.readfunc(ntdll["base"], f, h)
                    result = self.checkpatch(clean, dirty, f)
                    
                    fname = f.decode()
                    if result["patched"]:
                        cnt += 1
                        print(f"\n{fname} (0x{d_addr:x}):")
                        for line in result["info"]:
                            print(f"  {line}")
                    else:
                        print(f"{fname}: clean")
                except Exception as e:
                    print(f"{f.decode()}: error - {e}")
        finally:
            close_h(h)
        
        print("\nDone:")
        print("-" * 40)
        if cnt == 0:
            return "System looks clean!"
        return f"Found {cnt} patched functions!"

def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print('Run as admin')
        return
    
    checker = patchchecker()
    res = checker.run()
    print(f"Result: {res}")
    time.sleep(5)

if __name__ == '__main__':
    main()
