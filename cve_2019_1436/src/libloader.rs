use std::{
    ffi::{c_void, CString},
    mem::transmute_copy,
    ptr::NonNull,
    os::raw::c_char
};

type FarProc = NonNull<c_void>;
type HModule = NonNull<c_void>;

extern "stdcall" {
    fn LoadLibraryA(name: *const c_char) -> Option<HModule>;
    fn GetProcAddress(module: HModule, name: *const c_char) -> Option<FarProc>;
    fn GetModuleHandleA(name: *const c_char) -> Option<HModule>;
}

#[cfg(windows)]
pub struct LibLoader {
    module: HModule,
}

impl LibLoader {
    pub fn load_library(name: &str) -> Option<Self> {
        let name = CString::new(name).expect("CString::new failed");
        let resource = unsafe { LoadLibraryA(name.as_ptr()) };
        //println!("Loaded Library Address: {:?}", resource.unwrap());
        resource.map(|module| LibLoader { module })
    }

    pub fn get_proc<T>(&self, name: &str) -> Option<T> {
        let name = CString::new(name).expect("CString::new failed");
        let resource = unsafe { GetProcAddress(self.module, name.as_ptr()) };
        //println!("Exported function address: {:?}", resource.unwrap());
        resource.map(|proc| unsafe { transmute_copy(&proc) })
    }

    pub fn get_modulehandle(name: &str) -> Option<Self> {
        let name = CString::new(name).expect("Cstring::new failed");
        let resource = unsafe { GetModuleHandleA(name.as_ptr()) };
        //println!("Module address: {:?}", resource.unwrap());
        resource.map(|module| LibLoader { module })
    }
}