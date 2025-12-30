use std::path::{Path, PathBuf};
use sysinfo::{System, Pid};

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::RestartManager::{
    RmStartSession, RmRegisterResources, RmGetList, RM_PROCESS_INFO,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, ERROR_MORE_DATA, CloseHandle, HANDLE, MAX_PATH};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::ProcessStatus::GetProcessImageFileNameW;

#[cfg(target_os = "windows")]
fn get_exe_path_windows(pid: u32) -> Option<String> {
    unsafe {
        let handle: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if !handle.is_null() {
            let mut buffer = [0u16; MAX_PATH as usize];
            let mut size = buffer.len() as u32;

            if QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) != 0 {
                CloseHandle(handle);
                return Some(String::from_utf16_lossy(&buffer[..size as usize]));
            }
            
            size = buffer.len() as u32;
            if GetProcessImageFileNameW(handle, buffer.as_mut_ptr(), size) != 0 {
                let path = String::from_utf16_lossy(&buffer);
                let end = path.find('\0').unwrap_or(path.len());
                CloseHandle(handle);
                return Some(path[..end].to_string());
            }

            CloseHandle(handle);
        }
        None
    }
}

pub fn check_file(path: PathBuf, verbose: bool) {
    if verbose {
        println!("Canonicalizing path: {:?}", path);
    }
    let full_path = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            println!("Error: Could not resolve the full path for {:?}", path);
            return;
        }
    };

    println!("Inspecting file: {:?}", full_path);

    #[cfg(target_os = "windows")]
    let found_processes = get_processes_using_file_windows(&full_path);

    #[cfg(target_os = "linux")]
    let found_processes = get_processes_using_file_linux(&full_path);

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let found_processes: Vec<u32> = Vec::new();

    if verbose {
        println!("OS API found {} process(es) using the file.", found_processes.is_empty().then(|| 0).unwrap_or(found_processes.len()));
    }

    if found_processes.is_empty() {
        println!("No processes found using this file.");
        return;
    }

    if verbose {
        println!("Refreshing system process information...");
    }
    let mut sys = System::new_all();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    println!("\nProcesses using the file:");
    println!("{:<10} {:<20} {}", "PID", "Process Name", "Executable Path");
    println!("{}", "-".repeat(100));

    for pid_val in found_processes {
        let process = sys.process(Pid::from(pid_val as usize));
        
        let process_name = process
            .map(|p| p.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| "Unknown".to_string());
        
        let mut exe_path = process
            .and_then(|p| p.exe())
            .map(|p| p.to_string_lossy().into_owned());

        #[cfg(target_os = "windows")]
        if exe_path.is_none() {
            if verbose {
                println!("Attempting Windows-specific path lookup for PID {}", pid_val);
            }
            exe_path = get_exe_path_windows(pid_val);
        }
        
        let exe_path_display = exe_path.unwrap_or_else(|| "-".to_string());

        println!("{:<10} {:<20} {}", pid_val, process_name, exe_path_display);
    }
}

#[cfg(target_os = "windows")]
fn get_processes_using_file_windows(path: &Path) -> Vec<u32> {
    let mut pids = Vec::new();
    let mut session_handle = 0;
    let mut session_key = [0u16; 33]; // CCH_RM_SESSION_KEY + 1

    unsafe {
        let res = RmStartSession(&mut session_handle, 0, session_key.as_mut_ptr());
        if res != ERROR_SUCCESS {
            return pids;
        }

        let path_str = path.as_os_str().to_string_lossy();
        let path_wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();
        let path_ptr = path_wide.as_ptr();

        let res = RmRegisterResources(session_handle, 1, &path_ptr, 0, std::ptr::null(), 0, std::ptr::null());
        if res != ERROR_SUCCESS {
            windows_sys::Win32::System::RestartManager::RmEndSession(session_handle);
            return pids;
        }

        let mut n_proc_info_needed = 0;
        let mut n_proc_info = 0;
        let mut reboot_reasons = 0u32;

        // First call to get the required size
        let res = RmGetList(session_handle, &mut n_proc_info_needed, &mut n_proc_info, std::ptr::null_mut(), &mut reboot_reasons);
        
        if res == ERROR_MORE_DATA || (res == ERROR_SUCCESS && n_proc_info_needed > 0) {
            n_proc_info = n_proc_info_needed;
            let mut proc_info = vec![std::mem::zeroed::<RM_PROCESS_INFO>(); n_proc_info as usize];
            
            let res = RmGetList(session_handle, &mut n_proc_info_needed, &mut n_proc_info, proc_info.as_mut_ptr(), &mut reboot_reasons);
            if res == ERROR_SUCCESS {
                for i in 0..n_proc_info as usize {
                    pids.push(proc_info[i].Process.dwProcessId);
                }
            }
        }

        windows_sys::Win32::System::RestartManager::RmEndSession(session_handle);
    }

    pids
}

#[cfg(target_os = "linux")]
fn get_processes_using_file_linux(path: &Path) -> Vec<u32> {
    let mut pids = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if let Ok(pid) = file_name.parse::<u32>() {
                    let fd_path = entry.path().join("fd");
                    if let Ok(fds) = std::fs::read_dir(fd_path) {
                        for fd in fds.flatten() {
                            if let Ok(target) = std::fs::read_link(fd.path()) {
                                if target == path {
                                    pids.push(pid);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    pids
}
