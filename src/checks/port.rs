use netstat_esr::*;
use sysinfo::{System, Pid};

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
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
            
            // Try GetProcessImageFileNameW if QueryFullProcessImageNameW fails
            size = buffer.len() as u32;
            if GetProcessImageFileNameW(handle, buffer.as_mut_ptr(), size) != 0 {
                let path = String::from_utf16_lossy(&buffer);
                let end = path.find('\0').unwrap_or(path.len());
                CloseHandle(handle);
                return Some(path[..end].to_string());
            }

            CloseHandle(handle);
        }

        // Fallback for common system processes if we can't open them
        None
    }
}

pub fn check_port(port: u16, verbose: bool) {
    println!("Inspecting network port: {}", port);

    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    
    if verbose {
        println!("Retrieving socket information...");
    }
    let sockets_info = match get_sockets_info(af_flags, proto_flags) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Error: Failed to retrieve network information: {}", e);
            return;
        }
    };

    if verbose {
        println!("Found {} total active sockets.", sockets_info.len());
    }

    let mut found_any_socket = false;
    let mut matching_sockets = Vec::new();

    for si in sockets_info {
        let local_port = match &si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_info) => tcp_info.local_port,
            ProtocolSocketInfo::Udp(udp_info) => udp_info.local_port,
        };

        if local_port == port {
            if verbose {
                let (proto, addr) = match &si.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(t) => ("TCP", t.local_addr.to_string()),
                    ProtocolSocketInfo::Udp(u) => ("UDP", u.local_addr.to_string()),
                };
                println!("Match found: {} on {} (associated PIDs: {:?})", proto, addr, si.associated_pids);
            }
            found_any_socket = true;
            matching_sockets.push(si);
        }
    }

    if !found_any_socket {
        println!("No processes found listening on port {}.", port);
        return;
    }

    if verbose {
        println!("Refreshing system process information...");
    }
    let mut sys = System::new_all();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    println!("{:<10} {:<20} {:<10} {:<10} {:<20} {}", "PID", "Process Name", "Protocol", "State", "Local Address", "Executable Path");
    println!("{}", "-".repeat(120));

    let mut missing_pids = false;

    for si in matching_sockets {
        let (protocol, state, local_addr) = match &si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_info) => ("TCP", format!("{:?}", tcp_info.state), tcp_info.local_addr.to_string()),
            ProtocolSocketInfo::Udp(udp_info) => ("UDP", "-".to_string(), udp_info.local_addr.to_string()),
        };

        if si.associated_pids.is_empty() {
            println!("{:<10} {:<20} {:<10} {:<10} {:<20} {}", "Unknown", "Unknown", protocol, state, local_addr, "-");
            missing_pids = true;
        } else {
            for pid in si.associated_pids {
                let pid_val = pid as usize;
                let process = sys.process(Pid::from(pid_val));
                
                let process_name = process
                    .map(|p| p.name().to_string_lossy().into_owned())
                    .unwrap_or_else(|| "Unknown".to_string());
                
                let mut exe_path = process
                    .and_then(|p| p.exe())
                    .map(|p| p.to_string_lossy().into_owned());

                #[cfg(target_os = "windows")]
                if exe_path.is_none() {
                    if verbose {
                        println!("Attempting Windows-specific path lookup for PID {}", pid);
                    }
                    exe_path = get_exe_path_windows(pid);
                }

                // Fallback for svchost.exe if path is not found via standard APIs
                #[cfg(target_os = "windows")]
                if exe_path.is_none() && process_name.to_lowercase() == "svchost.exe" {
                    if verbose {
                        println!("Applying svchost.exe path fallback for PID {}", pid);
                    }
                    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
                    exe_path = Some(format!("{}\\System32\\svchost.exe", windir));
                }

                let exe_path_display = exe_path.unwrap_or_else(|| "-".to_string());

                println!("{:<10} {:<20} {:<10} {:<10} {:<20} {}", pid, process_name, protocol, state, local_addr, exe_path_display);
            }
        }
    }

    if missing_pids {
        println!("\nHint: Some process information could not be retrieved. Try running with elevated privileges (admin/sudo).");
    }
}
