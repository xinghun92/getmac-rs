extern crate regex;
#[macro_use]
extern crate error_chain;
#[cfg(target_os = "windows")]
extern crate winapi;

use regex::Regex;
use std::collections::HashSet;
use std::process::Command;

error_chain! {
    foreign_links {
        Regex(::regex::Error);
        IO(::std::io::Error);
        Env(::std::env::VarError);
    }
}

fn get_mac_addr_regex(delimiter: &str) -> Result<Regex> {
    Ok(Regex::new(&format!(
        "([A-Za-z0-9]{{2}}[{}]){{5}}[A-Za-z0-9]{{2}}",
        delimiter
    ))?)
}

fn get_zero_mac_addr_regex(delimiter: &str) -> Result<Regex> {
    Ok(Regex::new(&format!(
        "([0]{{2}}[{}]){{5}}[0]{{2}}",
        delimiter
    ))?)
}

fn get_mac<F>(filter: F) -> Result<HashSet<String>>
where
    F: Fn(&str) -> bool,
{
    #[cfg(target_os = "windows")]
    let output = {
        use std::env::var;
        use std::os::windows::process::CommandExt;
        use winapi::um::winbase::CREATE_NO_WINDOW;
        let root = var("SystemRoot")?;
        Command::new(format!("{}/System32/getmac.exe", root))
            .creation_flags(CREATE_NO_WINDOW)
            .output()?
    };
    #[cfg(not(target_os = "windows"))]
    let output = {
        let mut output = Command::new("/sbin/ifconfig").arg("-a").output();
        if output.is_err() {
            output = Command::new("/sbin/ip").arg("link").output();
        }
        output?
    };

    if !output.status.success() {
        return Err(Error::from(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let output = String::from_utf8_lossy(&output.stdout);
    #[cfg(target_os = "windows")]
    let delimiter = r#"\\-"#;
    #[cfg(not(target_os = "windows"))]
    let delimiter = ":";

    get_mac_from_output(filter, &output, delimiter)
}

fn get_mac_from_output<F>(filter: F, output: &str, delimiter: &str) -> Result<HashSet<String>>
where
    F: Fn(&str) -> bool,
{
    let lines = output.replace("\r\n", "\n");
    let lines: Vec<_> = lines.split("\n").collect();

    let mac_addr = get_mac_addr_regex(delimiter)?;
    let zero_mac_addrs = get_zero_mac_addr_regex(delimiter)?;

    let mut mac_addrs = HashSet::new();
    for line in lines {
        if !filter(line) {
            continue;
        }

        for cap in mac_addr.captures_iter(line) {
            let addr = cap
                .get(0)
                .ok_or_else(|| "addr not found")?
                .as_str()
                .to_owned();
            if zero_mac_addrs.is_match(&addr) {
                continue;
            }
            mac_addrs.insert(addr);
        }
    }

    Ok(mac_addrs)
}

/// Get specified mac address base on filter
pub fn get_mac_addrs_with_filter<F>(filter: F) -> Result<HashSet<String>>
where
    F: Fn(&str) -> bool,
{
    get_mac(filter)
}

fn default_filter(_: &str) -> bool {
    true
}

/// Get all mac addresses in this machine
pub fn get_all_mac_addrs() -> Result<HashSet<String>> {
    get_mac(default_filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOWS_OUTPUT: &str =
        "Physical Address    Transport Name\n \
         =================== ==========================================================\n \
         10-7B-44-8E-84-A5   \\Device\\Tcpip_{B4B2EBCC-E6AD-4763-A8F5-9D04D3698ED5}\n \
         00-19-86-00-17-11   Media disconnected\n \
         N/A                 Hardware not present\n";

    const LINUX_OUTPUT: &str =
        "eth0      Link encap:Ethernet  HWaddr 10:7b:44:8e:84:a5\n \
         inet addr:192.168.1.8  Bcast:192.168.1.255  Mask:255.255.255.0\n \
         inet6 addr: fe80::10f2:55a9:169:9fdb/64 Scope:Global\n \
         UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n \
         RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n \
         TX packets:0 errors:0 dropped:0 overruns:0 carrier:0\n \
         collisions:0\n \
         RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)\n \
         \n \
         eth1      Link encap:Ethernet  HWaddr 00:19:86:00:17:11\n \
         inet addr:169.254.233.224  Mask:255.255.0.0\n \
         inet6 addr: fe80::11f1:433d:65b0:e9e0/64 Scope:Global\n \
         RUNNING  MTU:1500  Metric:1\n \
         RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n \
         TX packets:0 errors:0 dropped:0 overruns:0 carrier:0\n \
         collisions:0\n \
         RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)\n \
         \n \
         eth2      Link encap:Ethernet  HWaddr 00:00:00:00:00:00\n \
         unspec addr:[NONE SET]  Mask:00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00\n \
         inet6 addr: 2001:0:9d38:6ab8:20fc:62:3f57:fef7/64 Scope:Global\n \
         inet6 addr: fe80::20fc:62:3f57:fef7/64 Scope:Global\n \
         UP RUNNING  MTU:1472  Metric:1\n \
         RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n \
         TX packets:0 errors:0 dropped:0 overruns:0 carrier:0\n \
         collisions:0\n \
         RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)\n \
         \n \
         lo        Link encap:Local Loopback\n \
         inet addr:127.0.0.1  Mask:255.0.0.0\n \
         inet6 addr: ::1/128 Scope:Global\n \
         UP LOOPBACK RUNNING  MTU:1500  Metric:1\n \
         RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n \
         TX packets:0 errors:0 dropped:0 overruns:0 carrier:0\n \
         collisions:0\n \
         RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)";

    const WINDOWS_DELIMITER: &str = "\\-";
    const LINUX_DELIMITER: &str = ":";

    #[test]
    fn test_windows_get_all() {
        let macs = get_mac_from_output(default_filter, WINDOWS_OUTPUT, WINDOWS_DELIMITER)
            .expect("get windows mac failed");
        let mut expected = HashSet::new();
        expected.insert("10-7B-44-8E-84-A5".to_owned());
        expected.insert("00-19-86-00-17-11".to_owned());
        assert_eq!(expected, macs);
    }

    #[test]
    fn test_windows_get_with_filter() {
        fn filter(input: &str) -> bool {
            input.contains("B4B2EBCC-E6AD-4763-A8F5-9D04D3698ED5")
        }
        let macs = get_mac_from_output(filter, WINDOWS_OUTPUT, WINDOWS_DELIMITER)
            .expect("get windows mac failed");
        let mut expected = HashSet::new();
        expected.insert("10-7B-44-8E-84-A5".to_owned());
        assert_eq!(expected, macs);
    }

    #[test]
    fn test_linux_get_all() {
        let macs = get_mac_from_output(default_filter, LINUX_OUTPUT, LINUX_DELIMITER)
            .expect("get linux mac failed");
        let mut expected = HashSet::new();
        expected.insert("10:7b:44:8e:84:a5".to_owned());
        expected.insert("00:19:86:00:17:11".to_owned());
        assert_eq!(expected, macs);
    }

    #[test]
    fn test_linux_get_with_filter() {
        fn filter(input: &str) -> bool {
            input.contains("eth0")
        }
        let macs = get_mac_from_output(filter, LINUX_OUTPUT, LINUX_DELIMITER)
            .expect("get linux mac failed");
        let mut expected = HashSet::new();
        expected.insert("10:7b:44:8e:84:a5".to_owned());
        assert_eq!(expected, macs);
    }
}
