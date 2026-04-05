use std::collections::HashMap;
use tracing::debug;

/// Look up a MAC address for a given IP by reading the system ARP/NDP table.
/// Returns the MAC in lowercase colon-separated format (e.g. "aa:bb:cc:dd:ee:ff").
/// Works for both IPv4 (ARP via /proc/net/arp) and IPv6 (NDP via `ip -6 neigh`).
pub fn lookup_mac(ip: &str) -> Option<String> {
    let table = read_arp_table();
    if let Some(mac) = table.get(ip) {
        return Some(mac.clone());
    }

    // Fall back to IPv6 neighbor table if not found in ARP
    let table = read_ndp_table();
    table.get(ip).cloned()
}

/// Read the ARP table into an IP → MAC map.
/// On Linux, reads /proc/net/arp. On other platforms, returns an empty map.
#[cfg(target_os = "linux")]
fn read_arp_table() -> HashMap<String, String> {
    let mut map = HashMap::new();

    if let Ok(contents) = std::fs::read_to_string("/proc/net/arp") {
        // Format: IP address, HW type, Flags, HW address, Mask, Device
        // Skip header line
        for line in contents.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 {
                let ip = fields[0].to_string();
                let mac = fields[3].to_lowercase();
                // Skip incomplete entries (00:00:00:00:00:00)
                if mac != "00:00:00:00:00:00" {
                    map.insert(ip, mac);
                }
            }
        }
    }

    debug!("ARP table: {} entries", map.len());
    map
}

#[cfg(not(target_os = "linux"))]
fn read_arp_table() -> HashMap<String, String> {
    debug!("ARP lookup not supported on this platform");
    HashMap::new()
}

/// Read the IPv6 neighbor (NDP) table into an IP → MAC map.
/// On Linux, runs `ip -6 neigh` to get IPv6 neighbor entries.
#[cfg(target_os = "linux")]
fn read_ndp_table() -> HashMap<String, String> {
    let mut map = HashMap::new();

    // `ip -6 neigh` output format: "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    if let Ok(output) = std::process::Command::new("ip")
        .args(["-6", "neigh"])
        .output()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            for line in stdout.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // Find the "lladdr" field and take the MAC after it
                if let Some(pos) = fields.iter().position(|&f| f == "lladdr") {
                    if pos + 1 < fields.len() {
                        let ip = fields[0].to_string();
                        let mac = fields[pos + 1].to_lowercase();
                        if mac != "00:00:00:00:00:00" {
                            map.insert(ip, mac);
                        }
                    }
                }
            }
        }
    }

    debug!("NDP table: {} entries", map.len());
    map
}

#[cfg(not(target_os = "linux"))]
fn read_ndp_table() -> HashMap<String, String> {
    debug!("NDP lookup not supported on this platform");
    HashMap::new()
}
