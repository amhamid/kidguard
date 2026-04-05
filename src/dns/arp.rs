use std::collections::HashMap;
use tracing::debug;

/// Look up a MAC address for a given IP by reading the system ARP table.
/// Returns the MAC in lowercase colon-separated format (e.g. "aa:bb:cc:dd:ee:ff").
pub fn lookup_mac(ip: &str) -> Option<String> {
    let table = read_arp_table();
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
