use std::collections::HashMap;

pub fn well_known_service(port: u16) -> Option<&'static str> {
    // keep this list small and extendable
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        67 | 68 => Some("dhcp"),
        69 => Some("tftp"),
        80 => Some("http"),
        110 => Some("pop3"),
        123 => Some("ntp"),
        143 => Some("imap"),
        161 | 162 => Some("snmp"),
        179 => Some("bgp"),
        443 => Some("https"),
        587 => Some("smtp-submission"),
        636 => Some("ldaps"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5900 => Some("vnc"),
        8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        9000 => Some("dev-server"),
        _ => None,
    }
}

pub fn well_known_service_owned(port: u16) -> Option<String> {
    well_known_service(port).map(|s| s.to_string())
}
