//! `guest-network-get-interfaces` (design §3, G4, §5.5; C-5).
//!
//! Enumerates interfaces with their hardware address and unicast IP
//! addresses. Loopback interfaces (by `IFF_LOOPBACK` and by address,
//! `127/8` and `::1`) and link-local addresses (`169.254/16`, `fe80::/10`)
//! are filtered out to limit host visibility into overlay and management
//! networks. An interface whose only addresses were link-local is still
//! listed, with an empty `ip-addresses` array, matching upstream
//! behaviour: the host learns the interface exists but not its
//! link-local address.
//!
//! Output is deterministic: interfaces are sorted by name; addresses keep
//! the order the kernel reported them in.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;

use crate::dispatch::Context;
use crate::handlers::NoArgs;
use crate::proto::{Error, Request, arguments};

/// One record from the kernel, before filtering: an interface name with
/// either a link-layer address or one IP address and its netmask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAddr {
    /// Interface name.
    pub ifname: String,
    /// `IFF_LOOPBACK` is set on the interface.
    pub loopback: bool,
    /// Link-layer (MAC) address, when this record is an `AF_PACKET` entry
    /// with a 6-byte address.
    pub mac: Option<[u8; 6]>,
    /// IP address, when this record is an `AF_INET`/`AF_INET6` entry.
    pub addr: Option<IpAddr>,
    /// Netmask for `addr`.
    pub netmask: Option<IpAddr>,
}

/// Where interface records come from; production uses `getifaddrs(3)`.
pub trait InterfaceSource: Send + Sync {
    /// Every record for every interface, in kernel order.
    fn addresses(&self) -> Result<Vec<RawAddr>, Error>;
}

/// Production source over `nix::ifaddrs::getifaddrs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemInterfaces;

impl InterfaceSource for SystemInterfaces {
    fn addresses(&self) -> Result<Vec<RawAddr>, Error> {
        let iter = nix::ifaddrs::getifaddrs()
            .map_err(|errno| Error::Internal(format!("getifaddrs failed: {errno}")))?;
        Ok(iter
            .map(|ifa| {
                let loopback = ifa
                    .flags
                    .contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK);
                let mac = ifa
                    .address
                    .as_ref()
                    .and_then(|a| a.as_link_addr())
                    .filter(|link| link.halen() == 6)
                    .and_then(|link| link.addr());
                let addr = ifa.address.as_ref().and_then(to_ip);
                let netmask = ifa.netmask.as_ref().and_then(to_ip);
                RawAddr {
                    ifname: ifa.interface_name,
                    loopback,
                    mac,
                    addr,
                    netmask,
                }
            })
            .collect())
    }
}

fn to_ip(addr: &nix::sys::socket::SockaddrStorage) -> Option<IpAddr> {
    if let Some(v4) = addr.as_sockaddr_in() {
        return Some(IpAddr::V4(v4.ip()));
    }
    if let Some(v6) = addr.as_sockaddr_in6() {
        return Some(IpAddr::V6(v6.ip()));
    }
    None
}

/// One `GuestIpAddress` (C-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpAddress {
    /// Textual address.
    #[serde(rename = "ip-address")]
    pub ip_address: String,
    /// `"ipv4"` or `"ipv6"`.
    #[serde(rename = "ip-address-type")]
    pub ip_address_type: &'static str,
    /// Prefix length derived from the netmask.
    pub prefix: u8,
}

/// One `GuestNetworkInterface` (C-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interface {
    /// Interface name.
    pub name: String,
    /// Lowercase colon-separated MAC, omitted when the interface has none.
    #[serde(rename = "hardware-address", skip_serializing_if = "Option::is_none")]
    pub hardware_address: Option<String>,
    /// Unicast addresses after filtering (may be empty).
    #[serde(rename = "ip-addresses")]
    pub ip_addresses: Vec<IpAddress>,
}

/// `true` for addresses the host must not see (§3): loopback and
/// link-local.
pub fn is_filtered(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || is_unicast_link_local_v6(v6),
    }
}

/// `fe80::/10`.
fn is_unicast_link_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// Prefix length of a netmask; `None` when the mask is not contiguous.
pub fn prefix_len(netmask: &IpAddr) -> Option<u8> {
    match netmask {
        IpAddr::V4(mask) => {
            let bits = u32::from(*mask);
            let ones = bits.leading_ones();
            (bits.checked_shl(ones).unwrap_or(0) == 0).then_some(ones as u8)
        }
        IpAddr::V6(mask) => {
            let bits = u128::from(*mask);
            let ones = bits.leading_ones();
            (bits.checked_shl(ones).unwrap_or(0) == 0).then_some(ones as u8)
        }
    }
}

/// Formats a MAC as lowercase colon-separated hex.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Groups, filters and sorts raw records into the reply.
pub fn collect(records: impl IntoIterator<Item = RawAddr>) -> Vec<Interface> {
    let mut by_name: BTreeMap<String, Interface> = BTreeMap::new();
    let mut loopbacks: Vec<String> = Vec::new();
    for record in records {
        if record.loopback {
            loopbacks.push(record.ifname.clone());
        }
        let entry = by_name
            .entry(record.ifname.clone())
            .or_insert_with(|| Interface {
                name: record.ifname.clone(),
                hardware_address: None,
                ip_addresses: Vec::new(),
            });
        if let Some(mac) = record.mac {
            entry.hardware_address = Some(format_mac(&mac));
        }
        if let Some(addr) = record.addr {
            if is_filtered(&addr) {
                continue;
            }
            let prefix = record
                .netmask
                .as_ref()
                .and_then(prefix_len)
                .unwrap_or(match addr {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                });
            entry.ip_addresses.push(IpAddress {
                ip_address: addr.to_string(),
                ip_address_type: match addr {
                    IpAddr::V4(_) => "ipv4",
                    IpAddr::V6(_) => "ipv6",
                },
                prefix,
            });
        }
    }
    for name in loopbacks {
        by_name.remove(&name);
    }
    by_name.into_values().collect()
}

/// Convenience for the tests and the handler: a plain IPv4 netmask.
pub fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// Bound on the encoded reply (§5.10, #43 §6): a guest with more
/// interfaces and addresses than fit is answered with an explicit error,
/// never a truncated list. 256 KiB is thousands of addresses.
pub const MAX_INTERFACES_REPLY_BYTES: usize = 256 * 1024;

/// `guest-network-get-interfaces` handler.
pub async fn handle(ctx: &Context, req: &Request) -> Result<Value, Error> {
    let NoArgs {} = arguments(req)?;
    let source: Arc<dyn InterfaceSource> = Arc::clone(&ctx.interfaces);
    let interfaces = collect(source.addresses()?);
    crate::handlers::bounded_reply("interfaces", &interfaces, MAX_INTERFACES_REPLY_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn link(ifname: &str, loopback: bool, mac: Option<[u8; 6]>) -> RawAddr {
        RawAddr {
            ifname: ifname.into(),
            loopback,
            mac,
            addr: None,
            netmask: None,
        }
    }

    fn ip(ifname: &str, addr: &str, netmask: Option<&str>) -> RawAddr {
        RawAddr {
            ifname: ifname.into(),
            loopback: false,
            mac: None,
            addr: Some(addr.parse().unwrap()),
            netmask: netmask.map(|m| m.parse().unwrap()),
        }
    }

    fn names(ifaces: &[Interface]) -> Vec<&str> {
        ifaces.iter().map(|i| i.name.as_str()).collect()
    }

    #[test]
    fn loopback_interface_is_dropped() {
        // By flag, even though the address itself is not 127/8.
        let out = collect([
            link("lo", true, Some([0; 6])),
            ip("lo", "10.0.0.1", Some("255.0.0.0")),
            link("eth0", false, Some([0xde, 0xad, 0xbe, 0xef, 0, 1])),
            ip("eth0", "192.0.2.10", Some("255.255.255.0")),
        ]);
        assert_eq!(names(&out), ["eth0"]);
        // By address: 127/8 and ::1 on a non-loopback interface are dropped
        // but the interface survives with its other addresses.
        let out = collect([
            ip("dummy0", "127.0.0.2", Some("255.0.0.0")),
            ip(
                "dummy0",
                "::1",
                Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            ),
            ip("dummy0", "198.51.100.1", Some("255.255.255.0")),
        ]);
        assert_eq!(names(&out), ["dummy0"]);
        assert_eq!(out[0].ip_addresses.len(), 1);
        assert_eq!(out[0].ip_addresses[0].ip_address, "198.51.100.1");
    }

    #[test]
    fn link_local_addresses_are_dropped() {
        let out = collect([
            ip("eth0", "169.254.7.8", Some("255.255.0.0")),
            ip("eth0", "fe80::1", Some("ffff:ffff:ffff:ffff::")),
            ip("eth0", "febf::1", Some("ffff:ffff:ffff:ffff::")),
            ip("eth0", "2001:db8::1", Some("ffff:ffff:ffff:ffff::")),
            ip("eth0", "10.1.2.3", Some("255.255.255.0")),
            // Only link-local: listed with an empty address list.
            ip("eth1", "169.254.1.1", Some("255.255.0.0")),
            ip("eth1", "fe80::2", Some("ffff:ffff:ffff:ffff::")),
        ]);
        assert_eq!(names(&out), ["eth0", "eth1"]);
        let eth0: Vec<&str> = out[0]
            .ip_addresses
            .iter()
            .map(|a| a.ip_address.as_str())
            .collect();
        assert_eq!(eth0, ["2001:db8::1", "10.1.2.3"]);
        assert!(out[1].ip_addresses.is_empty());
        // fec0::/10 is *not* link-local (site-local, deprecated but routable).
        assert!(!is_filtered(&"fec0::1".parse().unwrap()));
        assert!(is_filtered(&"fe80::".parse().unwrap()));
        assert!(is_filtered(&"febf:ffff::1".parse().unwrap()));
        assert!(!is_filtered(&"fe00::1".parse().unwrap()));
        assert!(!is_filtered(&"fc00::1".parse().unwrap()));
        assert!(is_filtered(&"169.254.255.255".parse().unwrap()));
        assert!(!is_filtered(&"169.255.0.1".parse().unwrap()));
    }

    #[test]
    fn prefix_is_derived_from_netmask() {
        assert_eq!(prefix_len(&v4(255, 255, 255, 0)), Some(24));
        assert_eq!(prefix_len(&v4(255, 255, 255, 255)), Some(32));
        assert_eq!(prefix_len(&v4(0, 0, 0, 0)), Some(0));
        assert_eq!(prefix_len(&v4(255, 255, 0, 255)), None, "non-contiguous");
        assert_eq!(
            prefix_len(&"ffff:ffff:ffff:ffff::".parse().unwrap()),
            Some(64)
        );
        assert_eq!(
            prefix_len(&"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()),
            Some(128)
        );
        assert_eq!(prefix_len(&"::".parse().unwrap()), Some(0));
        assert_eq!(prefix_len(&"ffff::ffff".parse().unwrap()), None);

        let out = collect([
            ip("eth0", "192.0.2.10", Some("255.255.255.0")),
            ip("eth0", "2001:db8::1", Some("ffff:ffff:ffff:ffff::")),
            ip("eth0", "192.0.2.11", None),
            ip("eth0", "2001:db8::2", None),
            ip("eth0", "192.0.2.12", Some("255.0.255.0")),
        ]);
        let prefixes: Vec<u8> = out[0].ip_addresses.iter().map(|a| a.prefix).collect();
        // Missing or malformed masks fall back to a host prefix.
        assert_eq!(prefixes, [24, 64, 32, 128, 32]);
    }

    #[test]
    fn hardware_address_is_lowercase_colon_hex_and_omitted_when_absent() {
        let out = collect([
            link("eth0", false, Some([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x0A])),
            ip("eth0", "192.0.2.10", Some("255.255.255.0")),
            ip("tun0", "10.8.0.2", Some("255.255.255.255")),
        ]);
        assert_eq!(
            out[0].hardware_address.as_deref(),
            Some("de:ad:be:ef:00:0a")
        );
        assert_eq!(out[1].hardware_address, None);
        let value = json!(out);
        assert_eq!(value[0]["hardware-address"], "de:ad:be:ef:00:0a");
        assert!(value[1].get("hardware-address").is_none());
        assert_eq!(
            format_mac(&[0, 1, 2, 0xab, 0xcd, 0xef]),
            "00:01:02:ab:cd:ef"
        );
    }

    #[test]
    fn addresses_are_grouped_by_interface_and_sorted_by_name() {
        let out = collect([
            ip("eth1", "10.0.1.1", Some("255.255.255.0")),
            ip("eth0", "10.0.0.1", Some("255.255.255.0")),
            ip("eth1", "10.0.1.2", Some("255.255.255.0")),
            link("br0", false, Some([1, 2, 3, 4, 5, 6])),
            ip("eth0", "10.0.0.2", Some("255.255.255.0")),
        ]);
        assert_eq!(names(&out), ["br0", "eth0", "eth1"]);
        let eth1: Vec<&str> = out[2]
            .ip_addresses
            .iter()
            .map(|a| a.ip_address.as_str())
            .collect();
        assert_eq!(
            eth1,
            ["10.0.1.1", "10.0.1.2"],
            "kernel order within an interface"
        );
        assert_eq!(out[1].ip_addresses.len(), 2);
        assert!(out[0].ip_addresses.is_empty());
        // Same input in a different order yields the same output.
        let again = collect([
            ip("eth0", "10.0.0.1", Some("255.255.255.0")),
            ip("eth0", "10.0.0.2", Some("255.255.255.0")),
            link("br0", false, Some([1, 2, 3, 4, 5, 6])),
            ip("eth1", "10.0.1.1", Some("255.255.255.0")),
            ip("eth1", "10.0.1.2", Some("255.255.255.0")),
        ]);
        assert_eq!(again, out);
        assert!(collect(Vec::new()).is_empty());
    }

    #[test]
    fn output_uses_qapi_field_names() {
        let out = collect([
            link("eth0", false, Some([1, 2, 3, 4, 5, 6])),
            ip("eth0", "192.0.2.10", Some("255.255.255.0")),
            ip("eth0", "2001:db8::1", Some("ffff:ffff:ffff:ffff::")),
        ]);
        let value = json!(out);
        let iface = &value[0];
        let mut keys: Vec<&str> = iface
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["hardware-address", "ip-addresses", "name"]);
        let addrs = iface["ip-addresses"].as_array().unwrap();
        for addr in addrs {
            let mut keys: Vec<&str> = addr
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, ["ip-address", "ip-address-type", "prefix"]);
        }
        assert_eq!(addrs[0]["ip-address-type"], "ipv4");
        assert_eq!(addrs[0]["prefix"], 24);
        assert_eq!(addrs[1]["ip-address-type"], "ipv6");
        assert_eq!(addrs[1]["ip-address"], "2001:db8::1");
        assert_eq!(addrs[1]["prefix"], 64);
    }

    #[test]
    fn system_source_never_reports_loopback_or_link_local() {
        let records = SystemInterfaces.addresses().unwrap();
        let out = collect(records);
        for iface in &out {
            assert_ne!(iface.name, "lo");
            for addr in &iface.ip_addresses {
                let parsed: IpAddr = addr.ip_address.parse().unwrap();
                assert!(!is_filtered(&parsed), "{addr:?}");
                assert!(addr.prefix <= 128);
            }
            if let Some(mac) = &iface.hardware_address {
                assert_eq!(mac.len(), 17);
                assert_eq!(mac.to_lowercase(), *mac);
            }
        }
    }

    struct Fake(Vec<RawAddr>);

    impl InterfaceSource for Fake {
        fn addresses(&self) -> Result<Vec<RawAddr>, Error> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn a_reply_beyond_the_bound_is_an_explicit_error_not_a_truncated_list() {
        // #43 §6: thousands of interfaces with an address each exceed the
        // reply bound; the command fails naming it. A few hundred are
        // answered whole.
        let records = |n: u32| -> Vec<RawAddr> {
            (0..n)
                .flat_map(|i| {
                    let name = format!("veth{i:05}");
                    let octets = i.to_be_bytes();
                    [
                        link(
                            &name,
                            false,
                            Some([2, 0, octets[1], octets[2], octets[3], 1]),
                        ),
                        ip(
                            &name,
                            &format!("10.{}.{}.{}", octets[1], octets[2], octets[3]),
                            Some("255.255.255.0"),
                        ),
                    ]
                })
                .collect()
        };
        let req =
            crate::proto::parse_request(br#"{"execute":"guest-network-get-interfaces"}"#).unwrap();
        let ctx = Context::for_tests().with_interfaces(Arc::new(Fake(records(4_000))));
        let err = handle(&ctx, &req).await.unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("over the 262144 byte bound") && text.contains("not truncated"),
            "{text}"
        );
        let ctx = Context::for_tests().with_interfaces(Arc::new(Fake(records(500))));
        let value = handle(&ctx, &req).await.unwrap();
        assert_eq!(value.as_array().unwrap().len(), 500);
    }

    #[tokio::test]
    async fn handler_uses_context_source_and_rejects_arguments() {
        let ctx = Context::for_tests().with_interfaces(Arc::new(Fake(vec![
            link("lo", true, None),
            ip("lo", "127.0.0.1", Some("255.0.0.0")),
            link("eth0", false, Some([1, 2, 3, 4, 5, 6])),
            ip("eth0", "192.0.2.10", Some("255.255.255.0")),
        ])));
        let req =
            crate::proto::parse_request(br#"{"execute":"guest-network-get-interfaces"}"#).unwrap();
        let value = handle(&ctx, &req).await.unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1);
        assert_eq!(value[0]["name"], "eth0");
        let req = crate::proto::parse_request(
            br#"{"execute":"guest-network-get-interfaces","arguments":{"x":1}}"#,
        )
        .unwrap();
        assert!(matches!(
            handle(&ctx, &req).await,
            Err(Error::InvalidArguments(_))
        ));
    }
}
