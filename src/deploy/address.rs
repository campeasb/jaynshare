//! The closed list of listener addresses, and whether an address
//! is assigned to this host.

use std::net::{IpAddr, SocketAddr};

use super::result::Check;

/// The classes. Only the first four pass; the list is not configurable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    Loopback,
    /// IPv4 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
    Private,
    /// IPv4 shared address space, `100.64.0.0/10`.
    SharedAddressSpace,
    /// IPv6 unique-local, `fc00::/7`.
    UniqueLocal,
    /// `0.0.0.0`, `::`.
    Unspecified,
    /// IPv4 `169.254.0.0/16`, IPv6 `fe80::/10`.
    LinkLocal,
    Multicast,
    /// Everything else, globally routable or not.
    Global,
}

impl AddressClass {
    /// The closed list.
    pub fn passes(self) -> bool {
        matches!(
            self,
            Self::Loopback | Self::Private | Self::SharedAddressSpace | Self::UniqueLocal
        )
    }
}

/// The class of one numeric address. An IPv4-mapped IPv6 address is
/// classified as its IPv4 address.
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(ip: std::net::Ipv4Addr) -> AddressClass {
    match ip.octets() {
        [0, 0, 0, 0] => AddressClass::Unspecified,
        [127, ..] => AddressClass::Loopback,
        [10, ..] | [172, 16..=31, ..] | [192, 168, ..] => AddressClass::Private,
        [100, 64..=127, ..] => AddressClass::SharedAddressSpace,
        [169, 254, ..] => AddressClass::LinkLocal,
        [224..=239, ..] => AddressClass::Multicast,
        _ => AddressClass::Global,
    }
}

fn classify_v6(ip: std::net::Ipv6Addr) -> AddressClass {
    let segments = ip.segments();
    if segments == [0; 8] {
        AddressClass::Unspecified
    } else if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
        AddressClass::Loopback
    } else if (segments[0] & 0xfe00) == 0xfc00 {
        AddressClass::UniqueLocal
    } else if (segments[0] & 0xffc0) == 0xfe80 {
        AddressClass::LinkLocal
    } else if (segments[0] & 0xff00) == 0xff00 {
        AddressClass::Multicast
    } else {
        AddressClass::Global
    }
}

/// One native listener: passes only on the closed list.
pub fn check_listener(name: &str, listener: SocketAddr) -> Check {
    let class = classify(listener.ip());
    let message = format!("{listener} is {class:?}");
    if class.passes() {
        Check::pass(name, message)
    } else {
        Check::fail(name, message)
    }
}

/// The interface that carries `ip` on this host, or `None` when no
/// interface does.
pub fn assigned(ip: IpAddr) -> Result<Option<String>, String> {
    let addrs =
        if_addrs::get_if_addrs().map_err(|e| format!("cannot enumerate interfaces: {e}"))?;
    for interface in addrs {
        if interface.ip() == ip {
            return Ok(Some(interface.name));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};

    fn class4(s: &str) -> AddressClass {
        classify(IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()))
    }

    fn class6(s: &str) -> AddressClass {
        classify(IpAddr::V6(s.parse::<Ipv6Addr>().unwrap()))
    }

    #[test]
    fn prefailing_unspecified() {
        assert_eq!(class4("0.0.0.0"), AddressClass::Unspecified);
        assert_eq!(class6("::"), AddressClass::Unspecified);
    }

    #[test]
    fn loopback_boundaries() {
        assert_eq!(class4("126.255.255.255"), AddressClass::Global);
        assert_eq!(class4("127.0.0.0"), AddressClass::Loopback);
        assert_eq!(class4("127.255.255.255"), AddressClass::Loopback);
        assert_eq!(class4("128.0.0.0"), AddressClass::Global);
        assert_eq!(class6("::1"), AddressClass::Loopback);
    }

    #[test]
    fn private_10_boundaries() {
        assert_eq!(class4("9.255.255.255"), AddressClass::Global);
        assert_eq!(class4("10.0.0.0"), AddressClass::Private);
        assert_eq!(class4("10.255.255.255"), AddressClass::Private);
        assert_eq!(class4("11.0.0.0"), AddressClass::Global);
    }

    #[test]
    fn private_172_boundaries() {
        assert_eq!(class4("172.15.255.255"), AddressClass::Global);
        assert_eq!(class4("172.16.0.0"), AddressClass::Private);
        assert_eq!(class4("172.31.255.255"), AddressClass::Private);
        assert_eq!(class4("172.32.0.0"), AddressClass::Global);
    }

    #[test]
    fn private_192_boundaries() {
        assert_eq!(class4("192.167.255.255"), AddressClass::Global);
        assert_eq!(class4("192.168.0.0"), AddressClass::Private);
        assert_eq!(class4("192.168.255.255"), AddressClass::Private);
        assert_eq!(class4("192.169.0.0"), AddressClass::Global);
    }

    #[test]
    fn shared_address_space_boundaries() {
        assert_eq!(class4("100.63.255.255"), AddressClass::Global);
        assert_eq!(class4("100.64.0.0"), AddressClass::SharedAddressSpace);
        assert_eq!(class4("100.127.255.255"), AddressClass::SharedAddressSpace);
        assert_eq!(class4("100.128.0.0"), AddressClass::Global);
    }

    #[test]
    fn link_local_v4_boundaries() {
        assert_eq!(class4("169.253.255.255"), AddressClass::Global);
        assert_eq!(class4("169.254.0.0"), AddressClass::LinkLocal);
        assert_eq!(class4("169.254.255.255"), AddressClass::LinkLocal);
        assert_eq!(class4("169.255.0.0"), AddressClass::Global);
    }

    #[test]
    fn multicast_v4_boundaries() {
        assert_eq!(class4("223.255.255.255"), AddressClass::Global);
        assert_eq!(class4("224.0.0.0"), AddressClass::Multicast);
        assert_eq!(class4("239.255.255.255"), AddressClass::Multicast);
        assert_eq!(class4("240.0.0.0"), AddressClass::Global);
    }

    #[test]
    fn documentation_ranges_are_global() {
        assert_eq!(class4("192.0.2.1"), AddressClass::Global);
        assert_eq!(class4("198.51.100.1"), AddressClass::Global);
        assert_eq!(class4("203.0.113.1"), AddressClass::Global);
        assert_eq!(class4("255.255.255.255"), AddressClass::Global);
    }

    #[test]
    fn unique_local_boundaries() {
        assert_eq!(class6("fbff:ffff::"), AddressClass::Global);
        assert_eq!(class6("fc00::"), AddressClass::UniqueLocal);
        assert_eq!(
            class6("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            AddressClass::UniqueLocal
        );
        assert_eq!(class6("fe00::"), AddressClass::Global);
    }

    #[test]
    fn link_local_v6_boundaries() {
        assert_eq!(class6("fe7f:ffff::"), AddressClass::Global);
        assert_eq!(class6("fe80::"), AddressClass::LinkLocal);
        assert_eq!(
            class6("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            AddressClass::LinkLocal
        );
        assert_eq!(class6("fec0::"), AddressClass::Global);
    }

    #[test]
    fn multicast_v6_boundary() {
        assert_eq!(class6("ff00::"), AddressClass::Multicast);
    }

    #[test]
    fn ipv4_mapped_uses_ipv4_classification() {
        assert_eq!(
            classify(IpAddr::V6("::ffff:10.0.0.1".parse().unwrap())),
            AddressClass::Private
        );
        assert_eq!(
            classify(IpAddr::V6("::ffff:8.8.8.8".parse().unwrap())),
            AddressClass::Global
        );
    }

    #[test]
    fn every_passing_class_passes() {
        assert!(AddressClass::Loopback.passes());
        assert!(AddressClass::Private.passes());
        assert!(AddressClass::SharedAddressSpace.passes());
        assert!(AddressClass::UniqueLocal.passes());
    }

    #[test]
    fn every_failing_class_fails() {
        assert!(!AddressClass::Unspecified.passes());
        assert!(!AddressClass::LinkLocal.passes());
        assert!(!AddressClass::Multicast.passes());
        assert!(!AddressClass::Global.passes());
    }

    #[test]
    fn check_listener_passes_on_private_address() {
        let check = check_listener(
            "preflight.listener",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080)),
        );
        assert!(check.passed, "10.0.0.1 must pass");
    }

    #[test]
    fn check_listener_fails_and_names_address_and_class() {
        let check = check_listener(
            "preflight.listener",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 8080)),
        );
        assert!(!check.passed, "8.8.8.8 must fail");
        assert!(check.message.contains("8.8.8.8"), "{}", check.message);
        assert!(check.message.contains("Global"), "{}", check.message);
    }

    #[test]
    fn assigned_finds_loopback_but_not_test_net() {
        let lo = assigned(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        assert!(lo.is_some(), "127.0.0.1 must be assigned on this host");
        assert_eq!(
            assigned(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
            None,
            "192.0.2.1 (TEST-NET) must not be assigned on this host"
        );
    }
}
