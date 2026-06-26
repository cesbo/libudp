//! Interface name resolution.

use std::{
    ffi::CString,
    io,
    net::Ipv4Addr,
};

/// Resolve an interface name to its kernel interface index.
pub fn interface_index(name: &str) -> io::Result<u32> {
    let cname = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // SAFETY: cname is a valid NUL-terminated C string for the duration of the
    // call; if_nametoindex only reads it.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface not found: {name}"),
        ));
    }
    Ok(idx)
}

/// RAII guard that frees a `getifaddrs`.
struct IfAddrs(*mut libc::ifaddrs);

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

/// Resolve an interface name to its first IPv4 address.
pub fn interface_ipv4(name: &str) -> io::Result<Ipv4Addr> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();

    let rc = unsafe { libc::getifaddrs(&mut head) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // Take ownership so the list is freed on every return path below.
    let _guard = IfAddrs(head);

    let mut cur = head;
    while !cur.is_null() {
        let node = unsafe { &*cur };
        cur = node.ifa_next;

        if node.ifa_name.is_null() || node.ifa_addr.is_null() {
            continue;
        }

        let this_name = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) };
        if this_name.to_bytes() != name.as_bytes() {
            continue;
        }

        let family = unsafe { (*node.ifa_addr).sa_family };
        if i32::from(family) != libc::AF_INET {
            continue;
        }

        let sin = node.ifa_addr as *const libc::sockaddr_in;
        let s_addr = unsafe { (*sin).sin_addr.s_addr };

        return Ok(Ipv4Addr::from(u32::from_be(s_addr)));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("interface has no IPv4 address: {name}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_index_lo() {
        // On Linux the loopback interface is always index 1.
        assert_eq!(interface_index("lo").unwrap(), 1);
    }

    #[test]
    fn interface_index_missing() {
        let err = interface_index("definitely-no-such-iface-zzz").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn interface_index_interior_nul() {
        let err = interface_index("lo\0bad").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn interface_ipv4_lo() {
        assert_eq!(interface_ipv4("lo").unwrap(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn interface_ipv4_missing() {
        let err = interface_ipv4("definitely-no-such-iface-zzz").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
