//! Multicast membership: ASM and SSM, via raw libc setsockopt.

use std::{
    io,
    mem,
    net::{
        Ipv4Addr,
        SocketAddrV4,
    },
    os::{
        fd::{
            AsFd,
            BorrowedFd,
        },
        unix::io::AsRawFd,
    },
};

/// Source-specific multicast request, layout-compatible with the system
/// `struct group_source_req` (`/usr/include/netinet/in.h`).
#[repr(C)]
struct GroupSourceReq {
    gsr_interface: u32,
    gsr_group: libc::sockaddr_storage,
    gsr_source: libc::sockaddr_storage,
}

/// Handle for a multicast membership.
pub struct Membership {
    group: SocketAddrV4,
    ifindex: u32,
    source: Option<Ipv4Addr>,
}

impl Membership {
    /// Describe a membership in `group` (ASM, or SSM when `source` is given),
    /// optionally on a named interface.
    pub fn new(
        group: SocketAddrV4,
        ifname: Option<&str>,
        source: Option<Ipv4Addr>,
    ) -> io::Result<Self> {
        if !group.ip().is_multicast() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multicast group required",
            ));
        }

        let ifindex = match ifname {
            Some(name) => crate::iface::interface_index(name).unwrap_or(0),
            None => 0,
        };

        Ok(Membership {
            group,
            ifindex,
            source,
        })
    }

    /// Build an `ip_mreqn` from the stored membership fields.
    fn ip_mreqn(&self) -> libc::ip_mreqn {
        libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from_ne_bytes(self.group.ip().octets()),
            },
            imr_address: libc::in_addr {
                s_addr: libc::INADDR_ANY,
            },
            imr_ifindex: self.ifindex as libc::c_int,
        }
    }

    /// Build a `GroupSourceReq` from the stored source-membership fields.
    fn group_source_req(&self, source: &Ipv4Addr) -> GroupSourceReq {
        GroupSourceReq {
            gsr_interface: self.ifindex,
            gsr_group: storage_from_v4(*self.group.ip(), self.group.port()),
            gsr_source: storage_from_v4(*source, 0),
        }
    }

    /// Join the group on `fd` (`IP_ADD_MEMBERSHIP` for ASM,
    /// `MCAST_JOIN_SOURCE_GROUP` for SSM).
    pub fn join(&self, fd: impl AsFd) -> io::Result<()> {
        let fd = fd.as_fd();
        if let Some(source) = &self.source {
            let gsr = self.group_source_req(source);
            unsafe { setsockopt_ip(fd, libc::MCAST_JOIN_SOURCE_GROUP, &gsr) }
        } else {
            let mreqn = self.ip_mreqn();
            unsafe { setsockopt_ip(fd, libc::IP_ADD_MEMBERSHIP, &mreqn) }
        }
    }

    /// Leave the group on `fd` (`IP_DROP_MEMBERSHIP` for ASM,
    /// `MCAST_LEAVE_SOURCE_GROUP` for SSM).
    pub fn leave(&self, fd: impl AsFd) -> io::Result<()> {
        let fd = fd.as_fd();
        if let Some(source) = &self.source {
            let gsr = self.group_source_req(source);
            unsafe { setsockopt_ip(fd, libc::MCAST_LEAVE_SOURCE_GROUP, &gsr) }
        } else {
            let mreqn = self.ip_mreqn();
            unsafe { setsockopt_ip(fd, libc::IP_DROP_MEMBERSHIP, &mreqn) }
        }
    }

    /// Renew the membership on `fd` by re-issuing the join
    /// (`IP_ADD_MEMBERSHIP` for ASM, `MCAST_JOIN_SOURCE_GROUP` for SSM).
    pub fn renew(&self, fd: impl AsFd) -> io::Result<()> {
        let fd = fd.as_fd();
        if let Some(source) = &self.source {
            let gsr = self.group_source_req(source);
            unsafe { setsockopt_ip(fd, libc::MCAST_JOIN_SOURCE_GROUP, &gsr) }
        } else {
            let mreqn = self.ip_mreqn();
            unsafe { setsockopt_ip(fd, libc::IP_ADD_MEMBERSHIP, &mreqn) }
        }
    }
}

/// Renew a multicast membership directly on a borrowed fd.
///
/// Builds a one-shot [`Membership`] from `group`/`ifname`/`source` - resolving
/// the interface name on every call, so a recreated interface is picked up -
/// and re-issues the join. Returns an error if `group` is not a multicast
/// address.
pub fn renew_membership(
    fd: impl AsFd,
    group: SocketAddrV4,
    ifname: Option<&str>,
    source: Option<Ipv4Addr>,
) -> io::Result<()> {
    Membership::new(group, ifname, source)?.renew(fd)
}

/// Build a zeroed `sockaddr_in` carrying an IPv4 address and port (host order
/// port; the `to_be` converts to network order).
fn sockaddr_in(addr: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is plain old data; an all-zero value is valid.
    let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = port.to_be();
    // octets() are already in network byte order; from_ne_bytes keeps them so.
    sin.sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
    sin
}

/// Copy a `sockaddr_in` into the front of a freshly zeroed `sockaddr_storage`.
fn storage_from_v4(addr: Ipv4Addr, port: u16) -> libc::sockaddr_storage {
    let sin = sockaddr_in(addr, port);
    let mut ss: libc::sockaddr_storage = unsafe { mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            &sin as *const libc::sockaddr_in as *const u8,
            &mut ss as *mut libc::sockaddr_storage as *mut u8,
            mem::size_of::<libc::sockaddr_in>(),
        );
    }
    ss
}

/// `setsockopt(fd, IPPROTO_IP, opt, &val, sizeof(T))`, mapping -1 to the last
/// OS error.
///
/// # Safety
/// `val` must point at an initialized value of the type the kernel expects for
/// `opt`, and `len` must be its size.
unsafe fn setsockopt_ip<T>(fd: BorrowedFd<'_>, opt: libc::c_int, val: &T) -> io::Result<()> {
    let rc = libc::setsockopt(
        fd.as_raw_fd(),
        libc::IPPROTO_IP,
        opt,
        val as *const T as *const libc::c_void,
        mem::size_of::<T>() as libc::socklen_t,
    );
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_non_multicast_is_err() {
        // 10.0.0.1 is not multicast: the constructor must reject it, so no
        // setsockopt is ever issued with a unicast group.
        let group = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234);
        let m = Membership::new(group, None, None);
        assert!(m.is_err());
    }

    #[test]
    fn new_unknown_ifname_degrades_to_index_zero() {
        let group = SocketAddrV4::new(Ipv4Addr::new(239, 255, 0, 1), 1234);
        let m = Membership::new(group, Some("no-such-if0"), None).expect("multicast group");
        assert_eq!(m.ifindex, 0);
    }

    #[test]
    fn join_renew_leave_lo_tolerant() {
        let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind");
        let group = SocketAddrV4::new(Ipv4Addr::new(239, 255, 0, 1), 1234);
        let m = Membership::new(group, Some("lo"), None).expect("multicast group");
        match m.join(&sock) {
            Ok(()) => {
                // a held membership rejects the duplicate add
                let dup = m.renew(&sock).expect_err("duplicate add");
                assert_eq!(dup.kind(), io::ErrorKind::AddrInUse);
                m.leave(&sock).expect("leave after join");
                // renew re-establishes a dropped membership
                m.renew(&sock).expect("renew after leave");
                m.leave(&sock).expect("final leave");
            }
            Err(e) => {
                let raw = e.raw_os_error();
                if matches!(
                    raw,
                    Some(libc::ENODEV) | Some(libc::EADDRNOTAVAIL) | Some(libc::EPERM)
                ) {
                    eprintln!(
                        "skip join_renew_leave_lo_tolerant: environment lacks capability ({e})"
                    );
                } else {
                    panic!("unexpected multicast join error: {e}");
                }
            }
        }
    }

    #[test]
    fn group_source_req_layout() {
        // Verified against a C probe on x86_64 glibc.
        assert_eq!(mem::size_of::<GroupSourceReq>(), 264);
        let base = 0usize;
        let g = unsafe { mem::zeroed::<GroupSourceReq>() };
        let p = &g as *const GroupSourceReq as usize;
        assert_eq!((&g.gsr_interface as *const u32 as usize) - p, base);
        assert_eq!((&g.gsr_group as *const _ as usize) - p, 8);
        assert_eq!((&g.gsr_source as *const _ as usize) - p, 136);
    }

    #[test]
    fn sockaddr_in_byte_order() {
        // 1.2.3.4 octets must land as network-order bytes in s_addr.
        let sin = sockaddr_in(Ipv4Addr::new(1, 2, 3, 4), 0x1234);
        let bytes = sin.sin_addr.s_addr.to_ne_bytes();
        assert_eq!(bytes, [1, 2, 3, 4]);
        // Port 0x1234 -> network order bytes [0x12, 0x34].
        assert_eq!(sin.sin_port.to_ne_bytes(), [0x12, 0x34]);
        assert_eq!(i32::from(sin.sin_family), libc::AF_INET);
    }
}
