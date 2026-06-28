//! UDP send-socket builder and wrapper.

use std::{
    io,
    net::SocketAddrV4,
    os::{
        fd::{
            AsFd,
            BorrowedFd,
        },
        unix::io::{
            AsRawFd,
            RawFd,
        },
    },
};

use socket2::{
    Domain,
    Protocol,
    SockAddr,
    Socket,
    Type,
};

use crate::{
    iface,
    setsockopt_ip,
};

/// A blocking AF_INET UDP send socket.
pub struct SendSocket {
    inner: Socket,
}

impl SendSocket {
    /// Create an unbound blocking AF_INET UDP socket (`SOCK_DGRAM` /
    /// `IPPROTO_UDP`). Mirrors `asc_socket_open_udp4`.
    pub fn new() -> io::Result<Self> {
        let inner = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        Ok(Self { inner })
    }

    /// Bind to `addr:port`.
    /// Set `SO_REUSEADDR` if port is not 0.
    pub fn bind(&self, addr: SocketAddrV4) -> io::Result<()> {
        if addr.port() != 0 {
            self.inner.set_reuse_address(true)?;
        }
        self.inner.bind(&SockAddr::from(addr))
    }

    /// Set the default peer so [`send`](Self::send) can be used (the
    /// connected-datagram path, mirroring a fixed-destination flow).
    pub fn connect(&self, addr: SocketAddrV4) -> io::Result<()> {
        self.inner.connect(&SockAddr::from(addr))
    }

    /// Toggle `SO_BROADCAST`.
    pub fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.inner.set_broadcast(on)
    }

    /// Select the multicast egress interface by name (`IP_MULTICAST_IF`).
    pub fn set_multicast_if(&self, ifname: &str) -> io::Result<()> {
        let ifindex = iface::interface_index(ifname)?;
        let mreqn = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: libc::INADDR_ANY,
            },
            imr_address: libc::in_addr {
                s_addr: libc::INADDR_ANY,
            },
            imr_ifindex: ifindex as libc::c_int,
        };

        unsafe { setsockopt_ip(self.as_fd(), libc::IP_MULTICAST_IF, &mreqn) }
    }

    /// Set the multicast TTL (`IP_MULTICAST_TTL`).
    pub fn set_multicast_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_multicast_ttl_v4(ttl)
    }

    /// Toggle multicast loopback (`IP_MULTICAST_LOOP`).
    pub fn set_multicast_loop(&self, on: bool) -> io::Result<()> {
        self.inner.set_multicast_loop_v4(on)
    }

    /// Set `SO_SNDBUF`.
    pub fn set_send_buffer_size(&self, bytes: usize) -> io::Result<()> {
        self.inner.set_send_buffer_size(bytes)
    }

    /// Read `SO_SNDBUF`.
    pub fn send_buffer_size(&self) -> io::Result<usize> {
        self.inner.send_buffer_size()
    }

    /// The locally bound address (resolves an ephemeral port chosen by bind 0).
    pub fn local_addr(&self) -> io::Result<SocketAddrV4> {
        let sa = self.inner.local_addr()?;
        sa.as_socket_ipv4()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "local_addr is not IPv4"))
    }

    /// Set non-blocking mode (`O_NONBLOCK`).
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Read `O_NONBLOCK`.
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.inner.nonblocking()
    }

    /// Convert into a [`std::net::UdpSocket`].
    pub fn into_std(self) -> std::net::UdpSocket {
        std::net::UdpSocket::from(self.inner)
    }
}

impl AsRawFd for SendSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsFd for SendSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn send_buffer_size_no_halving() {
        let sock = SendSocket::new().expect("new");
        // Set an exact value and confirm no halving is applied. The kernel
        // typically doubles SO_SNDBUF on readback, so we only assert the
        // readback is at least the requested value (never less, which a >>1
        // would cause).
        let want = 256 * 1024;
        sock.set_send_buffer_size(want)
            .expect("set_send_buffer_size");
        let got = sock.send_buffer_size().expect("send_buffer_size");
        assert!(
            got >= want,
            "readback {got} should be >= requested {want} (no halving)"
        );
    }

    #[test]
    fn set_nonblocking_toggles() {
        let sock = SendSocket::new().expect("new");
        // Default is blocking.
        assert!(!sock.nonblocking().expect("read default"));
        sock.set_nonblocking(true).expect("enable");
        assert!(sock.nonblocking().expect("read enabled"));
        sock.set_nonblocking(false).expect("disable");
        assert!(!sock.nonblocking().expect("read disabled"));
    }

    #[test]
    fn set_multicast_if_lo_tolerant() {
        let sock = SendSocket::new().expect("new");
        match sock.set_multicast_if("lo") {
            Ok(()) => { /* egress interface selected */ }
            Err(e) => {
                let raw = e.raw_os_error();
                if matches!(
                    raw,
                    Some(libc::ENODEV) | Some(libc::EADDRNOTAVAIL) | Some(libc::EPERM)
                ) {
                    eprintln!(
                        "skip set_multicast_if_lo_tolerant: environment lacks capability ({e})"
                    );
                } else {
                    panic!("unexpected set_multicast_if error: {e}");
                }
            }
        }
    }

    #[test]
    fn set_multicast_if_missing_iface() {
        let sock = SendSocket::new().expect("new");
        let err = sock
            .set_multicast_if("definitely-no-such-iface-zzz")
            .expect_err("missing interface should error");
        // Propagated from interface_index; no setsockopt is attempted.
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn set_multicast_ttl_and_loop_ok() {
        let sock = SendSocket::new().expect("new");
        for r in [
            sock.set_multicast_ttl(4),
            sock.set_multicast_loop(false),
            sock.set_multicast_loop(true),
        ] {
            if let Err(e) = r {
                if e.raw_os_error() == Some(libc::EPERM) {
                    eprintln!("skip set_multicast_ttl_and_loop_ok: lacks capability ({e})");
                } else {
                    panic!("unexpected multicast setsockopt error: {e}");
                }
            }
        }
    }

    #[test]
    fn bind_does_not_set_reuseaddr() {
        let first = SendSocket::new().expect("new first");
        first
            .bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind first");
        let addr = first.local_addr().expect("local_addr");

        // A second socket binding the same port must fail (no SO_REUSEADDR).
        let second = SendSocket::new().expect("new second");
        let err = second
            .bind(addr)
            .expect_err("second bind to same port should fail without SO_REUSEADDR");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EADDRINUSE),
            "expected EADDRINUSE without SO_REUSEADDR, got {err}"
        );
    }

    #[test]
    fn port_and_local_addr_agree() {
        let sock = SendSocket::new().expect("new");
        sock.bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind");
        let a = sock.local_addr().expect("local_addr");
        assert_eq!(*a.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(a.port(), 0);
    }
}
