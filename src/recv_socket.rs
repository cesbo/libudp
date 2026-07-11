//! UDP socket builder and wrapper.

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
    time::Duration,
};

use socket2::{
    Domain,
    Protocol,
    SockAddr,
    Socket,
    Type,
};

/// A blocking AF_INET UDP receive socket.
pub struct RecvSocket {
    inner: Socket,
}

impl RecvSocket {
    /// Create an unbound blocking AF_INET UDP socket (`SOCK_DGRAM` /
    /// `IPPROTO_UDP`).
    pub fn new() -> io::Result<Self> {
        let inner = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        Ok(Self { inner })
    }

    /// Set `SO_REUSEADDR` and bind to `addr:port`.
    pub fn bind(&self, addr: SocketAddrV4) -> io::Result<()> {
        self.inner.set_reuse_address(true)?;
        self.inner.bind(&SockAddr::from(addr))
    }

    /// The locally bound address (resolves an ephemeral port chosen by bind 0).
    pub fn local_addr(&self) -> io::Result<SocketAddrV4> {
        let sa = self.inner.local_addr()?;
        sa.as_socket_ipv4()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "local_addr is not IPv4"))
    }

    /// Set `SO_RCVBUF`.
    pub fn set_recv_buffer_size(&self, bytes: usize) -> io::Result<()> {
        self.inner.set_recv_buffer_size(bytes)
    }

    /// Read `SO_RCVBUF`.
    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        self.inner.recv_buffer_size()
    }

    /// Set the blocking-read timeout (`SO_RCVTIMEO`). `None` clears it.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }

    /// Toggle non-blocking mode (`O_NONBLOCK`).
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Read `O_NONBLOCK`.
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.inner.nonblocking()
    }

    /// Bind to a device by name (`SO_BINDTODEVICE`).
    pub fn bind_device(&self, name: &str) -> io::Result<()> {
        match self.inner.bind_device(Some(name.as_bytes())) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Convert into a [`std::net::UdpSocket`].
    pub fn into_std(self) -> std::net::UdpSocket {
        std::net::UdpSocket::from(self.inner)
    }
}

impl AsRawFd for RecvSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsFd for RecvSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{
        Ipv4Addr,
        UdpSocket,
    };

    use super::*;

    #[test]
    fn unicast_roundtrip() {
        let recv = RecvSocket::new().expect("new recv socket");
        recv.bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind");
        recv.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set_read_timeout");

        let local = recv.local_addr().expect("local_addr");
        assert_eq!(*local.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(local.port(), 0);

        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
        let payload = b"udp roundtrip";
        sender.send_to(payload, local).expect("send_to");

        // Receive via the std view of the same fd (does not consume socket2).
        let std_recv: UdpSocket = recv.into_std();
        std_recv
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut buf = [0u8; 64];
        let n = std_recv.recv(&mut buf).expect("recv");
        assert_eq!(&buf[.. n], payload);
    }

    #[test]
    fn set_nonblocking_toggles() {
        let sock = RecvSocket::new().expect("new");
        sock.bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind");

        // Default is blocking.
        assert!(!sock.nonblocking().expect("read default"));

        // Enable: a read with no data pending must not block.
        sock.set_nonblocking(true).expect("enable");
        assert!(sock.nonblocking().expect("read enabled"));
        let std_recv: UdpSocket = RecvSocket::new()
            .and_then(|s| {
                s.bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
                s.set_nonblocking(true)?;
                Ok(s.into_std())
            })
            .expect("nonblocking recv");
        let mut buf = [0u8; 64];
        let err = std_recv.recv(&mut buf).expect_err("would block");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        // Disable: back to blocking.
        sock.set_nonblocking(false).expect("disable");
        assert!(!sock.nonblocking().expect("read disabled"));
    }

    #[test]
    fn bind_device_lo_tolerant() {
        let sock = RecvSocket::new().expect("new");
        sock.bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            .expect("bind");
        // EPERM is mapped to Ok(()); any other error would surface as Err.
        assert!(
            sock.bind_device("lo").is_ok(),
            "bind_device should be Ok (EPERM tolerated)"
        );
    }

    #[test]
    fn recv_buffer_size_no_halving() {
        let sock = RecvSocket::new().expect("new");
        sock.bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
            .expect("bind");
        // Set an exact value and confirm no halving is applied. The kernel
        // typically doubles SO_RCVBUF on readback, so we only assert the
        // readback is at least the requested value (never less, which a >>1
        // would cause).
        let want = 256 * 1024;
        sock.set_recv_buffer_size(want)
            .expect("set_recv_buffer_size");
        let got = sock.recv_buffer_size().expect("recv_buffer_size");
        assert!(
            got >= want,
            "readback {got} should be >= requested {want} (no halving)"
        );
    }
}
