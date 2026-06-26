//! Batched datagram receive via raw `recvmmsg(2)`.

use std::{
    io,
    mem,
    os::fd::{
        AsRawFd,
        BorrowedFd,
    },
};

/// Default datagram capacity (bytes) for each slot in a [`MmsgBuf`].
pub const DEFAULT_MTU: usize = 1500;

/// Default number of datagrams received per `recvmmsg` batch.
pub const DEFAULT_BATCH: usize = 64;

/// A preallocated `recvmmsg` batch.
pub struct MmsgBuf {
    count: usize,
    mtu: usize,
    msgs: Vec<libc::mmsghdr>,

    #[allow(dead_code)]
    iov: Vec<libc::iovec>,

    buf: Vec<u8>,
}

impl MmsgBuf {
    /// Allocate a batch of `count` datagram slots, each `mtu` bytes.
    pub fn new(count: usize, mtu: usize) -> Self {
        debug_assert!(count > 0, "mmsg batch count must be > 0");
        debug_assert!(mtu > 0, "mmsg mtu must be > 0");

        let mut msgs: Vec<libc::mmsghdr> = vec![unsafe { mem::zeroed() }; count];
        let mut iov: Vec<libc::iovec> = vec![unsafe { mem::zeroed() }; count];
        let mut buf: Vec<u8> = vec![0u8; count * mtu];

        for i in 0 .. count {
            iov[i].iov_base = unsafe { buf.as_mut_ptr().add(i * mtu) } as *mut libc::c_void;
            iov[i].iov_len = mtu;
            msgs[i].msg_hdr.msg_iov = &mut iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }

        Self {
            count,
            mtu,
            msgs,
            iov,
            buf,
        }
    }

    /// Number of datagram slots in this batch.
    pub fn capacity(&self) -> usize {
        self.count
    }

    /// Receive a batch of datagrams into this buffer.
    pub fn recvmmsg(&mut self, fd: BorrowedFd<'_>) -> io::Result<usize> {
        loop {
            let n = unsafe {
                libc::recvmmsg(
                    fd.as_raw_fd(),
                    self.msgs.as_mut_ptr(),
                    self.count as libc::c_uint,
                    libc::MSG_WAITFORONE,
                    std::ptr::null_mut(),
                )
            };

            if n >= 0 {
                return Ok(n as usize);
            }

            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => return Ok(0),
                _ => return Err(err),
            }
        }
    }

    /// The bytes of the `i`-th received datagram (length = its `msg_len`).
    pub fn data(&self, i: usize) -> &[u8] {
        debug_assert!(i < self.count, "mmsg index out of range");

        let len = (self.msgs[i].msg_len as usize).min(self.mtu);
        let base = i * self.mtu;
        &self.buf[base .. base + len]
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{
            Ipv4Addr,
            SocketAddrV4,
            UdpSocket,
        },
        os::fd::AsFd,
        time::Duration,
    };

    use super::*;

    #[test]
    fn buf_layout() {
        let m = MmsgBuf::new(4, 1500);
        assert_eq!(m.capacity(), 4);
        // Each iovec must point at its own MTU-sized slice of the contiguous buf,
        // and each mmsghdr must reference its iovec.
        for i in 0 .. 4 {
            let want_base = unsafe { m.buf.as_ptr().add(i * 1500) } as *const libc::c_void;
            assert_eq!(m.iov[i].iov_base as *const libc::c_void, want_base);
            assert_eq!(m.iov[i].iov_len, 1500);
            assert_eq!(
                m.msgs[i].msg_hdr.msg_iov as *const libc::iovec,
                &m.iov[i] as *const libc::iovec
            );
            assert_eq!(m.msgs[i].msg_hdr.msg_iovlen, 1);
        }
    }

    #[test]
    fn eagain_maps_to_zero() {
        // A bound socket with a short read timeout and no traffic returns
        // EAGAIN, which recvmmsg() maps to Ok(0).
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set_read_timeout");
        let mut m = MmsgBuf::new(8, 1500);
        let n = m.recvmmsg(sock.as_fd()).expect("recvmmsg");
        assert_eq!(n, 0, "no traffic should yield Ok(0)");
    }

    #[test]
    fn loopback_batch_roundtrip() {
        // Send several datagrams to a loopback receiver and read them back in one
        // recvmmsg batch (tolerant of CI scheduling: a short timeout plus a
        // retry loop, never an indefinite block).
        let recv = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind recv");
        recv.set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set_read_timeout");
        let local = match recv.local_addr().expect("local_addr") {
            std::net::SocketAddr::V4(v4) => v4,
            _ => panic!("expected IPv4 local addr"),
        };
        assert_eq!(*local.ip(), Ipv4Addr::LOCALHOST);

        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind sender");
        let payloads: [&[u8]; 3] = [b"first", b"second-datagram", b"3"];
        for p in payloads {
            sender
                .send_to(p, SocketAddrV4::new(Ipv4Addr::LOCALHOST, local.port()))
                .expect("send_to");
        }

        let mut m = MmsgBuf::new(16, 1500);
        let mut received: Vec<Vec<u8>> = Vec::new();
        // Drain across up to a few recvmmsg calls; loopback may not deliver all
        // datagrams in a single batch.
        for _ in 0 .. 10 {
            let n = m.recvmmsg(recv.as_fd()).expect("recvmmsg");
            for i in 0 .. n {
                received.push(m.data(i).to_vec());
            }
            if received.len() >= payloads.len() {
                break;
            }
        }

        assert_eq!(received.len(), payloads.len(), "all datagrams received");
        for (got, want) in received.iter().zip(payloads.iter()) {
            assert_eq!(got.as_slice(), *want);
        }
    }
}
