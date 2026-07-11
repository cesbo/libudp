//! udp - a thin UDP socket builder.
//!
//! AF_INET UDP socket construction, multicast (ASM/SSM) membership and
//! multicast egress selection, interface name resolution. [`RecvSocket`]
//! builds the receive socket and [`SendSocket`] configures egress;
//! [`Membership`] carries a group membership and applies it to any socket fd.
//! I/O is driven by the caller; this crate only builds and
//! configures the socket.

mod iface;
mod multicast;
mod recv_socket;
mod send_socket;

use std::{
    io,
    mem,
    os::{
        fd::BorrowedFd,
        unix::io::AsRawFd,
    },
};

pub use self::{
    iface::{
        interface_index,
        interface_ipv4,
    },
    multicast::{
        renew_membership,
        Membership,
    },
    recv_socket::RecvSocket,
    send_socket::SendSocket,
};

/// `setsockopt(fd, IPPROTO_IP, opt, &val, sizeof(T))`, mapping -1 to the last
/// OS error.
///
/// # Safety
/// `val` must point at an initialized value of the type the kernel expects for
/// `opt`, and `len` must be its size.
pub unsafe fn setsockopt_ip<T>(fd: BorrowedFd<'_>, opt: libc::c_int, val: &T) -> io::Result<()> {
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
