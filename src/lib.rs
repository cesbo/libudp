//! udp - a thin UDP receive-socket builder.
//!
//! AF_INET UDP socket construction, multicast (ASM/SSM) membership, interface
//! name resolution, and batched `recvmmsg` receive. Reading is driven by the
//! caller; this crate only builds and configures the socket.

mod iface;
mod mmsg;
mod multicast;
mod recv_socket;

pub use self::{
    iface::{
        interface_index,
        interface_ipv4,
    },
    mmsg::{
        MmsgBuf,
        DEFAULT_BATCH,
        DEFAULT_MTU,
    },
    multicast::{
        renew_membership,
        Membership,
    },
    recv_socket::RecvSocket,
};
