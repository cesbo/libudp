//! udp - a thin UDP receive-socket builder.
//!
//! AF_INET UDP socket construction, multicast (ASM/SSM) membership, interface
//! name resolution. Reading is driven by the caller; this crate only builds
//! and configures the socket.

mod iface;
mod multicast;
mod recv_socket;

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
};
