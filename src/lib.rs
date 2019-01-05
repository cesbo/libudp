/// UDP Socket
///
/// # IBM Knowledge Center. Multicast:
///
/// Receiving:
/// - socket()
/// - setsockopt(SO_REUSEADDR)
/// - bind()
/// - setsockopt(IP_ADD_MEMBERSHIP)
/// - read()
///
/// Sending:
/// - socket()
/// - setsockopt(IP_MULTICAST_LOOPBACK)
/// - setsockopt(IP_MULTICAST_IF)
/// - sendto()

#[cfg(unix)] mod unix;
#[cfg(unix)] pub use crate::unix::UdpSocket;
