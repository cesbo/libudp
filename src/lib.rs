//! UDP Socket
//!
//! # IBM Knowledge Center. Multicast:
//!
//! Receiving:
//! - socket()
//! - setsockopt(SO_REUSEADDR)
//! - bind()
//! - setsockopt(IP_ADD_MEMBERSHIP)
//! - read()
//!
//! Sending:
//! - socket()
//! - setsockopt(IP_MULTICAST_LOOPBACK)
//! - setsockopt(IP_MULTICAST_IF)
//! - sendto()

use std::{
    mem,
    fmt,
    io,
    net::{
        SocketAddr,
        SocketAddrV4,
        SocketAddrV6,
    },
};

use libc;


pub struct UdpSocket {
    fd: libc::c_int,
    ifname: String,
    addr: SocketAddr,
    mreq: group_req,
}


const ON: libc::c_int = 1;


macro_rules! cvt {
    ($fn: expr) => ({
        let result = unsafe { $fn };
        if result != -1 {
            Ok(result)
        } else {
            Err(io::Error::last_os_error())
        }
    })
}


/// setsockopt wrapper
#[inline]
fn setsockopt<T>(fd: libc::c_int, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    let size = mem::size_of_val::<T>(value) as libc::socklen_t;
    let value = value as *const T as *const libc::c_void;
    cvt!(libc::setsockopt(fd, level, name, value, size))?;
    Ok(())
}


#[inline]
fn get_ifindex<R: AsRef<str>>(ifname: R) -> libc::c_uint {
    let ifname = ifname.as_ref().as_ptr() as *const i8;
    unsafe { libc::if_nametoindex(ifname) }
}


#[repr(C)]
struct ifreq_ifaddr {
    ifr_name: [u8; 16],
    ifr_addr: libc::sockaddr,
    stuff: [u8; 8],
}


/// Reads IPv4 interface address
fn get_ifaddr_v4(fd: libc::c_int, ifname: &str) -> io::Result<libc::in_addr_t> {
    if ifname.is_empty() || ifname.len() >= 16 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    let mut ifr: ifreq_ifaddr = unsafe { mem::zeroed() };
    ifr.ifr_name[.. ifname.len()].copy_from_slice(ifname.as_bytes());
    cvt!(libc::ioctl(fd, libc::SIOCGIFADDR, &mut ifr as *mut ifreq_ifaddr as *mut libc::c_void))?;

    if i32::from(ifr.ifr_addr.sa_family) != libc::AF_INET {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    let saddr = unsafe { *(&ifr.ifr_addr as *const libc::sockaddr as *const libc::sockaddr_in) };
    Ok(saddr.sin_addr.s_addr)
}


#[repr(C)]
struct group_req {
    pub gr_interface: libc::c_uint,
    pub gr_group: libc::sockaddr_storage,
}


#[inline]
fn get_sockaddr<'a>(addr: &'a SocketAddr) -> (*const libc::sockaddr, libc::socklen_t) {
    match addr {
        SocketAddr::V4(ref a) => (a as *const SocketAddrV4 as *const libc::sockaddr, mem::size_of_val(a) as libc::socklen_t),
        SocketAddr::V6(ref a) => (a as *const SocketAddrV6 as *const libc::sockaddr, mem::size_of_val(a) as libc::socklen_t),
    }
}


impl fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UdpSocket")
            .field("fd", &self.fd)
            .field("ifname", &self.ifname)
            .field("addr", &self.addr)
            .finish()
    }
}


impl Drop for UdpSocket {
    fn drop(&mut self) {
        match self.mreq.gr_group.ss_family as i32 {
            libc::AF_INET => setsockopt(self.fd, libc::IPPROTO_IP, libc::MCAST_LEAVE_GROUP, &self.mreq).unwrap(),
            libc::AF_INET6 => setsockopt(self.fd, libc::IPPROTO_IPV6, libc::MCAST_LEAVE_GROUP, &self.mreq).unwrap(),
            _ => {},
        };

        unsafe { libc::close(self.fd) };
    }
}


impl UdpSocket {
    fn new(addr: &str) -> io::Result<UdpSocket> {
        let mut ifname = String::new();
        let mut skip = 0;

        if let Some(d) = addr.find('@') {
            ifname.push_str(&addr[.. d]);
            skip = d + 1;
        }

        let addr: SocketAddr = match (&addr[skip ..]).parse() {
            Ok(v) => v,
            _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        };

        let family = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };

        let fd = cvt!(libc::socket(family, libc::SOCK_DGRAM, 0))?;
        let mreq: group_req = unsafe { mem::zeroed() };

        Ok(UdpSocket { fd, ifname, addr, mreq })
    }

    /// Open UDP socket for sending packets
    /// For multicast: turn on loop, set ttl to 8, and specify interface
    pub fn open(addr: &str) -> io::Result<UdpSocket> {
        let x = UdpSocket::new(addr)?;

        if x.addr.ip().is_multicast() {
            let ttl: libc::c_int = 8;

            match x.addr {
                SocketAddr::V4(_) => {
                    setsockopt(x.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, &ON)?;
                    setsockopt(x.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, &ttl)?;
                    if ! x.ifname.is_empty() {
                        let addr = get_ifaddr_v4(x.fd, &x.ifname)?;
                        setsockopt(x.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &addr)?;
                    }
                },
                SocketAddr::V6(_) => {
                    setsockopt(x.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, &ON)?;
                    setsockopt(x.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &ttl)?;
                    if ! x.ifname.is_empty() {
                        let ifindex = get_ifindex(&x.ifname);
                        setsockopt(x.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, &ifindex)?;
                    }
                },
            };
        }

        Ok(x)
    }

    /// Open and bind UDP socket for receiving packets
    /// For multicast: join to the group
    pub fn bind(addr: &str) -> io::Result<UdpSocket> {
        let mut x = UdpSocket::new(addr)?;

        let (saddr, slen) = get_sockaddr(&x.addr);

        setsockopt(x.fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &ON)?;
        cvt!(libc::bind(x.fd, saddr, slen))?;

        if x.addr.ip().is_multicast() {
            let level = match x.addr {
                SocketAddr::V4(_) => libc::IPPROTO_IP,
                SocketAddr::V6(_) => libc::IPPROTO_IPV6,
            };

            x.mreq.gr_interface = get_ifindex(&x.ifname);
            unsafe {
                libc::memcpy(&mut x.mreq.gr_group as *mut libc::sockaddr_storage as *mut libc::c_void,
                    saddr as *const libc::c_void,
                    slen as usize)
            };

            setsockopt(x.fd, level, libc::MCAST_JOIN_GROUP, &x.mreq)?;
        }

        Ok(x)
    }

    /// Send data to the remote socket
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let ret = cvt!(libc::send(self.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0))?;
        Ok(ret as usize)
    }

    /// Send data to the given address
    pub fn sendto(&self, data: &[u8]) -> io::Result<usize> {
        let (saddr, slen) = get_sockaddr(&self.addr);
        let ret = cvt!(libc::sendto(self.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            saddr, slen))?;
        Ok(ret as usize)
    }

    /// Receive data from remote socket
    pub fn recv(&self, data: &mut [u8]) -> io::Result<usize> {
        let ret = cvt!(libc::recv(self.fd,
            data.as_mut_ptr() as *mut libc::c_void,
            data.len(),
            0))?;
        Ok(ret as usize)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_get_ifaddr_v4() {
        #[cfg(target_os = "linux")] const LO: &str = "lo";
        #[cfg(target_os = "macos")] const LO: &str = "lo0";

        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let addr = get_ifaddr_v4(fd, LO).unwrap();
        let check = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(addr, u32::from(check).to_be());
        unsafe { libc::close(fd) };
    }
}
