use libc;
use std::{io, mem, fmt};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::os::unix::io::{RawFd, AsRawFd};

mod base;

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
///

const SIOCGIFINDEX: libc::c_ulong = 0x8933;

const MCAST_JOIN_GROUP: libc::c_int = 42;
const MCAST_LEAVE_GROUP: libc::c_int = 45;

//

#[repr(C)]
struct ifreq_ifindex {
    ifr_name: [u8; 16],
    ifr_ifindex: u32,
    stuff: [u8; 20],
}

#[repr(C)]
struct ifreq_ifaddr {
    ifr_name: [u8; 16],
    ifr_addr: libc::sockaddr,
    stuff: [u8; 8],
}

#[repr(C)]
struct group_req {
    pub gr_interface: u32,
    pub gr_group: libc::sockaddr_storage,
}

/// Get interface index by the name
fn ifname_to_index(fd: libc::c_int, ifname: &str) -> io::Result<u32> {
    if ifname.len() == 0 {
        return Ok(0);
    } else if ifname.len() >= 16 {
        return Err(io::Error::from_raw_os_error(libc::ENODEV));
    }

    let mut ifr: ifreq_ifindex = unsafe { mem::zeroed() };
    ifr.ifr_name[.. ifname.len()].copy_from_slice(ifname.as_bytes());
    base::cvt(unsafe { libc::ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut ifreq_ifindex as *mut libc::c_void) })?;

    return Ok(ifr.ifr_ifindex);
}

/// Get interface address by the name
fn ifname_to_addr(fd: libc::c_int, ifname: &str) -> io::Result<SocketAddr> {
    if ifname.len() == 0 {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
    } else if ifname.len() >= 16 {
        return Err(io::Error::from_raw_os_error(libc::ENODEV));
    }

    let mut ifr: ifreq_ifaddr = unsafe { mem::zeroed() };
    ifr.ifr_name[.. ifname.len()].copy_from_slice(ifname.as_bytes());
    base::cvt(unsafe { libc::ioctl(fd, libc::SIOCGIFADDR, &mut ifr as *mut ifreq_ifaddr as *mut libc::c_void) })?;

    base::sockaddr_from(&ifr.ifr_addr)
}

//

pub struct UdpSocket {
    ifname: String,
    addr: SocketAddr,
    fd: libc::c_int,
    mreq: Option<group_req>,
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

impl UdpSocket {
    fn new(addr: &str) -> io::Result<UdpSocket> {
        let mut ifname = String::new();
        let addr: SocketAddr = {
            let mut split = addr.splitn(2, '@');
            let a1 = split.next().unwrap();
            let a2 = match split.next() {
                Some(v) => {
                    ifname.push_str(a1);
                    v
                },
                None => a1,
            };
            match a2.parse() {
                Ok(v) => v,
                Err(_) => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
            }
        };

        let family = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };

        let fd = base::cvt(unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::O_CLOEXEC, 0) })?;

        Ok(UdpSocket {
            ifname: ifname,
            addr: addr,
            fd: fd,
            mreq: None,
        })
    }

    /// Open UDP socket
    /// For multicast: turn on loop, set ttl to 8, and specify interface
    pub fn open(addr: &str) -> io::Result<UdpSocket> {
        let x = UdpSocket::new(addr)?;

        if x.addr.ip().is_multicast() {
            let ttl: libc::c_int = 8;

            match x.addr {
                SocketAddr::V4(_) => {
                    base::setsockopt(x.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, &base::ON)?;
                    base::setsockopt(x.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, &ttl)?;
                    if x.ifname.len() > 0 {
                        let ifaddr = ifname_to_addr(x.fd, &x.ifname)?;
                        match ifaddr {
                            SocketAddr::V4(ref v) => base::setsockopt(x.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &u32::from(*v.ip()).to_be())?,
                            _ => unreachable!(),
                        };
                    }
                },
                SocketAddr::V6(_) => {
                    base::setsockopt(x.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, &base::ON)?;
                    base::setsockopt(x.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &ttl)?;
                    let ifindex = ifname_to_index(x.fd, &x.ifname)?;
                    if ifindex != 0 {
                        base::setsockopt(x.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, &ifindex)?;
                    }
                },
            };
        }

        Ok(x)
    }

    /// Open and bind UDP socket
    /// For multicast: join to the group
    pub fn bind(addr: &str) -> io::Result<UdpSocket> {
        let mut x = UdpSocket::new(addr)?;
        let (saddr, slen) = base::sockaddr_into(&x.addr);

        base::setsockopt(x.fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &base::ON)?;
        base::cvt(unsafe { libc::bind(x.fd, saddr, slen) })?;

        if x.addr.ip().is_multicast() {
            let level = match x.addr {
                SocketAddr::V4(_) => libc::IPPROTO_IP,
                SocketAddr::V6(_) => libc::IPPROTO_IPV6,
            };
            let mut mreq = group_req {
                gr_interface: ifname_to_index(x.fd, &x.ifname)?,
                gr_group: unsafe { mem::zeroed() },
            };
            unsafe { libc::memcpy(&mut mreq.gr_group as *mut libc::sockaddr_storage as *mut libc::c_void,
                saddr as *const libc::c_void, slen as usize) };
            base::setsockopt(x.fd, level, MCAST_JOIN_GROUP, &mreq)?;

            x.mreq = Some(mreq);
        }

        Ok(x)
    }

    /// Send data to the remote socket
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let ret = base::cvt(unsafe { libc::send(self.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_NOSIGNAL) as i32 })?;
        Ok(ret as usize)
    }

    /// Send data to the given address
    pub fn sendto(&self, data: &[u8]) -> io::Result<usize> {
        let (saddr, slen) = base::sockaddr_into(&self.addr);
        let ret = base::cvt(unsafe { libc::sendto(self.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_NOSIGNAL,
            saddr, slen) as i32 })?;
        Ok(ret as usize)
    }

    /// Receive data from remote socket
    pub fn recv(&self, data: &mut [u8]) -> io::Result<usize> {
        let ret = base::cvt(unsafe { libc::recv(self.fd,
            data.as_mut_ptr() as *mut libc::c_void,
            data.len(),
            0) as i32 })?;
        Ok(ret as usize)
    }
}

impl AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd as RawFd
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        match self.mreq {
            Some(ref v) => {
                let level = match self.addr {
                    SocketAddr::V4(_) => libc::IPPROTO_IP,
                    SocketAddr::V6(_) => libc::IPPROTO_IPV6,
                };
                base::setsockopt(self.fd, level, MCAST_LEAVE_GROUP, v).unwrap();
            },
            None => (),
        };

        if self.fd > 0 {
            unsafe { libc::close(self.fd) };
            self.fd = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    #[test]
    fn test_ifname_to_index() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let sys_dir = "/sys/class/net";
        let dir_list = fs::read_dir(sys_dir).unwrap();
        let mut content = String::new();
        for i in dir_list {
            let ifname = i.unwrap().file_name().to_str().unwrap().to_string();
            let ifindex = ifname_to_index(fd, ifname.as_str()).unwrap();

            let mut file = fs::File::open(format!("{}/{}/ifindex", sys_dir, ifname)).unwrap();
            content.clear();
            file.read_to_string(&mut content).unwrap();
            let sys_ifindex: u32 = content.trim().parse().unwrap();
            assert_eq!(ifindex, sys_ifindex);
        }
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_ifname_to_addr() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let addr = ifname_to_addr(fd, "lo").unwrap();
        let check = SocketAddr::new(IpAddr::from(Ipv4Addr::new(127, 0, 0, 1)), 0);
        assert_eq!(addr, check);
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_udpsocket_multicast() {
        let s = UdpSocket::bind("lo@239.255.1.1:1234").unwrap();
        mem::drop(s);
    }

    #[test]
    fn test_send_receive() {
        let ssock = UdpSocket::open("lo@127.0.0.1:10000").unwrap();
        let rsock = UdpSocket::bind("lo@127.0.0.1:10000").unwrap();
        let sdata = String::from("Hello, world!");
        let sbytes = ssock.sendto(sdata.as_bytes()).unwrap();
        let mut rdata = [0; 1460];
        let rbytes = rsock.recv(&mut rdata).unwrap();
        assert_eq!(sbytes, rbytes);
        assert_eq!(sdata.as_bytes(), &rdata[.. rbytes]);
    }
}
