use libc;
use std::{io, mem, fmt};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

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
pub struct UdpSocket {
    fd: libc::c_int,

    ifname: String,
    addr: SocketAddr,

    ifindex: libc::c_int,
    saddr: libc::sockaddr,
    slen: libc::socklen_t,
}

const ON: libc::c_int = 1;

const SIOCGIFINDEX: libc::c_ulong = 0x8933;

const MCAST_JOIN_GROUP: libc::c_int = 42;
const MCAST_LEAVE_GROUP: libc::c_int = 45;

//

#[inline]
pub fn cvt(result: i32) -> io::Result<i32> {
    if result != -1 {
        Ok(result)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// setsockopt wrapper
#[inline]
fn setsockopt<T>(fd: libc::c_int, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    let size = mem::size_of_val::<T>(value) as libc::socklen_t;
    let value = value as *const T as *const libc::c_void;
    cvt(unsafe { libc::setsockopt(fd, level, name, value, size) })?;
    Ok(())
}

#[repr(C)]
struct ifreq_ifindex {
    ifr_name: [u8; 16],
    ifr_ifindex: libc::c_int,
    stuff: [u8; 20],
}

/// Get interface index by the name
#[inline]
fn ifname_to_index(fd: libc::c_int, ifname: &str) -> io::Result<libc::c_int> {
    if ifname.is_empty() {
        return Ok(0);
    } else if ifname.len() >= 16 {
        return Err(io::Error::from_raw_os_error(libc::ENODEV));
    }

    let mut ifr: ifreq_ifindex = unsafe { mem::zeroed() };
    ifr.ifr_name[.. ifname.len()].copy_from_slice(ifname.as_bytes());
    cvt(unsafe { libc::ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut ifreq_ifindex as *mut libc::c_void) })?;
    Ok(ifr.ifr_ifindex)
}

#[repr(C)]
struct ifreq_ifaddr {
    ifr_name: [u8; 16],
    ifr_addr: libc::sockaddr,
    stuff: [u8; 8],
}

/// Reads IPv4 interface address
#[inline]
fn get_ifaddr_v4(fd: libc::c_int, ifname: &str) -> io::Result<libc::in_addr_t> {
    if ifname.is_empty() || ifname.len() >= 16 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    let mut ifr: ifreq_ifaddr = unsafe { mem::zeroed() };
    ifr.ifr_name[.. ifname.len()].copy_from_slice(ifname.as_bytes());
    cvt(unsafe { libc::ioctl(fd, libc::SIOCGIFADDR, &mut ifr as *mut ifreq_ifaddr as *mut libc::c_void) })?;

    if ifr.ifr_addr.sa_family != libc::AF_INET as u16 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    let saddr = unsafe { *(&ifr.ifr_addr as *const libc::sockaddr as *const libc::sockaddr_in) };
    Ok(saddr.sin_addr.s_addr.to_be())
}

#[repr(C)]
struct group_req {
    pub gr_interface: libc::c_int,
    pub gr_group: libc::sockaddr_storage,
}

//

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
        if self.addr.ip().is_multicast() {
            self.multicast_cmd(MCAST_LEAVE_GROUP).unwrap();
        }

        if self.fd > 0 {
            unsafe { libc::close(self.fd) };
            self.fd = 0;
        }
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

        let family: libc::c_int;
        let slen: libc::socklen_t;
        let mut saddr: libc::sockaddr = unsafe { mem::zeroed() };

        match addr {
            SocketAddr::V4(ref a) => {
                family = libc::AF_INET;
                unsafe {
                    slen = mem::size_of_val(a) as libc::socklen_t;
                    libc::memcpy(&mut saddr as *mut libc::sockaddr as *mut libc::c_void,
                        a as *const SocketAddrV4 as *const libc::c_void,
                        slen as usize);
                }
            },
            SocketAddr::V6(ref a) => {
                family = libc::AF_INET6;
                unsafe {
                    slen = mem::size_of_val(a) as libc::socklen_t;
                    libc::memcpy(&mut saddr as *mut libc::sockaddr as *mut libc::c_void,
                        a as *const SocketAddrV6 as *const libc::c_void,
                        slen as usize);
                }
            },
        };

        let fd = cvt(unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::O_CLOEXEC, 0) })?;
        let ifindex = ifname_to_index(fd, &ifname)?;

        Ok(UdpSocket { fd, ifname, addr, ifindex, saddr, slen })
    }

    /// Open UDP socket
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
                    if x.ifindex != 0 {
                        setsockopt(x.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, &x.ifindex)?;
                    }
                },
            };
        }

        Ok(x)
    }

    /// Open and bind UDP socket
    /// For multicast: join to the group
    pub fn bind(addr: &str) -> io::Result<UdpSocket> {
        let x = UdpSocket::new(addr)?;

        setsockopt(x.fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &ON)?;
        cvt(unsafe { libc::bind(x.fd, &x.saddr, x.slen) })?;

        if x.addr.ip().is_multicast() {
            x.multicast_cmd(MCAST_JOIN_GROUP)?;
        }

        Ok(x)
    }

    fn multicast_cmd(&self, cmd: libc::c_int) -> io::Result<()> {
        let level = match self.addr {
            SocketAddr::V4(_) => libc::IPPROTO_IP,
            SocketAddr::V6(_) => libc::IPPROTO_IPV6,
        };

        let mut mreq = group_req {
            gr_interface: self.ifindex,
            gr_group: unsafe { mem::zeroed() },
        };

        unsafe {
            libc::memcpy(&mut mreq.gr_group as *mut libc::sockaddr_storage as *mut libc::c_void,
                &self.saddr as *const libc::sockaddr as *const libc::c_void,
                self.slen as usize)
        };

        setsockopt(self.fd, level, cmd, &mreq)
    }

    /// Send data to the remote socket
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let ret = cvt(unsafe { libc::send(self.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_NOSIGNAL) as i32 })?;
        Ok(ret as usize)
    }

    /// Send data to the given address
    pub fn sendto(&self, data: &[u8]) -> io::Result<usize> {
        let ret = cvt(unsafe { libc::sendto(self.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_NOSIGNAL,
            &self.saddr, self.slen) as i32 })?;
        Ok(ret as usize)
    }

    /// Receive data from remote socket
    pub fn recv(&self, data: &mut [u8]) -> io::Result<usize> {
        let ret = cvt(unsafe { libc::recv(self.fd,
            data.as_mut_ptr() as *mut libc::c_void,
            data.len(),
            0) as i32 })?;
        Ok(ret as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::net::Ipv4Addr;

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
            let sys_ifindex: i32 = content.trim().parse().unwrap();
            assert_eq!(ifindex, sys_ifindex);
        }
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_get_ifaddr_v4() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let addr = get_ifaddr_v4(fd, "lo").unwrap();
        let addr = Ipv4Addr::from(addr);
        let check = Ipv4Addr::new(127, 0, 0, 1);
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
