use libc;
use std::{io, mem, fmt};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr};

pub struct UdpSocket {
    fd: libc::c_int,
    ifname: String,
    addr: SocketAddr,
    mreq: group_req,
}

const ON: libc::c_int = 1;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;
const MCAST_JOIN_GROUP: libc::c_int = 42;
const MCAST_LEAVE_GROUP: libc::c_int = 45;

//

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

#[repr(C)]
struct ifreq_ifindex {
    ifr_name: [u8; 16],
    ifr_ifindex: libc::c_int,
    stuff: [u8; 20],
}

/// Get interface index by the name
#[inline]
fn get_ifindex(fd: libc::c_int, ifname: &str) -> io::Result<libc::c_int> {
    if ifname.is_empty() {
        return Ok(0);
    } else if ifname.len() >= 16 {
        return Err(io::Error::from_raw_os_error(libc::ENODEV));
    }

    let mut ifr: ifreq_ifindex = unsafe { mem::zeroed() };
    ifr.ifr_name[.. ifname.len()].copy_from_slice(ifname.as_bytes());
    cvt!(libc::ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut ifreq_ifindex as *mut libc::c_void))?;
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
    cvt!(libc::ioctl(fd, libc::SIOCGIFADDR, &mut ifr as *mut ifreq_ifaddr as *mut libc::c_void))?;

    if ifr.ifr_addr.sa_family != libc::AF_INET as u16 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    let saddr = unsafe { *(&ifr.ifr_addr as *const libc::sockaddr as *const libc::sockaddr_in) };
    Ok(saddr.sin_addr.s_addr)
}

#[repr(C)]
struct group_req {
    pub gr_interface: libc::c_int,
    pub gr_group: libc::sockaddr_storage,
}

#[inline]
pub fn get_sockaddr<'a>(addr: &'a SocketAddr) -> (*const libc::sockaddr, libc::socklen_t) {
    match addr {
        SocketAddr::V4(ref a) => (a as *const SocketAddrV4 as *const libc::sockaddr, mem::size_of_val(a) as libc::socklen_t),
        SocketAddr::V6(ref a) => (a as *const SocketAddrV6 as *const libc::sockaddr, mem::size_of_val(a) as libc::socklen_t),
    }
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
        match self.mreq.gr_group.ss_family as i32 {
            libc::AF_INET => setsockopt(self.fd, libc::IPPROTO_IP, MCAST_LEAVE_GROUP, &self.mreq).unwrap(),
            libc::AF_INET6 => setsockopt(self.fd, libc::IPPROTO_IPV6, MCAST_LEAVE_GROUP, &self.mreq).unwrap(),
            _ => {},
        };

        unsafe { libc::close(self.fd) };
    }
}

impl Default for UdpSocket {
    fn default() -> Self {
        UdpSocket {
            fd: 0,
            ifname: String::new(),
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            mreq: unsafe { mem::zeroed() },
        }
    }
}

impl UdpSocket {
    fn init(&mut self, addr: &str) -> io::Result<()> {
        let mut skip = 0;

        if let Some(d) = addr.find('@') {
            self.ifname.push_str(&addr[.. d]);
            skip = d + 1;
        }

        self.addr = match (&addr[skip ..]).parse() {
            Ok(v) => v,
            _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        };

        let family = match self.addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };

        self.fd = cvt!(libc::socket(family, libc::SOCK_DGRAM | libc::O_CLOEXEC, 0))?;

        Ok(())
    }

    /// Open UDP socket for sending packets
    /// For multicast: turn on loop, set ttl to 8, and specify interface
    pub fn open(&mut self, addr: &str) -> io::Result<()> {
        self.init(addr)?;

        if self.addr.ip().is_multicast() {
            let ttl: libc::c_int = 8;

            match self.addr {
                SocketAddr::V4(_) => {
                    setsockopt(self.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, &ON)?;
                    setsockopt(self.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, &ttl)?;
                    if ! self.ifname.is_empty() {
                        let addr = get_ifaddr_v4(self.fd, &self.ifname)?;
                        setsockopt(self.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &addr)?;
                    }
                },
                SocketAddr::V6(_) => {
                    setsockopt(self.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, &ON)?;
                    setsockopt(self.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, &ttl)?;
                    if ! self.ifname.is_empty() {
                        let ifindex = get_ifindex(self.fd, &self.ifname)?;
                        setsockopt(self.fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, &ifindex)?;
                    }
                },
            };
        }

        Ok(())
    }

    /// Open and bind UDP socket for receiving packets
    /// For multicast: join to the group
    pub fn bind(&mut self, addr: &str) -> io::Result<()> {
        self.init(addr)?;

        let (saddr, slen) = get_sockaddr(&self.addr);

        setsockopt(self.fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &ON)?;
        cvt!(libc::bind(self.fd, saddr, slen))?;

        if self.addr.ip().is_multicast() {
            let level = match self.addr {
                SocketAddr::V4(_) => libc::IPPROTO_IP,
                SocketAddr::V6(_) => libc::IPPROTO_IPV6,
            };

            self.mreq.gr_interface = get_ifindex(self.fd, &self.ifname)?;
            unsafe {
                libc::memcpy(&mut self.mreq.gr_group as *mut libc::sockaddr_storage as *mut libc::c_void,
                    saddr as *const libc::c_void,
                    slen as usize)
            };

            setsockopt(self.fd, level, MCAST_JOIN_GROUP, &self.mreq)?;
        }

        Ok(())
    }

    /// Send data to the remote socket
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let ret = cvt!(libc::send(self.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_NOSIGNAL))?;
        Ok(ret as usize)
    }

    /// Send data to the given address
    pub fn sendto(&self, data: &[u8]) -> io::Result<usize> {
        let (saddr, slen) = get_sockaddr(&self.addr);
        let ret = cvt!(libc::sendto(self.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_NOSIGNAL,
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
    use std::fs;
    use std::io::Read;
    use std::net::Ipv4Addr;

    #[test]
    fn test_get_ifindex() {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let sys_dir = "/sys/class/net";
        let dir_list = fs::read_dir(sys_dir).unwrap();
        let mut content = String::new();
        for i in dir_list {
            let ifname = i.unwrap().file_name().to_str().unwrap().to_string();
            let ifindex = get_ifindex(fd, ifname.as_str()).unwrap();

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
        let check = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(addr, u32::from(check).to_be());
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_send_receive() {
        let mut ssock = UdpSocket::default();
        ssock.open("lo@239.255.1.1:10000").unwrap();
        let mut rsock = UdpSocket::default();
        rsock.bind("lo@239.255.1.1:10000").unwrap();
        let sdata = String::from("Hello, world!");
        let sbytes = ssock.sendto(sdata.as_bytes()).unwrap();
        let mut rdata = [0; 1460];
        let rbytes = rsock.recv(&mut rdata).unwrap();
        assert_eq!(sbytes, rbytes);
        assert_eq!(sdata.as_bytes(), &rdata[.. rbytes]);
    }
}
