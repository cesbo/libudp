use libc;
use std::{io, mem};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

pub const ON: libc::c_int = 1;

pub fn cvt(result: i32) -> io::Result<i32> {
    match result {
        -1 => Err(io::Error::last_os_error()),
        v => Ok(v),
    }
}

pub fn setsockopt<T>(fd: libc::c_int, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    let size = mem::size_of_val::<T>(value) as libc::socklen_t;
    let value = value as *const T as *const libc::c_void;
    cvt(unsafe { libc::setsockopt(fd, level, name, value, size) })?;
    Ok(())
}

//

pub fn sockaddr_into<'a>(addr: &'a SocketAddr) -> (*const libc::sockaddr, libc::socklen_t) {
    match addr {
        SocketAddr::V4(ref a) => (a as *const SocketAddrV4 as *const libc::sockaddr, mem::size_of_val(a) as libc::socklen_t),
        SocketAddr::V6(ref a) => (a as *const SocketAddrV6 as *const libc::sockaddr, mem::size_of_val(a) as libc::socklen_t),
    }
}

pub fn sockaddr_from(addr: *const libc::sockaddr) -> io::Result<SocketAddr> {
    let family: u16 = unsafe { *(addr as *const u16) };
    match family as i32 {
        libc::AF_INET => Ok(SocketAddr::V4(unsafe { *(addr as *const SocketAddrV4) })),
        libc::AF_INET6 => Ok(SocketAddr::V6(unsafe { *(addr as *const SocketAddrV6) })),
        _ => Err(io::Error::from_raw_os_error(libc::EINVAL)),
    }
}

//

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_sockaddr_v4() {
        let s = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 88, 1)), 0);
        let (saddr, _slen) = sockaddr_into(&s);
        let mut x = sockaddr_from(saddr).unwrap();
        assert_eq!(s, x);
        x.set_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 88, 10)));
        assert_ne!(s, x);
    }

    #[test]
    fn test_sockaddr_v6() {
        let s = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2a01, 0x04f8, 0x010a, 0x2e4e, 0x0000, 0x0000, 0x0000, 0x0002)), 0);
        let (saddr, _slen) = sockaddr_into(&s);
        let mut x = sockaddr_from(saddr).unwrap();
        assert_eq!(s, x);
        x.set_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0000, 0x0000, 0x0000, 0x0000, 0x8888)));
        assert_ne!(s, x);
    }
}
