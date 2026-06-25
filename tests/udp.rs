use std::{
    net::UdpSocket as StdUdpSocket,
    os::fd::{
        FromRawFd,
        IntoRawFd,
    },
};

use udp::UdpSocket;

#[cfg(target_os = "linux")]
const ADDR: &str = "lo@127.0.0.1:10000";
#[cfg(target_os = "macos")]
const ADDR: &str = "lo0@127.0.0.1:10000";

#[test]
fn test_send_receive() {
    let ssock = UdpSocket::open(ADDR).unwrap();
    let rsock = UdpSocket::bind(ADDR).unwrap();

    let dest = ssock.addr();

    // Hand the configured descriptors over to std for the actual I/O.
    let send = unsafe { StdUdpSocket::from_raw_fd(ssock.into_raw_fd()) };
    let recv = unsafe { StdUdpSocket::from_raw_fd(rsock.into_raw_fd()) };

    let sdata = b"Hello, world!";
    let sbytes = send.send_to(sdata, dest).unwrap();

    let mut rdata = [0; 1460];
    let rbytes = recv.recv(&mut rdata).unwrap();

    assert_eq!(sbytes, rbytes);
    assert_eq!(&sdata[..], &rdata[.. rbytes]);
}
