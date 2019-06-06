use udp::UdpSocket;


#[cfg(target_os = "linux")] const ADDR: &str = "lo@127.0.0.1:10000";
#[cfg(target_os = "macos")] const ADDR: &str = "lo0@127.0.0.1:10000";


#[test]
fn test_send_receive() {
    let ssock = UdpSocket::open(ADDR).unwrap();
    let rsock = UdpSocket::bind(ADDR).unwrap();
    let sdata = String::from("Hello, world!");
    let sbytes = ssock.sendto(sdata.as_bytes()).unwrap();
    let mut rdata = [0; 1460];
    let rbytes = rsock.recv(&mut rdata).unwrap();
    assert_eq!(sbytes, rbytes);
    assert_eq!(sdata.as_bytes(), &rdata[.. rbytes]);
}
