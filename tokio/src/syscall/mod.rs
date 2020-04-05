//! Syscall Dox

cfg_udp! {
    mod udp;
    pub use udp::UdpResource;
}

cfg_syscall! {
    use std::{
        fmt::Debug,
        io, net,
        task::{Context, Poll},
    };
    /// Syscalls
    pub trait Syscalls: Send + Sync + Debug {
        /// Return a UDP socket
        fn udp_bind(&self, addr: net::SocketAddr) -> io::Result<UdpResource>;

        /// Poll send
        fn poll_udp_send_to(
            &self,
            socket: UdpResource,
            cx: &mut Context<'_>,
            buf: &[u8],
            target: net::SocketAddr,
        ) -> Poll<io::Result<usize>>;
    }

    /// Ensure that Syscalls remains object safe
    #[allow(dead_code)]
    fn assert_obj_safe(_: Box<dyn Syscalls>) {}

}
