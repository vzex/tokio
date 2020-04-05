//! The [syscall] module is intended to provide a centralized location
//! for interacting with OS resources such as disks and network.
//!
//! ## Extension
//! The [`Syscall`] trait allows hooking into implementations of Tokio
//! disk and networking resources to supply alternate implementations
//! or mocks.
//!
//! [syscall]:crate::syscall
//! [`Syscall`]:crate::syscall::Syscall

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
        /// Create and return a new UdpResource, an attempt to bind it to the `addr`
        /// provided.
        fn udp_bind(&self, addr: &net::SocketAddr) -> io::Result<UdpResource>;

        /// Poll send
        fn poll_udp_send_to(
            &self,
            socket: &UdpResource,
            cx: &mut Context<'_>,
            buf: &[u8],
            target: &net::SocketAddr,
        ) -> Poll<io::Result<usize>>;
    }

    /// Ensure that Syscalls remains object safe
    #[allow(dead_code)]
    fn assert_obj_safe(_: Box<dyn Syscalls>) {}

}
