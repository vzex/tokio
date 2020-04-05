use std::{
    convert::TryFrom,
    io, net,
    task::{Context, Poll},
};

cfg_syscall! {
    use crate::syscall::Syscalls;
    use std::sync::Arc;
    /// A representation of a UDP socket.
    #[derive(Debug, Copy, Clone)]
    pub struct UdpResource(usize);

    fn syscalls() -> Arc<dyn Syscalls> {
        crate::runtime::context::syscalls().expect("Syscalls not supplied to the Runtime")
    }
}
cfg_not_syscall! {
    use crate::io::PollEvented;
    /// A representation of a UDP socket.
    pub type UdpResource = PollEvented<mio::net::UdpSocket>;
}

impl UdpResource {
    pub(crate) fn bind_addr(addr: &net::SocketAddr) -> io::Result<Self> {
        cfg_if_syscall! {
            {
                syscalls().udp_bind(addr)
            } else {
                let sys = mio::net::UdpSocket::bind(&addr)?;
                let io = PollEvented::new(sys)?;
                Ok(io)
            }
        }
    }

    pub(crate) fn connect(&self, addr: net::SocketAddr) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().connect(addr)
            }
        }
    }

    pub(crate) fn from_std(socket: net::UdpSocket) -> io::Result<Self> {
        cfg_if_syscall! {
            {
                panic!("cannot convert net::UdpSocket to UdpResource with provided syscalls");
            } else {
                let io = mio::net::UdpSocket::from_socket(socket)?;
                PollEvented::new(io)
            }
        }
    }

    pub(crate) fn local_addr(&self) -> io::Result<net::SocketAddr> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().local_addr()
            }
        }
    }

    pub(crate) fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                ready!(self.poll_write_ready(cx))?;
                match self.get_ref().send(buf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.clear_write_ready(cx)?;
                        Poll::Pending
                    }
                    x => Poll::Ready(x),
                }
            }
        }
    }

    pub(crate) fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                ready!(self.poll_read_ready(cx, mio::Ready::readable()))?;

                match self.get_ref().recv(buf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.clear_read_ready(cx, mio::Ready::readable())?;
                        Poll::Pending
                    }
                    x => Poll::Ready(x),
                }
            }
        }
    }

    pub(crate) fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &net::SocketAddr,
    ) -> Poll<io::Result<usize>> {
        cfg_if_syscall! {
            {
                syscalls().poll_udp_send_to(&self, cx, buf, target)
            } else {
                ready!(self.poll_write_ready(cx))?;

                match self.get_ref().send_to(buf, target) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.clear_write_ready(cx)?;
                        Poll::Pending
                    }
                    x => Poll::Ready(x),
                }
            }
        }
    }

    pub(crate) fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, net::SocketAddr)>> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                ready!(self.poll_read_ready(cx, mio::Ready::readable()))?;

                match self.get_ref().recv_from(buf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.clear_read_ready(cx, mio::Ready::readable())?;
                        Poll::Pending
                    }
                    x => Poll::Ready(x),
                }
            }
        }
    }

    pub(crate) fn broadcast(&self) -> io::Result<bool> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().broadcast()
            }
        }
    }

    pub(crate) fn set_broadcast(&self, on: bool) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().set_broadcast(on)
            }
        }
    }

    pub(crate) fn multicast_loop_v4(&self) -> io::Result<bool> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().multicast_loop_v4()
            }
        }
    }

    pub(crate) fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().set_multicast_loop_v4(on)
            }
        }
    }

    pub(crate) fn multicast_ttl_v4(&self) -> io::Result<u32> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().multicast_ttl_v4()
            }
        }
    }

    pub(crate) fn set_multicast_ttl_v4(&self, ttl: u32) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().set_multicast_ttl_v4(ttl)
            }
        }
    }

    pub(crate) fn multicast_loop_v6(&self) -> io::Result<bool> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().multicast_loop_v6()
            }
        }
    }

    pub(crate) fn set_multicast_loop_v6(&self, on: bool) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().set_multicast_loop_v6(on)
            }
        }
    }

    pub(crate) fn ttl(&self) -> io::Result<u32> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().ttl()
            }
        }
    }

    pub(crate) fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().set_ttl(ttl)
            }
        }
    }

    pub(crate) fn join_multicast_v4(
        &self,
        multiaddr: net::Ipv4Addr,
        interface: net::Ipv4Addr,
    ) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().join_multicast_v4(&multiaddr, &interface)
            }
        }
    }
    pub(crate) fn join_multicast_v6(
        &self,
        multiaddr: &net::Ipv6Addr,
        interface: u32,
    ) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().join_multicast_v6(&multiaddr, interface)
            }
        }
    }

    pub(crate) fn leave_multicast_v4(
        &self,
        multiaddr: net::Ipv4Addr,
        interface: net::Ipv4Addr,
    ) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().leave_multicast_v4(&multiaddr, &interface)
            }
        }
    }
    pub(crate) fn leave_multicast_v6(
        &self,
        multiaddr: &net::Ipv6Addr,
        interface: u32,
    ) -> io::Result<()> {
        cfg_if_syscall! {
            {
                unimplemented!()
            } else {
                self.get_ref().leave_multicast_v6(&multiaddr, interface)
            }
        }
    }
}

impl TryFrom<UdpResource> for mio::net::UdpSocket {
    type Error = io::Error;
    fn try_from(value: UdpResource) -> Result<Self, Self::Error> {
        cfg_if_syscall! {
            {
                panic!("cannot convert UdpResource to mio::net::UdpSocket with provided syscalls");
            } else {
                value.into_inner()
            }
        }
    }
}

#[cfg(all(unix))]
mod sys {
    use super::UdpResource;
    use std::os::unix::prelude::*;

    impl AsRawFd for UdpResource {
        fn as_raw_fd(&self) -> RawFd {
            cfg_if_syscall! {
                {
                    panic!("cannot convert UdpResource to RawFd with provided syscalls");
                } else {
                    self.get_ref().as_raw_fd()
                }
            }
        }
    }
}
