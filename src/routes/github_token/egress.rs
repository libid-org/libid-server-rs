//! Reaching the notary a request names: resolve the host once, refuse a
//! private or internal address, connect to a resolved address on the wire port.

use std::{
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
    },
    time::Duration,
};

use tokio::net::TcpStream;

use crate::error::{
    Error,
    Result,
};

/// The budget for resolving the notary and connecting to it.
const REACH_TIMEOUT: Duration = Duration::from_secs(5);

/// Dials the notary each token request names.
#[derive(Debug)]
pub struct NotaryEgress {
    /// The port of every notary's MPC-TLS wire listener.
    wire_port: u16,
}

impl NotaryEgress {
    pub(crate) fn new(wire_port: u16) -> Self {
        NotaryEgress { wire_port }
    }

    /// The notary's wire as a connected socket.
    ///
    /// `host` is a DNS name or IP literal, with or without brackets. It is
    /// resolved once; if any resolved address is private or internal the
    /// request is refused without a connection, otherwise the first address
    /// that accepts is returned. Loopback is dialled.
    pub(crate) async fn reach(&self, host: &str) -> Result<TcpStream> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        tokio::time::timeout(REACH_TIMEOUT, self.reach_unbounded(host))
            .await
            .map_err(|_| Error::NotaryConnect {
                addr: self.wire_of(host),
                detail: "did not answer in time".into(),
            })?
    }

    /// `host:port` of the wire, bracketed for an IPv6 literal.
    fn wire_of(&self, host: &str) -> String {
        if host.contains(':') {
            format!("[{host}]:{}", self.wire_port)
        } else {
            format!("{host}:{}", self.wire_port)
        }
    }

    async fn reach_unbounded(&self, host: &str) -> Result<TcpStream> {
        let unreachable = |detail: String| Error::NotaryConnect {
            addr: self.wire_of(host),
            detail,
        };

        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, self.wire_port))
            .await
            .map_err(|e| unreachable(format!("resolving: {e}")))?
            .collect();
        if addrs.is_empty() {
            return Err(unreachable("resolved to no address".into()));
        }
        if let Some(private) = addrs.iter().find(|a| is_internal(a.ip())) {
            tracing::warn!(
                notary = host,
                resolved = %private.ip(),
                "refused a token request naming a private or internal notary"
            );
            return Err(Error::NotaryRefused {
                detail: "resolved to a private or internal address".into(),
            });
        }

        let mut last = None;
        for addr in &addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(unreachable(match last {
            Some(e) => e.to_string(),
            None => "no address to connect to".into(),
        }))
    }
}

/// Whether an address is refused as a notary destination: the unspecified,
/// private, link-local, carrier-grade NAT, documentation, multicast, broadcast
/// and reserved ranges. An IPv4 address carried in IPv6 (mapped or NAT64) is
/// judged as the IPv4 address. Loopback is not refused.
pub(crate) fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal_v4(v4);
            }
            let s = v6.segments();
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [a, b] = [s[6], s[7]].map(u16::to_be_bytes);
                return is_internal_v4(Ipv4Addr::new(a[0], a[1], b[0], b[1]));
            }
            v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                // 2001:db8::/32, documentation.
                || (s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

fn is_internal_v4(v4: Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    v4.is_unspecified()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_multicast()
        // 0.0.0.0/8, "this network".
        || a == 0
        // 100.64.0.0/10, carrier-grade NAT.
        || (a == 100 && (64..=127).contains(&b))
        // 240.0.0.0/4, reserved.
        || a >= 240
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One row per range the policy names, and the addresses it leaves alone.
    #[test]
    fn internal_addresses_are_the_ones_the_policy_names() {
        for (ip, internal) in [
            ("10.0.0.1", true),
            ("172.16.0.1", true),
            ("172.31.255.255", true),
            ("192.168.1.1", true),
            ("169.254.169.254", true),
            ("100.64.0.1", true),
            ("0.0.0.0", true),
            ("240.0.0.1", true),
            ("255.255.255.255", true),
            ("224.0.0.1", true),
            ("192.0.2.1", true),
            ("::", true),
            ("fc00::1", true),
            ("fe80::1", true),
            ("ff02::1", true),
            ("2001:db8::1", true),
            ("::ffff:10.0.0.1", true),
            ("64:ff9b::a00:1", true),
            ("127.0.0.1", false),
            ("::1", false),
            ("::ffff:127.0.0.1", false),
            ("8.8.8.8", false),
            ("1.1.1.1", false),
            ("172.32.0.1", false),
            ("100.128.0.1", false),
            ("2606:4700::1111", false),
            ("::ffff:8.8.8.8", false),
            ("64:ff9b::808:808", false),
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert_eq!(is_internal(parsed), internal, "{ip}");
        }
    }

    /// A private address is refused without a socket; loopback is dialled --
    /// here on a port nothing listens on, so the dial fails at once.
    #[tokio::test]
    async fn a_private_notary_is_refused_and_a_loopback_one_is_dialled() {
        let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let egress = NotaryEgress::new(port);

        let err = egress.reach("10.0.0.1").await.unwrap_err();
        assert!(matches!(err, Error::NotaryRefused { .. }), "{err}");

        let err = egress.reach("127.0.0.1").await.unwrap_err();
        assert!(matches!(err, Error::NotaryConnect { .. }), "{err}");
        assert!(err.to_string().contains(&port.to_string()), "{err}");
    }
}
