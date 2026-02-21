//! some random protocol poc, helped by GPT and Gemini
//!
//! ```text
//! +------+----------+----------+----------+----------+
//! | ATYP | DST.ADDR | DST.PORT | Checksum | Payload  |
//! +------+----------+----------+----------+----------+
//! |  1   | Variable |    2     |    4     | Variable |
//! +------+----------+----------+----------+----------+
//!
//! where:
//!     o  ATYP address type of following address
//!         o  IP V4 address: X'01'
//!         o  DOMAINNAME: X'03'
//!         o  IP V6 address: X'04'
//!     o  DST.ADDR desired destination address
//!     o  DST.PORT desired destination port in network octet order
//!     o  CHECKSUM integrity protection field in network octet order
//!        computed over:
//!            ATYP + DST.ADDR + DST.PORT
//!
//! where: DST.ADDR
//!
//! IP V4:
//! +------+
//! |  IP  |
//! +------+
//! |  4   |
//! +------+
//!
//! DOMAINNAME:
//! +--------+------------+
//! | LENGTH | DOMAINNAME |
//! +--------+------------+
//! |   2    |  Variable  |
//! +--------+------------+
//!
//! IP V6:
//! +------+
//! |  IP  |
//! +------+
//! |  16  |
//! +------+
//! ```
//!
//! This PoC protocol intentionally trades a small amount of computation for a smaller proxy header footprint.

use std::{
    io::{self, Error, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, Copy)]
pub enum Addr<'a> {
    Ipv4(Ipv4Addr, u16),
    Domain(&'a str, u16),
    Ipv6(Ipv6Addr, u16),
}

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const ATYP_LEN: usize = 1;
const PORT_LEN: usize = 2;
const DOMAIN_LEN_LEN: usize = 2;
const IPV4_LEN: usize = 4;
const IPV6_LEN: usize = 16;
const CHECKSUM_LEN: usize = 4;

pub struct Protocol;

impl Protocol {
    pub fn encode_into(addr: Addr, out: &mut [u8]) -> io::Result<usize> {
        let mut pos = 0;

        macro_rules! ensure_space {
            ($n:expr) => {
                if pos + $n > out.len() {
                    return Err(Error::new(ErrorKind::WriteZero, "buffer too small"));
                }
            };
        }

        match addr {
            Addr::Ipv4(ipv4, port) => {
                ensure_space!(ATYP_LEN + IPV4_LEN + PORT_LEN);
                out[pos] = ATYP_IPV4;
                pos += ATYP_LEN;

                out[pos..pos + IPV4_LEN].copy_from_slice(&ipv4.octets());
                pos += IPV4_LEN;

                out[pos..pos + 2].copy_from_slice(&port.to_be_bytes());
                pos += PORT_LEN;
            }

            Addr::Domain(domain, port) => {
                let len = domain.len();
                if len > u16::MAX as usize {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "domain len exceed u16::MAX",
                    ));
                }

                ensure_space!(ATYP_LEN + DOMAIN_LEN_LEN + len + PORT_LEN);

                out[pos] = ATYP_DOMAIN;
                pos += ATYP_LEN;

                out[pos..pos + DOMAIN_LEN_LEN].copy_from_slice(&(len as u16).to_be_bytes());
                pos += DOMAIN_LEN_LEN;

                out[pos..pos + len].copy_from_slice(domain.as_bytes());
                pos += len;

                out[pos..pos + PORT_LEN].copy_from_slice(&port.to_be_bytes());
                pos += PORT_LEN;
            }

            Addr::Ipv6(ipv6, port) => {
                ensure_space!(ATYP_LEN + IPV6_LEN + PORT_LEN);

                out[pos] = ATYP_IPV6;
                pos += ATYP_LEN;

                out[pos..pos + IPV6_LEN].copy_from_slice(&ipv6.octets());
                pos += IPV6_LEN;

                out[pos..pos + PORT_LEN].copy_from_slice(&port.to_be_bytes());
                pos += PORT_LEN;
            }
        }

        // checksum
        ensure_space!(CHECKSUM_LEN);
        let chksum = Self::chksum(&out[..pos]);
        out[pos..pos + CHECKSUM_LEN].copy_from_slice(&chksum.to_be_bytes());
        pos += CHECKSUM_LEN;

        Ok(pos)
    }

    pub fn decode_from<'a>(buf: &'a [u8]) -> io::Result<(Addr<'a>, usize)> {
        if buf.len() < ATYP_LEN {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "buffer too short for atyp",
            ));
        }

        let mut pos = 0;

        let atyp = buf[0];
        pos += ATYP_LEN;

        let header_len = ATYP_LEN
            + if atyp == ATYP_DOMAIN {
                DOMAIN_LEN_LEN
            } else {
                0
            }
            + Self::addr_len(buf, atyp)?
            + CHECKSUM_LEN;

        if buf.len() < header_len {
            return Err(Error::new(ErrorKind::UnexpectedEof, "buffer too short"));
        }

        let data = &buf[..header_len];

        if !Self::check_chksum(data) {
            return Err(Error::new(ErrorKind::InvalidData, "bad checksum"));
        }

        Ok((
            match atyp {
                ATYP_IPV4 => {
                    let ip = Ipv4Addr::from(
                        <[u8; IPV4_LEN]>::try_from(&data[pos..pos + IPV4_LEN]).unwrap(),
                    );
                    pos += IPV4_LEN;

                    let port = u16::from_be_bytes(data[pos..pos + PORT_LEN].try_into().unwrap());

                    Addr::Ipv4(ip, port)
                }

                ATYP_DOMAIN => {
                    pos += DOMAIN_LEN_LEN;

                    let domain_end = data.len() - PORT_LEN - CHECKSUM_LEN;
                    let domain_bytes = &data[pos..domain_end];

                    let domain = std::str::from_utf8(domain_bytes)
                        .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid utf8"))?;

                    pos = domain_end;

                    let port = u16::from_be_bytes(data[pos..pos + PORT_LEN].try_into().unwrap());

                    Addr::Domain(domain, port)
                }

                ATYP_IPV6 => {
                    let ip = Ipv6Addr::from(
                        <[u8; IPV6_LEN]>::try_from(&data[pos..pos + IPV6_LEN]).unwrap(),
                    );
                    pos += IPV6_LEN;

                    let port = u16::from_be_bytes(data[pos..pos + PORT_LEN].try_into().unwrap());

                    Addr::Ipv6(ip, port)
                }

                _ => unreachable!(),
            },
            header_len,
        ))
    }

    fn addr_len(buf: &[u8], atyp: u8) -> Result<usize, Error> {
        Ok(match atyp {
            ATYP_IPV4 => IPV4_LEN + PORT_LEN,
            ATYP_IPV6 => IPV6_LEN + PORT_LEN,
            ATYP_DOMAIN => {
                if buf.len() < ATYP_LEN + DOMAIN_LEN_LEN {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "partial domain len"));
                }

                let len_bytes = &buf[ATYP_LEN..ATYP_LEN + DOMAIN_LEN_LEN];
                let domain_len = u16::from_be_bytes(len_bytes.try_into().unwrap()) as usize;

                domain_len + PORT_LEN
            }
            _ => return Err(Error::new(ErrorKind::InvalidData, "unknown atyp")),
        })
    }

    pub fn obfs<F>(buf: &mut [u8], f: F) -> io::Result<()>
    where
        F: FnOnce(&mut [u8]),
    {
        if buf.len() < ATYP_LEN {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "buffer too short for atyp",
            ));
        }

        let atyp = buf[0];

        let addr_len = Self::addr_len(buf, atyp)?;

        let start_offset = if atyp == ATYP_DOMAIN {
            ATYP_LEN + DOMAIN_LEN_LEN
        } else {
            ATYP_LEN
        };

        let end_offset = start_offset + addr_len;

        if buf.len() < end_offset {
            return Err(Error::new(ErrorKind::UnexpectedEof, "unexpected EOF"));
        }

        f(&mut buf[start_offset..end_offset]);

        Ok(())
    }

    fn check_chksum(buf: &[u8]) -> bool {
        if buf.len() < CHECKSUM_LEN {
            return false;
        }

        let split = buf.len() - CHECKSUM_LEN;
        let (data, chksum) = buf.split_at(split);

        let Ok(bytes) = chksum.try_into() else {
            return false;
        };

        let given = u32::from_be_bytes(bytes);
        let computed = Self::chksum(data);

        computed == given
    }

    fn chksum(buf: &[u8]) -> u32 {
        let mut chksum = buf
            .chunks(4)
            .map(|chunk| {
                let mut tmp = [0u8; 4];
                tmp[..chunk.len()].copy_from_slice(chunk);
                u32::from_be_bytes(tmp)
            })
            .fold(0u32, |acc, v| acc ^ v);

        chksum ^= chksum >> 16;
        chksum = chksum.wrapping_mul(0x7feb352d);
        chksum ^= chksum >> 15;
        chksum = chksum.wrapping_mul(0x846ca68b);
        chksum ^= chksum >> 16;
        chksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(addr: Addr) {
        let mut buf = [0u8; 512];

        let len = Protocol::encode_into(addr, &mut buf).unwrap();
        let decoded = Protocol::decode_from(&buf[..len]).unwrap();

        match (addr, decoded.0) {
            (Addr::Ipv4(a_ip, a_port), Addr::Ipv4(b_ip, b_port)) => {
                assert_eq!(a_ip, b_ip);
                assert_eq!(a_port, b_port);
            }
            (Addr::Ipv6(a_ip, a_port), Addr::Ipv6(b_ip, b_port)) => {
                assert_eq!(a_ip, b_ip);
                assert_eq!(a_port, b_port);
            }
            (Addr::Domain(a_dom, a_port), Addr::Domain(b_dom, b_port)) => {
                assert_eq!(a_dom, b_dom);
                assert_eq!(a_port, b_port);
            }
            _ => panic!("variant mismatch"),
        }
    }

    #[test]
    fn test_ipv4_roundtrip() {
        roundtrip(Addr::Ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080));
    }

    #[test]
    fn test_ipv6_roundtrip() {
        roundtrip(Addr::Ipv6(Ipv6Addr::LOCALHOST, 443));
    }

    #[test]
    fn test_domain_roundtrip() {
        roundtrip(Addr::Domain("example.com", 53));
    }

    #[test]
    fn test_bad_checksum() {
        let mut buf = [0u8; 512];

        let len =
            Protocol::encode_into(Addr::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 1234), &mut buf).unwrap();

        buf[1] ^= 0xFF;

        Protocol::decode_from(&buf[..len]).unwrap_err();
    }

    fn xor_obfs(buf: &mut [u8]) {
        buf.iter_mut().for_each(|b| *b ^= 0xAA);
    }

    #[test]
    fn test_obfs_roundtrip_ok() {
        let mut buf = [0u8; 512];

        let addr = Addr::Domain("abc.com", 80);

        let len = Protocol::encode_into(addr, &mut buf).unwrap();

        Protocol::obfs(&mut buf[..len], xor_obfs).unwrap();

        Protocol::obfs(&mut buf[..len], xor_obfs).unwrap();

        let decoded = Protocol::decode_from(&buf[..len]).unwrap().0;

        match decoded {
            Addr::Domain(d, p) => {
                assert_eq!(d, "abc.com");
                assert_eq!(p, 80);
            }
            _ => panic!("unexpected addr type"),
        }
    }

    #[test]
    fn test_obfs_single_round_fails() {
        let mut buf = [0u8; 512];

        let len = Protocol::encode_into(Addr::Domain("abc.com", 80), &mut buf).unwrap();

        Protocol::obfs(&mut buf[..len], xor_obfs).unwrap();

        Protocol::decode_from(&buf[..len]).unwrap_err();
    }
}
