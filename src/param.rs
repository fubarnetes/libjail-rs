//! Module for inspection and manipulation of jail parameters

use libc;

use std::convert;
use std::ffi::{CStr, CString};
use std::mem;
use std::net;
use std::slice;

use sys::JailFlags;
use JailError;

use byteorder::{ByteOrder, LittleEndian, NetworkEndian, WriteBytesExt};
use sysctl::{Ctl, CtlType, CtlValue};

use nix;

/// An enum representing the type of a parameter.
#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub enum Type {
    String,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    Int,
    Long,
    Uint,
    Ulong,
    Ipv4Addrs,
    Ipv6Addrs,
}

impl<'a> convert::From<&'a Value> for Type {
    fn from(t: &'a Value) -> Type {
        match t {
            Value::Int(_) => Type::Int,
            Value::String(_) => Type::String,
            Value::S64(_) => Type::S64,
            Value::Uint(_) => Type::Uint,
            Value::Long(_) => Type::Long,
            Value::Ulong(_) => Type::Ulong,
            Value::U64(_) => Type::U64,
            Value::U8(_) => Type::U8,
            Value::U16(_) => Type::U16,
            Value::S8(_) => Type::S8,
            Value::S16(_) => Type::S16,
            Value::S32(_) => Type::S32,
            Value::U32(_) => Type::U32,
            Value::Ipv4Addrs(_) => Type::Ipv4Addrs,
            Value::Ipv6Addrs(_) => Type::Ipv6Addrs,
        }
    }
}

// impl convert::From<Value> for Type {
//     fn from(t: Value) -> Type {
//         match t {
//             Value::Int(_) => Type::Int,
//             Value::String(_) => Type::String,
//             Value::S64(_) => Type::S64,
//             Value::Uint(_) => Type::Uint,
//             Value::Long(_) => Type::Long,
//             Value::Ulong(_) => Type::Ulong,
//             Value::U64(_) => Type::U64,
//             Value::U8(_) => Type::U8,
//             Value::U16(_) => Type::U16,
//             Value::S8(_) => Type::S8,
//             Value::S16(_) => Type::S16,
//             Value::S32(_) => Type::S32,
//             Value::U32(_) => Type::U32,
//         }
//     }
// }

impl convert::Into<CtlType> for Type {
    fn into(self: Type) -> CtlType {
        match self {
            Type::String => CtlType::String,
            Type::U8 => CtlType::U8,
            Type::U16 => CtlType::U16,
            Type::U32 => CtlType::U32,
            Type::U64 => CtlType::U64,
            Type::S8 => CtlType::S8,
            Type::S16 => CtlType::S16,
            Type::S32 => CtlType::S32,
            Type::S64 => CtlType::S64,
            Type::Int => CtlType::Int,
            Type::Long => CtlType::Long,
            Type::Uint => CtlType::Uint,
            Type::Ulong => CtlType::Ulong,
            Type::Ipv4Addrs => CtlType::Struct,
            Type::Ipv6Addrs => CtlType::Struct,
        }
    }
}

/// An enum representing the value of a parameter.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Value {
    Int(libc::c_int),
    String(String),
    S64(i64),
    Uint(libc::c_uint),
    Long(libc::c_long),
    Ulong(libc::c_ulong),
    U64(u64),
    U8(u8),
    U16(u16),
    S8(i8),
    S16(i16),
    S32(i32),
    U32(u32),

    /// Represent a list of IPv4 addresses.
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Value;
    /// let rfc1918 = Value::Ipv4Addrs(vec![
    ///     "10.0.0.0".parse().unwrap(),
    ///     "172.16.0.0".parse().unwrap(),
    ///     "192.168.0.0".parse().unwrap(),
    /// ]);
    /// ```
    Ipv4Addrs(Vec<net::Ipv4Addr>),

    /// Represent a list of IPv6 addresses.
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Value;
    /// let all_nodes = Value::Ipv6Addrs(vec![
    ///     "ff01::1".parse().unwrap(),
    ///     "ff02::1".parse().unwrap(),
    /// ]);
    /// ```
    Ipv6Addrs(Vec<net::Ipv6Addr>),
}

impl Value {
    /// Attempt to unpack the Vector of IPv4 addresses contained in this value
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Value;
    /// use std::net;
    /// # let rfc1918 = Value::Ipv4Addrs(vec![
    /// #     "10.0.0.0".parse().unwrap(),
    /// #     "172.16.0.0".parse().unwrap(),
    /// #     "192.168.0.0".parse().unwrap(),
    /// # ]);
    /// let ips = rfc1918
    ///     .into_ipv4()
    ///     .expect("could not unwrap RFC1918 IP Addresses");
    /// assert_eq!(ips[0], net::Ipv4Addr::new(10,0,0,0));
    /// ```
    ///
    /// Attempting to unwrap a different value will fail:
    /// ```should_panic
    /// use jail::param::Value;
    /// let not_ipv4_addrs = Value::U8(42);
    /// not_ipv4_addrs.into_ipv4().unwrap();
    /// ```
    pub fn into_ipv4(self) -> Result<Vec<net::Ipv4Addr>, JailError> {
        match self {
            Value::Ipv4Addrs(v) => Ok(v),
            _ => Err(JailError::ParameterUnpackError),
        }
    }

    /// Attempt to unpack the Vector of IPv4 addresses contained in this value
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Value;
    /// use std::net;
    /// # let all_nodes = Value::Ipv6Addrs(vec![
    /// #     "ff01::1".parse().unwrap(),
    /// #     "ff02::1".parse().unwrap(),
    /// # ]);
    /// let ips = all_nodes
    ///     .into_ipv6()
    ///     .expect("could not unwrap 'All Nodes' IPv6 Addresses");
    /// assert_eq!(ips[0], net::Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 1))
    /// ```
    ///
    /// Attempting to unwrap a different value will fail:
    /// ```should_panic
    /// use jail::param::Value;
    /// # let rfc1918 = Value::Ipv4Addrs(vec![
    /// #     "10.0.0.0".parse().unwrap(),
    /// #     "172.16.0.0".parse().unwrap(),
    /// #     "192.168.0.0".parse().unwrap(),
    /// # ]);
    /// rfc1918.into_ipv6().unwrap();
    /// ```
    pub fn into_ipv6(self) -> Result<Vec<net::Ipv6Addr>, JailError> {
        match self {
            Value::Ipv6Addrs(v) => Ok(v),
            _ => Err(JailError::ParameterUnpackError),
        }
    }
}

#[cfg(target_os = "freebsd")]
fn info(name: &str) -> Result<(CtlType, usize), JailError> {
    // Get parameter type
    let ctlname = format!("security.jail.param.{}", name);

    let ctl = Ctl::new(&ctlname).map_err(|_| JailError::NoSuchParameter(name.to_string()))?;

    let paramtype = ctl.value_type().map_err(JailError::ParameterTypeError)?;

    let typesize = match paramtype {
        CtlType::Int => mem::size_of::<libc::c_int>(),
        CtlType::String => {
            let length = match ctl.value().map_err(JailError::ParameterStringLengthError)? {
                CtlValue::String(l) => l,
                _ => panic!("param sysctl reported to be string, but isn't"),
            };

            length
                .parse::<usize>()
                .map_err(|_| JailError::ParameterLengthNaN(length.to_string()))?
        }

        CtlType::S64 => mem::size_of::<i64>(),
        CtlType::Uint => mem::size_of::<libc::c_uint>(),
        CtlType::Long => mem::size_of::<libc::c_long>(),
        CtlType::Ulong => mem::size_of::<libc::c_ulong>(),
        CtlType::U64 => mem::size_of::<u64>(),
        CtlType::U8 => mem::size_of::<u8>(),
        CtlType::U16 => mem::size_of::<u16>(),
        CtlType::S8 => mem::size_of::<i8>(),
        CtlType::S16 => mem::size_of::<i16>(),
        CtlType::S32 => mem::size_of::<i32>(),
        CtlType::U32 => mem::size_of::<u32>(),
        CtlType::Struct => match ctl.value().map_err(JailError::ParameterStructLengthError)? {
            CtlValue::Struct(data) => {
                assert!(
                    data.len() >= mem::size_of::<usize>(),
                    "Error: struct sysctl returned too few bytes."
                );
                LittleEndian::read_uint(&data, mem::size_of::<usize>()) as usize
            }
            _ => panic!("param sysctl reported to be struct, but isn't"),
        },
        _ => return Err(JailError::ParameterTypeUnsupported(paramtype)),
    };

    Ok((paramtype, typesize))
}

/// Get a jail parameter given the jid and the parameter name.
///
/// # Examples
/// ```
/// use jail::param;
/// # use jail::StoppedJail;
/// # let jail = StoppedJail::new("/rescue")
/// #     .name("testjail_getparam")
/// #     .start()
/// #     .expect("could not start jail");
/// # let jid = jail.jid;
///
/// let hostuuid = param::get(jid, "host.hostuuid")
///     .expect("could not get parameter");
///
/// println!("{:?}", hostuuid);
/// #
/// # jail.kill().expect("could not stop jail");
/// ```
#[cfg(target_os = "freebsd")]
pub fn get(jid: i32, name: &str) -> Result<Value, JailError> {
    let (paramtype, typesize) = info(name)?;

    // ip4.addr and ip6.addr are arrays, which can be up to
    // security.jail.jail_max_af_ips long:
    let jail_max_af_ips = match Ctl::new("security.jail.jail_max_af_ips")
        .map_err(JailError::JailMaxAfIpsFailed)?
        .value()
        .map_err(JailError::JailMaxAfIpsFailed)?
    {
        CtlValue::Uint(u) => u as usize,
        _ => panic!("security.jail.jail_max_af_ips has the wrong type."),
    };

    let valuesize = match name {
        "ip4.addr" => typesize * jail_max_af_ips,
        "ip6.addr" => typesize * jail_max_af_ips,
        _ => typesize,
    };

    let paramname = CString::new(name).expect("Could not convert parameter name to CString");

    let mut value: Vec<u8> = vec![0; valuesize];
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"jid\0"),
        iovec!(&jid as *const _, mem::size_of::<i32>()),
        iovec!(paramname.as_ptr(), paramname.as_bytes().len() + 1),
        iovec!(value.as_mut_ptr(), valuesize),
        iovec!(b"errmsg\0"),
        iovec!(errmsg.as_mut_ptr(), errmsg.len()),
    ];

    let jid = unsafe {
        libc::jail_get(
            jiov[..].as_mut_ptr() as *mut libc::iovec,
            jiov.len() as u32,
            JailFlags::empty().bits(),
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut i8) }
        .to_string_lossy()
        .to_string();

    let value = match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(JailError::from_errno()),
            _ => Err(JailError::JailGetError(err)),
        },
        _ => Ok(value),
    }?;

    // Wrap in Enum and return
    match paramtype {
        CtlType::Int => Ok(Value::Int(
            LittleEndian::read_int(&value, mem::size_of::<libc::c_int>()) as libc::c_int,
        )),
        CtlType::S64 => Ok(Value::S64(LittleEndian::read_i64(&value))),
        CtlType::Uint => Ok(Value::Uint(LittleEndian::read_uint(
            &value,
            mem::size_of::<libc::c_uint>(),
        ) as libc::c_uint)),
        CtlType::Long => Ok(Value::Long(LittleEndian::read_int(
            &value,
            mem::size_of::<libc::c_long>(),
        ) as libc::c_long)),
        CtlType::Ulong => Ok(Value::Ulong(LittleEndian::read_uint(
            &value,
            mem::size_of::<libc::c_ulong>(),
        ) as libc::c_ulong)),
        CtlType::U64 => Ok(Value::U64(LittleEndian::read_u64(&value))),
        CtlType::U8 => Ok(Value::U8(value[0])),
        CtlType::U16 => Ok(Value::U16(LittleEndian::read_u16(&value))),
        CtlType::S8 => Ok(Value::S8(value[0] as i8)),
        CtlType::S16 => Ok(Value::S16(LittleEndian::read_i16(&value))),
        CtlType::S32 => Ok(Value::S32(LittleEndian::read_i32(&value))),
        CtlType::U32 => Ok(Value::U32(LittleEndian::read_u32(&value))),
        CtlType::String => Ok(Value::String({
            unsafe { CStr::from_ptr(value.as_ptr() as *mut i8) }
                .to_string_lossy()
                .into_owned()
        })),
        CtlType::Struct => match name {
            // FIXME: The following is just placeholder code.
            "ip4.addr" => {
                // Make sure we got the right data size
                let addrsize = mem::size_of::<libc::in_addr>();
                let count = valuesize / addrsize;

                assert_eq!(
                    0,
                    typesize % addrsize,
                    "Error: memory size mismatch. Length of data \
                     retrieved is not a multiple of the size of in_addr."
                );

                #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
                let ips: Vec<net::Ipv4Addr> = unsafe {
                    slice::from_raw_parts(value.as_ptr() as *const libc::in_addr, count)
                }.iter()
                    .map(|in_addr| u32::from_be(in_addr.s_addr))
                    .map(net::Ipv4Addr::from)
                    .filter(|ip| !ip.is_unspecified())
                    .collect();

                Ok(Value::Ipv4Addrs(ips))
            }
            "ip6.addr" => {
                // Make sure we got the right data size
                let addrsize = mem::size_of::<libc::in6_addr>();
                let count = valuesize / addrsize;

                assert_eq!(
                    0,
                    typesize % addrsize,
                    "Error: memory size mismatch. Length of data \
                     retrieved is not a multiple of the size of in_addr."
                );

                #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
                let ips: Vec<net::Ipv6Addr> = unsafe {
                    slice::from_raw_parts(value.as_ptr() as *const libc::in6_addr, count)
                }.iter()
                    .map(|in6_addr| net::Ipv6Addr::from(in6_addr.s6_addr))
                    .filter(|ip| !ip.is_unspecified())
                    .collect();

                Ok(Value::Ipv6Addrs(ips))
            }
            _ => Err(JailError::ParameterTypeUnsupported(paramtype)),
        },
        _ => Err(JailError::ParameterTypeUnsupported(paramtype)),
    }
}

/// Set a jail parameter given the jid, the parameter name and the value.
///
/// # Examples
/// ```
/// use jail::param;
/// # use jail::StoppedJail;
/// # let jail = StoppedJail::new("/rescue")
/// #     .name("testjail_getparam")
/// #     .start()
/// #     .expect("could not start jail");
/// # let jid = jail.jid;
///
/// param::set(jid, "allow.raw_sockets", param::Value::Int(1))
///     .expect("could not set parameter");
/// #
/// # let readback = param::get(jid, "allow.raw_sockets")
/// #     .expect("could not read back value");
/// # assert_eq!(readback, param::Value::Int(1));
/// # jail.kill().expect("could not stop jail");
/// ```
pub fn set(jid: i32, name: &str, value: Value) -> Result<(), JailError> {
    let (ctltype, _) = info(name)?;

    let paramname = CString::new(name).expect("Could not convert parameter name to CString");

    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };
    let mut bytes: Vec<u8> = vec![];

    let paramtype: Type = (&value).into();
    assert_eq!(ctltype, paramtype.into());

    // Some conversions are identity on 64 bit, but not on 32 bit and vice versa
    #[allow(identity_conversion)]
    match value {
        Value::String(s) => {
            bytes = CString::new(s)
                .expect("Could not create CString from value")
                .to_bytes_with_nul()
                .to_vec();
            Ok(())
        }
        Value::U8(v) => bytes.write_u8(v),
        Value::S8(v) => bytes.write_i8(v),
        Value::U16(v) => bytes.write_u16::<LittleEndian>(v),
        Value::U32(v) => bytes.write_u32::<LittleEndian>(v),
        Value::U64(v) => bytes.write_u64::<LittleEndian>(v),
        Value::S16(v) => bytes.write_i16::<LittleEndian>(v),
        Value::S32(v) => bytes.write_i32::<LittleEndian>(v),
        Value::S64(v) => bytes.write_i64::<LittleEndian>(v),
        Value::Int(v) => bytes.write_int::<LittleEndian>(v.into(), mem::size_of::<libc::c_int>()),
        Value::Long(v) => bytes.write_int::<LittleEndian>(v.into(), mem::size_of::<libc::c_long>()),
        Value::Uint(v) => {
            bytes.write_uint::<LittleEndian>(v.into(), mem::size_of::<libc::c_uint>())
        }
        Value::Ulong(v) => {
            bytes.write_uint::<LittleEndian>(v.into(), mem::size_of::<libc::c_ulong>())
        }
        Value::Ipv4Addrs(addrs) => {
            for addr in addrs {
                let s_addr = nix::sys::socket::Ipv4Addr::from_std(&addr).0.s_addr;
                let host_u32 = u32::from_be(s_addr);
                bytes
                    .write_u32::<NetworkEndian>(host_u32)
                    .map_err(|_| JailError::SerializeFailed)?;
            }
            Ok(())
        }
        Value::Ipv6Addrs(addrs) => {
            for addr in addrs {
                bytes.extend_from_slice(&addr.octets());
            }
            Ok(())
        }
    }.map_err(|_| JailError::SerializeFailed)?;

    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"jid\0"),
        iovec!(&jid as *const _, mem::size_of::<i32>()),
        iovec!(paramname.as_ptr(), paramname.as_bytes().len() + 1),
        iovec!(bytes.as_mut_ptr(), bytes.len()),
        iovec!(b"errmsg\0"),
        iovec!(errmsg.as_mut_ptr(), errmsg.len()),
    ];

    let jid = unsafe {
        libc::jail_set(
            jiov[..].as_mut_ptr() as *mut libc::iovec,
            jiov.len() as u32,
            JailFlags::UPDATE.bits(),
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut i8) }
        .to_string_lossy()
        .to_string();

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(JailError::from_errno()),
            _ => Err(JailError::JailSetError(err)),
        },
        _ => Ok(()),
    }
}
