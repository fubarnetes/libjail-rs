use libc;

use std::convert;
use std::ffi::{CStr, CString};
use std::mem;

use sys::JailFlags;
use JailError;

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use sysctl::{Ctl, CtlType, CtlValue};

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
}

#[cfg(target_os = "freebsd")]
fn info(name: &str) -> Result<(CtlType, usize), JailError> {
    // Get parameter type
    let ctlname = format!("security.jail.param.{}", name);

    let ctl = Ctl::new(&ctlname).map_err(|_| JailError::NoSuchParameter(name.to_string()))?;

    let paramtype = ctl
        .value_type()
        .map_err(|e| JailError::ParameterTypeError(e))?;

    let typesize = match paramtype {
        CtlType::Int => mem::size_of::<libc::c_int>(),
        CtlType::String => {
            let length = match ctl
                .value()
                .map_err(|e| JailError::ParameterStringLengthError(e))?
            {
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
        _ => return Err(JailError::ParameterTypeUnsupported(paramtype)),
    };

    Ok((paramtype, typesize))
}

/// Get a jail parameter given the jid and the parameter name.
///
/// # Examples
/// ```
/// # extern crate jail;
/// # use jail::param;
/// # use std::path::Path;
/// #
/// # let jid = jail::sys::jail_create(Path::new("/rescue"), Some("testjail_param"), None)
/// #     .expect("could not start jail");
/// #
/// let hostuuid = jail::param::get(jid, "host.hostuuid")
///     .expect("could not get parameter");
///
/// println!("{:?}", hostuuid);
/// #
/// # jail::sys::jail_remove(jid);
/// ```
#[cfg(target_os = "freebsd")]
pub fn get(jid: i32, name: &str) -> Result<Value, JailError> {
    let (paramtype, typesize) = info(name)?;

    let paramname = CString::new(name).expect("Could not convert parameter name to CString");

    let mut value: Vec<u8> = vec![0; typesize];
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"jid\0"),
        iovec!(&jid as *const _, mem::size_of::<i32>()),
        iovec!(paramname.as_ptr(), paramname.as_bytes().len() + 1),
        iovec!(value.as_mut_ptr(), typesize),
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
        _ => return Err(JailError::ParameterTypeUnsupported(paramtype)),
    }
}

/// Set a jail parameter given the jid, the parameter name and the value.
///
/// # Examples
/// ```
/// # extern crate jail;
/// # use jail::param;
/// # use std::path::Path;
/// #
/// # let jid = jail::sys::jail_create(Path::new("/rescue"), Some("testjail_setparam"), None)
/// #     .expect("could not start jail");
/// #
/// param::set(jid, "allow.raw_sockets", param::Value::Int(1))
///     .expect("could not set parameter");
/// #
/// # let readback = param::get(jid, "allow.raw_sockets")
/// #     .expect("could not read back value");
/// # assert_eq!(readback, param::Value::Int(1));
/// # jail::sys::jail_remove(jid);
/// ```
pub fn set(jid: i32, name: &str, value: Value) -> Result<(), JailError> {
    let (ctltype, _) = info(name)?;

    let paramname = CString::new(name).expect("Could not convert parameter name to CString");

    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };
    let mut bytes: Vec<u8> = vec![];

    let paramtype: Type = (&value).into();
    assert_eq!(ctltype, paramtype.into());

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
        Value::Int(v) => bytes.write_int::<LittleEndian>(v as i64, mem::size_of::<libc::c_int>()),
        Value::Long(v) => bytes.write_int::<LittleEndian>(v as i64, mem::size_of::<libc::c_long>()),
        Value::Uint(v) => {
            bytes.write_uint::<LittleEndian>(v as u64, mem::size_of::<libc::c_uint>())
        }
        Value::Ulong(v) => {
            bytes.write_uint::<LittleEndian>(v as u64, mem::size_of::<libc::c_ulong>())
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
