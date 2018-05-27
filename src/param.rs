use libc;

use std::ffi::{CStr, CString};
use std::mem;

use sys::JailFlags;
use JailError;

use byteorder::{ByteOrder, LittleEndian};
use sysctl::{Ctl, CtlType, CtlValue};

/// An enum representing the value of a parameter.
#[derive(PartialEq, Debug, Clone)]
pub enum Value {
    Int(i32),
    String(String),
    S64(u64),
    Uint(u32),
    Long(i64),
    Ulong(u64),
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
/// extern crate jail;
/// use jail::param;
/// use std::path::Path;
///
/// let jid = jail::sys::jail_create(Path::new("/rescue"), Some("testjail_param"), None)
///     .expect("could not start jail");
///
/// let hostuuid = jail::param::get(jid, "host.hostuuid")
///     .expect("could not get parameter");
///
/// println!("{:?}", hostuuid);
///
/// jail::sys::jail_remove(jid);
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
        CtlType::Int => Ok(Value::Int(LittleEndian::read_i32(&value))),
        CtlType::S64 => Ok(Value::S64(LittleEndian::read_u64(&value))),
        CtlType::Uint => Ok(Value::Uint(LittleEndian::read_u32(&value))),
        CtlType::Long => Ok(Value::Long(LittleEndian::read_i64(&value))),
        CtlType::Ulong => Ok(Value::Ulong(LittleEndian::read_u64(&value))),
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
