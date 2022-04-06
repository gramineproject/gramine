//! This module defines various bitflags, with the primary goal of pretty-printing
//! them in logging output.

// Note: There are some bitflag libraries in the Rust ecosystem. However, we need
// a bit more control than they provide:
//  - Printing that meaningfully handles unknown bits, and with & and ~ when desired
//    (`bitflags` fails, `enumflags2` provides iterators that let us implement this
//    ourselves)
//  - Storing bits that don't have a named flag (`enumflags2` fails, `bitflags` seems
//    to support it, but the relevant APIs look sketchy)
//  - Having flags that combine a few bits at once (`enumflags2` fails)
//
// So we roll our own, small wrapper type that only provides the functionality we need,
// avoiding the fancier utilities that make these requirements problematic.

use core::{cmp, fmt, mem::size_of_val, ops};

/// A wrapper type that, when `Display`ed, describes the value using bitflag constants.
///
/// The flags present in the value will be OR-ed together.
///
/// The set of bitflags to be used is passed as a type parameter.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Flags<T: BitFlags>(pub T::Numeric);

/// A wrapper type that, when `Display`ed, describes the value using bitflag constants.
///
/// The negations of the flags *not* present in the value will be AND-ed together.
///
/// The set of bitflags to be used is passed as a type parameter.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Mask<T: BitFlags>(pub T::Numeric);

pub trait BitFlags {
    type Numeric: ops::Not<Output = Self::Numeric>
        + ops::BitAnd<Self::Numeric, Output = Self::Numeric>
        + ops::BitOrAssign<Self::Numeric>
        + cmp::PartialEq
        + fmt::LowerHex
        + Clone
        + Copy
        + 'static;
    const ZERO: Self::Numeric;
    const FLAGS: &'static [(Self::Numeric, &'static str)];
}

/// Declare a set of flags for use with [`Flags`] or [`Mask`].
macro_rules! flags {
    ($name:ident : $num:ty {
        $($flag:ident = $value:expr,)*
    }) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub enum $name {}

        impl $name {
            $(
                pub const $flag: $num = $value;
            )*
        }

        impl BitFlags for $name {
            type Numeric = $num;
            const ZERO: Self::Numeric = 0;
            const FLAGS: &'static [(Self::Numeric, &'static str)] = &[
                $(
                    ($name::$flag, stringify!($flag)),
                )*
            ];
        }
    }
}

impl<T> fmt::Display for Flags<T>
where
    T: BitFlags,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0width$x} (", self.0, width = 2 * size_of_val(&self.0))?;
        write_flags::<T>(f, self.0, "", " | ", "no flags set")?;
        write!(f, ")")
    }
}

impl<T> fmt::Display for Mask<T>
where
    T: BitFlags,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0width$x} (", self.0, width = 2 * size_of_val(&self.0))?;
        write_flags::<T>(f, !self.0, "~", " & ", "all flags masked")?;
        write!(f, ")")
    }
}

fn write_flags<T>(
    f: &mut fmt::Formatter<'_>,
    flags: T::Numeric,
    flag_prefix: &str,
    flag_separator: &str,
    empty: &str,
) -> fmt::Result
where
    T: BitFlags,
{
    let mut first = true;
    let mut sep = |f: &mut fmt::Formatter<'_>| {
        if first {
            first = false;
            Ok(())
        } else {
            f.write_str(flag_separator)
        }
    };

    let mut known_bits = T::ZERO;
    for (val, name) in T::FLAGS.iter().copied() {
        if flags & val == val {
            known_bits |= val;
            sep(f)?;
            write!(f, "{}{}", flag_prefix, name)?;
        }
    }

    let unknown_bits = flags & !known_bits;

    if unknown_bits != T::ZERO {
        sep(f)?;
        write!(
            f,
            "{}0x{:0width$x}",
            flag_prefix,
            unknown_bits,
            width = 2 * size_of_val(&unknown_bits)
        )?;
    };

    if first {
        f.write_str(empty)?;
    }

    Ok(())
}

flags! {
    AttrFlags: u64 {
        INIT = 1 << 0,
        DEBUG = 1 << 1,
        MODE64BIT = 1 << 2,
        // bit 3 is reserved
        PROVISIONKEY = 1 << 4,
        EINITTOKENKEY = 1 << 5,
        CET = 1 << 6,
        KSS = 1 << 7,
    }
}

flags! {
    XFRM: u64 {
        LEGACY = 0x03,
        AVX    = 0x04,
        MPX    = 0x18,
        AVX512 = 0xe4,
        PKRU   = 0x200,
        AMX    = 0x60000,
    }
}

flags! {
    Miscselect: u32 {
        EXINFO = 0x01,
    }
}
