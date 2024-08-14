//! Contains error types and other error handling tools.

pub use crate::parse::ParseIntError;

/// Impls std::error::Error for the specified type with appropriate attributes, possibly returning
/// source.
macro_rules! impl_std_error {
    // No source available
    ($type:ty) => {
        impl std::error::Error for $type {}
    };
    // Struct with $field as source
    ($type:ty, $field:ident) => {
        impl std::error::Error for $type {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.$field)
            }
        }
    };
}
pub(crate) use impl_std_error;

/// Formats error. If `std` feature is OFF appends error source (delimited by `: `). We do this
/// because `e.source()` is only available in std builds, without this macro the error source is
/// lost for no-std builds.
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr)*; $source:expr) => {
        {
            let _ = &$source;   // Prevents clippy warnings.
            write!($writer, $string $(, $args)*)
        }
    }
}
pub(crate) use write_err;
