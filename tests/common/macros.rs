#[macro_export]
macro_rules! matches_enum_variant {
    ($x:expr, $p:pat) => {
        match $x {
            $p => true,
            _ => false,
        }
    };
}
