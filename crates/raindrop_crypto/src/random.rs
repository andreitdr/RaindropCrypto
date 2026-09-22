use zeroize::Zeroizing;

/// `N` bytes from the operating system's CSPRNG. Kept in one place so every key in this crate comes
/// from the same source, independent of which `rand` version a dependency happens to pull in.
pub(crate) fn bytes<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    getrandom::fill(out.as_mut()).expect("the operating system's random source is unavailable");
    out
}
