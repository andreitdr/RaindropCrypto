//! A borrowed, writable camera frame in I420.
//!
//! I420 is what every camera pipeline Raindrop touches hands over: a full-size
//! luma (Y) plane and two half-size chroma planes (U, V), each with its own
//! stride that may be wider than the picture. Effects rewrite these planes in
//! place, so the frame that reaches the encoder is the same frame the camera
//! produced — no second track, no copy, and nothing for the frame cryptor to
//! notice.
//!
//! This is the crate's only `unsafe`. The planes come from native code as raw
//! pointers, and every access goes through the row accessors here so a stride
//! wider than the width can never be overrun.

use crate::Error;

/// Which plane a row is being asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Plane {
    Y,
    U,
    V,
}

/// One camera frame, borrowed for the length of one call.
///
/// Dimensions are the *picture*; strides are the memory layout, and are always
/// at least the plane's width. Chroma planes are `(width + 1) / 2` by
/// `(height + 1) / 2`, rounding up, which is what makes odd sizes work.
pub struct I420FrameMut<'a> {
    y: *mut u8,
    u: *mut u8,
    v: *mut u8,
    y_stride: usize,
    u_stride: usize,
    v_stride: usize,
    width: usize,
    height: usize,
    _life: core::marker::PhantomData<&'a mut u8>,
}

impl<'a> I420FrameMut<'a> {
    /// Borrows three planes as one frame.
    ///
    /// # Safety
    ///
    /// The caller guarantees that, for the lifetime `'a` and with no other
    /// reference to the same memory:
    ///
    /// - `y` points to at least `y_stride * height` writable bytes;
    /// - `u` and `v` each point to at least `stride * chroma_height()` writable
    ///   bytes, where `chroma_height()` is `(height + 1) / 2`;
    /// - each stride is at least that plane's width.
    ///
    /// Everything else — odd dimensions, padded strides, zero-sized frames — is
    /// checked here and reported as [`Error::BadFrame`] rather than trusted.
    #[allow(
        clippy::too_many_arguments,
        reason = "I420 is three planes, three strides and two dimensions"
    )]
    pub unsafe fn new(
        y: *mut u8,
        y_stride: usize,
        u: *mut u8,
        u_stride: usize,
        v: *mut u8,
        v_stride: usize,
        width: usize,
        height: usize,
    ) -> Result<Self, Error> {
        if y.is_null() || u.is_null() || v.is_null() {
            return Err(Error::BadFrame("a plane pointer was null"));
        }
        if width == 0 || height == 0 {
            return Err(Error::BadFrame("the frame has no pixels"));
        }

        let chroma_width = width.div_ceil(2);
        if y_stride < width || u_stride < chroma_width || v_stride < chroma_width {
            return Err(Error::BadFrame("a stride is narrower than its plane"));
        }

        Ok(Self {
            y,
            u,
            v,
            y_stride,
            u_stride,
            v_stride,
            width,
            height,
            _life: core::marker::PhantomData,
        })
    }

    /// Borrows three plane slices as one frame, for tests and for callers that
    /// already hold the pixels. The planes must not overlap.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors `new`, which takes the planes I420 has"
    )]
    pub fn from_slices(
        y: &'a mut [u8],
        y_stride: usize,
        u: &'a mut [u8],
        u_stride: usize,
        v: &'a mut [u8],
        v_stride: usize,
        width: usize,
        height: usize,
    ) -> Result<Self, Error> {
        let chroma_height = height.div_ceil(2);

        if y.len() < y_stride.saturating_mul(height)
            || u.len() < u_stride.saturating_mul(chroma_height)
            || v.len() < v_stride.saturating_mul(chroma_height)
        {
            return Err(Error::BadFrame("a plane is shorter than its stride and height imply"));
        }

        // SAFETY: the slices live for 'a, are distinct (three separate &mut),
        // and were just checked to be long enough for the strides and height.
        unsafe {
            Self::new(
                y.as_mut_ptr(),
                y_stride,
                u.as_mut_ptr(),
                u_stride,
                v.as_mut_ptr(),
                v_stride,
                width,
                height,
            )
        }
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }

    /// Chroma planes are half-size, rounded up, so a 641-wide frame has 321
    /// chroma columns rather than 320.
    pub fn chroma_width(&self) -> usize {
        self.width.div_ceil(2)
    }

    pub fn chroma_height(&self) -> usize {
        self.height.div_ceil(2)
    }

    pub fn plane_width(&self, plane: Plane) -> usize {
        match plane {
            Plane::Y => self.width,
            Plane::U | Plane::V => self.chroma_width(),
        }
    }

    pub fn plane_height(&self, plane: Plane) -> usize {
        match plane {
            Plane::Y => self.height,
            Plane::U | Plane::V => self.chroma_height(),
        }
    }

    /// One row of a plane, exactly as wide as the picture — never into the
    /// stride padding, which belongs to whoever allocated the frame.
    pub fn row(&self, plane: Plane, y: usize) -> &[u8] {
        let (base, stride) = self.plane(plane);
        let width = self.plane_width(plane);
        assert!(y < self.plane_height(plane), "row out of range");

        // SAFETY: `new` checked stride >= width and the caller guaranteed
        // stride * height bytes, and `y` is inside the plane's height.
        unsafe { core::slice::from_raw_parts(base.add(y * stride), width) }
    }

    pub fn row_mut(&mut self, plane: Plane, y: usize) -> &mut [u8] {
        let (base, stride) = self.plane(plane);
        let width = self.plane_width(plane);
        assert!(y < self.plane_height(plane), "row out of range");

        // SAFETY: as `row`, and `&mut self` means no other borrow is live.
        unsafe { core::slice::from_raw_parts_mut(base.add(y * stride), width) }
    }

    fn plane(&self, plane: Plane) -> (*mut u8, usize) {
        match plane {
            Plane::Y => (self.y, self.y_stride),
            Plane::U => (self.u, self.u_stride),
            Plane::V => (self.v, self.v_stride),
        }
    }
}
