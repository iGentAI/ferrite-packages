use crate::wasm::compat::cold_path;
use alloc::vec::Vec;
use alloc::{boxed::Box, sync::Arc};
use core::cmp::min;
use core::ops::{Deref, DerefMut};

use crate::wasm::types::MemoryType;

use crate::wasm::rt::interpreter::Value128;
use crate::wasm::rt::{Error, Result};

mod instance;
mod lazy;

mod paged;
// FERRITE PATCH: upstream keeps this backend in `vec.rs` and reaches it with
// `#[path = "vec.rs"] mod vec_memory;` (the module cannot be `vec` — that
// collides with the `alloc::vec` import above). `#[path]` compiles a file of
// the app's choosing as source, which the platform code gate refuses as
// CODE_BUILD_TIME_READ, so the file is named for its module instead. Renaming
// it back to `vec.rs` re-breaks `source_deployable_labs_apps_pass_the_real_code_gate`.
mod vec_memory;

pub(crate) use instance::MemoryInstance;
pub use {lazy::LazyLinearMemory, paged::PagedMemory, vec_memory::VecMemory};

/// Backend storage for a linear memory
///
/// This is a low-level trait that abstracts over the actual storage mechanism for linear memory.
/// This will probably change in the future to allow more efficient implementations.
/// See [`MemoryBackend`] for a higher-level interface to configuring memory storage.
pub trait LinearMemory {
    /// Returns the current memory length in bytes.
    fn len(&self) -> usize;

    /// Returns true if the memory is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Grows the memory to `new_len` bytes.
    ///
    /// The runtime only calls this with lengths that are exact multiples of the Wasm page size for
    /// the owning memory.
    fn grow_to(&mut self, new_len: usize) -> core::result::Result<(), crate::wasm::rt::Trap>;

    /// Reads up to `dst.len()` bytes starting at `addr` and returns the number of bytes read.
    ///
    /// Backends may return fewer bytes than requested even when more data is available. This lets
    /// non-contiguous backends stop at a natural boundary such as the end of a chunk.
    fn read(&self, addr: usize, dst: &mut [u8]) -> usize;

    /// Writes up to `src.len()` bytes starting at `addr` and returns the number of bytes written.
    ///
    /// Backends may return fewer bytes than requested even when more space is available. This lets
    /// non-contiguous backends stop at a natural boundary such as the end of a chunk.
    fn write(&mut self, addr: usize, src: &[u8]) -> usize;

    /// Writes all bytes in `src` starting at `addr`, or returns `None` if any byte could not be written.
    fn write_all(&mut self, addr: usize, src: &[u8]) -> Option<()> {
        let end = addr.checked_add(src.len())?;
        if end > self.len() {
            return None;
        }

        let mut offset = 0;
        while offset < src.len() {
            let written = self.write(addr + offset, &src[offset..]);
            if written == 0 {
                return None;
            }
            offset += written;
        }

        Some(())
    }

    /// Fills the range `[addr, addr + len)` with `val`.
    fn fill(&mut self, addr: usize, len: usize, val: u8) -> Option<()> {
        let end = addr.checked_add(len)?;
        if end > self.len() {
            return None;
        }

        let mut offset = 0;
        while offset < len {
            let chunk_len = min(len - offset, 1024);
            let chunk = vec![val; chunk_len];
            self.write_all(addr + offset, &chunk)?;
            offset += chunk_len;
        }

        Some(())
    }

    /// Copies `len` bytes from `src` to `dst` within the same memory.
    fn copy_within(&mut self, dst: usize, src: usize, len: usize) -> Option<()> {
        let src_end = src.checked_add(len)?;
        let dst_end = dst.checked_add(len)?;
        if src_end > self.len() || dst_end > self.len() {
            return None;
        }

        if len == 0 || dst == src {
            return Some(());
        }

        // If the source and destination ranges are disjoint, we can copy forward without a temporary buffer.
        if dst < src || dst >= src_end {
            let mut offset = 0;
            while offset < len {
                let chunk_len = min(len - offset, 1024);
                let mut chunk = vec![0; chunk_len];
                self.read_exact(src + offset, &mut chunk)?;
                self.write_all(dst + offset, &chunk)?;
                offset += chunk_len;
            }
        } else {
            // Otherwise, we need to copy backward to avoid overwriting the source data before it's read.
            let mut offset = len;
            while offset > 0 {
                let chunk_len = min(offset, 1024);
                offset -= chunk_len;
                let mut chunk = vec![0; chunk_len];
                self.read_exact(src + offset, &mut chunk)?;
                self.write_all(dst + offset, &chunk)?;
            }
        }

        Some(())
    }

    /// Reads exactly `dst.len()` bytes starting at `addr`.
    fn read_exact(&self, addr: usize, dst: &mut [u8]) -> Option<()> {
        let end = addr.checked_add(dst.len())?;
        if end > self.len() {
            return None;
        }

        let mut offset = 0;
        while offset < dst.len() {
            let read = self.read(addr + offset, &mut dst[offset..]);
            if read == 0 {
                return None;
            }
            offset += read;
        }

        Some(())
    }

    /// Reads `len` bytes starting at `addr` into a newly allocated buffer.
    fn read_vec(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        let end = addr.checked_add(len)?;
        if end > self.len() {
            return None;
        }

        let mut data = vec![0; len];
        self.read_exact(addr, &mut data)?;
        Some(data)
    }

    /// Reads exactly 1 byte at the effective address `base + offset`.
    fn read_8(&self, base: u64, offset: u64) -> core::result::Result<u8, crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<1>(self.len(), base, offset)?;
        let mut bytes = [0; 1];
        self.read_exact(addr, &mut bytes).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 1, self.len())
        })?;
        Ok(bytes[0])
    }

    /// Reads exactly 2 bytes at the effective address `base + offset`.
    fn read_16(
        &self,
        base: u64,
        offset: u64,
    ) -> core::result::Result<[u8; 2], crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<2>(self.len(), base, offset)?;
        let mut bytes = [0; 2];
        self.read_exact(addr, &mut bytes).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 2, self.len())
        })?;
        Ok(bytes)
    }

    /// Reads exactly 4 bytes at the effective address `base + offset`.
    fn read_32(
        &self,
        base: u64,
        offset: u64,
    ) -> core::result::Result<[u8; 4], crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<4>(self.len(), base, offset)?;
        let mut bytes = [0; 4];
        self.read_exact(addr, &mut bytes).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 4, self.len())
        })?;
        Ok(bytes)
    }

    /// Reads exactly 8 bytes at the effective address `base + offset`.
    fn read_64(
        &self,
        base: u64,
        offset: u64,
    ) -> core::result::Result<[u8; 8], crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<8>(self.len(), base, offset)?;
        let mut bytes = [0; 8];
        self.read_exact(addr, &mut bytes).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 8, self.len())
        })?;
        Ok(bytes)
    }

    /// Reads exactly 16 bytes at the effective address `base + offset`.
    fn read_128(
        &self,
        base: u64,
        offset: u64,
    ) -> core::result::Result<[u8; 16], crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<16>(self.len(), base, offset)?;
        let mut bytes = [0; 16];
        self.read_exact(addr, &mut bytes).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 16, self.len())
        })?;
        Ok(bytes)
    }

    /// Writes exactly 1 byte at the effective address `base + offset`.
    fn write_8(
        &mut self,
        base: u64,
        offset: u64,
        byte: u8,
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<1>(self.len(), base, offset)?;
        self.write_all(addr, &[byte]).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 1, self.len())
        })
    }

    /// Writes exactly 2 bytes at the effective address `base + offset`.
    fn write_16(
        &mut self,
        base: u64,
        offset: u64,
        bytes: [u8; 2],
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<2>(self.len(), base, offset)?;
        self.write_all(addr, &bytes).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 2, self.len())
        })
    }

    /// Writes exactly 4 bytes at the effective address `base + offset`.
    fn write_32(
        &mut self,
        base: u64,
        offset: u64,
        bytes: [u8; 4],
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<4>(self.len(), base, offset)?;
        self.write_all(addr, &bytes).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 4, self.len())
        })
    }

    /// Writes exactly 8 bytes at the effective address `base + offset`.
    fn write_64(
        &mut self,
        base: u64,
        offset: u64,
        bytes: [u8; 8],
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<8>(self.len(), base, offset)?;
        self.write_all(addr, &bytes).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 8, self.len())
        })
    }

    /// Writes exactly 16 bytes at the effective address `base + offset`.
    fn write_128(
        &mut self,
        base: u64,
        offset: u64,
        bytes: [u8; 16],
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        let addr = checked_effective_addr::<16>(self.len(), base, offset)?;
        self.write_all(addr, &bytes).ok_or_else(|| {
            cold_path();
            memory_oob(addr, 16, self.len())
        })
    }
}

type MemoryFactory = dyn Fn(MemoryType) -> Result<Box<dyn LinearMemory + Send>> + Send + Sync;

/// Configures how runtime memory instances are created.
#[derive(Clone, Default)]
pub struct MemoryBackend {
    kind: MemoryBackendKind,
}

#[derive(Clone)]
enum MemoryBackendKind {
    Vec,
    Paged {
        chunk_size: usize,
    },
    Custom(Arc<MemoryFactory>),
}

// Written out: the code gate refuses the derive-default variant attribute.
#[allow(clippy::derivable_impls)]
impl Default for MemoryBackendKind {
    fn default() -> Self {
        Self::Vec
    }
}

impl MemoryBackend {
    /// Uses a contiguous [`VecMemory`] for each memory instance.
    ///
    /// This is usually the fastest option for reads and writes, but large grows can be expensive
    /// because they may reallocate and copy the entire buffer.
    pub const fn vec() -> Self {
        Self {
            kind: MemoryBackendKind::Vec,
        }
    }

    /// Uses sparse chunked storage for each memory instance.
    ///
    /// `chunk_size` is the backend chunk size in bytes. It is independent from the Wasm page size.
    ///
    /// This generally makes growth cheaper than [`Self::vec`], but read and write operations do a
    /// little more work and may be slightly slower.
    pub fn paged(chunk_size: usize) -> Self {
        assert!(
            chunk_size.is_power_of_two(),
            "chunk_size must be a power of two"
        );
        Self {
            kind: MemoryBackendKind::Paged { chunk_size },
        }
    }

    /// Uses a custom factory to create memory instances.
    pub fn custom<F, M>(factory: F) -> Self
    where
        F: Fn(MemoryType) -> Result<M> + Send + Sync + 'static,
        // FERRITE PATCH: `+ Send`, so the whole `Store` is `Send` and a paged run
        // can be held across an `await`.
        M: LinearMemory + Send + 'static,
    {
        Self {
            kind: MemoryBackendKind::Custom(Arc::new(move |ty| {
                let memory = factory(ty)?;
                Ok(Box::new(memory) as Box<dyn LinearMemory + Send>)
            })),
        }
    }

    pub(crate) fn create(&self, ty: MemoryType, initial_len: usize) -> Result<MemoryStorage> {
        let storage = match &self.kind {
            MemoryBackendKind::Vec => {
                Box::new(VecMemory::try_new(initial_len).map_err(Error::Trap)?)
                    as Box<dyn LinearMemory + Send>
            }
            MemoryBackendKind::Paged { chunk_size } => {
                Box::new(PagedMemory::try_new(initial_len, *chunk_size).map_err(Error::Trap)?)
                    as Box<dyn LinearMemory + Send>
            }
            MemoryBackendKind::Custom(factory) => factory(ty)?,
        };

        // Eager and lazy memories alike hold exactly the declared pages: a
        // larger backend would allow accesses past the memory's page count.
        if storage.len() != initial_len {
            return Err(Error::Other(format!(
                "memory backend returned {} bytes for a memory that requires {initial_len}",
                storage.len()
            )));
        }

        Ok(MemoryStorage(storage))
    }

    pub(crate) fn create_lazy(&self, ty: MemoryType, initial_len: usize) -> Result<MemoryStorage> {
        Ok(MemoryStorage(Box::new(
            LazyLinearMemory::new_with_initial_len(ty, initial_len, self.clone()),
        )))
    }
}

impl core::fmt::Debug for MemoryBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.kind {
            MemoryBackendKind::Vec => f.debug_tuple("MemoryBackend::Vec").finish(),
            MemoryBackendKind::Paged { chunk_size } => f
                .debug_struct("MemoryBackend::Paged")
                .field("chunk_size", chunk_size)
                .finish(),
            MemoryBackendKind::Custom(_) => f.debug_tuple("MemoryBackend::Custom").finish(),
        }
    }
}

pub(crate) struct MemoryStorage(Box<dyn LinearMemory + Send>);

impl Deref for MemoryStorage {
    type Target = dyn LinearMemory;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl DerefMut for MemoryStorage {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl core::fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MemoryStorage")
            .field(&format!("{} bytes", self.len()))
            .finish()
    }
}

/// A trait for types that can be converted to and from static byte arrays
pub(crate) trait MemValue<const N: usize>: Copy + Default {
    /// Store a value in memory
    fn to_mem_bytes(self) -> [u8; N];

    /// Load a value from memory
    fn from_mem_bytes(bytes: [u8; N]) -> Self;

    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap>;
}

impl MemValue<1> for u8 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 1]) -> Self {
        bytes[0]
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 1] {
        [self]
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        mem.read_8(base, offset)
    }
}

impl MemValue<1> for i8 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 1]) -> Self {
        i8::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 1] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(mem.read_8(base, offset)? as i8)
    }
}

// `MemValue` per width-carrying scalar, written out per type (the code gate
// refuses app-defined macros). Each body is the little-endian pair plus the
// matching `LinearMemory::read_*`.
impl MemValue<2> for u16 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 2]) -> Self {
        u16::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 2] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(Self::from_mem_bytes(mem.read_16(base, offset)?))
    }
}

impl MemValue<2> for i16 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 2]) -> Self {
        i16::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 2] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(Self::from_mem_bytes(mem.read_16(base, offset)?))
    }
}

impl MemValue<4> for u32 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 4]) -> Self {
        u32::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 4] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(Self::from_mem_bytes(mem.read_32(base, offset)?))
    }
}

impl MemValue<4> for i32 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 4]) -> Self {
        i32::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 4] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(Self::from_mem_bytes(mem.read_32(base, offset)?))
    }
}

impl MemValue<4> for f32 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 4]) -> Self {
        f32::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 4] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(Self::from_mem_bytes(mem.read_32(base, offset)?))
    }
}

impl MemValue<8> for u64 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 8]) -> Self {
        u64::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 8] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(Self::from_mem_bytes(mem.read_64(base, offset)?))
    }
}

impl MemValue<8> for i64 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 8]) -> Self {
        i64::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 8] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(Self::from_mem_bytes(mem.read_64(base, offset)?))
    }
}

impl MemValue<8> for f64 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 8]) -> Self {
        f64::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 8] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(Self::from_mem_bytes(mem.read_64(base, offset)?))
    }
}

impl MemValue<16> for Value128 {
    #[inline(always)]
    fn from_mem_bytes(bytes: [u8; 16]) -> Self {
        Value128::from_le_bytes(bytes)
    }

    #[inline(always)]
    fn to_mem_bytes(self) -> [u8; 16] {
        self.to_le_bytes()
    }

    #[inline(always)]
    fn load(
        mem: &dyn LinearMemory,
        base: u64,
        offset: u64,
    ) -> core::result::Result<Self, crate::wasm::rt::Trap> {
        Ok(Self::from_mem_bytes(mem.read_128(base, offset)?))
    }
}

fn memory_oob(offset: usize, len: usize, max: usize) -> crate::wasm::rt::Trap {
    crate::wasm::rt::Trap::MemoryOutOfBounds { offset, len, max }
}

fn checked_effective_addr<const LEN: usize>(
    max: usize,
    base: u64,
    offset: u64,
) -> core::result::Result<usize, crate::wasm::rt::Trap> {
    let Some(max_addr) = max.checked_sub(LEN).map(|max_addr| max_addr as u64) else {
        cold_path();
        return Err(memory_oob(
            usize::try_from(base).unwrap_or(usize::MAX),
            LEN,
            max,
        ));
    };

    let addr = base.wrapping_add(offset);
    if addr < base || addr > max_addr {
        cold_path();
        return Err(memory_oob(
            usize::try_from(addr).unwrap_or(usize::MAX),
            LEN,
            max,
        ));
    }

    Ok(addr as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::types::MemoryArch;

    fn create_test_memory(kind: MemoryType, backend: MemoryBackend) -> MemoryInstance {
        MemoryInstance::new(kind, &backend).unwrap()
    }

    fn test_backends() -> [MemoryBackend; 2] {
        [MemoryBackend::vec(), MemoryBackend::paged(4)]
    }

    #[test]
    fn the_default_write_8_traps_when_the_backend_writes_nothing() {
        struct Refusing(Vec<u8>);
        impl LinearMemory for Refusing {
            fn len(&self) -> usize {
                self.0.len()
            }
            fn grow_to(&mut self, _new_len: usize) -> core::result::Result<(), crate::wasm::rt::Trap> {
                Err(crate::wasm::rt::Trap::OutOfMemory)
            }
            fn read(&self, addr: usize, dst: &mut [u8]) -> usize {
                let n = self.0.len().saturating_sub(addr).min(dst.len());
                dst[..n].copy_from_slice(&self.0[addr..addr + n]);
                n
            }
            fn write(&mut self, _addr: usize, _src: &[u8]) -> usize {
                0
            }
        }
        let mut memory = Refusing(vec![0; 16]);
        assert!(memory.write_8(1, 0, 7).is_err());
    }

    #[test]
    fn a_backend_with_more_bytes_than_declared_is_refused_eager_or_lazy() {
        let ty = MemoryType::new(MemoryArch::I32, 1, None, None);
        let backend = MemoryBackend::custom(|ty: MemoryType| {
            VecMemory::try_new(ty.initial_size() as usize * 2).map_err(crate::wasm::rt::Error::Trap)
        });
        assert!(MemoryInstance::new(ty, &backend).is_err());
        let lazy = MemoryInstance::new_lazy(ty, &backend).unwrap();
        assert_eq!(lazy.inner.len(), 65536, "the lazy memory reports its declared length");
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn a_paged_backend_refuses_a_chunk_size_that_is_not_a_power_of_two() {
        let _ = MemoryBackend::paged(3);
    }

    #[test]
    fn a_lazy_memory_whose_backend_fails_grows_by_zero_and_reads_zeros_without_panicking() {
        let ty = MemoryType::new(MemoryArch::I32, 1, Some(4), None);
        let backend = MemoryBackend::custom(|_ty: MemoryType| -> crate::wasm::rt::Result<VecMemory> {
            Err(crate::wasm::rt::Error::Trap(crate::wasm::rt::Trap::OutOfMemory))
        });
        let mut memory = MemoryInstance::new_lazy(ty, &backend).unwrap();
        assert_eq!(memory.grow(0, true).unwrap(), Some(1));
        assert_eq!(memory.inner.read_vec(65530, 6), Some(vec![0; 6]));
        assert_eq!(memory.inner.read_vec(65531, 6), None);
        assert!(memory.inner.write_all(0, &[1]).is_none());
        assert!(memory.grow(1, true).is_err());
    }

    #[test]
    fn a_memory64_at_the_full_page_ceiling_still_grows() {
        let ty = MemoryType::new(MemoryArch::I64, 1, Some(1 << 48), None);
        let mut memory = MemoryInstance::new(ty, &MemoryBackend::paged(65536)).unwrap();
        assert_eq!(memory.grow(1, true).unwrap(), Some(1));
        assert!(
            MemoryInstance::new(MemoryType::new(MemoryArch::I32, 2, Some(1), None), &MemoryBackend::vec()).is_err(),
            "an initial size above the maximum is an error, not a panic"
        );
    }

    #[test]
    fn memory_copy_from_slice_and_read_vec_work() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            let data = [1, 2, 3, 4];
            assert!(memory.inner.write_all(0, &data).is_some());
            assert_eq!(memory.inner.read_vec(0, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn memory_read_returns_partial_count() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(1), Some(4));
            let memory = create_test_memory(kind, backend);
            let mut dst = [9; 8];
            assert_eq!(memory.inner.read(2, &mut dst), 2);
            assert_eq!(&dst[..2], &[0, 0]);
            assert_eq!(&dst[2..], &[9; 6]);
        }
    }

    #[test]
    fn memory_copy_from_slice_out_of_bounds_fails() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            let data = [1, 2, 3, 4];
            let len = memory.inner.len();
            assert!(memory.inner.write_all(len, &data).is_none());
        }
    }

    #[test]
    fn memory_fill_works() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            assert!(memory.inner.fill(0, 10, 42).is_some());
            assert_eq!(memory.inner.read_vec(0, 10).unwrap(), vec![42; 10]);
        }
    }

    #[test]
    fn memory_fill_out_of_bounds_fails() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            let len = memory.inner.len();
            assert!(memory.inner.fill(len, 10, 42).is_none());
        }
    }

    #[test]
    fn memory_copy_within_works() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            memory.inner.fill(0, 10, 1).unwrap();
            assert!(memory.copy_within(10, 0, 10).is_ok());
            assert_eq!(memory.inner.read_vec(10, 10).unwrap(), vec![1; 10]);
        }
    }

    #[test]
    fn memory_copy_within_out_of_bounds_fails() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            assert!(memory.copy_within(memory.inner.len(), 0, 10).is_err());
        }
    }

    #[test]
    fn memory_grow_works() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            let original_pages = memory.page_count;
            assert_eq!(memory.grow(1, false).unwrap(), Some(original_pages as i64));
            assert_eq!(memory.page_count, original_pages + 1);
        }
    }

    #[test]
    fn memory_grow_out_of_bounds_fails() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            assert_eq!(
                memory
                    .grow(memory.kind.max_size() as i64 + 1, false)
                    .unwrap(),
                None
            );
        }
    }

    #[test]
    fn memory_grow_respects_max_pages() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            assert_eq!(memory.grow(1, false).unwrap(), Some(1));
            assert_eq!(memory.grow(1, false).unwrap(), None);
        }
    }

    #[test]
    fn memory_grow_negative_delta_fails() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), None);
            let mut memory = create_test_memory(kind, backend);
            let original_pages = memory.page_count;
            assert_eq!(memory.grow(-1, false).unwrap(), None);
            assert_eq!(memory.page_count, original_pages);
        }
    }

    #[test]
    fn memory_custom_page_size_out_of_bounds_fails() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), Some(1));
            let mut memory = create_test_memory(kind, backend);
            let data = [1, 2];
            assert!(memory.inner.write_all(0, &data).is_none());
        }
    }

    #[test]
    fn memory_custom_page_size_grow_works() {
        for backend in test_backends() {
            let kind = MemoryType::new(MemoryArch::I32, 1, Some(2), Some(1));
            let mut memory = create_test_memory(kind, backend);
            assert_eq!(memory.grow(1, false).unwrap(), Some(1));
            let data = [1, 2];
            assert!(memory.inner.write_all(0, &data).is_some());
            assert_eq!(memory.inner.read_vec(0, data.len()).unwrap(), data);
        }
    }
}
