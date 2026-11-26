use crate::wasm::compat::cold_path;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::wasm::types::MemoryType;

use crate::wasm::rt::{Error, MemoryBackend, Result};

use super::LinearMemory;

/// A linear memory wrapper that materializes its inner backend on first access.
///
/// Until the first write or grow it allocates nothing: its length is the
/// declared initial length and reads see zeros. If the wrapped backend fails to
/// create the inner memory, the access that needed it fails (a trap for typed
/// accesses, `0` or `None` for the bulk methods) instead of panicking.
pub struct LazyLinearMemory {
    ty: MemoryType,
    initial_len: usize,
    backend: MemoryBackend,
    inner: RefCell<Option<Box<dyn LinearMemory + Send>>>,
}

impl LazyLinearMemory {
    /// Creates a lazy memory for `ty` using `backend` for the eventual materialized storage.
    pub fn try_new(ty: MemoryType, backend: MemoryBackend) -> Result<Self> {
        let initial_len = usize::try_from(ty.initial_size())
            .map_err(|_| Error::UnsupportedFeature("memory size exceeds the host address space"))?;
        Ok(Self::new_with_initial_len(ty, initial_len, backend))
    }

    pub(crate) fn new_with_initial_len(
        ty: MemoryType,
        initial_len: usize,
        backend: MemoryBackend,
    ) -> Self {
        Self {
            ty,
            initial_len,
            backend,
            inner: RefCell::new(None),
        }
    }

    fn is_materialized(&self) -> bool {
        self.inner.borrow().is_some()
    }

    /// Whether `[addr, addr + len)` lies inside the not yet materialized memory.
    fn unmaterialized_in_bounds(&self, addr: usize, len: usize) -> bool {
        addr.checked_add(len).is_some_and(|end| end <= self.initial_len)
    }

    fn try_with_inner<R>(
        &self,
        f: impl FnOnce(&dyn LinearMemory) -> R,
    ) -> core::result::Result<R, crate::wasm::rt::Trap> {
        self.try_ensure_materialized()?;
        let inner = self.inner.borrow();
        Ok(f(inner
            .as_deref()
            .expect("lazy memory should be materialized")))
    }

    fn try_with_inner_mut<R>(
        &self,
        f: impl FnOnce(&mut dyn LinearMemory) -> R,
    ) -> core::result::Result<R, crate::wasm::rt::Trap> {
        self.try_ensure_materialized()?;
        let mut inner = self.inner.borrow_mut();
        Ok(f(inner
            .as_deref_mut()
            .expect("lazy memory should be materialized")))
    }

    fn try_ensure_materialized(&self) -> core::result::Result<(), crate::wasm::rt::Trap> {
        if self.inner.borrow().is_some() {
            return Ok(());
        }

        let storage = match self.backend.create(self.ty, self.initial_len) {
            Ok(storage) => storage,
            Err(Error::Trap(trap)) => {
                cold_path();
                return Err(trap);
            }
            Err(_) => {
                cold_path();
                return Err(crate::wasm::rt::Trap::Other("lazy memory materialization failed"));
            }
        };
        *self.inner.borrow_mut() = Some(storage.0);
        Ok(())
    }
}

impl LinearMemory for LazyLinearMemory {
    fn len(&self) -> usize {
        if !self.is_materialized() {
            // `MemoryBackend::create` refuses storage of any other length.
            return self.initial_len;
        }
        self.try_with_inner(|inner| inner.len()).unwrap_or(self.initial_len)
    }

    fn grow_to(&mut self, new_len: usize) -> Result<(), crate::wasm::rt::Trap> {
        self.try_with_inner_mut(|inner| inner.grow_to(new_len))?
    }

    fn read(&self, addr: usize, dst: &mut [u8]) -> usize {
        if !self.is_materialized() {
            let n = self.initial_len.saturating_sub(addr).min(dst.len());
            dst[..n].fill(0);
            return n;
        }
        self.try_with_inner(|inner| inner.read(addr, dst)).unwrap_or(0)
    }

    fn write(&mut self, addr: usize, src: &[u8]) -> usize {
        self.try_with_inner_mut(|inner| inner.write(addr, src)).unwrap_or(0)
    }

    fn write_all(&mut self, addr: usize, src: &[u8]) -> Option<()> {
        self.try_with_inner_mut(|inner| inner.write_all(addr, src)).ok()?
    }

    fn fill(&mut self, addr: usize, len: usize, val: u8) -> Option<()> {
        if val == 0 && !self.is_materialized() {
            // Unwritten memory is already zero.
            return self.unmaterialized_in_bounds(addr, len).then_some(());
        }
        self.try_with_inner_mut(|inner| inner.fill(addr, len, val)).ok()?
    }

    fn copy_within(&mut self, dst: usize, src: usize, len: usize) -> Option<()> {
        if !self.is_materialized() {
            // Copying zeros over zeros changes nothing.
            return (self.unmaterialized_in_bounds(dst, len)
                && self.unmaterialized_in_bounds(src, len))
            .then_some(());
        }
        self.try_with_inner_mut(|inner| inner.copy_within(dst, src, len)).ok()?
    }

    fn read_exact(&self, addr: usize, dst: &mut [u8]) -> Option<()> {
        if !self.is_materialized() {
            if !self.unmaterialized_in_bounds(addr, dst.len()) {
                return None;
            }
            dst.fill(0);
            return Some(());
        }
        self.try_with_inner(|inner| inner.read_exact(addr, dst)).ok()?
    }

    fn read_vec(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        if !self.is_materialized() {
            return self.unmaterialized_in_bounds(addr, len).then(|| vec![0; len]);
        }
        self.try_with_inner(|inner| inner.read_vec(addr, len)).ok()?
    }

    fn read_8(&self, base: u64, offset: u64) -> core::result::Result<u8, crate::wasm::rt::Trap> {
        self.try_with_inner(|inner| inner.read_8(base, offset))?
    }

    fn read_16(
        &self,
        base: u64,
        offset: u64,
    ) -> core::result::Result<[u8; 2], crate::wasm::rt::Trap> {
        self.try_with_inner(|inner| inner.read_16(base, offset))?
    }

    fn read_32(
        &self,
        base: u64,
        offset: u64,
    ) -> core::result::Result<[u8; 4], crate::wasm::rt::Trap> {
        self.try_with_inner(|inner| inner.read_32(base, offset))?
    }

    fn read_64(
        &self,
        base: u64,
        offset: u64,
    ) -> core::result::Result<[u8; 8], crate::wasm::rt::Trap> {
        self.try_with_inner(|inner| inner.read_64(base, offset))?
    }

    fn read_128(
        &self,
        base: u64,
        offset: u64,
    ) -> core::result::Result<[u8; 16], crate::wasm::rt::Trap> {
        self.try_with_inner(|inner| inner.read_128(base, offset))?
    }

    fn write_8(
        &mut self,
        base: u64,
        offset: u64,
        byte: u8,
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        self.try_with_inner_mut(|inner| inner.write_8(base, offset, byte))?
    }

    fn write_16(
        &mut self,
        base: u64,
        offset: u64,
        bytes: [u8; 2],
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        self.try_with_inner_mut(|inner| inner.write_16(base, offset, bytes))?
    }

    fn write_32(
        &mut self,
        base: u64,
        offset: u64,
        bytes: [u8; 4],
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        self.try_with_inner_mut(|inner| inner.write_32(base, offset, bytes))?
    }

    fn write_64(
        &mut self,
        base: u64,
        offset: u64,
        bytes: [u8; 8],
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        self.try_with_inner_mut(|inner| inner.write_64(base, offset, bytes))?
    }

    fn write_128(
        &mut self,
        base: u64,
        offset: u64,
        bytes: [u8; 16],
    ) -> core::result::Result<(), crate::wasm::rt::Trap> {
        self.try_with_inner_mut(|inner| inner.write_128(base, offset, bytes))?
    }
}

impl core::fmt::Debug for LazyLinearMemory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LazyLinearMemory")
            .field("ty", &self.ty)
            .field("materialized", &self.inner.borrow().is_some())
            .finish()
    }
}
