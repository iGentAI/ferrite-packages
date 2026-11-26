use crate::wasm::rt::{Result, Trap};
use crate::wasm::types::{Addr, ExternRef, FuncRef, TableAddr, TableType, WasmType, WasmValue};
use alloc::vec::Vec;

const MAX_TABLE_SIZE: u32 = 10_000_000;

/// A WebAssembly Table Instance
///
/// See <https://webassembly.github.io/spec/core/exec/runtime.html#table-instances>
#[derive(Debug)]
pub(crate) struct TableInstance {
    pub(crate) elements: Vec<TableElement>,
    pub(crate) kind: TableType,
}

impl TableInstance {
    pub(crate) fn new(kind: TableType) -> Result<Self, Trap> {
        Self::new_with_init(kind, TableElement::Uninitialized)
    }

    /// The most elements a table of this type may ever hold.
    fn limit(kind: &TableType) -> usize {
        kind.size_max.map_or(MAX_TABLE_SIZE, |max| max.min(MAX_TABLE_SIZE)) as usize
    }

    pub(crate) fn new_with_init(kind: TableType, init: TableElement) -> Result<Self, Trap> {
        let initial = kind.size_initial as usize;
        if kind.size_max.is_some_and(|max| kind.size_initial > max) || initial > Self::limit(&kind) {
            return Err(Trap::Other("table initial size exceeds its maximum"));
        }
        let mut elements = Vec::new();
        if elements.try_reserve_exact(initial).is_err() {
            return Err(Trap::OutOfMemory);
        }
        elements.resize(initial, init);
        Ok(Self { elements, kind })
    }

    #[inline(never)]
    #[cold]
    fn trap_oob(&self, addr: usize, len: usize) -> Trap {
        crate::wasm::rt::Trap::TableOutOfBounds {
            offset: addr,
            len,
            max: self.elements.len(),
        }
    }

    pub(crate) fn get_wasm_val(&self, addr: TableAddr) -> Result<WasmValue, Trap> {
        let val = self.get(addr)?.addr();

        Ok(match self.kind.element_type {
            WasmType::RefFunc => WasmValue::RefFunc(FuncRef::new(val)),
            WasmType::RefExtern => WasmValue::RefExtern(ExternRef::new(val)),
            _ => Err(Trap::Other("non-ref table"))?,
        })
    }

    /// Fill `len` elements from `addr` with `val`. A funcref on the operand
    /// stack is already a store address (as for `set` and `grow`), so it is
    /// written as it is, never resolved through the module's index space.
    pub(crate) fn fill(&mut self, addr: usize, len: usize, val: TableElement) -> Result<(), Trap> {
        let end = addr
            .checked_add(len)
            .ok_or_else(|| self.trap_oob(addr, len))?;
        if end > self.elements.len() {
            return Err(self.trap_oob(addr, len));
        }

        self.elements[addr..end].fill(val);
        Ok(())
    }

    pub(crate) fn get(&self, addr: TableAddr) -> Result<&TableElement, Trap> {
        self.elements
            .get(addr as usize)
            .ok_or(Trap::TableOutOfBounds {
                offset: addr as usize,
                len: 1,
                max: self.elements.len(),
            })
    }

    pub(crate) fn copy_from_slice(&mut self, dst: usize, src: &[TableElement]) -> Result<(), Trap> {
        let end = dst
            .checked_add(src.len())
            .ok_or_else(|| self.trap_oob(dst, src.len()))?;

        if end > self.elements.len() {
            return Err(self.trap_oob(dst, src.len()));
        }

        self.elements[dst..end].copy_from_slice(src);
        Ok(())
    }

    pub(crate) fn load(&self, addr: usize, len: usize) -> Result<&[TableElement], Trap> {
        let Some(end) = addr.checked_add(len) else {
            return Err(self.trap_oob(addr, len));
        };

        if end > self.elements.len() {
            return Err(self.trap_oob(addr, len));
        }

        Ok(&self.elements[addr..end])
    }

    pub(crate) fn copy_within(&mut self, dst: usize, src: usize, len: usize) -> Result<(), Trap> {
        let src_end = src
            .checked_add(len)
            .ok_or_else(|| self.trap_oob(src, len))?;
        if src_end > self.elements.len() {
            return Err(self.trap_oob(src, len));
        }

        let dst_end = dst
            .checked_add(len)
            .ok_or_else(|| self.trap_oob(dst, len))?;
        if dst_end > self.elements.len() {
            return Err(self.trap_oob(dst, len));
        }

        self.elements.copy_within(src..src_end, dst);
        Ok(())
    }

    pub(crate) fn set(&mut self, table_idx: TableAddr, value: TableElement) -> Result<(), Trap> {
        if table_idx as usize >= self.elements.len() {
            return Err(self.trap_oob(table_idx as usize, 1));
        }

        self.elements[table_idx as usize] = value;
        Ok(())
    }

    pub(crate) fn grow(&mut self, n: i32, init: TableElement) -> Result<(), Trap> {
        if n < 0 {
            return Err(crate::wasm::rt::Trap::TableOutOfBounds {
                offset: 0,
                len: 1,
                max: self.elements.len(),
            });
        }

        let max = Self::limit(&self.kind);
        let len = match (n as usize).checked_add(self.elements.len()) {
            Some(len) if len <= max => len,
            _ => {
                return Err(crate::wasm::rt::Trap::TableOutOfBounds {
                    offset: (n as usize).saturating_add(self.elements.len()),
                    len: 1,
                    max: self.elements.len(),
                });
            }
        };

        if self.elements.try_reserve_exact(len - self.elements.len()).is_err() {
            return Err(Trap::OutOfMemory);
        }
        self.elements.resize(len, init);
        Ok(())
    }

    pub(crate) fn size(&self) -> i32 {
        self.elements.len() as i32
    }

    pub(crate) fn init(&mut self, offset: i64, init: &[TableElement]) -> Result<(), Trap> {
        let offset = offset as usize;
        let end = offset
            .checked_add(init.len())
            .ok_or_else(|| self.trap_oob(offset, init.len()))?;

        if end > self.elements.len() {
            return Err(self.trap_oob(offset, init.len()));
        }
        self.elements[offset..end].copy_from_slice(init);
        Ok(())
    }
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub(crate) enum TableElement {
    Uninitialized,
    Initialized(TableAddr),
}

impl From<Option<Addr>> for TableElement {
    fn from(addr: Option<Addr>) -> Self {
        match addr {
            None => Self::Uninitialized,
            Some(addr) => Self::Initialized(addr),
        }
    }
}

impl TableElement {
    pub(crate) fn addr(&self) -> Option<Addr> {
        match self {
            Self::Uninitialized => None,
            Self::Initialized(addr) => Some(*addr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a dummy TableType
    fn dummy_table_type() -> TableType {
        TableType {
            element_type: WasmType::RefFunc,
            size_initial: 10,
            size_max: Some(20),
        }
    }

    #[test]
    fn fill_writes_the_store_address_it_is_given() {
        // A funcref on the stack is already a store address: fill must not
        // re-resolve it through a module's index space (which panicked for an
        // address past that space and wrote the wrong function otherwise).
        let mut table_instance = TableInstance::new(dummy_table_type()).unwrap();
        table_instance.fill(2, 3, TableElement::Initialized(57)).unwrap();
        for i in 2..5 {
            assert_eq!(table_instance.get(i).unwrap().addr(), Some(57));
        }
        assert_eq!(table_instance.get(5).unwrap().addr(), None);
        assert!(table_instance.fill(9, 2, TableElement::Initialized(1)).is_err());
    }

    #[test]
    fn a_table_never_exceeds_its_maximum_or_the_size_cap() {
        let over = TableType { element_type: WasmType::RefFunc, size_initial: 5, size_max: Some(4) };
        assert!(TableInstance::new(over).is_err(), "initial above maximum");
        let huge = TableType { element_type: WasmType::RefFunc, size_initial: u32::MAX, size_max: None };
        assert!(TableInstance::new(huge).is_err(), "initial above the size cap");
        let wide = TableType { element_type: WasmType::RefFunc, size_initial: 1, size_max: Some(u32::MAX) };
        let mut table = TableInstance::new(wide).unwrap();
        assert!(table.grow(i32::MAX, TableElement::Uninitialized).is_err(), "grow past the size cap");
        assert_eq!(table.size(), 1);
        assert!(table.grow(3, TableElement::Uninitialized).is_ok());
        assert_eq!(table.size(), 4);
    }

    #[test]
    fn test_table_instance_creation() {
        let kind = dummy_table_type();
        let table_instance = TableInstance::new(kind.clone()).unwrap();
        assert_eq!(
            table_instance.size(),
            kind.size_initial as i32,
            "Table instance creation failed: size mismatch"
        );
    }

    #[test]
    fn test_get_wasm_val() {
        let kind = dummy_table_type();
        let mut table_instance = TableInstance::new(kind).unwrap();

        table_instance
            .set(0, TableElement::Initialized(0))
            .expect("Setting table element failed");
        table_instance
            .set(1, TableElement::Uninitialized)
            .expect("Setting table element failed");

        match table_instance.get_wasm_val(0) {
            Ok(WasmValue::RefFunc(_)) => {}
            _ => panic!("get_wasm_val failed to return the correct WasmValue"),
        }

        match table_instance.get_wasm_val(1) {
            Ok(WasmValue::RefFunc(f)) if f.is_null() => {}
            _ => panic!("get_wasm_val failed to return the correct WasmValue"),
        }

        match table_instance.get_wasm_val(999) {
            Err(Trap::TableOutOfBounds { .. }) => {}
            _ => panic!("get_wasm_val failed to handle undefined element correctly"),
        }
    }

    #[test]
    fn test_set_and_get() {
        let kind = dummy_table_type();
        let mut table_instance = TableInstance::new(kind).unwrap();

        let result = table_instance.set(0, TableElement::Initialized(1));
        assert!(result.is_ok(), "Setting table element failed");

        let elem = table_instance.get(0);
        assert!(
            elem.is_ok() && matches!(elem.unwrap(), &TableElement::Initialized(1)),
            "Getting table element failed or returned incorrect value"
        );
    }

    #[test]
    fn test_table_init() {
        let kind = dummy_table_type();
        let mut table_instance = TableInstance::new(kind).unwrap();

        let init_elements = vec![TableElement::Initialized(0); 5];
        let result = table_instance.init(0, &init_elements);

        assert!(result.is_ok(), "Initializing table with elements failed");

        for i in 0..5 {
            let elem = table_instance.get(i);
            assert!(
                elem.is_ok() && matches!(elem.unwrap(), &TableElement::Initialized(_)),
                "Element not initialized correctly at index {i}"
            );
        }
    }
}
