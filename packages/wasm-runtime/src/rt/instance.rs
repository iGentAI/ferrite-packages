use crate::wasm::compat::cold_path;
use crate::wasm::types::{DataAddr, ElemAddr, Export, ExternVal, ExternalKind, FuncAddr, FuncType, GlobalAddr, LocalMemoryAllocation, MemAddr, Module, ModuleInstanceAddr, TableAddr, WasmValue};
use alloc::{boxed::Box, sync::Arc};

use crate::wasm::rt::func::{FromWasmValues, IntoWasmValues, ToWasmTypes};
use crate::wasm::rt::{
    Error, Function, FunctionTyped, Global, Imports, Memory, Result, Store, Table, Trap,
};

/// A typed view over an exported extern value.
pub enum ExternItem {
    /// Exported function handle.
    Func(Function),
    /// Exported memory reference.
    Memory(Memory),
    /// Exported table reference.
    Table(Table),
    /// Exported global reference.
    Global(Global),
}

/// An instantiated WebAssembly module
///
/// Create a `ModuleInstance` by parsing a module, creating a [`Store`], and then calling
/// [`ModuleInstance::instantiate`].
///
/// Backed by an Arc, so cloning is cheap (FERRITE PATCH: Arc, not Rc, so a
/// paged run can be held across an `await` in `FerriteApp::run`)
///
/// See <https://webassembly.github.io/spec/core/exec/runtime.html#module-instances>
#[derive(Clone)]
#[derive(Debug)]
pub struct ModuleInstance(Arc<ModuleInstanceInner>);

#[derive(Debug)]
struct ModuleInstanceInner {
    store_id: usize,
    idx: ModuleInstanceAddr,
    types: Arc<[Arc<FuncType>]>,
    func_type_idxs: Arc<[u32]>,
    func_addrs: Box<[FuncAddr]>,
    table_addrs: Box<[TableAddr]>,
    mem_addrs: Box<[MemAddr]>,
    global_addrs: Box<[GlobalAddr]>,
    elem_addrs: Box<[ElemAddr]>,
    data_addrs: Box<[DataAddr]>,
    func_start: Option<FuncAddr>,
    exports: Arc<[Export]>,
}

impl ModuleInstance {
    #[inline]
    pub(crate) fn idx(&self) -> ModuleInstanceAddr {
        self.0.idx
    }

    /// Type indices come from the module type section and are used by indirect calls.
    #[inline]
    pub(crate) fn func_type_by_type_index(&self, type_idx: u32) -> &Arc<FuncType> {
        match self.0.types.get(type_idx as usize) {
            Some(ty) => ty,
            None => {
                cold_path();
                unreachable!("invalid type index: {type_idx}")
            }
        }
    }

    /// Function indices need their own lookup because they are not type-section indices.
    #[inline]
    pub(crate) fn func_type_idx(&self, addr: FuncAddr) -> u32 {
        match self.0.func_type_idxs.get(addr as usize) {
            Some(idx) => *idx,
            None => {
                cold_path();
                unreachable!("invalid function address: {addr}")
            }
        }
    }

    /// resolve a function address to the global store address
    #[inline]
    pub(crate) fn resolve_func_addr(&self, addr: FuncAddr) -> FuncAddr {
        match self.0.func_addrs.get(addr as usize) {
            Some(addr) => *addr,
            None => {
                cold_path();
                unreachable!("invalid function address: {addr}")
            }
        }
    }

    /// resolve a table address to the global store address
    #[inline]
    pub(crate) fn resolve_table_addr(&self, addr: TableAddr) -> TableAddr {
        match self.0.table_addrs.get(addr as usize) {
            Some(addr) => *addr,
            None => {
                cold_path();
                unreachable!("invalid table address: {addr}")
            }
        }
    }

    /// resolve a memory address to the global store address
    #[inline]
    pub(crate) fn resolve_mem_addr(&self, addr: MemAddr) -> MemAddr {
        match self.0.mem_addrs.get(addr as usize) {
            Some(addr) => *addr,
            None => {
                cold_path();
                unreachable!("invalid memory address: {addr}")
            }
        }
    }

    /// resolve a data address to the global store address
    #[inline]
    pub(crate) fn resolve_data_addr(&self, addr: DataAddr) -> DataAddr {
        match self.0.data_addrs.get(addr as usize) {
            Some(addr) => *addr,
            None => {
                cold_path();
                unreachable!("invalid data address: {addr}")
            }
        }
    }

    /// resolve an element address to the global store address
    #[inline]
    pub(crate) fn resolve_elem_addr(&self, addr: ElemAddr) -> ElemAddr {
        match self.0.elem_addrs.get(addr as usize) {
            Some(addr) => *addr,
            None => {
                cold_path();
                unreachable!("invalid element address: {addr}")
            }
        }
    }

    /// resolve a global address to the global store address
    #[inline]
    pub(crate) fn resolve_global_addr(&self, addr: GlobalAddr) -> GlobalAddr {
        match self.0.global_addrs.get(addr as usize) {
            Some(addr) => *addr,
            None => {
                cold_path();
                unreachable!("invalid global address: {addr}")
            }
        }
    }

    #[inline]
    pub(crate) fn validate_store(&self, store: &Store) -> Result<()> {
        if self.0.store_id != store.id() {
            cold_path();
            return Err(Trap::InvalidStore.into());
        }
        Ok(())
    }

    /// Get the module instance's address
    pub fn id(&self) -> ModuleInstanceAddr {
        self.0.idx
    }

    /// Instantiate the module in the given store
    ///
    /// See <https://webassembly.github.io/spec/core/exec/modules.html#exec-instantiation>
    pub fn instantiate(
        store: &mut Store,
        module: &Module,
        imports: Option<Imports>,
    ) -> Result<Self> {
        let instance = ModuleInstance::instantiate_no_start(store, module, imports)?;
        let _ = instance.start(store)?;
        Ok(instance)
    }

    /// Instantiate the module in the given store (without running the start function)
    ///
    /// See <https://webassembly.github.io/spec/core/exec/modules.html#exec-instantiation>
    pub fn instantiate_no_start(
        store: &mut Store,
        module: &Module,
        imports: Option<Imports>,
    ) -> Result<Self> {
        let idx = store.next_module_instance_idx();
        let mut addrs = imports.unwrap_or_default().link(store, module)?;
        addrs.funcs.extend(store.init_funcs(&module.funcs, idx));
        // From here this module's functions are in the store, owned by `idx`.
        // A failure below still records an instance at `idx` (with what was
        // allocated so far), so the slot is never reused by a later module
        // and a function left reachable through a shared table runs against
        // its own module, never another one.
        let mut elem_addrs: Box<[ElemAddr]> = Box::default();
        let mut data_addrs: Box<[DataAddr]> = Box::default();
        let outcome = Self::init_after_funcs(store, module, &mut addrs, &mut elem_addrs, &mut data_addrs);

        let instance = ModuleInstanceInner {
            store_id: store.id(),
            idx,
            types: module.func_types.clone(),
            func_type_idxs: module.func_type_idxs.clone(),
            func_addrs: addrs.funcs.into_boxed_slice(),
            table_addrs: addrs.tables.into_boxed_slice(),
            mem_addrs: addrs.memories.into_boxed_slice(),
            global_addrs: addrs.globals.into_boxed_slice(),
            elem_addrs,
            data_addrs,
            func_start: module.start_func,
            exports: module.exports.clone(),
        };

        let instance = ModuleInstance(Arc::new(instance));
        store.add_instance(instance.clone());

        match outcome {
            Err(e) => {
                cold_path();
                Err(e)
            }
            Ok(Some(trap)) => {
                cold_path();
                Err(trap.into())
            }
            Ok(None) => Ok(instance),
        }
    }

    /// The fallible part of instantiation after the module's functions are
    /// in the store: tables, memories, globals, then element and data
    /// segments. An element segment that traps aborts before any data
    /// segment is written, as the spec requires.
    fn init_after_funcs(
        store: &mut Store,
        module: &Module,
        addrs: &mut crate::wasm::rt::imports::ResolvedImports,
        elem_addrs: &mut Box<[ElemAddr]>,
        data_addrs: &mut Box<[DataAddr]>,
    ) -> Result<Option<Trap>> {
        addrs.tables.extend(store.init_tables(&module.table_types)?);
        match module.local_memory_allocation {
            LocalMemoryAllocation::Skip => {}
            LocalMemoryAllocation::Lazy => addrs
                .memories
                .extend(store.init_lazy_memories(&module.memory_types)?),
            LocalMemoryAllocation::Eager => addrs
                .memories
                .extend(store.init_memories(&module.memory_types)?),
        }

        store.init_globals(&mut addrs.globals, &module.globals, &addrs.funcs)?;
        let (elems, elem_trapped) = store.init_elements(
            &addrs.tables,
            &addrs.funcs,
            &addrs.globals,
            &module.elements,
        )?;
        *elem_addrs = elems;
        // After an element trap the data segments are still allocated, so the
        // module's data table is complete, but none of them is written.
        let (datas, data_trapped) = store.init_data(
            &addrs.memories,
            &addrs.globals,
            &addrs.funcs,
            &module.data,
            elem_trapped.is_none(),
        )?;
        *data_addrs = datas;
        Ok(elem_trapped.or(data_trapped))
    }

    fn func_handle(&self, addr: FuncAddr, ty: Arc<FuncType>) -> Function {
        Function {
            item: crate::wasm::rt::StoreItem::new(self.0.store_id, addr),
            module_addr: self.id(),
            addr,
            ty,
        }
    }

    /// Get a export by name
    pub fn export_addr(&self, name: &str) -> Option<ExternVal> {
        let exports = self.0.exports.iter().find(|e| *e.name == *name)?;
        let addr = match exports.kind {
            ExternalKind::Func => self.0.func_addrs.get(exports.index as usize)?,
            ExternalKind::Table => self.0.table_addrs.get(exports.index as usize)?,
            ExternalKind::Memory => self.0.mem_addrs.get(exports.index as usize)?,
            ExternalKind::Global => self.0.global_addrs.get(exports.index as usize)?,
        };
        Some(ExternVal::new(exports.kind, *addr))
    }

    /// Returns an iterator over all exported extern values for this instance.
    pub fn exports(&self) -> impl Iterator<Item = (&str, ExternItem)> + '_ {
        self.0.exports.iter().map(move |export| {
            let item = match export.kind {
                ExternalKind::Func => {
                    let func_addr = self.resolve_func_addr(export.index);
                    ExternItem::Func(self.func_handle(
                        func_addr,
                        self.func_type_by_type_index(self.func_type_idx(export.index))
                            .clone(),
                    ))
                }
                ExternalKind::Table => ExternItem::Table(Table::from_store_addr(
                    self.0.store_id,
                    self.resolve_table_addr(export.index),
                )),
                ExternalKind::Memory => ExternItem::Memory(Memory::from_store_addr(
                    self.0.store_id,
                    self.resolve_mem_addr(export.index),
                )),
                ExternalKind::Global => ExternItem::Global(Global::from_store_addr(
                    self.0.store_id,
                    self.resolve_global_addr(export.index),
                )),
            };

            (export.name.as_ref(), item)
        })
    }

    #[inline]
    fn require_export(&self, name: &str) -> Result<ExternVal> {
        match self.export_addr(name) {
            Some(addr) => Ok(addr),
            None => {
                cold_path();
                Err(Error::Other(format!("Export not found: {name}")))
            }
        }
    }

    /// Get any exported extern value by name.
    pub fn extern_item(&self, name: &str) -> Result<ExternItem> {
        match self.require_export(name)? {
            ExternVal::Func(addr) => {
                let export = self.0.exports.iter().find(|e| e.name == name.into());
                let export =
                    export.ok_or_else(|| Error::Other(format!("Export not found: {name}")))?;
                Ok(ExternItem::Func(self.func_handle(
                    addr,
                    self.func_type_by_type_index(self.func_type_idx(export.index))
                        .clone(),
                )))
            }
            ExternVal::Memory(addr) => Ok(ExternItem::Memory(Memory::from_store_addr(
                self.0.store_id,
                addr,
            ))),
            ExternVal::Table(addr) => Ok(ExternItem::Table(Table::from_store_addr(
                self.0.store_id,
                addr,
            ))),
            ExternVal::Global(addr) => Ok(ExternItem::Global(Global::from_store_addr(
                self.0.store_id,
                addr,
            ))),
        }
    }

    /// Get a function export by name.
    ///
    /// For typed access, see [`Self::func`].
    pub fn func_untyped(&self, store: &Store, name: &str) -> Result<Function> {
        self.validate_store(store)?;

        let func_addr = match self.require_export(name)? {
            ExternVal::Func(func_addr) => func_addr,
            _ => {
                cold_path();
                return Err(Error::Other(format!("Export is not a function: {name}")));
            }
        };

        Ok(self.func_handle(func_addr, store.state.get_func(func_addr).ty().clone()))
    }

    /// Get a typed function export by name.
    ///
    /// For untyped access, see [`Self::func_untyped`] and [`Self::extern_item`].
    ///
    /// For signatures that exceed tuple arity 12, see [`crate::wasm::rt::WasmTupleChain`], which can be used
    /// directly as `instance.func::<crate::wasm::rt::WasmTupleChain<_, _>, _>(...)`.
    pub fn func<P: IntoWasmValues + ToWasmTypes, R: FromWasmValues + ToWasmTypes>(
        &self,
        store: &Store,
        name: &str,
    ) -> Result<FunctionTyped<P, R>> {
        let func = self.func_untyped(store, name)?;
        Self::validate_typed_func::<P, R>(&func, name)?;
        Ok(FunctionTyped {
            func,
            marker: core::marker::PhantomData,
        })
    }

    fn validate_typed_func<P: ToWasmTypes, R: ToWasmTypes>(
        func: &Function,
        func_name: &str,
    ) -> Result<()> {
        if *func.ty.params() != *P::wasm_types() || *func.ty.results() != *R::wasm_types() {
            cold_path();

            return Err(Error::Other(format!(
                "function type mismatch for {func_name}: expected {:?}, actual {:?}",
                FuncType::new(&P::wasm_types(), &R::wasm_types()),
                func.ty
            )));

        }

        Ok(())
    }

    /// Get a memory export by name.
    pub fn memory(&self, name: &str) -> Result<Memory> {
        match self.require_export(name)? {
            ExternVal::Memory(mem_addr) => Ok(Memory::from_store_addr(self.0.store_id, mem_addr)),
            _ => {
                cold_path();
                Err(Error::Other(format!("Export is not a memory: {name}")))
            }
        }
    }

    /// Get a table export by name.
    pub fn table(&self, name: &str) -> Result<Table> {
        match self.require_export(name)? {
            ExternVal::Table(table_addr) => Ok(Table::from_store_addr(self.0.store_id, table_addr)),
            _ => Err(Error::Other(format!("Export is not a table: {name}"))),
        }
    }

    /// Get the value of a global export by name.
    pub fn global_get(&self, store: &Store, name: &str) -> Result<WasmValue> {
        self.global(name)?.get(store)
    }

    /// Get a global export by name.
    pub fn global(&self, name: &str) -> Result<Global> {
        match self.require_export(name)? {
            ExternVal::Global(global_addr) => {
                Ok(Global::from_store_addr(self.0.store_id, global_addr))
            }
            _ => Err(Error::Other(format!("Export is not a global: {name}"))),
        }
    }

    /// Set the value of a mutable global export by name.
    pub fn global_set(&self, store: &mut Store, name: &str, value: WasmValue) -> Result<()> {
        self.global(name)?.set(store, value)
    }

    /// Get the start function of the module
    ///
    /// Returns `None` if the module has no start section.
    ///
    /// See <https://webassembly.github.io/spec/core/syntax/modules.html#start-function>
    pub fn start_func(&self, store: &Store) -> Result<Option<Function>> {
        self.validate_store(store)?;

        let Some(func_index) = self.0.func_start else {
            return Ok(None);
        };
        let func_addr = self.resolve_func_addr(func_index);

        Ok(Some(self.func_handle(
            func_addr,
            store.state.get_func(func_addr).ty().clone(),
        )))
    }

    /// Invoke the start function of the module
    ///
    /// Returns `None` if the module has no start function
    ///
    /// See <https://webassembly.github.io/spec/core/syntax/modules.html#syntax-start>
    pub fn start(&self, store: &mut Store) -> Result<Option<()>> {
        match self.start_func(store)? {
            Some(func) => func.call(store, &[]).map(|_| Some(())),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::types::{Export, FuncType, Instruction, ModuleInner, WasmFunction};

    fn module_with_exported_start(start_section: Option<u32>) -> Module {
        let ty = Arc::new(FuncType::new(&[], &[]));
        let trap_fn = Arc::new(WasmFunction {
            instructions: alloc::boxed::Box::new([Instruction::Unreachable]),
            ty: Arc::clone(&ty),
            ..Default::default()
        });
        Module::from(ModuleInner {
            start_func: start_section,
            funcs: alloc::boxed::Box::new([trap_fn]),
            func_types: Arc::from([ty]),
            func_type_idxs: Arc::from([0u32]),
            exports: Arc::from([Export {
                name: "_start".into(),
                kind: ExternalKind::Func,
                index: 0,
            }]),
            ..Default::default()
        })
    }

    #[test]
    fn instantiate_does_not_execute_exported_underscore_start_when_start_section_is_absent() {
        let mut store = Store::default();
        let module = module_with_exported_start(None);
        let inst = ModuleInstance::instantiate(&mut store, &module, None)
            .expect("exported _start must not run automatically during instantiate");
        assert!(
            inst.start_func(&store).unwrap().is_none(),
            "start_func must only reflect the WebAssembly start section"
        );

        let mut store2 = Store::default();
        let with_start = module_with_exported_start(Some(0));
        assert!(
            ModuleInstance::instantiate(&mut store2, &with_start, None).is_err(),
            "explicit start section still executes during instantiate"
        );
    }
}
