use crate::wasm::compat::cold_path;
use crate::wasm::types::{Addr, Data, DataAddr, ElemAddr, Element, ElementItem, ElementKind, FuncAddr, Global, GlobalAddr, MemAddr, MemoryType, ModuleInstanceAddr, TableAddr, TableType, WasmFunction};
use alloc::sync::Arc;
use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::wasm::rt::interpreter::stack::{CallStack, ValueStack};
use crate::wasm::rt::interpreter::{TinyWasmValue, ValueRef};
use crate::wasm::rt::{Engine, Error, ModuleInstance, Result, Trap};

mod data;
mod element;
mod function;
mod global;
mod memory;
mod table;

pub use memory::{LazyLinearMemory, LinearMemory, MemoryBackend, PagedMemory, VecMemory};
pub(crate) use memory::{MemValue, MemoryInstance};
pub(crate) use self::data::{DataInstance};
pub(crate) use self::element::{ElementInstance};
pub(crate) use self::function::{FunctionInstance, WasmFunctionInstance};
pub(crate) use self::global::{GlobalInstance};
pub(crate) use self::table::{TableElement, TableInstance};

static STORE_ID: AtomicUsize = AtomicUsize::new(0);

/// What bounds a nested call made while an invocation is resumed.
#[derive(Clone)]
pub(crate) enum NestedBudget {
    /// A plain (unbudgeted) call.
    Unbounded,
    /// `resume_with_fuel`: nested calls spend `Store::execution_fuel`.
    Fuel,
    /// `resume_with_time_budget`: nested calls stop at this clock reading.
    Deadline { clock: ferrite_app::Clock, deadline_ms: u64 },
}

// Written out because the platform builder's SDK `Clock` has no `Debug`.
impl core::fmt::Debug for NestedBudget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unbounded => f.write_str("Unbounded"),
            Self::Fuel => f.write_str("Fuel"),
            Self::Deadline { deadline_ms, .. } => write!(f, "Deadline {{ deadline_ms: {deadline_ms} }}"),
        }
    }
}

// Written out because the platform's code gate does not admit the `#[default]` variant attribute.
impl Default for NestedBudget {
    fn default() -> Self {
        Self::Unbounded
    }
}

/// Global state that can be manipulated by WebAssembly programs
///
/// Note that the state doesn't do any garbage collection - so it will grow
/// indefinitely if you keep adding modules to it. When calling temporary
/// functions, you should create a new store and then drop it when you're done (e.g. in a request handler).
///
///  See <https://webassembly.github.io/spec/core/exec/runtime.html#store>
pub struct Store {
    id: usize,
    module_instances: Vec<ModuleInstance>,

    pub(crate) engine: Engine,
    pub(crate) execution_fuel: u32,
    pub(crate) execution_active: bool,
    /// The budget of the invocation being resumed, which a nested call (a
    /// host function calling back into the guest) must also respect.
    pub(crate) nested_budget: NestedBudget,
    pub(crate) state: State,
    pub(crate) call_stack: CallStack,
    pub(crate) value_stack: ValueStack,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store")
            .field("id", &self.id)
            .field("module_instances", &self.module_instances)
            .field("engine", &self.engine)
            .finish()
    }
}

impl Store {
    /// Create a new store
    pub fn new(engine: Engine) -> Self {
        let id = STORE_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            id,
            module_instances: Vec::new(),
            state: State::default(),
            call_stack: CallStack::new(engine.config()),
            value_stack: ValueStack::new(engine.config()),
            engine,
            execution_fuel: 0,
            execution_active: false,
            nested_budget: NestedBudget::Unbounded,
        }
    }

    /// Get a module instance by the internal id
    pub fn get_module_instance(&self, addr: ModuleInstanceAddr) -> Option<ModuleInstance> {
        self.module_instances.get(addr as usize).cloned()
    }

    #[inline]
    pub(crate) fn get_module_instance_internal(&self, addr: ModuleInstanceAddr) -> ModuleInstance {
        match self.module_instances.get(addr as usize) {
            Some(instance) => instance.clone(),
            None => {
                cold_path();
                unreachable!("module instance {addr} not found. This should be unreachable")
            }
        }
    }

    pub(crate) fn enter_execution(&mut self) -> Result<()> {
        if self.execution_active {
            return Err(Trap::Other(
                "cannot call a function while another invocation is active; use FuncContext::call from host functions",
            )
            .into());
        }
        self.execution_active = true;
        Ok(())
    }

    pub(crate) fn exit_execution(&mut self) {
        self.execution_active = false;
    }

    /// Capture a byte-exact snapshot of mutable WebAssembly state (linear
    /// memories, globals, and tables) for fast deterministic cloning onto a
    /// freshly instantiated store of the exact same module and imports.
    pub fn snapshot(&self) -> Result<StoreSnapshot> {
        let mut memories = Vec::with_capacity(self.state.memories.len());
        for mem in &self.state.memories {
            let len = mem.inner.len();
            let bytes = mem
                .inner
                .read_vec(0, len)
                .ok_or_else(|| Error::Other("failed to snapshot linear memory".into()))?;
            memories.push((mem.page_count, bytes));
        }
        let globals = self
            .state
            .globals
            .iter()
            .map(|global| global.value.get())
            .collect();
        let tables = self
            .state
            .tables
            .iter()
            .map(|table| table.elements.clone())
            .collect();
        Ok(StoreSnapshot {
            memories,
            globals,
            tables,
        })
    }

    /// Restore a previously captured [`StoreSnapshot`] into a freshly
    /// instantiated store of the exact same module and imports.
    pub fn restore_snapshot(&mut self, snapshot: &StoreSnapshot) -> Result<()> {
        if self.state.memories.len() != snapshot.memories.len()
            || self.state.globals.len() != snapshot.globals.len()
            || self.state.tables.len() != snapshot.tables.len()
        {
            return Err(Error::Other(
                "store snapshot shape does not match instantiated module".into(),
            ));
        }
        for (mem, (page_count, bytes)) in self.state.memories.iter_mut().zip(&snapshot.memories) {
            if mem.inner.len() != bytes.len() {
                mem.inner.grow_to(bytes.len())?;
            }
            mem.inner
                .write_all(0, bytes)
                .ok_or_else(|| Error::Other("failed to restore linear memory".into()))?;
            mem.page_count = *page_count;
        }
        for (global, value) in self.state.globals.iter().zip(&snapshot.globals) {
            global.value.set(*value);
        }
        for (table, elements) in self.state.tables.iter_mut().zip(&snapshot.tables) {
            table.elements.clone_from(elements);
        }
        Ok(())
    }
}

/// Reusable snapshot of a [`Store`]'s mutable WebAssembly state.
#[derive(Clone, Debug)]
pub struct StoreSnapshot {
    memories: Vec<(usize, Vec<u8>)>,
    globals: Vec<TinyWasmValue>,
    tables: Vec<Vec<TableElement>>,
}

impl PartialEq for Store {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new(Engine::default())
    }
}

#[derive(Default)]
/// Global state that can be manipulated by WebAssembly programs
///
/// Data should only be addressable by the module that owns it
/// See <https://webassembly.github.io/spec/core/exec/runtime.html#store>
pub(crate) struct State {
    pub(crate) funcs: Vec<FunctionInstance>,
    pub(crate) tables: Vec<TableInstance>,
    pub(crate) memories: Vec<MemoryInstance>,
    pub(crate) globals: Vec<GlobalInstance>,
    pub(crate) elements: Vec<ElementInstance>,
    pub(crate) data: Vec<DataInstance>,
}

impl State {
    /// Get the function at the actual index in the store
    pub(crate) fn get_func(&self, addr: FuncAddr) -> &FunctionInstance {
        match self.funcs.get(addr as usize) {
            Some(func) => func,
            None => {
                cold_path();
                unreachable!("function {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get a wasm function at the actual index in the store, panicking if it's a host function (which should be guaranteed by the validator)
    pub(crate) fn get_wasm_func(&self, addr: FuncAddr) -> &WasmFunctionInstance {
        match self.funcs.get(addr as usize) {
            Some(FunctionInstance::Wasm(wasm_func)) => wasm_func,
            _ => {
                cold_path();
                unreachable!("function {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get the memory at the actual index in the store
    pub(crate) fn get_mem(&self, addr: MemAddr) -> &MemoryInstance {
        match self.memories.get(addr as usize) {
            Some(mem) => mem,
            None => {
                cold_path();
                unreachable!("memory {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get the memory at the actual index in the store
    pub(crate) fn get_mem_mut(&mut self, addr: MemAddr) -> &mut MemoryInstance {
        match self.memories.get_mut(addr as usize) {
            Some(mem) => mem,
            None => {
                cold_path();
                unreachable!("memory {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get the memory at the actual index in the store
    pub(crate) fn get_mems_mut(
        &mut self,
        addr: MemAddr,
        addr2: MemAddr,
    ) -> (&mut MemoryInstance, &mut MemoryInstance) {
        match self
            .memories
            .get_disjoint_mut([addr as usize, addr2 as usize])
        {
            Ok([mem_a, mem_b]) => (mem_a, mem_b),
            Err(_) => {
                cold_path();
                unreachable!("memory {addr} or {addr2} not found. This should be unreachable")
            }
        }
    }

    /// Get the table at the actual index in the store
    pub(crate) fn get_table(&self, addr: TableAddr) -> &TableInstance {
        match self.tables.get(addr as usize) {
            Some(table) => table,
            None => {
                cold_path();
                unreachable!("table {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get the table at the actual index in the store
    pub(crate) fn get_table_mut(&mut self, addr: TableAddr) -> &mut TableInstance {
        match self.tables.get_mut(addr as usize) {
            Some(table) => table,
            None => {
                cold_path();
                unreachable!("table {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get two mutable tables at the actual index in the store
    pub(crate) fn get_tables_mut(
        &mut self,
        addr: TableAddr,
        addr2: TableAddr,
    ) -> (&mut TableInstance, &mut TableInstance) {
        match self
            .tables
            .get_disjoint_mut([addr as usize, addr2 as usize])
        {
            Ok([table_a, table_b]) => (table_a, table_b),
            Err(_) => {
                cold_path();
                unreachable!("table {addr} or {addr2} not found. This should be unreachable")
            }
        }
    }

    /// Get the data at the actual index in the store
    pub(crate) fn get_data_mut(&mut self, addr: DataAddr) -> &mut DataInstance {
        match self.data.get_mut(addr as usize) {
            Some(data) => data,
            None => {
                cold_path();
                unreachable!("data {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get the element at the actual index in the store
    pub(crate) fn get_elem_mut(&mut self, addr: ElemAddr) -> &mut ElementInstance {
        match self.elements.get_mut(addr as usize) {
            Some(elem) => elem,
            None => {
                cold_path();
                unreachable!("element {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get the global at the actual index in the store
    pub(crate) fn get_global(&self, addr: GlobalAddr) -> &GlobalInstance {
        match self.globals.get(addr as usize) {
            Some(global) => global,
            None => {
                cold_path();
                unreachable!("global {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get the global at the actual index in the store
    pub(crate) fn get_global_mut(&mut self, addr: GlobalAddr) -> &mut GlobalInstance {
        match self.globals.get_mut(addr as usize) {
            Some(global) => global,
            None => {
                cold_path();
                unreachable!("global {addr} not found. This should be unreachable")
            }
        }
    }

    /// Get the global at the actual index in the store
    pub(crate) fn get_global_val(&self, addr: GlobalAddr) -> TinyWasmValue {
        match self.globals.get(addr as usize) {
            Some(global) => global.value.get(),
            None => {
                cold_path();
                unreachable!("global {addr} not found. This should be unreachable")
            }
        }
    }

    /// Set the global at the actual index in the store
    pub(crate) fn set_global_val(&mut self, addr: GlobalAddr, value: TinyWasmValue) {
        match self.globals.get_mut(addr as usize) {
            Some(global) => global.value.set(value),
            None => {
                cold_path();
                unreachable!("global {addr} not found. This should be unreachable")
            }
        }
    }
}

impl Store {
    /// Get the store's ID (unique per process)
    pub fn id(&self) -> usize {
        self.id
    }

    pub(crate) fn next_module_instance_idx(&self) -> ModuleInstanceAddr {
        self.module_instances.len() as ModuleInstanceAddr
    }

    pub(crate) fn add_instance(&mut self, instance: ModuleInstance) {
        debug_assert!(instance.idx() == self.module_instances.len() as ModuleInstanceAddr);
        self.module_instances.push(instance);
    }

    /// Get the global at the actual index in the store
    #[doc(hidden)]
    pub fn get_global_val(&self, addr: GlobalAddr) -> TinyWasmValue {
        self.state.get_global_val(addr)
    }

    /// Set the global at the actual index in the store
    #[doc(hidden)]
    pub fn set_global_val(&mut self, addr: GlobalAddr, value: TinyWasmValue) {
        self.state.set_global_val(addr, value);
    }
}

impl Store {
    /// Add functions to the store, returning their addresses in the store
    pub(crate) fn init_funcs(
        &mut self,
        funcs: &[Arc<WasmFunction>],
        idx: ModuleInstanceAddr,
    ) -> impl ExactSizeIterator<Item = FuncAddr> {
        let start = self.state.funcs.len() as FuncAddr;
        self.state.funcs.extend(
            funcs
                .iter()
                .map(|func| FunctionInstance::new_wasm(func.clone(), idx)),
        );
        start..start + funcs.len() as FuncAddr
    }

    /// Add tables to the store, returning their addresses in the store
    pub(crate) fn init_tables(
        &mut self,
        tables: &[TableType],
    ) -> Result<impl ExactSizeIterator<Item = TableAddr>> {
        let start = self.state.tables.len() as TableAddr;
        let instances = tables
            .iter()
            .map(|table| TableInstance::new(table.clone()))
            .collect::<core::result::Result<Vec<_>, Trap>>()?;
        self.state.tables.extend(instances);
        Ok(start..start + tables.len() as TableAddr)
    }

    /// Add memories to the store, returning their addresses in the store
    pub(crate) fn init_memories(
        &mut self,
        memories: &[MemoryType],
    ) -> Result<impl ExactSizeIterator<Item = MemAddr>> {
        let start = self.state.memories.len() as MemAddr;
        self.state.memories.reserve_exact(memories.len());
        for &mem in memories {
            self.state.memories.push(MemoryInstance::new(
                mem,
                &self.engine.config().memory_backend,
            )?);
        }
        Ok(start..start + memories.len() as MemAddr)
    }

    pub(crate) fn init_lazy_memories(
        &mut self,
        memories: &[MemoryType],
    ) -> Result<impl ExactSizeIterator<Item = MemAddr>> {
        let start = self.state.memories.len() as MemAddr;
        self.state.memories.reserve_exact(memories.len());
        for &mem in memories {
            self.state.memories.push(MemoryInstance::new_lazy(
                mem,
                &self.engine.config().memory_backend,
            )?);
        }
        Ok(start..start + memories.len() as MemAddr)
    }

    /// Add globals to the store, returning their addresses in the store
    pub(crate) fn init_globals(
        &mut self,
        out: &mut Vec<Addr>,
        new_globals: &[Global],
        func_addrs: &[FuncAddr],
    ) -> Result<()> {
        let start = self.state.globals.len() as Addr;
        out.reserve_exact(new_globals.len());
        self.state.globals.reserve_exact(new_globals.len());

        for (i, global) in new_globals.iter().enumerate() {
            let value = match self.eval_const(&global.init, out, func_addrs) {
                Ok(val) => val,
                Err(e) => {
                    cold_path();
                    return Err(e);
                }
            };

            self.state
                .globals
                .push(GlobalInstance::new(global.ty, value));
            out.push(start + i as Addr);
        }

        Ok(())
    }

    fn elem_addr(
        &self,
        item: &ElementItem,
        globals: &[Addr],
        funcs: &[FuncAddr],
    ) -> Result<Option<u32>> {
        let res = match item {
            ElementItem::Func(addr) => match funcs.get(*addr as usize) {
                Some(func_addr) => Some(*func_addr),
                None => {
                    cold_path();
                    return Err(Error::Other(format!(
                        "function {addr} not found. This should have been caught by the validator"
                    )));
                }
            },
            ElementItem::Expr(expr) => self.eval_ref_const(expr, globals, funcs)?,
        };

        Ok(res)
    }

    /// Add elements to the store, returning their addresses in the store
    /// Should be called after the tables have been added
    ///
    /// Every segment is allocated before any active segment runs, as the
    /// WebAssembly 2.0 instantiation order requires: a trap in an active
    /// segment still leaves the module a complete segment table, so a function
    /// an earlier segment already put in an imported table can use any of its
    /// segments without reaching a missing one.
    pub(crate) fn init_elements(
        &mut self,
        table_addrs: &[TableAddr],
        func_addrs: &[FuncAddr],
        global_addrs: &[Addr],
        elements: &[Element],
    ) -> Result<(Box<[Addr]>, Option<Trap>)> {
        let elem_count = self.state.elements.len();
        let mut elem_addrs = Vec::with_capacity(elements.len());
        for (i, element) in elements.iter().enumerate() {
            let init = element
                .items
                .iter()
                .map(|item| {
                    Ok(TableElement::from(self.elem_addr(
                        item,
                        global_addrs,
                        func_addrs,
                    )?))
                })
                .collect::<Result<Vec<_>>>()?;

            let items = match &element.kind {
                // Declared segments only declare references: dropped at once.
                ElementKind::Declared => None,
                // Passive segments wait for `table.init`; active ones run below
                // and are dropped once they have.
                ElementKind::Passive | ElementKind::Active { .. } => Some(init),
            };
            self.state
                .elements
                .push(ElementInstance::new(element.kind.clone(), items));
            elem_addrs.push((i + elem_count) as Addr);
        }

        for (i, element) in elements.iter().enumerate() {
            let ElementKind::Active { offset, table } = &element.kind else {
                continue;
            };
            let offset = self.eval_size_const(offset, global_addrs, func_addrs)?;
            let table_addr = table_addrs.get(*table as usize).copied().ok_or_else(|| {
                Error::Other(format!("table {table} not found for element {i}"))
            })?;
            let elem_addr = elem_count + i;
            let init = self.state.elements[elem_addr].items.take().unwrap_or_default();

            let Some(table) = self.state.tables.get_mut(table_addr as usize) else {
                return Err(Error::Other(format!("table {table} not found for element {i}")));
            };

            // In wasm 2.0, it's possible to call a function that hasn't been instantiated yet,
            // when using a partially initialized active element segments.
            // This isn't mentioned in the spec, but the "unofficial" testsuite has a test for it:
            // https://github.com/WebAssembly/testsuite/blob/5a1a590603d81f40ef471abba70a90a9ae5f4627/linking.wast#L264-L276
            if let Err(trap) = table.init(offset, &init) {
                return Ok((elem_addrs.into_boxed_slice(), Some(trap)));
            }
            // The segment ran: it is dropped (`elem.drop i`), as `take` left it.
        }

        Ok((elem_addrs.into_boxed_slice(), None))
    }

    /// Add data to the store, returning their addresses in the store
    ///
    /// Every segment is allocated first; active segments are then written in
    /// order only when `run_active` is set (it is not after an element segment
    /// trapped), so the module's data table is always complete.
    pub(crate) fn init_data(
        &mut self,
        mem_addrs: &[MemAddr],
        global_addrs: &[Addr],
        func_addrs: &[FuncAddr],
        data: &[Data],
        run_active: bool,
    ) -> Result<(Box<[Addr]>, Option<Trap>)> {
        let data_count = self.state.data.len();
        let mut data_addrs = Vec::with_capacity(data.len());
        for (i, segment) in data.iter().enumerate() {
            self.state.data.push(DataInstance::new(Some(segment.data.to_vec())));
            data_addrs.push((i + data_count) as Addr);
        }
        if !run_active {
            return Ok((data_addrs.into_boxed_slice(), None));
        }

        for (i, segment) in data.iter().enumerate() {
            let crate::wasm::types::DataKind::Active {
                mem: mem_addr,
                offset,
            } = &segment.kind
            else {
                continue;
            };
            let Some(mem_addr) = mem_addrs.get(*mem_addr as usize) else {
                return Err(Error::Other(format!(
                    "memory {mem_addr} not found for data segment {i}"
                )));
            };

            let offset = self.eval_size_const(offset, global_addrs, func_addrs)?;
            let Some(mem) = self.state.memories.get_mut(*mem_addr as usize) else {
                return Err(Error::Other(format!(
                    "memory {mem_addr} not found for data segment {i}"
                )));
            };

            if mem.inner.write_all(offset as usize, &segment.data).is_none() {
                return Ok((
                    data_addrs.into_boxed_slice(),
                    Some(crate::wasm::rt::Trap::MemoryOutOfBounds {
                        offset: offset as usize,
                        len: segment.data.len(),
                        max: mem.inner.len(),
                    }),
                ));
            }
            // The segment ran: drop it (`data.drop i`).
            self.state.data[data_count + i].drop();
        }

        Ok((data_addrs.into_boxed_slice(), None))
    }

    pub(crate) fn add_func(&mut self, func: FunctionInstance) -> FuncAddr {
        self.state.funcs.push(func);
        self.state.funcs.len() as FuncAddr - 1
    }

    /// Evaluate a constant expression that's either a i32 or a i64 as a global or a const instruction
    fn eval_size_const(
        &self,
        const_instrs: &[crate::wasm::types::ConstInstruction],
        module_global_addrs: &[Addr],
        module_func_addrs: &[FuncAddr],
    ) -> Result<i64> {
        let value = self.eval_const(const_instrs, module_global_addrs, module_func_addrs)?;
        match value {
            TinyWasmValue::Value32(i) => Ok(i64::from(i)),
            TinyWasmValue::Value64(i) => Ok(i as i64),
            other => Err(Error::Other(format!("expected i32 or i64, got {other:?}"))),
        }
    }

    /// Evaluate a constant expression
    fn eval_const(
        &self,
        const_instrs: &[crate::wasm::types::ConstInstruction],
        module_global_addrs: &[Addr],
        module_func_addrs: &[FuncAddr],
    ) -> Result<TinyWasmValue> {
        use crate::wasm::types::ConstInstruction::{I32Const, I64Const, F32Const, F64Const, V128Const, GlobalGet, RefFunc, RefExtern, I32Add, I32Sub, I32Mul, I64Add, I64Sub, I64Mul};

        let resolve_global = |idx: u32| -> Result<TinyWasmValue> {
            let Some(addr) = module_global_addrs.get(idx as usize) else {
                cold_path();
                return Err(Error::Other(format!(
                    "global {idx} not found. This should have been caught by the validator"
                )));
            };

            let Some(global) = self.state.globals.get(*addr as usize) else {
                cold_path();
                return Err(Error::Other(format!("global {addr} not found")));
            };

            Ok(global.value.get())
        };

        let resolve_func = |idx: u32| -> Result<u32> {
            match module_func_addrs.get(idx as usize).copied() {
                Some(func_addr) => Ok(func_addr),
                None => {
                    cold_path();
                    Err(Error::Other(format!(
                        "function {idx} not found. This should have been caught by the validator"
                    )))
                }
            }
        };

        if const_instrs.len() == 1 {
            let val = match &const_instrs[0] {
                F32Const(f) => (*f).into(),
                F64Const(f) => (*f).into(),
                I32Const(i) => (*i).into(),
                I64Const(i) => (*i).into(),
                V128Const(i) => (*i).into(),
                GlobalGet(addr) => resolve_global(*addr)?,
                RefFunc(None) => TinyWasmValue::ValueRef(ValueRef::NULL),
                RefExtern(None) => TinyWasmValue::ValueRef(ValueRef::NULL),
                RefFunc(Some(idx)) => {
                    TinyWasmValue::ValueRef(ValueRef::from_addr(Some(resolve_func(*idx)?)))
                }
                _ => {
                    cold_path();
                    return Err(Error::other("unsupported const instruction"));
                }
            };

            return Ok(val);
        }

        let mut stack = Vec::with_capacity(const_instrs.len());
        for instr in const_instrs {
            match instr {
                I32Const(i) => stack.push(TinyWasmValue::Value32(*i as u32)),
                I64Const(i) => stack.push(TinyWasmValue::Value64(*i as u64)),
                F32Const(f) => stack.push(TinyWasmValue::Value32(f.to_bits())),
                F64Const(f) => stack.push(TinyWasmValue::Value64(f.to_bits())),
                V128Const(i) => stack.push(TinyWasmValue::Value128((*i).into())),
                GlobalGet(addr) => stack.push(resolve_global(*addr)?),
                RefFunc(None) | RefExtern(None) => {
                    stack.push(TinyWasmValue::ValueRef(ValueRef::NULL))
                }
                RefFunc(Some(idx)) => stack.push(TinyWasmValue::ValueRef(ValueRef::from_addr(
                    Some(resolve_func(*idx)?),
                ))),
                RefExtern(Some(_)) => {
                    cold_path();
                    return Err(Error::other(
                        "ref.extern constants are not supported in init expressions",
                    ));
                }
                I32Add | I32Sub | I32Mul => {
                    let rhs = stack
                        .pop()
                        .ok_or_else(|| Error::other("const stack underflow"))?;
                    let lhs = stack
                        .pop()
                        .ok_or_else(|| Error::other("const stack underflow"))?;
                    let (TinyWasmValue::Value32(lhs), TinyWasmValue::Value32(rhs)) = (lhs, rhs)
                    else {
                        cold_path();
                        return Err(Error::other("type mismatch in const i32 op"));
                    };
                    let lhs = lhs as i32;
                    let rhs = rhs as i32;
                    let out = match instr {
                        I32Add => lhs.wrapping_add(rhs),
                        I32Sub => lhs.wrapping_sub(rhs),
                        I32Mul => lhs.wrapping_mul(rhs),
                        _ => unreachable!("invalid const instruction in i32 op"),
                    };
                    stack.push(TinyWasmValue::Value32(out as u32));
                }
                I64Add | I64Sub | I64Mul => {
                    let rhs = stack.pop();
                    let lhs = stack.pop();
                    let (Some(TinyWasmValue::Value64(lhs)), Some(TinyWasmValue::Value64(rhs))) =
                        (lhs, rhs)
                    else {
                        cold_path();
                        return Err(Error::other("type mismatch in const i64 op"));
                    };

                    let lhs = lhs as i64;
                    let rhs = rhs as i64;
                    let out = match instr {
                        I64Add => lhs.wrapping_add(rhs),
                        I64Sub => lhs.wrapping_sub(rhs),
                        I64Mul => lhs.wrapping_mul(rhs),
                        _ => {
                            cold_path();
                            unreachable!("invalid const instruction in i64 op")
                        }
                    };
                    stack.push(TinyWasmValue::Value64(out as u64));
                }
            }
        }

        let Some(value) = stack.pop() else {
            cold_path();
            return Err(Error::other("empty const expression"));
        };

        if !stack.is_empty() {
            cold_path();
            return Err(Error::other(
                "const expression did not reduce to single value",
            ));
        }
        Ok(value)
    }

    fn eval_ref_const(
        &self,
        const_instrs: &[crate::wasm::types::ConstInstruction],
        module_global_addrs: &[Addr],
        module_func_addrs: &[FuncAddr],
    ) -> Result<Option<u32>> {
        let value = self.eval_const(const_instrs, module_global_addrs, module_func_addrs)?;
        match value {
            TinyWasmValue::ValueRef(v) => Ok(v.addr()),
            other => Err(Error::Other(format!(
                "expected reference const value, got {other:?}"
            ))),
        }
    }
}
