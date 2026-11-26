use crate::wasm::compat::cold_path;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::wasm::rt::{Function, Global, LinkingError, Memory, Result, Table};
use crate::wasm::types::{ExternVal, FuncAddr, GlobalAddr, Import, ImportKind, MemAddr, MemoryType, Module, TableAddr, TableType};

#[derive(Clone)]
#[derive(Debug)]
#[non_exhaustive]
/// An external import value.
pub enum Extern {
    /// A global instance.
    Global(Global),
    /// A table instance.
    Table(Table),
    /// A memory instance.
    Memory(Memory),
    /// A function import.
    Function(Function),
}

impl From<Global> for Extern {
    fn from(value: Global) -> Self {
        Self::Global(value)
    }
}

impl From<Table> for Extern {
    fn from(value: Table) -> Self {
        Self::Table(value)
    }
}

impl From<Memory> for Extern {
    fn from(value: Memory) -> Self {
        Self::Memory(value)
    }
}

impl From<Function> for Extern {
    fn from(value: Function) -> Self {
        Self::Function(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
/// Name of an import
pub struct ExternName {
    module: String,
    name: String,
}

impl From<&Import> for ExternName {
    fn from(import: &Import) -> Self {
        Self {
            module: import.module.to_string(),
            name: import.name.to_string(),
        }
    }
}

/// Imports for a module instance
///
/// This is used to link a module instance to its imports.
/// Pass it to [`crate::wasm::rt::ModuleInstance::instantiate`].
#[derive(Default, Clone)]
#[derive(Debug)]
pub struct Imports {
    externs: BTreeMap<ExternName, Extern>,
    modules: BTreeMap<String, crate::wasm::rt::ModuleInstance>,
}

pub(crate) struct ResolvedImports {
    pub(crate) globals: Vec<GlobalAddr>,
    pub(crate) tables: Vec<TableAddr>,
    pub(crate) memories: Vec<MemAddr>,
    pub(crate) funcs: Vec<FuncAddr>,
}

impl Imports {
    /// Create a new empty import set
    pub const fn new() -> Self {
        Self {
            externs: BTreeMap::new(),
            modules: BTreeMap::new(),
        }
    }

    /// Merge two import sets
    pub fn merge(mut self, other: Self) -> Self {
        self.externs.extend(other.externs);
        self.modules.extend(other.modules);
        self
    }

    /// Link a module
    ///
    /// This will automatically link all imported values on instantiation
    pub fn link_module(
        &mut self,
        name: &str,
        instance: crate::wasm::rt::ModuleInstance,
    ) -> Result<&mut Self> {
        self.modules.insert(name.to_string(), instance);
        Ok(self)
    }

    /// Define an import value.
    pub fn define(&mut self, module: &str, name: &str, value: impl Into<Extern>) -> &mut Self {
        let name = ExternName {
            module: module.to_string(),
            name: name.to_string(),
        };
        self.externs.insert(name, value.into());
        self
    }

    pub(crate) fn take_defined(&self, import: &Import) -> Option<Extern> {
        let name = ExternName::from(import);
        self.externs.get(&name).cloned()
    }


    fn compare_types<T: PartialEq + core::fmt::Debug>(
        import: &Import,
        actual: &T,
        expected: &T,
    ) -> Result<()> {
        if expected != actual {
            cold_path();
            return Err(LinkingError::incompatible_import_type(import).into());
        }
        Ok(())
    }

    fn compare_table_types(
        import: &Import,
        expected: &TableType,
        actual: &TableType,
    ) -> Result<()> {
        Self::compare_types(import, &actual.element_type, &expected.element_type)?;
        if actual.size_initial > expected.size_initial {
            cold_path();
            return Err(LinkingError::incompatible_import_type(import).into());
        }

        match (expected.size_max, actual.size_max) {
            (None, Some(_)) => {
                cold_path();
                Err(LinkingError::incompatible_import_type(import).into())
            }
            (Some(expected_max), Some(actual_max)) if actual_max < expected_max => {
                cold_path();
                Err(LinkingError::incompatible_import_type(import).into())
            }
            _ => Ok(()),
        }
    }

    fn compare_memory_types(
        import: &Import,
        expected: &MemoryType,
        actual: &MemoryType,
        real_size: usize,
    ) -> Result<()> {
        Self::compare_types(import, &expected.arch(), &actual.arch())?;

        if actual.page_count_initial() > expected.page_count_initial()
            && actual.page_count_initial() > real_size as u64
        {
            return Err(LinkingError::incompatible_import_type(import).into());
        }

        if expected.page_size() != actual.page_size() {
            return Err(LinkingError::incompatible_import_type(import).into());
        }

        // `expected` is the memory provided, `actual` the import's declaration.
        // An import that declares a maximum needs a provided memory with one no
        // larger; an unbounded memory never satisfies it, whatever the default
        // ceiling `page_count_max()` would report for it.
        match (expected.declared_page_count_max(), actual.declared_page_count_max()) {
            (None, Some(_)) => {
                cold_path();
                Err(LinkingError::incompatible_import_type(import).into())
            }
            (Some(provided_max), Some(import_max)) if provided_max > import_max => {
                cold_path();
                Err(LinkingError::incompatible_import_type(import).into())
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn link(
        &self,
        store: &mut crate::wasm::rt::Store,
        module: &Module,
    ) -> Result<ResolvedImports> {
        let (global_count, table_count, mem_count, func_count) =
            module
                .imports
                .iter()
                .fold((0, 0, 0, 0), |(g, t, m, f), import| match import.kind {
                    ImportKind::Global(_) => (g + 1, t, m, f),
                    ImportKind::Table(_) => (g, t + 1, m, f),
                    ImportKind::Memory(_) => (g, t, m + 1, f),
                    ImportKind::Function(_) => (g, t, m, f + 1),
                });

        let mut imports = ResolvedImports {
            globals: Vec::with_capacity(global_count + module.globals.len()),
            tables: Vec::with_capacity(table_count + module.table_types.len()),
            memories: Vec::with_capacity(mem_count + module.memory_types.len()),
            funcs: Vec::with_capacity(func_count + module.funcs.len()),
        };

        for import in &*module.imports {
            if let Some(defined) = self.take_defined(import) {
                match defined {
                    Extern::Global(global) => {
                        let ImportKind::Global(import_ty) = &import.kind else {
                            cold_path();
                            return Err(LinkingError::incompatible_import_type(import).into());
                        };
                        global.0.validate_store(store)?;
                        let global_instance = store.state.get_global(global.0.addr);
                        Self::compare_types(import, &global_instance.ty, import_ty)?;
                        imports.globals.push(global.0.addr);
                    }
                    Extern::Table(table) => {
                        let ImportKind::Table(import_ty) = &import.kind else {
                            cold_path();
                            return Err(LinkingError::incompatible_import_type(import).into());
                        };
                        table.0.validate_store(store)?;
                        let table_instance = store.state.get_table(table.0.addr);
                        let mut kind = table_instance.kind.clone();
                        kind.size_initial = table_instance.size() as u32;
                        Self::compare_table_types(import, &kind, import_ty)?;
                        imports.tables.push(table.0.addr);
                    }
                    Extern::Memory(memory) => {
                        let ImportKind::Memory(import_ty) = &import.kind else {
                            cold_path();
                            return Err(LinkingError::incompatible_import_type(import).into());
                        };
                        memory.0.validate_store(store)?;
                        let mem = store.state.get_mem(memory.0.addr);
                        Self::compare_memory_types(import, &mem.kind, import_ty, mem.page_count)?;
                        imports.memories.push(memory.0.addr);
                    }
                    Extern::Function(func_handle) => {
                        let ImportKind::Function(ty) = &import.kind else {
                            cold_path();
                            return Err(LinkingError::incompatible_import_type(import).into());
                        };
                        let import_func_type = module
                            .func_types
                            .get(*ty as usize)
                            .ok_or_else(|| LinkingError::incompatible_import_type(import))?;
                        func_handle.item.validate_store(store)?;
                        Self::compare_types(import, &func_handle.ty, import_func_type)?;
                        imports.funcs.push(func_handle.addr);
                    }
                }
                continue;
            }

            let name = ExternName::from(import);
            let Some(instance) = self.modules.get(&name.module) else {
                cold_path();
                return Err(LinkingError::unknown_import(import).into());
            };
            instance.validate_store(store)?;

            let val = instance
                .export_addr(&import.name)
                .ok_or_else(|| LinkingError::unknown_import(import))?;

            if val.kind() != (&import.kind).into() {
                cold_path();
                return Err(LinkingError::incompatible_import_type(import).into());
            }

            match (val, &import.kind) {
                (ExternVal::Global(global_addr), ImportKind::Global(ty)) => {
                    let global = store.state.get_global(global_addr);
                    Self::compare_types(import, &global.ty, ty)?;
                    imports.globals.push(global_addr);
                }
                (ExternVal::Table(table_addr), ImportKind::Table(ty)) => {
                    let table = store.state.get_table(table_addr);
                    let mut kind = table.kind.clone();
                    kind.size_initial = table.size() as u32;
                    Self::compare_table_types(import, &kind, ty)?;
                    imports.tables.push(table_addr);
                }
                (ExternVal::Memory(memory_addr), ImportKind::Memory(ty)) => {
                    let mem = store.state.get_mem(memory_addr);
                    Self::compare_memory_types(import, &mem.kind, ty, mem.page_count)?;
                    imports.memories.push(memory_addr);
                }
                (ExternVal::Func(func_addr), ImportKind::Function(ty)) => {
                    let func = store.state.get_func(func_addr);
                    let import_func_type = module
                        .func_types
                        .get(*ty as usize)
                        .ok_or_else(|| LinkingError::incompatible_import_type(import))?;

                    Self::compare_types(import, func.ty(), import_func_type)?;
                    imports.funcs.push(func_addr);
                }
                _ => return Err(LinkingError::incompatible_import_type(import).into()),
            }
        }

        Ok(imports)
    }
}
