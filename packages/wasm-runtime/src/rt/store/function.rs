use crate::wasm::types::{FuncType, ModuleInstanceAddr, WasmFunction};
use alloc::sync::Arc;

use crate::wasm::rt::func::HostFunction;

/// A WebAssembly Function Instance
///
/// See <https://webassembly.github.io/spec/core/exec/runtime.html#function-instances>
#[derive(Clone)]
#[derive(Debug)]
pub(crate) enum FunctionInstance {
    /// A host function
    Host(Arc<HostFunction>),

    /// A pointer to a WebAssembly function
    Wasm(WasmFunctionInstance),
}

impl FunctionInstance {
    #[inline]
    pub(crate) fn ty(&self) -> &Arc<FuncType> {
        match self {
            Self::Host(f) => &f.ty,
            Self::Wasm(f) => f.ty(),
        }
    }

    pub(crate) fn new_wasm(func: Arc<WasmFunction>, owner: ModuleInstanceAddr) -> Self {
        Self::Wasm(WasmFunctionInstance { func, owner })
    }
}

#[derive(Clone)]
#[derive(Debug)]
pub(crate) struct WasmFunctionInstance {
    pub(crate) func: Arc<WasmFunction>,
    pub(crate) owner: ModuleInstanceAddr,
}

impl WasmFunctionInstance {
    #[inline]
    pub(crate) fn ty(&self) -> &Arc<FuncType> {
        &self.func.ty
    }
}
