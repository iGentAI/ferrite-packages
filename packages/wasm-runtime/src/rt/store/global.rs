use crate::wasm::rt::interpreter::TinyWasmValue;
use crate::wasm::types::GlobalType;
use core::cell::Cell;

/// A WebAssembly Global Instance
///
/// See <https://webassembly.github.io/spec/core/exec/runtime.html#global-instances>
#[derive(Debug)]
pub(crate) struct GlobalInstance {
    pub(crate) value: Cell<TinyWasmValue>,
    pub(crate) ty: GlobalType,
}

impl GlobalInstance {
    pub(crate) fn new(ty: GlobalType, value: TinyWasmValue) -> Self {
        Self {
            ty,
            value: value.into(),
        }
    }
}
