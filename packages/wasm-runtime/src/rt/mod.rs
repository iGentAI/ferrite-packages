//! `tinywasm` provides a small, portable WebAssembly interpreter with support for
//! the WebAssembly MVP, WebAssembly 2.0, and a growing set of newer proposals.
//! It is designed to stay lightweight while still being practical to embed in
//! applications and tools.
//!
//! ## Configuration
//! Upstream tinywasm gates parts of itself behind cargo features (`std`,
//! `canonicalize-nans`, `debug` and others). This vendored tree has one
//! configuration and declares no features: it uses `std` (a memory cursor is a
//! `std::io` reader, writer and seeker, an [`Error`] converts into a
//! `std::io::Error`, and the time budget is a `std::time::Duration` read
//! against a `ferrite_app::Clock`), always canonicalizes NaNs, which the
//! consumers' replay contract relies on, and always derives `Debug`.
//!
//! For non-default runtime behavior, construct a [`Store`] with a custom [`Engine`]
//! and [`engine::Config`] to control stack sizing, fuel accounting, memory backends,
//! and trap-on-OOM behavior.
//!
//! ## Imports
//!
//! To provide imports to a module, you can use the [`Imports`] struct.
//! This struct allows you to register custom functions, globals, memories, tables,
//! and other modules to be linked into the module when it is instantiated.
//!
//! See the [`Imports`] documentation for more information.

extern crate alloc;

// Logging is compiled out in this vendored build: the no-op `log` shim and
// its call sites are removed outright (the code gate refuses app-defined
// macros, and the shim expanded to nothing).
//
// FERRITE PATCH: upstream's `parser` feature (re-exporting
// tinywasm_parser's error type) and `guest-debug` feature (the `*_by_index`
// inspection APIs) are removed as well. A Ferrite app cannot depend on
// tinywasm_parser and no consumer declares `guest-debug`, so neither could be
// compiled in; the gated code only drew unexpected-cfg warnings.

mod error;
pub use self::error::{Error, HOST_YIELD, LinkingError, Result, Trap};
pub use func::{
    ExecProgress, FuncContext, FuncExecution, FuncExecutionTyped, Function, FunctionTyped,
    HostFunction, ToWasmTypes, WasmTupleChain,
};
pub use self::imports::{Extern, ExternName, Imports};
pub use instance::{ExternItem, ModuleInstance};
pub use self::reference::{Global, Memory, MemoryCursor, Table};
pub(crate) use self::reference::{StoreItem};
pub use self::store::{Store, StoreSnapshot};
pub(crate) use self::store::{FunctionInstance, MemValue, MemoryInstance, TableElement, WasmFunctionInstance};

mod func;
mod imports;
mod instance;
mod reference;
mod store;

mod interpreter;
use interpreter::InterpreterRuntime;

pub mod engine;
pub use engine::{
    Engine, LazyLinearMemory, LinearMemory, MemoryBackend, PagedMemory, StackConfig, VecMemory,
};

pub mod types {
    pub use crate::wasm::types::*;
}

pub use crate::wasm::types::Module;

pub(crate) fn unlikely(b: bool) -> bool {
    if b {
        crate::wasm::compat::cold_path();
    };
    b
}
