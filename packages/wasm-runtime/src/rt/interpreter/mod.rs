pub(crate) mod executor;
pub(crate) mod num_helpers;
pub(crate) mod simd;
pub(crate) mod stack;
pub(crate) mod values;

use crate::wasm::rt::{interpreter::stack::CallFrame, Result, Store, Trap};
pub(crate) use self::simd::{Value128};
pub(crate) use self::values::{InternalValue, TinyWasmValue, Value32, Value64, ValueRef};

#[derive(Clone)]
#[derive(Debug)]
pub(crate) enum ExecState {
    Completed,
    Suspended(CallFrame),
}

/// The main `TinyWasm` runtime.
///
/// This is the default runtime used by `TinyWasm`.
#[derive(Default)]
#[derive(Debug)]
pub(crate) struct InterpreterRuntime;

impl InterpreterRuntime {
    pub(crate) fn exec(store: &mut Store, cf: CallFrame, call_stack_base: u32) -> Result<(), Trap> {
        executor::Executor::<false>::new(store, cf, call_stack_base).run_to_completion()
    }

    /// Run a nested call under the budget of the invocation being resumed:
    /// it spends that invocation's fuel, or stops at its deadline, and traps
    /// rather than run past it (a nested call cannot suspend).
    pub(crate) fn exec_nested(store: &mut Store, cf: CallFrame, call_stack_base: u32) -> Result<(), Trap> {
        match store.nested_budget.clone() {
            crate::wasm::rt::store::NestedBudget::Unbounded => Self::exec(store, cf, call_stack_base),
            crate::wasm::rt::store::NestedBudget::Fuel => {
                executor::Executor::<true>::new(store, cf, call_stack_base).run_nested_with_fuel()
            }
            crate::wasm::rt::store::NestedBudget::Deadline { clock, deadline_ms } => {
                executor::Executor::<false>::new(store, cf, call_stack_base).run_nested_until(&clock, deadline_ms)
            }
        }
    }

    pub(crate) fn exec_with_fuel(
        store: &mut Store,
        cf: CallFrame,
        fuel: u32,
    ) -> Result<ExecState, Trap> {
        executor::Executor::<true>::new(store, cf, 0).run_with_fuel(fuel)
    }

    pub(crate) fn exec_with_time_budget(
        store: &mut Store,
        cf: CallFrame,
        time_budget: core::time::Duration,
        clock: &ferrite_app::Clock,
    ) -> Result<ExecState, Trap> {
        executor::Executor::<false>::new(store, cf, 0).run_with_time_budget(time_budget, clock)
    }
}
