use crate::wasm::rt::interpreter::stack::{CallFrame, ValueStack};
use crate::wasm::rt::reference::StoreItem;
use crate::wasm::rt::{unlikely, Error, FunctionInstance, InterpreterRuntime, Result, Store};
use crate::wasm::types::{ExternRef, FuncRef, FuncType, ModuleInstanceAddr, WasmType, WasmValue};
use alloc::{boxed::Box, sync::Arc, vec::Vec};

impl Function {
    /// Call a function (Invocation)
    ///
    /// See <https://webassembly.github.io/spec/core/exec/modules.html#invocation>
    #[inline]
    pub fn call(&self, store: &mut Store, params: &[WasmValue]) -> Result<Vec<WasmValue>> {
        #[inline]
        fn call_inner(
            func: &Function,
            store: &mut Store,
            params: &[WasmValue],
        ) -> Result<Vec<WasmValue>> {
            let func_instance = store.state.get_func(func.addr);
            let wasm_func = match func_instance {
                FunctionInstance::Host(host_func) => {
                    return host_func.clone().call(
                        FuncContext {
                            store,
                            module_addr: func.module_addr,
                        },
                        params,
                    );
                }
                FunctionInstance::Wasm(wasm_func) => wasm_func,
            };

            store.call_stack.clear();
            store.value_stack.clear();
            store.value_stack.extend_from_wasmvalues(params)?;
            let locals_base = store
                .value_stack
                .enter_locals(&wasm_func.func.params, &wasm_func.func.locals)?;
            let callframe = CallFrame::new(func.addr, locals_base, wasm_func.func.locals);

            InterpreterRuntime::exec(store, callframe, 0)?;
            collect_call_results(&mut store.value_stack, &func.ty)
        }

        self.item.validate_store(store)?;
        validate_call_params(&self.ty, params)?;

        store.enter_execution()?;
        // A plain call has no fuel: `FuncContext::remaining_fuel` reads 0, not
        // whatever an earlier resumable call left behind.
        store.execution_fuel = 0;
        let result = call_inner(self, store, params);
        store.exit_execution();

        result
    }

    /// Call a function and return a resumable execution handle.
    ///
    /// The returned handle keeps a mutable borrow of the [`Store`] until it
    /// completes. Use [`FuncExecution::resume_with_fuel`] (or
    /// [`FuncExecution::resume_with_time_budget`]) to continue.
    pub fn call_resumable<'store>(
        &self,
        store: &'store mut Store,
        params: &[WasmValue],
    ) -> Result<FuncExecution<'store>> {
        #[inline]
        fn call_resumable_inner(
            func: &Function,
            store: &mut Store,
            params: &[WasmValue],
        ) -> Result<FuncExecutionState> {
            let func_instance = store.state.get_func(func.addr);
            match func_instance {
                // A host function runs when the execution is resumed, under that
                // resume's fuel or time budget, so it can yield like any call.
                FunctionInstance::Host(host_func) => Ok(FuncExecutionState::PendingHost {
                    func: host_func.clone(),
                    params: params.to_vec(),
                    module_addr: func.module_addr,
                }),
                FunctionInstance::Wasm(wasm_func) => {
                    store.call_stack.clear();
                    store.value_stack.clear();
                    store.value_stack.extend_from_wasmvalues(params)?;
                    let locals_base = store
                        .value_stack
                        .enter_locals(&wasm_func.func.params, &wasm_func.func.locals)?;
                    let callframe = CallFrame::new(func.addr, locals_base, wasm_func.func.locals);

                    Ok(FuncExecutionState::Running {
                        exec_state: ExecutionState { callframe },
                        root_func_addr: func.addr,
                    })
                }
            }
        }

        self.item.validate_store(store)?;
        validate_call_params(&self.ty, params)?;

        store.enter_execution()?;
        let result = call_resumable_inner(self, store, params);
        store.exit_execution();

        Ok(FuncExecution {
            store,
            state: result?,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
/// Progress for fuel-limited function execution.
pub enum ExecProgress<T> {
    /// Execution completed and produced a result.
    Completed(T),
    /// Execution suspended after exhausting fuel or time budget.
    Suspended,
}

#[derive(Clone)]
#[derive(Debug)]
pub(crate) struct ExecutionState {
    pub(crate) callframe: CallFrame,
}

/// A function handle
#[derive(Clone)]
#[derive(Debug)]
pub struct Function {
    pub(crate) item: StoreItem,
    pub(crate) module_addr: ModuleInstanceAddr,
    pub(crate) addr: u32,
    pub(crate) ty: Arc<FuncType>,
}

/// A typed function handle
#[derive(Debug)]
pub struct FunctionTyped<P, R> {
    /// The underlying function handle
    pub func: Function,
    pub(crate) marker: core::marker::PhantomData<(P, R)>,
}

/// A host function
pub struct HostFunction {
    pub(crate) ty: Arc<crate::wasm::types::FuncType>,
    pub(crate) func: HostFuncInner,
}

impl HostFunction {
    /// Get the function's type
    pub fn ty(&self) -> &Arc<crate::wasm::types::FuncType> {
        &self.ty
    }

    /// Call the function
    pub fn call(&self, ctx: FuncContext<'_>, args: &[WasmValue]) -> Result<Vec<WasmValue>> {
        (self.func)(ctx, args)
    }

    /// Create a new untyped host function import.
    pub fn from_untyped(
        store: &mut Store,
        ty: &FuncType,
        func: impl Fn(FuncContext<'_>, &[WasmValue]) -> Result<Vec<WasmValue>> + Send + Sync + 'static,
    ) -> Function {
        let ty = Arc::new(ty.clone());
        let host_ty = ty.clone();

        let inner_func =
            move |ctx: FuncContext<'_>, args: &[WasmValue]| -> Result<Vec<WasmValue>> {
                let result = func(ctx, args)?;
                let expected = host_ty.results();

                let valid = result.len() == expected.len()
                    && result
                        .iter()
                        .zip(expected)
                        .all(|(val, ty)| WasmType::from(val) == *ty);

                if !valid {
                    return Err(crate::wasm::rt::Error::InvalidHostFnReturn {
                        expected: Arc::clone(&host_ty),
                        actual: result,
                    });
                }

                Ok(result)
            };

        let addr = store.add_func(FunctionInstance::Host(Arc::new(Self {
            func: Box::new(inner_func),
            ty: ty.clone(),
        })));
        Function {
            item: crate::wasm::rt::StoreItem::new(store.id(), addr),
            module_addr: 0,
            addr,
            ty,
        }
    }

    /// Create a new typed host function import.
    pub fn from<P, R>(
        store: &mut Store,
        func: impl Fn(FuncContext<'_>, P) -> Result<R> + Send + Sync + 'static,
    ) -> Function
    where
        P: FromWasmValues + ToWasmTypes,
        R: IntoWasmValues + ToWasmTypes,
    {
        let inner_func =
            move |ctx: FuncContext<'_>, args: &[WasmValue]| -> Result<Vec<WasmValue>> {
                Ok(func(ctx, P::from_wasm_values(args)?)?.into_wasm_values())
            };

        let ty = Arc::new(crate::wasm::types::FuncType::new(
            &P::wasm_types(),
            &R::wasm_types(),
        ));
        let addr = store.add_func(FunctionInstance::Host(Arc::new(Self {
            func: Box::new(inner_func),
            ty: ty.clone(),
        })));
        Function {
            item: crate::wasm::rt::StoreItem::new(store.id(), addr),
            module_addr: 0,
            addr,
            ty,
        }
    }
}

// FERRITE PATCH: `+ Send + Sync` so `Arc<HostFunction>` is `Send` and a paged
// run can be held across an `await` (`FerriteApp::run` returns `impl Future + Send`).
pub(crate) type HostFuncInner =
    Box<dyn Fn(FuncContext<'_>, &[WasmValue]) -> Result<Vec<WasmValue>> + Send + Sync>;

/// The context of a host-function call
#[derive(Debug)]
pub struct FuncContext<'a> {
    pub(crate) store: &'a mut crate::wasm::rt::Store,
    pub(crate) module_addr: ModuleInstanceAddr,
}

impl FuncContext<'_> {
    /// Get the store.
    pub fn store(&self) -> &crate::wasm::rt::Store {
        self.store
    }

    /// Get mutable access to the store.
    pub fn store_mut(&mut self) -> &mut crate::wasm::rt::Store {
        self.store
    }

    /// Get the module instance.
    ///
    /// A host function called directly through its own handle, rather than
    /// from a module, has no module instance, and this returns an error.
    pub fn module(&self) -> Result<crate::wasm::rt::ModuleInstance> {
        self.store
            .get_module_instance(self.module_addr)
            .ok_or_else(|| Error::other("host function context has no module instance"))
    }

    /// Get a memory export.
    pub fn memory(&self, name: &str) -> Result<crate::wasm::rt::Memory> {
        self.module()?.memory(name)
    }

    /// Get any exported extern value by name.
    pub fn extern_item(&self, name: &str) -> Result<crate::wasm::rt::ExternItem> {
        self.module()?.extern_item(name)
    }

    /// Get a table export.
    pub fn table(&self, name: &str) -> Result<crate::wasm::rt::Table> {
        self.module()?.table(name)
    }

    /// Get the value of a global export.
    pub fn global_get(&self, name: &str) -> Result<WasmValue> {
        self.module()?.global_get(self.store, name)
    }

    /// Get a global export.
    pub fn global(&self, name: &str) -> Result<crate::wasm::rt::Global> {
        self.module()?.global(name)
    }

    /// Set the value of a mutable global export.
    pub fn global_set(&mut self, name: &str, value: WasmValue) -> Result<()> {
        self.module()?.global_set(self.store, name, value)
    }

    /// Charge additional fuel from the currently running resumable invocation.
    ///
    /// This is a no-op when the current invocation is not using fuel-based
    /// resumption.
    pub fn charge_fuel(&mut self, fuel: u32) {
        self.store.execution_fuel = self.store.execution_fuel.saturating_sub(fuel);
    }

    /// Get remaining fuel for the current invocation.
    ///
    /// Returns `0` when fuel-based resumption is not active.
    pub fn remaining_fuel(&self) -> u32 {
        self.store.execution_fuel
    }

    /// Call a function from within the current host-function invocation.
    ///
    /// This is the safe way for host functions to perform blocking reentrant
    /// calls into Wasm. Unlike [`Function::call`], it preserves the active
    /// invocation's stacks and resumes the host caller after the nested call
    /// completes.
    ///
    /// Nested calls are currently blocking only. If the surrounding invocation
    /// is resumed with fuel or a time budget, this method does not suspend and
    /// later continue the host function in the middle of the nested call.
    pub fn call_untyped(&mut self, func: &Function, args: &[WasmValue]) -> Result<Vec<WasmValue>> {
        if !self.store.execution_active {
            return Err(Error::other(
                "FuncContext::call requires an active host-function invocation",
            ));
        }

        func.item.validate_store(self.store)?;
        validate_call_params(&func.ty, args)?;

        let func_instance = self.store.state.get_func(func.addr).clone();
        match func_instance {
            // A host function handle carries no module of its own: it runs in
            // the context of the module whose host function is calling it.
            FunctionInstance::Host(host_func) => host_func.call(
                FuncContext {
                    store: &mut *self.store,
                    module_addr: self.module_addr,
                },
                args,
            ),
            FunctionInstance::Wasm(wasm_func) => {
                let call_stack_base = self.store.call_stack.len();
                let value_stack_base = self.store.value_stack.base();

                self.store
                    .value_stack
                    .extend_from_wasmvalues(args)
                    .inspect_err(|_| {
                        self.store.value_stack.truncate_to_base(value_stack_base);
                    })?;

                let locals_base = self
                    .store
                    .value_stack
                    .enter_locals(&wasm_func.func.params, &wasm_func.func.locals)
                    .inspect_err(|_| self.store.value_stack.truncate_to_base(value_stack_base))?;

                let callframe = CallFrame::new(func.addr, locals_base, wasm_func.func.locals);
                InterpreterRuntime::exec_nested(self.store, callframe, call_stack_base).inspect_err(
                    |_| {
                        self.store.call_stack.truncate_to(call_stack_base);
                        self.store.value_stack.truncate_to_base(value_stack_base);
                    },
                )?;

                collect_call_results(&mut self.store.value_stack, &func.ty)
            }
        }
    }

    /// Call a typed function from within the current host-function invocation.
    ///
    /// See [`Self::call_untyped`] for reentrancy and resumable-execution
    /// limitations.
    pub fn call<P, R>(&mut self, func: &FunctionTyped<P, R>, params: P) -> Result<R>
    where
        P: IntoWasmValues,
        R: FromWasmValues,
    {
        R::from_wasm_values(&self.call_untyped(&func.func, &params.into_wasm_values())?)
    }
}

impl core::ops::Deref for FuncContext<'_> {
    type Target = crate::wasm::rt::Store;

    fn deref(&self) -> &Self::Target {
        self.store
    }
}

impl core::ops::DerefMut for FuncContext<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.store
    }
}

impl<'a> FuncContext<'a> {
    /// Create a new host function context.
    pub const fn new(
        store: &'a mut crate::wasm::rt::Store,
        module_addr: ModuleInstanceAddr,
    ) -> Self {
        Self { store, module_addr }
    }
}

impl core::fmt::Debug for HostFunction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HostFunction")
            .field("ty", &self.ty)
            .field("func", &"...")
            .finish()
    }
}

/// Resumable execution for an untyped function call.
#[derive(Debug)]
pub struct FuncExecution<'store> {
    store: &'store mut Store,
    state: FuncExecutionState,
}

#[derive(Debug)]
enum FuncExecutionState {
    Running {
        exec_state: ExecutionState,
        root_func_addr: u32,
    },
    /// A host function invoked directly, run (again, after a yield) by the
    /// next resume.
    PendingHost {
        func: Arc<HostFunction>,
        params: Vec<WasmValue>,
        module_addr: ModuleInstanceAddr,
    },
    Completed {
        result: Option<Vec<WasmValue>>,
    },
}

/// Resumable execution for a typed function call.
#[derive(Debug)]
pub struct FuncExecutionTyped<'store, R> {
    execution: FuncExecution<'store>,
    marker: core::marker::PhantomData<R>,
}

impl<'store> FuncExecution<'store> {
    /// Fuel left from the allowance the last [`Self::resume_with_fuel`] was
    /// given. After a suspension that was not fuel exhaustion (a host-call
    /// yield), `allowance - remaining_fuel()` is what that resume consumed, so
    /// a driver that resumes after each yield can hold the whole invocation to
    /// one budget instead of granting a fresh allowance every time.
    pub fn remaining_fuel(&self) -> u32 {
        self.store.execution_fuel
    }

    /// Resume execution with up to `fuel` units of fuel.
    ///
    /// Fuel is accounted in chunks, so execution may overshoot the requested
    /// fuel before returning [`ExecProgress::Suspended`] (currently the chunk size is 128 instructions between fuel checks, but this may change in the future).
    ///
    /// Returns [`ExecProgress::Suspended`] when fuel is exhausted, or
    /// [`ExecProgress::Completed`] with the final values once the invocation
    /// returns.
    ///
    /// Reentrant calls made by host functions through [`FuncContext::call`] are
    /// currently blocking. They do not suspend and later resume the host
    /// function in the middle of the nested call.
    pub fn resume_with_fuel(&mut self, fuel: u32) -> Result<ExecProgress<Vec<WasmValue>>> {
        if matches!(self.state, FuncExecutionState::PendingHost { .. }) {
            return self.resume_host(|store| {
                store.execution_fuel = fuel;
                store.nested_budget = crate::wasm::rt::store::NestedBudget::Fuel;
            });
        }
        self.resume_with(|store, callframe| {
            store.nested_budget = crate::wasm::rt::store::NestedBudget::Fuel;
            let result = InterpreterRuntime::exec_with_fuel(store, callframe, fuel);
            store.nested_budget = crate::wasm::rt::store::NestedBudget::Unbounded;
            result
        })
    }

    /// Runs a pending host function under the budget `setup` installs. A
    /// `HOST_YIELD` suspends it, and the next resume runs it again.
    fn resume_host(
        &mut self,
        setup: impl FnOnce(&mut Store),
    ) -> Result<ExecProgress<Vec<WasmValue>>> {
        let FuncExecutionState::PendingHost {
            func,
            params,
            module_addr,
        } = &self.state
        else {
            unreachable!("resume_host needs a pending host function")
        };
        let (func, params, module_addr) = (Arc::clone(func), params.clone(), *module_addr);

        self.store.enter_execution()?;
        setup(self.store);
        let result = func.call(
            FuncContext {
                store: &mut *self.store,
                module_addr,
            },
            &params,
        );
        self.store.nested_budget = crate::wasm::rt::store::NestedBudget::Unbounded;
        self.store.exit_execution();

        match result {
            Err(Error::Other(ref message)) if message.as_str() == crate::wasm::rt::HOST_YIELD => {
                Ok(ExecProgress::Suspended)
            }
            Ok(values) => {
                self.state = FuncExecutionState::Completed { result: None };
                Ok(ExecProgress::Completed(values))
            }
            Err(err) => {
                self.state = FuncExecutionState::Completed { result: None };
                Err(err)
            }
        }
    }

    fn resume_with(
        &mut self,
        run: impl FnOnce(
            &mut Store,
            CallFrame,
        ) -> core::result::Result<crate::wasm::rt::interpreter::ExecState, crate::wasm::rt::Trap>,
    ) -> Result<ExecProgress<Vec<WasmValue>>> {
        let FuncExecutionState::Running {
            exec_state,
            root_func_addr,
        } = &mut self.state
        else {
            let FuncExecutionState::Completed { result } = &mut self.state else {
                unreachable!("invalid function execution state")
            };
            return match result.take() {
                Some(res) => Ok(ExecProgress::Completed(res)),
                None => Err(Error::other("execution already completed")),
            };
        };

        self.store.enter_execution()?;
        let result = run(self.store, exec_state.callframe);
        self.store.exit_execution();

        let result = match result {
            Ok(state) => state,
            Err(trap) => {
                // A trap leaves the stacks mid-call and the saved frame stale:
                // the invocation is over, and a later resume reports that
                // instead of re-entering the interpreter on that state.
                self.store.call_stack.clear();
                self.store.value_stack.clear();
                self.state = FuncExecutionState::Completed { result: None };
                return Err(trap.into());
            }
        };
        match result {
            crate::wasm::rt::interpreter::ExecState::Completed => {
                let result_ty = self.store.state.get_func(*root_func_addr).ty().clone();
                self.state = FuncExecutionState::Completed { result: None };
                Ok(ExecProgress::Completed(collect_call_results(
                    &mut self.store.value_stack,
                    &result_ty,
                )?))
            }
            crate::wasm::rt::interpreter::ExecState::Suspended(callframe) => {
                exec_state.callframe = callframe;
                Ok(ExecProgress::Suspended)
            }
        }
    }

    /// Resume execution for at most `time_budget` wall-clock time, as read from
    /// `clock` (the application's injected clock, `AppContext::clock`).
    ///
    /// Time is checked periodically, so execution may overshoot the requested
    /// time budget before returning [`ExecProgress::Suspended`] (currently time is checked every 128 instructions, but this may change in the future).
    ///
    /// Returns [`ExecProgress::Suspended`] when the budget is exhausted, or
    /// [`ExecProgress::Completed`] with the final values once the invocation
    /// returns.
    ///
    /// Reentrant calls made by host functions through [`FuncContext::call`] are
    /// currently blocking. They do not suspend and later resume the host
    /// function in the middle of the nested call.
    pub fn resume_with_time_budget(
        &mut self,
        time_budget: std::time::Duration,
        clock: &ferrite_app::Clock,
    ) -> Result<ExecProgress<Vec<WasmValue>>> {
        if matches!(self.state, FuncExecutionState::PendingHost { .. }) {
            let budget_ms = u64::try_from(time_budget.as_millis()).unwrap_or(u64::MAX);
            return self.resume_host(|store| {
                store.execution_fuel = 0;
                store.nested_budget = crate::wasm::rt::store::NestedBudget::Deadline {
                    clock: clock.clone(),
                    deadline_ms: clock.now_ms().saturating_add(budget_ms),
                };
            });
        }
        self.resume_with(|store, callframe| {
            let budget_ms = u64::try_from(time_budget.as_millis()).unwrap_or(u64::MAX);
            store.nested_budget = crate::wasm::rt::store::NestedBudget::Deadline {
                clock: clock.clone(),
                deadline_ms: clock.now_ms().saturating_add(budget_ms),
            };
            let result = InterpreterRuntime::exec_with_time_budget(store, callframe, time_budget, clock);
            store.nested_budget = crate::wasm::rt::store::NestedBudget::Unbounded;
            result
        })
    }
}

fn validate_call_params(func_ty: &FuncType, params: &[WasmValue]) -> Result<()> {
    if unlikely(func_ty.params().len() != params.len()) {
        return Err(Error::Other(format!(
            "param count mismatch: expected {}, got {}",
            func_ty.params().len(),
            params.len()
        )));
    }

    if !(func_ty
        .params()
        .iter()
        .zip(params)
        .all(|(ty, param)| ty == &param.into()))
    {
        return Err(Error::other("Type mismatch"));
    }

    Ok(())
}

fn collect_call_results(
    value_stack: &mut ValueStack,
    func_ty: &FuncType,
) -> Result<Vec<WasmValue>> {
    debug_assert!(value_stack.len() >= func_ty.results().len()); // m values are on the top of the stack (Ensured by validation)
    let mut res: Vec<_> = value_stack
        .pop_types(func_ty.results().iter().rev())
        .collect();
    res.reverse();
    Ok(res)
}

pub trait IntoWasmValues {
    fn into_wasm_values(self) -> Vec<WasmValue>;
}

pub trait FromWasmValues: Sized {
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self>;
}

impl<P: IntoWasmValues, R: FromWasmValues> FunctionTyped<P, R> {
    /// Call a typed function
    pub fn call(&self, store: &mut Store, params: P) -> Result<R> {
        let wasm_values = params.into_wasm_values();
        let result = self.func.call(store, &wasm_values)?;
        R::from_wasm_values(&result)
    }

    /// Call a typed function and return a resumable execution handle.
    ///
    /// The handle keeps a mutable borrow of the [`Store`] until completion.
    pub fn call_resumable<'store>(
        &self,
        store: &'store mut Store,
        params: P,
    ) -> Result<FuncExecutionTyped<'store, R>> {
        let wasm_values = params.into_wasm_values();
        let execution = self.func.call_resumable(store, &wasm_values)?;
        Ok(FuncExecutionTyped {
            execution,
            marker: core::marker::PhantomData,
        })
    }
}

impl<'store, R: FromWasmValues> FuncExecutionTyped<'store, R> {
    /// Fuel left from the last resume's allowance; see
    /// [`FuncExecution::remaining_fuel`].
    pub fn remaining_fuel(&self) -> u32 {
        self.execution.remaining_fuel()
    }

    /// Resume typed execution with up to `fuel` units of fuel.
    ///
    /// Fuel is accounted in chunks, so execution may overshoot the requested
    /// fuel before returning [`ExecProgress::Suspended`].
    pub fn resume_with_fuel(&mut self, fuel: u32) -> Result<ExecProgress<R>> {
        match self.execution.resume_with_fuel(fuel)? {
            ExecProgress::Completed(values) => {
                Ok(ExecProgress::Completed(R::from_wasm_values(&values)?))
            }
            ExecProgress::Suspended => Ok(ExecProgress::Suspended),
        }
    }

    /// Resume typed execution for at most `time_budget` wall-clock time, as
    /// read from `clock`.
    ///
    /// Time is checked periodically, so execution may overshoot the requested
    /// time budget before returning [`ExecProgress::Suspended`].
    pub fn resume_with_time_budget(
        &mut self,
        time_budget: std::time::Duration,
        clock: &ferrite_app::Clock,
    ) -> Result<ExecProgress<R>> {
        match self.execution.resume_with_time_budget(time_budget, clock)? {
            ExecProgress::Completed(values) => {
                Ok(ExecProgress::Completed(R::from_wasm_values(&values)?))
            }
            ExecProgress::Suspended => Ok(ExecProgress::Suspended),
        }
    }
}

/// Describes the WebAssembly value types produced by a Rust value or tuple shape.
pub trait ToWasmTypes {
    /// Return the flattened WebAssembly value types for this tuple shape.
    fn wasm_types() -> Box<[WasmType]>;
}

/// Describes the WebAssembly value types produced by a scalar Rust type.
pub trait ToWasmType {
    /// Return the single WebAssembly value type for this scalar type.
    fn wasm_type() -> WasmType;
}

/// Shared conversion for the scalar `FromWasmValues` impls below.
#[inline]
fn scalar_from_wasm_values<T>(values: &[WasmValue]) -> Result<T>
where
    T: TryFrom<WasmValue>,
    <T as TryFrom<WasmValue>>::Error: core::fmt::Debug,
{
    let value = *values
        .first()
        .ok_or(Error::other("Not enough elemennts in &[WasmValue]"))?;
    T::try_from(value).map_err(|e| {
        Error::Other(format!(
            "FromWasmValues: Could not convert WasmValue to expected type: {e:?}"
        ))
    })
}

/// Shared per-element conversion for the tuple `FromWasmValues` impls below.
#[inline]
fn tuple_next_value<T: TryFrom<WasmValue, Error = ()>>(
    iter: &mut core::slice::Iter<'_, WasmValue>,
) -> Result<T> {
    T::try_from(
        *iter
            .next()
            .ok_or(Error::other("Not enough values in WasmValue vector"))?,
    )
    .map_err(|e| {
        Error::Other(format!(
            "FromWasmValues: Could not convert WasmValue to expected type: {e:?}"
        ))
    })
}

// The scalar wasm-trait impls, written out per type (the code gate refuses
// app-defined macros).
impl ToWasmType for i32 {
    #[inline]
    fn wasm_type() -> WasmType {
        WasmType::I32
    }
}

impl ToWasmTypes for i32 {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([WasmType::I32])
    }
}

impl IntoWasmValues for i32 {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.into()]
    }
}

impl FromWasmValues for i32 {
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        scalar_from_wasm_values(values)
    }
}

impl ToWasmType for i64 {
    #[inline]
    fn wasm_type() -> WasmType {
        WasmType::I64
    }
}

impl ToWasmTypes for i64 {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([WasmType::I64])
    }
}

impl IntoWasmValues for i64 {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.into()]
    }
}

impl FromWasmValues for i64 {
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        scalar_from_wasm_values(values)
    }
}

impl ToWasmType for f32 {
    #[inline]
    fn wasm_type() -> WasmType {
        WasmType::F32
    }
}

impl ToWasmTypes for f32 {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([WasmType::F32])
    }
}

impl IntoWasmValues for f32 {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.into()]
    }
}

impl FromWasmValues for f32 {
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        scalar_from_wasm_values(values)
    }
}

impl ToWasmType for f64 {
    #[inline]
    fn wasm_type() -> WasmType {
        WasmType::F64
    }
}

impl ToWasmTypes for f64 {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([WasmType::F64])
    }
}

impl IntoWasmValues for f64 {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.into()]
    }
}

impl FromWasmValues for f64 {
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        scalar_from_wasm_values(values)
    }
}

impl ToWasmType for FuncRef {
    #[inline]
    fn wasm_type() -> WasmType {
        WasmType::RefFunc
    }
}

impl ToWasmTypes for FuncRef {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([WasmType::RefFunc])
    }
}

impl IntoWasmValues for FuncRef {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.into()]
    }
}

impl FromWasmValues for FuncRef {
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        scalar_from_wasm_values(values)
    }
}

impl ToWasmType for ExternRef {
    #[inline]
    fn wasm_type() -> WasmType {
        WasmType::RefExtern
    }
}

impl ToWasmTypes for ExternRef {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([WasmType::RefExtern])
    }
}

impl IntoWasmValues for ExternRef {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.into()]
    }
}

impl FromWasmValues for ExternRef {
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        scalar_from_wasm_values(values)
    }
}

// The tuple wasm-trait impls for arities 1..=12, written out per arity (the
// code gate refuses app-defined macros).
impl<T1: ToWasmType> ToWasmTypes for (T1,) {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([T1::wasm_type()])
    }
}

impl<T1: Into<WasmValue>> IntoWasmValues for (T1,) {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.0.into()]
    }
}

impl<T1: TryFrom<WasmValue, Error = ()>> FromWasmValues for (T1,) {
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((tuple_next_value(&mut iter)?,))
    }
}

impl<T1: ToWasmType, T2: ToWasmType> ToWasmTypes for (T1, T2) {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([T1::wasm_type(), T2::wasm_type()])
    }
}

impl<T1: Into<WasmValue>, T2: Into<WasmValue>> IntoWasmValues for (T1, T2) {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.0.into(), self.1.into()]
    }
}

impl<T1: TryFrom<WasmValue, Error = ()>, T2: TryFrom<WasmValue, Error = ()>> FromWasmValues
    for (T1, T2)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((tuple_next_value(&mut iter)?, tuple_next_value(&mut iter)?))
    }
}

impl<T1: ToWasmType, T2: ToWasmType, T3: ToWasmType> ToWasmTypes for (T1, T2, T3) {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([T1::wasm_type(), T2::wasm_type(), T3::wasm_type()])
    }
}

impl<T1: Into<WasmValue>, T2: Into<WasmValue>, T3: Into<WasmValue>> IntoWasmValues
    for (T1, T2, T3)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.0.into(), self.1.into(), self.2.into()]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

impl<T1: ToWasmType, T2: ToWasmType, T3: ToWasmType, T4: ToWasmType> ToWasmTypes
    for (T1, T2, T3, T4)
{
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([
            T1::wasm_type(),
            T2::wasm_type(),
            T3::wasm_type(),
            T4::wasm_type(),
        ])
    }
}

impl<T1: Into<WasmValue>, T2: Into<WasmValue>, T3: Into<WasmValue>, T4: Into<WasmValue>>
    IntoWasmValues for (T1, T2, T3, T4)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![self.0.into(), self.1.into(), self.2.into(), self.3.into()]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
        T4: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3, T4)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

impl<T1: ToWasmType, T2: ToWasmType, T3: ToWasmType, T4: ToWasmType, T5: ToWasmType> ToWasmTypes
    for (T1, T2, T3, T4, T5)
{
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([
            T1::wasm_type(),
            T2::wasm_type(),
            T3::wasm_type(),
            T4::wasm_type(),
            T5::wasm_type(),
        ])
    }
}

impl<
        T1: Into<WasmValue>,
        T2: Into<WasmValue>,
        T3: Into<WasmValue>,
        T4: Into<WasmValue>,
        T5: Into<WasmValue>,
    > IntoWasmValues for (T1, T2, T3, T4, T5)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![
            self.0.into(),
            self.1.into(),
            self.2.into(),
            self.3.into(),
            self.4.into(),
        ]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
        T4: TryFrom<WasmValue, Error = ()>,
        T5: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3, T4, T5)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

impl<
        T1: ToWasmType,
        T2: ToWasmType,
        T3: ToWasmType,
        T4: ToWasmType,
        T5: ToWasmType,
        T6: ToWasmType,
    > ToWasmTypes for (T1, T2, T3, T4, T5, T6)
{
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([
            T1::wasm_type(),
            T2::wasm_type(),
            T3::wasm_type(),
            T4::wasm_type(),
            T5::wasm_type(),
            T6::wasm_type(),
        ])
    }
}

impl<
        T1: Into<WasmValue>,
        T2: Into<WasmValue>,
        T3: Into<WasmValue>,
        T4: Into<WasmValue>,
        T5: Into<WasmValue>,
        T6: Into<WasmValue>,
    > IntoWasmValues for (T1, T2, T3, T4, T5, T6)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![
            self.0.into(),
            self.1.into(),
            self.2.into(),
            self.3.into(),
            self.4.into(),
            self.5.into(),
        ]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
        T4: TryFrom<WasmValue, Error = ()>,
        T5: TryFrom<WasmValue, Error = ()>,
        T6: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3, T4, T5, T6)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

impl<
        T1: ToWasmType,
        T2: ToWasmType,
        T3: ToWasmType,
        T4: ToWasmType,
        T5: ToWasmType,
        T6: ToWasmType,
        T7: ToWasmType,
    > ToWasmTypes for (T1, T2, T3, T4, T5, T6, T7)
{
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([
            T1::wasm_type(),
            T2::wasm_type(),
            T3::wasm_type(),
            T4::wasm_type(),
            T5::wasm_type(),
            T6::wasm_type(),
            T7::wasm_type(),
        ])
    }
}

impl<
        T1: Into<WasmValue>,
        T2: Into<WasmValue>,
        T3: Into<WasmValue>,
        T4: Into<WasmValue>,
        T5: Into<WasmValue>,
        T6: Into<WasmValue>,
        T7: Into<WasmValue>,
    > IntoWasmValues for (T1, T2, T3, T4, T5, T6, T7)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![
            self.0.into(),
            self.1.into(),
            self.2.into(),
            self.3.into(),
            self.4.into(),
            self.5.into(),
            self.6.into(),
        ]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
        T4: TryFrom<WasmValue, Error = ()>,
        T5: TryFrom<WasmValue, Error = ()>,
        T6: TryFrom<WasmValue, Error = ()>,
        T7: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3, T4, T5, T6, T7)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

impl<
        T1: ToWasmType,
        T2: ToWasmType,
        T3: ToWasmType,
        T4: ToWasmType,
        T5: ToWasmType,
        T6: ToWasmType,
        T7: ToWasmType,
        T8: ToWasmType,
    > ToWasmTypes for (T1, T2, T3, T4, T5, T6, T7, T8)
{
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([
            T1::wasm_type(),
            T2::wasm_type(),
            T3::wasm_type(),
            T4::wasm_type(),
            T5::wasm_type(),
            T6::wasm_type(),
            T7::wasm_type(),
            T8::wasm_type(),
        ])
    }
}

impl<
        T1: Into<WasmValue>,
        T2: Into<WasmValue>,
        T3: Into<WasmValue>,
        T4: Into<WasmValue>,
        T5: Into<WasmValue>,
        T6: Into<WasmValue>,
        T7: Into<WasmValue>,
        T8: Into<WasmValue>,
    > IntoWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![
            self.0.into(),
            self.1.into(),
            self.2.into(),
            self.3.into(),
            self.4.into(),
            self.5.into(),
            self.6.into(),
            self.7.into(),
        ]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
        T4: TryFrom<WasmValue, Error = ()>,
        T5: TryFrom<WasmValue, Error = ()>,
        T6: TryFrom<WasmValue, Error = ()>,
        T7: TryFrom<WasmValue, Error = ()>,
        T8: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

impl<
        T1: ToWasmType,
        T2: ToWasmType,
        T3: ToWasmType,
        T4: ToWasmType,
        T5: ToWasmType,
        T6: ToWasmType,
        T7: ToWasmType,
        T8: ToWasmType,
        T9: ToWasmType,
    > ToWasmTypes for (T1, T2, T3, T4, T5, T6, T7, T8, T9)
{
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([
            T1::wasm_type(),
            T2::wasm_type(),
            T3::wasm_type(),
            T4::wasm_type(),
            T5::wasm_type(),
            T6::wasm_type(),
            T7::wasm_type(),
            T8::wasm_type(),
            T9::wasm_type(),
        ])
    }
}

impl<
        T1: Into<WasmValue>,
        T2: Into<WasmValue>,
        T3: Into<WasmValue>,
        T4: Into<WasmValue>,
        T5: Into<WasmValue>,
        T6: Into<WasmValue>,
        T7: Into<WasmValue>,
        T8: Into<WasmValue>,
        T9: Into<WasmValue>,
    > IntoWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8, T9)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![
            self.0.into(),
            self.1.into(),
            self.2.into(),
            self.3.into(),
            self.4.into(),
            self.5.into(),
            self.6.into(),
            self.7.into(),
            self.8.into(),
        ]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
        T4: TryFrom<WasmValue, Error = ()>,
        T5: TryFrom<WasmValue, Error = ()>,
        T6: TryFrom<WasmValue, Error = ()>,
        T7: TryFrom<WasmValue, Error = ()>,
        T8: TryFrom<WasmValue, Error = ()>,
        T9: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8, T9)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

impl<
        T1: ToWasmType,
        T2: ToWasmType,
        T3: ToWasmType,
        T4: ToWasmType,
        T5: ToWasmType,
        T6: ToWasmType,
        T7: ToWasmType,
        T8: ToWasmType,
        T9: ToWasmType,
        T10: ToWasmType,
    > ToWasmTypes for (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)
{
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([
            T1::wasm_type(),
            T2::wasm_type(),
            T3::wasm_type(),
            T4::wasm_type(),
            T5::wasm_type(),
            T6::wasm_type(),
            T7::wasm_type(),
            T8::wasm_type(),
            T9::wasm_type(),
            T10::wasm_type(),
        ])
    }
}

impl<
        T1: Into<WasmValue>,
        T2: Into<WasmValue>,
        T3: Into<WasmValue>,
        T4: Into<WasmValue>,
        T5: Into<WasmValue>,
        T6: Into<WasmValue>,
        T7: Into<WasmValue>,
        T8: Into<WasmValue>,
        T9: Into<WasmValue>,
        T10: Into<WasmValue>,
    > IntoWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![
            self.0.into(),
            self.1.into(),
            self.2.into(),
            self.3.into(),
            self.4.into(),
            self.5.into(),
            self.6.into(),
            self.7.into(),
            self.8.into(),
            self.9.into(),
        ]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
        T4: TryFrom<WasmValue, Error = ()>,
        T5: TryFrom<WasmValue, Error = ()>,
        T6: TryFrom<WasmValue, Error = ()>,
        T7: TryFrom<WasmValue, Error = ()>,
        T8: TryFrom<WasmValue, Error = ()>,
        T9: TryFrom<WasmValue, Error = ()>,
        T10: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

impl<
        T1: ToWasmType,
        T2: ToWasmType,
        T3: ToWasmType,
        T4: ToWasmType,
        T5: ToWasmType,
        T6: ToWasmType,
        T7: ToWasmType,
        T8: ToWasmType,
        T9: ToWasmType,
        T10: ToWasmType,
        T11: ToWasmType,
    > ToWasmTypes for (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)
{
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([
            T1::wasm_type(),
            T2::wasm_type(),
            T3::wasm_type(),
            T4::wasm_type(),
            T5::wasm_type(),
            T6::wasm_type(),
            T7::wasm_type(),
            T8::wasm_type(),
            T9::wasm_type(),
            T10::wasm_type(),
            T11::wasm_type(),
        ])
    }
}

impl<
        T1: Into<WasmValue>,
        T2: Into<WasmValue>,
        T3: Into<WasmValue>,
        T4: Into<WasmValue>,
        T5: Into<WasmValue>,
        T6: Into<WasmValue>,
        T7: Into<WasmValue>,
        T8: Into<WasmValue>,
        T9: Into<WasmValue>,
        T10: Into<WasmValue>,
        T11: Into<WasmValue>,
    > IntoWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![
            self.0.into(),
            self.1.into(),
            self.2.into(),
            self.3.into(),
            self.4.into(),
            self.5.into(),
            self.6.into(),
            self.7.into(),
            self.8.into(),
            self.9.into(),
            self.10.into(),
        ]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
        T4: TryFrom<WasmValue, Error = ()>,
        T5: TryFrom<WasmValue, Error = ()>,
        T6: TryFrom<WasmValue, Error = ()>,
        T7: TryFrom<WasmValue, Error = ()>,
        T8: TryFrom<WasmValue, Error = ()>,
        T9: TryFrom<WasmValue, Error = ()>,
        T10: TryFrom<WasmValue, Error = ()>,
        T11: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

impl<
        T1: ToWasmType,
        T2: ToWasmType,
        T3: ToWasmType,
        T4: ToWasmType,
        T5: ToWasmType,
        T6: ToWasmType,
        T7: ToWasmType,
        T8: ToWasmType,
        T9: ToWasmType,
        T10: ToWasmType,
        T11: ToWasmType,
        T12: ToWasmType,
    > ToWasmTypes for (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)
{
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([
            T1::wasm_type(),
            T2::wasm_type(),
            T3::wasm_type(),
            T4::wasm_type(),
            T5::wasm_type(),
            T6::wasm_type(),
            T7::wasm_type(),
            T8::wasm_type(),
            T9::wasm_type(),
            T10::wasm_type(),
            T11::wasm_type(),
            T12::wasm_type(),
        ])
    }
}

impl<
        T1: Into<WasmValue>,
        T2: Into<WasmValue>,
        T3: Into<WasmValue>,
        T4: Into<WasmValue>,
        T5: Into<WasmValue>,
        T6: Into<WasmValue>,
        T7: Into<WasmValue>,
        T8: Into<WasmValue>,
        T9: Into<WasmValue>,
        T10: Into<WasmValue>,
        T11: Into<WasmValue>,
        T12: Into<WasmValue>,
    > IntoWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)
{
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![
            self.0.into(),
            self.1.into(),
            self.2.into(),
            self.3.into(),
            self.4.into(),
            self.5.into(),
            self.6.into(),
            self.7.into(),
            self.8.into(),
            self.9.into(),
            self.10.into(),
            self.11.into(),
        ]
    }
}

impl<
        T1: TryFrom<WasmValue, Error = ()>,
        T2: TryFrom<WasmValue, Error = ()>,
        T3: TryFrom<WasmValue, Error = ()>,
        T4: TryFrom<WasmValue, Error = ()>,
        T5: TryFrom<WasmValue, Error = ()>,
        T6: TryFrom<WasmValue, Error = ()>,
        T7: TryFrom<WasmValue, Error = ()>,
        T8: TryFrom<WasmValue, Error = ()>,
        T9: TryFrom<WasmValue, Error = ()>,
        T10: TryFrom<WasmValue, Error = ()>,
        T11: TryFrom<WasmValue, Error = ()>,
        T12: TryFrom<WasmValue, Error = ()>,
    > FromWasmValues for (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12)
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let mut iter = values.iter();
        Ok((
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
            tuple_next_value(&mut iter)?,
        ))
    }
}

/// A helper type for using tuples of arbitrary number of elements as function parameters or results,
/// by concatenating the Wasm types of each element.
///
/// This is useful when a function signature exceeds tuple arity 12. `tinywasm` only implements
/// direct tuple conversions up to arity 12, but `WasmTupleChain` lets you describe longer
/// signatures by combining smaller tuples at the type level.
#[derive(Default)]
pub struct WasmTupleChain<T1, T2>(T1, T2);

impl<T1, T2> WasmTupleChain<T1, T2> {
    /// Create a new concatenated tuple wrapper.
    pub const fn new(left: T1, right: T2) -> Self {
        Self(left, right)
    }

    /// Split the wrapper back into its two component values.
    pub fn into_inner(self) -> (T1, T2) {
        (self.0, self.1)
    }
}

impl<T1, T2> From<(T1, T2)> for WasmTupleChain<T1, T2> {
    fn from((left, right): (T1, T2)) -> Self {
        Self::new(left, right)
    }
}

impl<T1: ToWasmTypes, T2: ToWasmTypes> ToWasmTypes for WasmTupleChain<T1, T2> {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        let mut types = Vec::new();
        types.extend_from_slice(&T1::wasm_types());
        types.extend_from_slice(&T2::wasm_types());
        types.into_boxed_slice()
    }
}

impl<T1: IntoWasmValues, T2: IntoWasmValues> IntoWasmValues for WasmTupleChain<T1, T2> {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        let (left, right) = self.into_inner();
        let mut values = Vec::new();
        values.extend(left.into_wasm_values());
        values.extend(right.into_wasm_values());
        values
    }
}

impl<T1: FromWasmValues + ToWasmTypes, T2: FromWasmValues> FromWasmValues
    for WasmTupleChain<T1, T2>
{
    #[inline]
    fn from_wasm_values(values: &[WasmValue]) -> Result<Self> {
        let left_len = T1::wasm_types().len();
        let left = T1::from_wasm_values(&values[..values.len().min(left_len)])?;
        let right = T2::from_wasm_values(values.get(left_len..).unwrap_or(&[]))?;
        Ok(Self::new(left, right))
    }
}

impl ToWasmTypes for () {
    #[inline]
    fn wasm_types() -> Box<[WasmType]> {
        Box::new([])
    }
}

impl IntoWasmValues for () {
    #[inline]
    fn into_wasm_values(self) -> Vec<WasmValue> {
        vec![]
    }
}

impl FromWasmValues for () {
    #[inline]
    fn from_wasm_values(_values: &[WasmValue]) -> Result<Self> {
        Ok(())
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    use crate::wasm::rt::{Extern, Imports, Memory, ModuleInstance, Table};
    use crate::wasm::types::{
        Data, DataKind, Element, ElementItem, ElementKind, Export, ExternalKind, Import, ImportKind, Instruction,
        LocalMemoryAllocation, MemoryArch, MemoryType, Module, ModuleInner, TableType, ConstInstruction, WasmFunction,
    };
    use std::sync::Mutex;

    fn unit() -> Arc<FuncType> {
        Arc::new(FuncType::new(&[], &[]))
    }

    fn func(instructions: Vec<Instruction>) -> Arc<WasmFunction> {
        Arc::new(WasmFunction { instructions: instructions.into_boxed_slice(), ty: unit(), ..Default::default() })
    }

    fn export(name: &str, index: u32) -> Export {
        Export { name: name.into(), kind: ExternalKind::Func, index }
    }

    fn one_page() -> MemoryType {
        MemoryType::new(MemoryArch::I32, 1, None, None)
    }

    #[test]
    fn a_trapped_resumable_call_is_over() {
        let module = Module::from(ModuleInner {
            funcs: Box::new([func(vec![Instruction::Unreachable])]),
            func_types: Arc::from([unit()]),
            func_type_idxs: Arc::from([0u32]),
            exports: Arc::from([export("f", 0)]),
            ..Default::default()
        });
        let mut store = Store::default();
        let instance = ModuleInstance::instantiate(&mut store, &module, None).unwrap();
        let f = instance.func_untyped(&store, "f").unwrap();
        let mut exec = f.call_resumable(&mut store, &[]).unwrap();
        assert!(exec.resume_with_fuel(1_000).is_err(), "the call traps");
        let Err(again) = exec.resume_with_fuel(1_000) else { panic!("a finished call resumed") };
        assert!(again.to_string().contains("already completed"), "{again}");
    }

    #[test]
    fn a_nested_call_spends_the_outer_fuel_and_traps_when_it_runs_out() {
        // run -> host import -> spin (an endless loop). Before, the nested
        // call ran unbudgeted and never returned.
        let spin_handle: Arc<Mutex<Option<Function>>> = Arc::new(Mutex::new(None));
        let mut store = Store::default();
        let handle = Arc::clone(&spin_handle);
        let host = HostFunction::from_untyped(&mut store, &FuncType::new(&[], &[]), move |mut ctx, _| {
            let spin = handle.lock().unwrap().clone().expect("spin is linked");
            ctx.call_untyped(&spin, &[])
        });
        let mut imports = Imports::new();
        imports.define("env", "cb", Extern::Function(host));
        let module = Module::from(ModuleInner {
            funcs: Box::new([
                func(vec![Instruction::Jump(0)]),
                func(vec![Instruction::Call(0), Instruction::Return]),
            ]),
            func_types: Arc::from([unit()]),
            func_type_idxs: Arc::from([0u32, 0, 0]),
            imports: Box::new([Import { module: "env".into(), name: "cb".into(), kind: ImportKind::Function(0) }]),
            exports: Arc::from([export("spin", 1), export("run", 2)]),
            ..Default::default()
        });
        let instance = ModuleInstance::instantiate(&mut store, &module, Some(imports)).unwrap();
        *spin_handle.lock().unwrap() = Some(instance.func_untyped(&store, "spin").unwrap());
        let run = instance.func_untyped(&store, "run").unwrap();
        let mut exec = run.call_resumable(&mut store, &[]).unwrap();
        let Err(err) = exec.resume_with_fuel(10_000) else { panic!("the nested loop finished") };
        assert!(err.to_string().contains("fuel exhausted"), "{err}");
    }

    #[test]
    fn memory_init_with_wrapping_operands_traps_instead_of_panicking() {
        let module = Module::from(ModuleInner {
            funcs: Box::new([func(vec![
                Instruction::Const32(1),  // dst
                Instruction::Const32(1),  // offset
                Instruction::Const32(-1), // size (u32::MAX)
                Instruction::MemoryInit(0, 0),
                Instruction::Return,
            ])]),
            func_types: Arc::from([unit()]),
            func_type_idxs: Arc::from([0u32]),
            exports: Arc::from([export("f", 0)]),
            memory_types: Box::new([one_page()]),
            data: Box::new([Data { data: Box::new([1, 2, 3]), range: 0..3, kind: DataKind::Passive }]),
            local_memory_allocation: LocalMemoryAllocation::Eager,
            ..Default::default()
        });
        let mut store = Store::default();
        let instance = ModuleInstance::instantiate(&mut store, &module, None).unwrap();
        let f = instance.func_untyped(&store, "f").unwrap();
        assert!(f.call(&mut store, &[]).is_err());
    }

    #[test]
    fn an_import_from_another_store_is_refused() {
        let mut other = Store::default();
        let foreign = Memory::new(&mut other, one_page()).unwrap();
        let mut imports = Imports::new();
        imports.define("env", "mem", Extern::Memory(foreign));
        let module = Module::from(ModuleInner {
            imports: Box::new([Import { module: "env".into(), name: "mem".into(), kind: ImportKind::Memory(one_page()) }]),
            ..Default::default()
        });
        let mut store = Store::default();
        assert!(ModuleInstance::instantiate(&mut store, &module, Some(imports)).is_err());
    }

    #[test]
    fn a_failed_instantiation_keeps_its_slot_and_an_element_trap_writes_no_data() {
        let mut store = Store::default();
        let shared = Memory::new(&mut store, one_page()).unwrap();
        let mut imports = Imports::new();
        imports.define("env", "mem", Extern::Memory(shared));
        let module = Module::from(ModuleInner {
            funcs: Box::new([func(vec![Instruction::Return])]),
            func_types: Arc::from([unit()]),
            func_type_idxs: Arc::from([0u32]),
            imports: Box::new([Import { module: "env".into(), name: "mem".into(), kind: ImportKind::Memory(one_page()) }]),
            table_types: Box::new([TableType { element_type: crate::wasm::types::WasmType::RefFunc, size_initial: 1, size_max: None }]),
            elements: Box::new([Element {
                kind: ElementKind::Active { table: 0, offset: Box::new([ConstInstruction::I32Const(5)]) },
                items: Box::new([ElementItem::Func(0)]),
                range: 0..1,
                ty: crate::wasm::types::WasmType::RefFunc,
            }]),
            data: Box::new([Data {
                data: Box::new([9]),
                range: 0..1,
                kind: DataKind::Active { mem: 0, offset: Box::new([ConstInstruction::I32Const(0)]) },
            }]),
            ..Default::default()
        });
        assert_eq!(store.next_module_instance_idx(), 0);
        assert!(ModuleInstance::instantiate(&mut store, &module, Some(imports)).is_err());
        assert_eq!(store.next_module_instance_idx(), 1, "the failed module keeps its instance slot");
        assert_eq!(shared.read_vec(&store, 0, 1).unwrap(), vec![0], "no data segment ran after the element trap");
        assert_eq!(store.state.elements.len(), 1, "the trapping element segment is allocated");
        assert_eq!(store.state.data.len(), 1, "data segments are allocated even after an element trap");
    }

    #[test]
    fn memory_init_reads_the_memory_then_the_data_operand() {
        let module = Module::from(ModuleInner {
            funcs: Box::new([func(vec![
                Instruction::Const32(0), // dst
                Instruction::Const32(0), // offset
                Instruction::Const32(3), // size
                Instruction::MemoryInit(0, 1),
                Instruction::Return,
            ])]),
            func_types: Arc::from([unit()]),
            func_type_idxs: Arc::from([0u32]),
            exports: Arc::from([export("f", 0), Export { name: "mem".into(), kind: ExternalKind::Memory, index: 0 }]),
            memory_types: Box::new([one_page()]),
            data: Box::new([
                Data { data: Box::new([1, 2, 3]), range: 0..3, kind: DataKind::Passive },
                Data { data: Box::new([7, 8, 9]), range: 0..3, kind: DataKind::Passive },
            ]),
            local_memory_allocation: LocalMemoryAllocation::Eager,
            ..Default::default()
        });
        let mut store = Store::default();
        let instance = ModuleInstance::instantiate(&mut store, &module, None).unwrap();
        instance.func_untyped(&store, "f").unwrap().call(&mut store, &[]).unwrap();
        let mem = instance.memory("mem").unwrap();
        assert_eq!(mem.read_vec(&store, 0, 3).unwrap(), vec![7, 8, 9]);
    }

    #[test]
    fn a_resumable_host_call_runs_on_resume_and_can_yield() {
        let calls = Arc::new(Mutex::new(0u32));
        let mut store = Store::default();
        let seen = Arc::clone(&calls);
        let host = HostFunction::from_untyped(&mut store, &FuncType::new(&[], &[WasmType::I32]), move |ctx, _| {
            let mut n = seen.lock().unwrap();
            *n += 1;
            if *n == 1 {
                return Err(Error::Other(crate::wasm::rt::HOST_YIELD.into()));
            }
            Ok(vec![WasmValue::I32(ctx.remaining_fuel() as i32)])
        });
        let mut exec = host.call_resumable(&mut store, &[]).unwrap();
        assert_eq!(*calls.lock().unwrap(), 0, "nothing runs before the first resume");
        assert!(matches!(exec.resume_with_fuel(50).unwrap(), ExecProgress::Suspended));
        let ExecProgress::Completed(values) = exec.resume_with_fuel(70).unwrap() else { panic!("not completed") };
        assert_eq!(values, vec![WasmValue::I32(70)], "the host call ran under the resume's fuel");
        drop(exec);
        let plain = host.call(&mut store, &[]).unwrap();
        assert_eq!(plain, vec![WasmValue::I32(0)], "a plain call has no fuel left over");
    }

    #[test]
    fn a_host_handle_called_directly_has_no_module_instead_of_panicking() {
        let mut store = Store::default();
        let host = HostFunction::from_untyped(&mut store, &FuncType::new(&[], &[WasmType::I32]), |ctx, _| {
            Ok(vec![WasmValue::I32(i32::from(ctx.memory("memory").is_err()))])
        });
        assert_eq!(host.call(&mut store, &[]).unwrap(), vec![WasmValue::I32(1)]);
    }

    #[test]
    fn an_unbounded_memory_does_not_satisfy_an_import_with_a_maximum() {
        let mut store = Store::default();
        let unbounded = Memory::new(&mut store, one_page()).unwrap();
        let mut imports = Imports::new();
        imports.define("env", "mem", Extern::Memory(unbounded));
        let module = Module::from(ModuleInner {
            imports: Box::new([Import {
                module: "env".into(),
                name: "mem".into(),
                kind: ImportKind::Memory(MemoryType::new(MemoryArch::I32, 1, Some(65536), None)),
            }]),
            ..Default::default()
        });
        assert!(ModuleInstance::instantiate(&mut store, &module, Some(imports)).is_err());
    }

    #[test]
    fn strings_read_from_memory_near_its_end_and_in_utf16() {
        let mut store = Store::default();
        let mem = Memory::new(&mut store, one_page()).unwrap();
        mem.copy_from_slice(&mut store, 65533, b"hi\0").unwrap();
        let s = mem.read_cstring_until_null(&store, 65533, 4096).unwrap();
        assert_eq!(s.as_bytes(), b"hi");
        mem.copy_from_slice(&mut store, 65534, b"xy").unwrap();
        assert!(mem.read_cstring_until_null(&store, 65534, 4096).is_err(), "memory ends before a null");

        let text = "a\u{1F600}";
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        mem.copy_from_slice(&mut store, 0, &bytes).unwrap();
        assert_eq!(mem.read_js_string(&store, 0, bytes.len()).unwrap(), text);
        assert!(mem.read_js_string(&store, 0, bytes.len() - 1).is_err(), "an odd byte length");
    }

    #[test]
    fn a_function_reference_outside_the_store_is_refused() {
        let mut store = Store::default();
        let ty = TableType { element_type: WasmType::RefFunc, size_initial: 1, size_max: None };
        let bogus = WasmValue::RefFunc(FuncRef::new(Some(999)));
        assert!(Table::new(&mut store, ty.clone(), bogus).is_err());
        let table = Table::new(&mut store, ty, WasmValue::RefFunc(FuncRef::null())).unwrap();
        assert!(table.set(&mut store, 0, bogus).is_err());
        assert!(table.grow(&mut store, 1, bogus).is_err());
        let gty = crate::wasm::types::GlobalType { mutable: true, ty: WasmType::RefFunc };
        assert!(crate::wasm::rt::Global::new(&mut store, gty, bogus).is_err());
    }
}
