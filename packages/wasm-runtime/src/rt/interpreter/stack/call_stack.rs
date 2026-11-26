use crate::wasm::compat::cold_path;
use crate::wasm::rt::{Result, Trap};

use crate::wasm::types::{FuncAddr, ValueCounts};
use alloc::vec::Vec;

#[derive(Debug)]
pub(crate) struct CallStack {
    stack: Vec<CallFrame>,
    max_size: usize,
    dynamic: bool,
}

impl CallStack {
    pub(crate) fn new(config: &crate::wasm::rt::engine::Config) -> Self {
        let stack = config.call_stack;
        // The limit is `max_size`, and a fixed stack never holds more than it
        // reserved; the reservation itself never exceeds the limit.
        let max_size = if stack.dynamic {
            stack.max_size
        } else {
            stack.initial_size.min(stack.max_size)
        };
        Self {
            stack: Vec::with_capacity(stack.initial_size.min(max_size)),
            max_size,
            dynamic: stack.dynamic,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.stack.clear();
    }

    #[inline(always)]
    pub(crate) fn len(&self) -> u32 {
        self.stack.len() as u32
    }

    pub(crate) fn truncate_to(&mut self, len: u32) {
        debug_assert!(len as usize <= self.stack.len());
        self.stack.truncate(len as usize);
    }

    #[inline(always)]
    pub(crate) fn pop_frame(&mut self, base: u32) -> Option<CallFrame> {
        if self.len() == base {
            None
        } else {
            self.stack.pop()
        }
    }

    #[inline(always)]
    pub(crate) fn push(&mut self, mut call_frame: CallFrame) -> Result<(), Trap> {
        self.ensure_capacity_for(self.stack.len() + 1)?;
        call_frame.incr_instr_ptr();
        self.stack.push(call_frame);
        Ok(())
    }

    #[inline(always)]
    fn ensure_capacity_for(&mut self, required_len: usize) -> Result<(), Trap> {
        // The limit is checked before the capacity: `Vec` may hold more
        // capacity than was asked for, and that spare room is not depth.
        if required_len > self.max_size {
            cold_path();
            return Err(Trap::CallStackOverflow);
        }
        if required_len <= self.stack.capacity() {
            return Ok(());
        }

        if !self.dynamic {
            cold_path();
            return Err(Trap::CallStackOverflow);
        }

        let target_capacity = required_len
            .max(self.stack.capacity().max(1).saturating_mul(2))
            .min(self.max_size);
        let Ok(()) = self
            .stack
            .try_reserve_exact(target_capacity.saturating_sub(self.stack.len()))
        else {
            cold_path();
            return Err(Trap::CallStackOverflow);
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::rt::engine::{Config, StackConfig};

    fn frame() -> CallFrame {
        CallFrame::new(0, StackBase::default(), ValueCounts { c32: 0, c64: 0, c128: 0 })
    }

    #[test]
    fn the_call_stack_never_exceeds_max_size() {
        for (initial, max) in [(1, 2), (64, 100), (3, 5)] {
            let config = Config::default().with_call_stack(StackConfig::dynamic(initial, max));
            let mut stack = CallStack::new(&config);
            for _ in 0..max {
                stack.push(frame()).unwrap();
            }
            assert!(stack.push(frame()).is_err(), "depth {max} is the limit for dynamic({initial}, {max})");
        }
        let mut config = Config::default();
        config.call_stack = StackConfig { initial_size: 8, max_size: 3, dynamic: false };
        let mut stack = CallStack::new(&config);
        for _ in 0..3 {
            stack.push(frame()).unwrap();
        }
        assert!(stack.push(frame()).is_err(), "a lowered max_size holds below initial_size");
    }
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub(crate) struct CallFrame {
    pub(crate) instr_ptr: u32,
    pub(crate) func_addr: FuncAddr,
    pub(crate) locals_base: StackBase,
    pub(crate) stack_offset: ValueCounts,
}

#[derive(Clone, Copy, Default)]
#[derive(Debug)]
pub(crate) struct StackBase {
    pub(crate) s32: u32,
    pub(crate) s64: u32,
    pub(crate) s128: u32,
}

impl CallFrame {
    pub(crate) fn new(
        func_addr: FuncAddr,
        locals_base: StackBase,
        stack_offset: ValueCounts,
    ) -> Self {
        Self {
            instr_ptr: 0,
            func_addr,
            locals_base,
            stack_offset,
        }
    }

    #[inline]
    pub(crate) fn stack_base(&self) -> StackBase {
        StackBase {
            s32: self.locals_base.s32 + self.stack_offset.c32 as u32,
            s64: self.locals_base.s64 + self.stack_offset.c64 as u32,
            s128: self.locals_base.s128 + self.stack_offset.c128 as u32,
        }
    }

    #[inline(always)]
    pub(crate) fn incr_instr_ptr(&mut self) {
        self.instr_ptr += 1;
    }
}
