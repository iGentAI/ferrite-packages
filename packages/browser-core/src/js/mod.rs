//! js — a std-only JavaScript engine for the browser core: lexer, parser,
//! tree-walking interpreter, promise/microtask machinery, virtual-clock
//! timers, and DOM bindings that mutate the same arena `dom::Document` the
//! layout, extraction, and screenshot stages consume.
//!
//! Like every other stage the engine is panic-free and bounded: hostile
//! scripts terminate against a step budget, syntax errors surface as script
//! errors on the page, and the engine itself performs no I/O — network is
//! delegated to the consumer through `interp::HostHooks` so egress stays
//! declared and scoped.

pub mod ast;
pub mod builtins;
pub mod builtins_array;
pub mod builtins_es;
pub mod builtins_ext;
pub mod builtins_web;
pub mod coroutine;
pub mod desugar;
pub mod dom_bindings;
pub mod eval;
pub mod events;
pub mod function_meta;
pub mod globals;
pub mod interp;
pub mod json;
pub mod lexer;
pub mod parser;
pub mod regex;
pub mod runtime;
pub mod value;
