//! html-dom: an arena-backed HTML document tree and its serialiser.
//!
//! [`tree`] holds the document: nodes live in one flat arena, relationships
//! are index links, and a [`NodeId`] stays valid for the life of its
//! document. [`serialize`] writes a document or a subtree back as HTML,
//! escaping text and attribute values so that content supplied as text can
//! never become markup.
//!
//! The package is dependency-free (`std` only) and performs no parsing: a
//! caller builds a tree with [`Document::create_element`],
//! [`Document::create_text`] and [`Document::append_child`], or receives one
//! from a parser that targets this tree.

pub mod serialize;
pub mod tree;

pub use self::serialize::{inner_html, is_void, outer_html, serialize_html, VOID_ELEMENTS};
pub use self::tree::{
    AncestorIter, ChildIter, DescendantIter, Document, ElementData, Node, NodeData, NodeId,
};
