//! DOM tree: an arena-backed document object model.
//!
//! Nodes live in a flat `Vec` arena; relationships are index links. This keeps
//! the tree compact, cache-friendly and free of `Rc` cycles, and gives O(1)
//! append. IDs are stable for the life of the document (removal only unlinks;
//! slots are never reused within one document).

use std::collections::HashMap;

/// Index of a node in the document arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u32);

impl NodeId {
    /// The document root node id (always 0).
    pub const DOCUMENT: NodeId = NodeId(0);

    #[inline]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// The kind and payload of a DOM node.
#[derive(Debug, Clone, PartialEq)]
pub enum NodeData {
    /// The document root.
    Document,
    /// A doctype declaration, e.g. `<!DOCTYPE html>`.
    Doctype { name: String },
    /// An element with a lowercase tag name and its attributes.
    Element(ElementData),
    /// A text node.
    Text(String),
    /// A comment node.
    Comment(String),
}

/// Element payload: tag name plus attributes in document order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ElementData {
    /// Lowercase tag name (HTML is case-insensitive; we canonicalize once).
    pub tag: String,
    /// Attributes in source order. Names are lowercase; values are the raw
    /// input, preserved faithfully (no normalization of the stored value).
    pub attrs: Vec<(String, String)>,
}

impl ElementData {
    pub fn new(tag: impl Into<String>) -> Self {
        ElementData {
            tag: tag.into(),
            attrs: Vec::new(),
        }
    }

    /// First attribute value by (lowercase) name.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The element's `id` attribute.
    pub fn id(&self) -> Option<&str> {
        self.attr("id")
    }

    /// Whitespace-separated class list.
    pub fn classes(&self) -> impl Iterator<Item = &str> {
        self.attr("class").unwrap_or("").split_ascii_whitespace()
    }

    pub fn has_class(&self, class: &str) -> bool {
        self.classes().any(|c| c == class)
    }
}

/// One node in the arena: payload plus tree links.
#[derive(Debug, Clone)]
pub struct Node {
    pub data: NodeData,
    pub parent: Option<NodeId>,
    pub first_child: Option<NodeId>,
    pub last_child: Option<NodeId>,
    pub prev_sibling: Option<NodeId>,
    pub next_sibling: Option<NodeId>,
}

impl Node {
    fn new(data: NodeData) -> Self {
        Node {
            data,
            parent: None,
            first_child: None,
            last_child: None,
            prev_sibling: None,
            next_sibling: None,
        }
    }

    pub fn as_element(&self) -> Option<&ElementData> {
        match &self.data {
            NodeData::Element(e) => Some(e),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match &self.data {
            NodeData::Text(t) => Some(t.as_str()),
            _ => None,
        }
    }
}

/// An arena-backed DOM document.
#[derive(Debug, Clone)]
pub struct Document {
    nodes: Vec<Node>,
    /// Lazy index from element id attribute to node, rebuilt on demand.
    id_index: HashMap<String, NodeId>,
    id_index_valid: bool,
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

impl Document {
    /// A new document containing only the root node.
    pub fn new() -> Self {
        Document {
            nodes: vec![Node::new(NodeData::Document)],
            id_index: HashMap::new(),
            id_index_valid: false,
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        // The root always exists; "empty" means no content nodes.
        self.nodes.len() <= 1
    }

    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id.index()]
    }

    /// Bounds-checked node access, for a caller holding an id that may not
    /// belong to this document: an unknown id yields `None`.
    pub fn get(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id.index())
    }

    pub fn node_mut(&mut self, id: NodeId) -> &mut Node {
        self.id_index_valid = false;
        &mut self.nodes[id.index()]
    }

    /// Allocate a detached node.
    pub fn create_node(&mut self, data: NodeData) -> NodeId {
        let id = NodeId(self.nodes.len() as u32);
        self.nodes.push(Node::new(data));
        self.id_index_valid = false;
        id
    }

    pub fn create_element(&mut self, tag: impl Into<String>) -> NodeId {
        self.create_node(NodeData::Element(ElementData::new(tag)))
    }

    pub fn create_text(&mut self, text: impl Into<String>) -> NodeId {
        self.create_node(NodeData::Text(text.into()))
    }

    /// Append `child` as the last child of `parent`. The child must be
    /// detached (or is detached first).
    pub fn append_child(&mut self, parent: NodeId, child: NodeId) {
        debug_assert_ne!(parent, child, "cannot append a node to itself");
        self.detach(child);
        let old_last = self.nodes[parent.index()].last_child;
        self.nodes[child.index()].parent = Some(parent);
        self.nodes[child.index()].prev_sibling = old_last;
        match old_last {
            Some(last) => self.nodes[last.index()].next_sibling = Some(child),
            None => self.nodes[parent.index()].first_child = Some(child),
        }
        self.nodes[parent.index()].last_child = Some(child);
        self.id_index_valid = false;
    }

    /// Insert `node` immediately before `reference` under the same parent.
    pub fn insert_before(&mut self, reference: NodeId, node: NodeId) {
        self.detach(node);
        let parent = self.nodes[reference.index()]
            .parent
            .unwrap_or(NodeId::DOCUMENT);
        let prev = self.nodes[reference.index()].prev_sibling;
        self.nodes[node.index()].parent = Some(parent);
        self.nodes[node.index()].prev_sibling = prev;
        self.nodes[node.index()].next_sibling = Some(reference);
        self.nodes[reference.index()].prev_sibling = Some(node);
        match prev {
            Some(p) => self.nodes[p.index()].next_sibling = Some(node),
            None => self.nodes[parent.index()].first_child = Some(node),
        }
        self.id_index_valid = false;
    }

    /// Unlink a node from its parent and siblings (subtree stays intact).
    pub fn detach(&mut self, id: NodeId) {
        let (parent, prev, next) = {
            let n = &self.nodes[id.index()];
            (n.parent, n.prev_sibling, n.next_sibling)
        };
        if let Some(p) = prev {
            self.nodes[p.index()].next_sibling = next;
        } else if let Some(par) = parent {
            self.nodes[par.index()].first_child = next;
        }
        if let Some(nx) = next {
            self.nodes[nx.index()].prev_sibling = prev;
        } else if let Some(par) = parent {
            self.nodes[par.index()].last_child = prev;
        }
        let n = &mut self.nodes[id.index()];
        n.parent = None;
        n.prev_sibling = None;
        n.next_sibling = None;
        self.id_index_valid = false;
    }

    /// Children of a node, in order.
    pub fn children(&self, id: NodeId) -> ChildIter<'_> {
        ChildIter {
            doc: self,
            next: self.nodes[id.index()].first_child,
        }
    }

    /// All descendants of `id` in document (pre-)order, excluding `id`.
    pub fn descendants(&self, id: NodeId) -> DescendantIter<'_> {
        DescendantIter {
            doc: self,
            root: id,
            next: self.nodes[id.index()].first_child,
        }
    }

    /// Ancestors from the parent upward.
    pub fn ancestors(&self, id: NodeId) -> AncestorIter<'_> {
        AncestorIter {
            doc: self,
            next: self.nodes[id.index()].parent,
        }
    }

    /// The `<html>` element, if present.
    pub fn document_element(&self) -> Option<NodeId> {
        self.children(NodeId::DOCUMENT)
            .find(|&c| self.node(c).as_element().is_some())
    }

    /// First element in document order matching the tag name.
    pub fn find_tag(&self, tag: &str) -> Option<NodeId> {
        self.descendants(NodeId::DOCUMENT)
            .find(|&n| self.node(n).as_element().map(|e| e.tag == tag) == Some(true))
    }

    /// Detach every child of `id` (subtrees stay in the arena, unlinked).
    pub fn remove_children(&mut self, id: NodeId) {
        let kids: Vec<NodeId> = self.children(id).collect();
        for k in kids {
            self.detach(k);
        }
    }

    /// Set (or add) an attribute on an element node. Non-elements ignore it.
    pub fn set_attr(&mut self, id: NodeId, name: &str, value: &str) {
        self.id_index_valid = false;
        if let Some(node) = self.nodes.get_mut(id.index()) {
            if let NodeData::Element(e) = &mut node.data {
                let lname = name.to_ascii_lowercase();
                if let Some(slot) = e.attrs.iter_mut().find(|(n, _)| *n == lname) {
                    slot.1 = value.to_string();
                } else {
                    e.attrs.push((lname, value.to_string()));
                }
            }
        }
    }

    /// `get_element_by_id` under a shorter name.
    pub fn element_by_id(&mut self, id_attr: &str) -> Option<NodeId> {
        self.get_element_by_id(id_attr)
    }

    /// Element lookup by `id` attribute (first match, document order).
    pub fn get_element_by_id(&mut self, id_attr: &str) -> Option<NodeId> {
        if !self.id_index_valid {
            self.id_index.clear();
            let ids: Vec<(String, NodeId)> = self
                .descendants(NodeId::DOCUMENT)
                .filter_map(|n| {
                    self.node(n)
                        .as_element()
                        .and_then(|e| e.id())
                        .map(|v| (v.to_string(), n))
                })
                .collect();
            for (k, v) in ids {
                self.id_index.entry(k).or_insert(v);
            }
            self.id_index_valid = true;
        }
        self.id_index.get(id_attr).copied()
    }

    /// Element lookup by `id` attribute without requiring `&mut self` (linear
    /// scan; use `get_element_by_id` for the cached path).
    pub fn get_element_by_id_ref(&self, id_attr: &str) -> Option<NodeId> {
        self.descendants(NodeId::DOCUMENT).find(|&n| {
            self.node(n)
                .as_element()
                .and_then(|e| e.id())
                .map(|v| v == id_attr)
                .unwrap_or(false)
        })
    }

    /// Concatenated text of the subtree (like `textContent`).
    pub fn text_content(&self, id: NodeId) -> String {
        let mut out = String::new();
        if let Some(t) = self.node(id).as_text() {
            out.push_str(t);
        }
        for d in self.descendants(id) {
            if let Some(t) = self.node(d).as_text() {
                out.push_str(t);
            }
        }
        out
    }
}

/// Iterator over the children of one node.
pub struct ChildIter<'a> {
    doc: &'a Document,
    next: Option<NodeId>,
}

impl<'a> Iterator for ChildIter<'a> {
    type Item = NodeId;
    fn next(&mut self) -> Option<NodeId> {
        let cur = self.next?;
        self.next = self.doc.node(cur).next_sibling;
        Some(cur)
    }
}

/// Pre-order iterator over a subtree, excluding the root.
pub struct DescendantIter<'a> {
    doc: &'a Document,
    root: NodeId,
    next: Option<NodeId>,
}

impl<'a> Iterator for DescendantIter<'a> {
    type Item = NodeId;
    fn next(&mut self) -> Option<NodeId> {
        let cur = self.next?;
        // Compute the next node in pre-order without recursion.
        let node = self.doc.node(cur);
        self.next = if let Some(fc) = node.first_child {
            Some(fc)
        } else {
            // Walk up until a next sibling exists or we reach the root.
            let mut at = cur;
            loop {
                if at == self.root {
                    break None;
                }
                let n = self.doc.node(at);
                if let Some(ns) = n.next_sibling {
                    break Some(ns);
                }
                match n.parent {
                    Some(p) if p != self.root => at = p,
                    _ => break None,
                }
            }
        };
        Some(cur)
    }
}

/// Iterator over ancestors, nearest first.
pub struct AncestorIter<'a> {
    doc: &'a Document,
    next: Option<NodeId>,
}

impl<'a> Iterator for AncestorIter<'a> {
    type Item = NodeId;
    fn next(&mut self) -> Option<NodeId> {
        let cur = self.next?;
        self.next = self.doc.node(cur).parent;
        Some(cur)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_walk() {
        let mut doc = Document::new();
        let html = doc.create_element("html");
        doc.append_child(NodeId::DOCUMENT, html);
        let body = doc.create_element("body");
        doc.append_child(html, body);
        let p = doc.create_element("p");
        doc.append_child(body, p);
        let t = doc.create_text("hello");
        doc.append_child(p, t);

        assert_eq!(doc.document_element(), Some(html));
        assert_eq!(doc.find_tag("p"), Some(p));
        assert_eq!(doc.text_content(NodeId::DOCUMENT), "hello");
        let desc: Vec<NodeId> = doc.descendants(NodeId::DOCUMENT).collect();
        assert_eq!(desc, vec![html, body, p, t]);
    }

    #[test]
    fn detach_and_insert_before() {
        let mut doc = Document::new();
        let html = doc.create_element("html");
        doc.append_child(NodeId::DOCUMENT, html);
        let a = doc.create_element("a");
        let b = doc.create_element("b");
        let c = doc.create_element("c");
        doc.append_child(html, a);
        doc.append_child(html, c);
        doc.insert_before(c, b);
        let kids: Vec<NodeId> = doc.children(html).collect();
        assert_eq!(kids, vec![a, b, c]);
        doc.detach(b);
        let kids: Vec<NodeId> = doc.children(html).collect();
        assert_eq!(kids, vec![a, c]);
    }

    #[test]
    fn id_lookup_and_classes() {
        let mut doc = Document::new();
        let div = doc.create_element("div");
        if let NodeData::Element(e) = &mut doc.node_mut(div).data {
            e.attrs.push(("id".into(), "main".into()));
            e.attrs.push(("class".into(), "a  b\tc".into()));
        }
        doc.append_child(NodeId::DOCUMENT, div);
        assert_eq!(doc.get_element_by_id("main"), Some(div));
        assert_eq!(doc.get_element_by_id("nope"), None);
        let e = doc.node(div).as_element().unwrap();
        assert!(e.has_class("a") && e.has_class("b") && e.has_class("c"));
        assert!(!e.has_class("d"));
    }

    #[test]
    fn empty_document_edges() {
        let doc = Document::new();
        assert!(doc.is_empty());
        assert_eq!(doc.document_element(), None);
        assert_eq!(doc.descendants(NodeId::DOCUMENT).count(), 0);
        assert_eq!(doc.text_content(NodeId::DOCUMENT), "");
    }
}
