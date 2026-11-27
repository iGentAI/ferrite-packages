# html-dom

An HTML document tree and its serialiser, as a Ferrite source package. An application builds a document from elements, attributes and text, walks or edits it, and writes it back as HTML. The serialiser escapes text and attribute values, so a value that arrives as text (a user's message, a file name, a model's reply) is written as text and can never become markup.

The package has no dependencies beyond `std` and does no I/O. It mounts at `html_dom`.

## API

| Module | Contents |
| --- | --- |
| `tree` | `Document`, an arena of `Node` values addressed by `NodeId`. Nodes are a document root, doctype, element (`ElementData`: a lowercase tag and attributes in order), text or comment (`NodeData`). `create_element`, `create_text`, `append_child`, `insert_before`, `detach`, `remove_children` and `set_attr` build and edit the tree; `children`, `descendants` and `ancestors` iterate it; `find_tag`, `get_element_by_id` and `text_content` query it. |
| `serialize` | `serialize_html` and `inner_html` write a node's children as HTML, and `outer_html` writes the node itself. `is_void` and `VOID_ELEMENTS` name the elements that take no end tag. |

The names in both modules are also exported from the package root, so `html_dom::Document` and `html_dom::serialize_html` work without naming the module.

A `NodeId` stays valid for the life of its document: detaching a node unlinks it and never reuses its slot. `NodeId::DOCUMENT` is the root.

## Serialisation rules

- Text is escaped for `&`, `<` and `>`. Attribute values are escaped for those and for `"`, and every attribute is written in double quotes.
- Text directly inside `script` or `style` is written as it is, because HTML reads the content of those elements as raw text. An application that places untrusted text there must make it safe for that context itself.
- A void element (`br`, `img`, `meta` and the rest of `VOID_ELEMENTS`) is written without an end tag, and any children the tree holds for it are left out.
- Tag and attribute names are written as stored. `set_attr` lowercases the attribute name; the caller chooses tag names.

## Consumers

```bash
ferrite add html-dom
```

Declare `pub mod html_dom;` in the crate root, then build and serialise a document:

```rust
use crate::html_dom::{serialize_html, Document, NodeId};

let mut doc = Document::new();
let article = doc.create_element("article");
doc.append_child(NodeId::DOCUMENT, article);
doc.set_attr(article, "data-role", "user");
let text = doc.create_text("1 < 2 & <b>not bold</b>");
doc.append_child(article, text);

assert_eq!(
    serialize_html(&doc, NodeId::DOCUMENT),
    "<article data-role=\"user\">1 &lt; 2 &amp; &lt;b&gt;not bold&lt;/b&gt;</article>"
);
```

Installed copies are generated: edit the package source and recompose with `ferrite-pkg`, never by modifying a vendored copy.

## Status

Active source package compiled directly into constrained Ferrite applications. It has no dependencies beyond `std`.

## Not claimed

This package does not parse HTML and does not validate that a tree is a conforming document: it serialises the tree it is given. It is not a sanitiser for markup that is already markup; its guarantee is that text nodes and attribute values are escaped on the way out. It is not independently deployable.

## Validation

This directory includes a standalone test harness (`Cargo.toml` and `harness/lib.rs`, ignored by `ferrite-pkg` and `ferrite add`) that runs the unit tests:

```bash
cargo test --manifest-path packages/html-dom/Cargo.toml
node tools/ferrite-pkg/ferrite-pkg.mjs check
```
