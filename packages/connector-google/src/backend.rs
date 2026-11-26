//! The vendor boundary: everything that actually touches Google.
//!
//! The connector core never sees a credential or a socket — it calls a
//! [`GoogleBackend`]. The offline gates use [`FixtureBackend`], an in-memory
//! Google Drive good enough to prove the governance semantics; a deployed
//! connector app supplies a live backend over its declared egress, holding
//! its token the way the AI gateway holds provider keys.

use ferrite_app::serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// A Drive file as the connector reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct FileMeta {
    pub id: String,
    pub name: String,
    pub mime_type: String,
}

/// One document's fixture state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct DocState {
    /// Body snapshots, one per revision; `revisions[r]` is the body at
    /// revision `r` and the LAST entry is the current body.
    pub revisions: Vec<String>,
    /// Users with direct read access — the ACL observer verification consults.
    pub readers: Vec<String>,
}

/// One Drive folder's fixture state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "ferrite_app::serde")]
pub struct FolderState {
    /// The files a listing returns.
    pub files: Vec<FileMeta>,
    /// Users with direct read access to the folder itself.
    pub readers: Vec<String>,
    /// Per-file readers, keyed by file id — the ACL the DataSetTracking
    /// observer verification consults for `folder/file` sub-resource keys.
    pub file_readers: BTreeMap<String, Vec<String>>,
}

/// An append's exact vendor identity. `token` must identify that mutation,
/// not merely a reusable revision number; adapters persist it with the action.
#[derive(Debug, Clone)]
pub struct AppendEffect { pub revision: u64, pub token: String }

/// A completed conditional exchange. `Conflict` certifies that no mutation ran;
/// transport errors remain `Err` and must never be retried without reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertOutcome { Reverted, Conflict }

#[derive(Debug, Default)]
struct EffectTokens { next: u64, by_document: BTreeMap<String, Vec<String>> }

/// The vendor operations the connector needs. Implementations decide how
/// they reach Google (fixtures in tests, declared egress in deployment).
pub trait GoogleBackend: Send {
    /// Resolve the actual Drive MIME kind from trusted vendor metadata, never a pasted URL.
    /// Adapters that cannot establish it refuse document/sheet operations.
    fn resource_kind(&self, _id: &str) -> Result<&'static str, String> {
        Err("backend cannot establish the actual resource kind".into())
    }
    /// Current body of a document.
    fn read_document(&self, doc_id: &str) -> Result<String, String>;
    /// Current textual/tabular body of a spreadsheet, using the Sheets API.
    fn read_sheet(&self, sheet_id: &str) -> Result<String, String>;
    fn append_to_sheet(&self, sheet_id: &str, text: &str) -> Result<u64, String>;
    fn revert_sheet(&self, sheet_id: &str, revision: u64) -> Result<(), String>;
    /// List the files in a Drive folder.
    fn list_folder(&self, folder_id: &str) -> Result<Vec<FileMeta>, String>;
    /// Append `text` to a document; returns the new revision number.
    fn append_to_document(&self, doc_id: &str, text: &str) -> Result<u64, String>;
    /// Restore a document to an earlier `revision`.
    fn revert_document(&self, doc_id: &str, revision: u64) -> Result<(), String>;
    /// Atomic append returning a non-reusable vendor mutation token.
    /// Adapters without receipt support fail closed before mutation.
    fn append_document_with_receipt(&self, _id: &str, _text: &str) -> Result<AppendEffect, String> {
        Err("backend does not support receipt-bound document append".into())
    }
    fn append_sheet_with_receipt(&self, _id: &str, _text: &str) -> Result<AppendEffect, String> {
        Err("backend does not support receipt-bound sheet append".into())
    }
    /// Atomically compare the current mutation token and restore its predecessor.
    /// Never emulate this with a racy read then unconditional write.
    fn revert_document_with_receipt(&self, _id: &str, _revision: u64, _token: &str) -> Result<RevertOutcome, String> {
        Err("backend does not support receipt-bound document revert".into())
    }
    fn revert_sheet_with_receipt(&self, _id: &str, _revision: u64, _token: &str) -> Result<RevertOutcome, String> {
        Err("backend does not support receipt-bound sheet revert".into())
    }
    /// Can `user` directly read `unit` with their OWN credentials? `unit` is
    /// a doc/sheet id, a folder id, or a `folder/file` sub-resource key.
    fn user_can_read(&self, user: &str, unit: &str) -> bool;
}

/// The in-memory backend the offline gates run against.
#[derive(Debug, Default)]
pub struct FixtureBackend {
    docs: Mutex<BTreeMap<String, DocState>>,
    kinds: Mutex<BTreeMap<String, &'static str>>,
    effects: Mutex<EffectTokens>,
    folders: Mutex<BTreeMap<String, FolderState>>,
}

impl FixtureBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed_document(&self, doc_id: &str, state: DocState) {
        let mut docs=self.docs.lock().unwrap();
        let mut effects=self.effects.lock().unwrap();
        effects.by_document.remove(doc_id);
        docs.insert(doc_id.to_string(), state);
        self.kinds.lock().unwrap().insert(doc_id.to_string(), "google.doc");
    }

    /// Seed a Sheets fixture with authoritative spreadsheet identity.
    pub fn seed_sheet(&self, sheet_id: &str, state: DocState) {
        self.seed_document(sheet_id, state);
        self.kinds.lock().unwrap().insert(sheet_id.to_string(), "google.sheet");
    }

    pub fn seed_folder(&self, folder_id: &str, state: FolderState) {
        self.folders
            .lock()
            .unwrap()
            .insert(folder_id.to_string(), state);
    }

    pub fn document(&self, doc_id: &str) -> Option<DocState> {
        self.docs.lock().unwrap().get(doc_id).cloned()
    }

    pub fn folder(&self, folder_id: &str) -> Option<FolderState> {
        self.folders.lock().unwrap().get(folder_id).cloned()
    }
}

impl GoogleBackend for FixtureBackend {
    fn resource_kind(&self, id: &str) -> Result<&'static str, String> {
        self.kinds.lock().unwrap().get(id).copied().ok_or_else(|| "resource is absent from vendor catalogue".into())
    }
    // This offline fixture stores both content kinds as revisioned text.
    // The connector still chooses a distinct vendor operation for Sheets.
    fn read_sheet(&self, sheet_id: &str) -> Result<String, String> {
        self.read_document(sheet_id)
    }
    fn append_to_sheet(&self, sheet_id: &str, text: &str) -> Result<u64, String> {
        self.append_to_document(sheet_id, text)
    }
    fn revert_sheet(&self, sheet_id: &str, revision: u64) -> Result<(), String> {
        self.revert_document(sheet_id, revision)
    }

    fn read_document(&self, doc_id: &str) -> Result<String, String> {
        self.docs
            .lock()
            .unwrap()
            .get(doc_id)
            .map(|d| d.revisions.last().cloned().unwrap_or_default())
            .ok_or_else(|| format!("unknown document {doc_id}"))
    }

    fn list_folder(&self, folder_id: &str) -> Result<Vec<FileMeta>, String> {
        self.folders
            .lock()
            .unwrap()
            .get(folder_id)
            .map(|f| f.files.clone())
            .ok_or_else(|| format!("unknown folder {folder_id}"))
    }

    fn append_to_document(&self, id: &str, text: &str) -> Result<u64, String> {
        self.append_document_with_receipt(id,text).map(|r|r.revision)
    }

    fn append_document_with_receipt(&self, id: &str, text: &str) -> Result<AppendEffect, String> {
        let mut docs=self.docs.lock().unwrap();
        let d=docs.get_mut(id).ok_or_else(||format!("unknown document {id}"))?;
        let mut effects=self.effects.lock().unwrap();
        effects.next=effects.next.checked_add(1).ok_or("fixture mutation identity exhausted")?;
        let token=format!("fixture-append-{}",effects.next);
        let tokens=effects.by_document.entry(id.into()).or_default();
        tokens.resize(d.revisions.len(),String::new());
        // A document with no revisions yet reads as empty: that empty body is revision 0,
        // so the first append is revision 1 and has a predecessor to revert to.
        if d.revisions.is_empty() {
            d.revisions.push(String::new());
            tokens.resize(1, String::new());
        }
        let next=format!("{}{}",d.revisions.last().cloned().unwrap_or_default(),text);
        d.revisions.push(next);
        tokens.push(token.clone());
        Ok(AppendEffect {revision:(d.revisions.len()-1) as u64,token})
    }
    fn append_sheet_with_receipt(&self, id: &str, text: &str) -> Result<AppendEffect, String> {
        self.append_document_with_receipt(id,text)
    }

    fn revert_document(&self, doc_id: &str, revision: u64) -> Result<(), String> {
        let mut docs = self.docs.lock().unwrap();
        let d = docs
            .get_mut(doc_id)
            .ok_or_else(|| format!("unknown document {doc_id}"))?;
        let idx = revision as usize;
        if idx >= d.revisions.len() {
            return Err(format!("unknown revision {revision} for document {doc_id}"));
        }
        d.revisions.truncate(idx + 1);
        if let Some(tokens)=self.effects.lock().unwrap().by_document.get_mut(doc_id) { tokens.truncate(idx+1); }
        Ok(())
    }

    fn revert_sheet_with_receipt(&self, id: &str, revision: u64, token: &str) -> Result<RevertOutcome, String> {
        self.revert_document_with_receipt(id,revision,token)
    }
    fn revert_document_with_receipt(&self, id: &str, revision: u64, token: &str) -> Result<RevertOutcome, String> {
        let mut docs=self.docs.lock().unwrap();
        let d=docs.get_mut(id).ok_or_else(||format!("unknown document {id}"))?;
        let mut effects=self.effects.lock().unwrap();
        let tokens=effects.by_document.get_mut(id).ok_or("document has no mutation receipt")?;
        if token.is_empty() || tokens.last().map(String::as_str)!=Some(token)
            || d.revisions.len().checked_sub(2).map(|n|n as u64)!=Some(revision) {
            return Ok(RevertOutcome::Conflict);
        }
        d.revisions.truncate(revision as usize+1);
        tokens.truncate(revision as usize+1);
        Ok(RevertOutcome::Reverted)
    }

    fn user_can_read(&self, user: &str, unit: &str) -> bool {
        // `folder/file` composite keys are the DataSetTracking sub-resource form.
        if let Some((folder, file)) = unit.split_once('/') {
            return self
                .folders
                .lock()
                .unwrap()
                .get(folder)
                .and_then(|f| f.file_readers.get(file))
                .is_some_and(|readers| readers.iter().any(|u| u == user));
        }
        if let Some(d) = self.docs.lock().unwrap().get(unit) {
            return d.readers.iter().any(|u| u == user);
        }
        self.folders
            .lock()
            .unwrap()
            .get(unit)
            .is_some_and(|f| f.readers.iter().any(|u| u == user))
    }
}
