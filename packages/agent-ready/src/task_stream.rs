//! Task notifications for hosts that can hold a real subscription transport.
//! The callback re-authorizes and reads every selected task on every tick.
use super::event_stream::SUBSCRIPTION_META as SUBSCRIPTION_ID;
use super::tasks::{client_supports, TaskError};
use ferrite_app::serde_json::{json, Value};

pub struct TaskSubscription {
    id: Value,
    task_ids: Vec<String>,
    previous: Vec<Value>,
    acknowledged: bool,
    ended: bool,
}
impl TaskSubscription {
    pub fn new(id: Value, params: &Value) -> Result<Self, TaskError> {
        if !id.is_string() && !id.is_i64() && !id.is_u64() {
            return Err(TaskError::invalid());
        }
        if !client_supports(params) {
            return Err(TaskError::missing_capability());
        }
        let ids = params["notifications"]["taskIds"]
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 32)
            .ok_or_else(TaskError::invalid)?;
        let mut task_ids = Vec::new();
        for value in ids {
            let id = value
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 128)
                .ok_or_else(TaskError::invalid)?;
            if !task_ids.iter().any(|existing| existing == id) {
                task_ids.push(id.to_string());
            }
        }
        Ok(Self {
            id,
            task_ids,
            previous: Vec::new(),
            acknowledged: false,
            ended: false,
        })
    }
    pub fn ended(&self) -> bool {
        self.ended
    }
    pub fn close(&mut self) -> Value {
        self.ended = true;
        json!({"jsonrpc":"2.0","id":self.id,"result":{"resultType":"complete","_meta":{SUBSCRIPTION_ID:self.id}}})
    }
    pub async fn next<F, Fut>(&mut self, get: F) -> Result<Vec<Value>, TaskError>
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Result<Value, TaskError>>,
    {
        if self.ended {
            return Ok(Vec::new());
        }
        let mut snapshots = Vec::new();
        // Authorize the complete requested set before exposing the acknowledgement.
        for id in &self.task_ids {
            let mut task = get(id.clone()).await?;
            task.as_object_mut()
                .ok_or_else(TaskError::storage)?
                .remove("resultType");
            if task["taskId"] != *id {
                return Err(TaskError::storage());
            }
            snapshots.push(task);
        }
        let mut messages = Vec::new();
        if !self.acknowledged {
            messages.push(json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"notifications":{"taskIds":self.task_ids},"_meta":{SUBSCRIPTION_ID:self.id}}}));
            self.acknowledged = true;
        }
        for (index, task) in snapshots.iter().enumerate() {
            if self.previous.get(index) != Some(task) {
                let mut params = task.clone();
                params["_meta"] = json!({SUBSCRIPTION_ID:self.id});
                messages
                    .push(json!({"jsonrpc":"2.0","method":"notifications/tasks","params":params}));
            }
        }
        let complete = snapshots.iter().all(|task| {
            matches!(
                task["status"].as_str(),
                Some("completed" | "cancelled" | "failed")
            )
        });
        self.previous = snapshots;
        if complete {
            messages.push(self.close());
        }
        Ok(messages)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn params() -> Value {
        json!({"notifications":{"taskIds":["one","two"]},"_meta":{"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}})
    }
    fn task(id: &str, status: &str) -> Value {
        json!({"taskId":id,"status":status,"resultType":"complete"})
    }
    #[tokio::test]
    async fn reauthorization_rejects_an_entire_batch_before_exposing_changes() {
        let mut stream = TaskSubscription::new(json!(1), &params()).unwrap();
        let first = stream
            .next(|id| async move { Ok(task(&id, "working")) })
            .await
            .unwrap();
        assert_eq!(first.len(), 3);
        assert!(stream
            .next(|id| async move {
                if id == "two" {
                    Err(TaskError::unavailable())
                } else {
                    Ok(task(&id, "completed"))
                }
            })
            .await
            .is_err());
        // No new task data was published when the second requested identity failed.
        assert_eq!(stream.previous[0]["status"], "working");
        stream.close();
        assert!(stream
            .next(|_| async { panic!("closed observer must release its read source") })
            .await
            .unwrap()
            .is_empty());
    }
    #[tokio::test]
    async fn unchanged_snapshots_are_silent_and_terminal_releases_polling() {
        let mut stream = TaskSubscription::new(json!(2), &params()).unwrap();
        stream
            .next(|id| async move { Ok(task(&id, "working")) })
            .await
            .unwrap();
        assert!(stream
            .next(|id| async move { Ok(task(&id, "working")) })
            .await
            .unwrap()
            .is_empty());
        let final_frames = stream
            .next(|id| async move { Ok(task(&id, "completed")) })
            .await
            .unwrap();
        assert_eq!(final_frames.len(), 3);
        assert_eq!(final_frames[2]["id"], 2);
        assert!(stream.ended());
        assert!(stream
            .next(|_| async { panic!("terminal observer must not read again") })
            .await
            .unwrap()
            .is_empty());
    }
}
