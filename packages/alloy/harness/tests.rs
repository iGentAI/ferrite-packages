use super::alloy::{app::serve, AlloyApp, Result};
use ferrite_app::tracing::instrument::WithSubscriber;
use ferrite_app::{serde_json, AppContext, IngressReply, IngressRequest};
use ferrite_app_test::{ingress, TestEnv, TestHarness};
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
};

struct FastGetApp;

impl AlloyApp for FastGetApp {
    const BUILD: &'static str = "fast-get-hedge";
    const SHELL: &'static str = "";

    async fn seed(_ctx: &AppContext) -> Result<()> {
        Ok(())
    }

    async fn request_budget(ctx: &AppContext, req: &IngressRequest) -> Option<IngressReply> {
        let mut store = ctx.store("data").unwrap();
        store.add(b"admissions", 1).await.unwrap();
        if store.get(b"deny").await.unwrap().is_some() {
            Some(IngressReply::to(req, 429, b"budget refused".to_vec()))
        } else {
            None
        }
    }

    async fn answer(ctx: &AppContext, req: &IngressRequest) -> Result<IngressReply> {
        let (calls, _) = ctx
            .store("data")
            .unwrap()
            .add(b"handler_calls", 1)
            .await
            .unwrap();
        Ok(IngressReply::to(
            req,
            200,
            format!("handler call {calls}").into_bytes(),
        ))
    }
}

async fn env() -> TestEnv {
    TestHarness::new()
        .with_queue("requests")
        .with_queue("replies")
        .with_queue("observed")
        .with_store("cache")
        .with_store("data")
        .with_ape("tags")
        .manual_clock(100_000)
        .build()
        .await
}

fn request() -> IngressRequest {
    let mut req = ingress::get("/fast");
    req.correlation_id = "same-gateway-delivery".into();
    req.reply_to = "observed".into();
    req.published_ms = 100_000;
    req.deadline_ms = 108_000;
    req
}

async fn send(env: &TestEnv, req: &IngressRequest) {
    env.queue("requests")
        .publish(&serde_json::to_vec(req).unwrap())
        .await
        .unwrap();
}

async fn receive(env: &TestEnv) -> IngressReply {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut replies = env.queue("observed");
        let lease = replies
            .poll_wait(1_000)
            .await
            .unwrap()
            .expect("published reply");
        let reply = serde_json::from_slice(&lease.payload).unwrap();
        replies.ack(lease.token).await.unwrap();
        reply
    })
    .await
    .expect("serve loop answered")
}

async fn count(env: &TestEnv, key: &[u8]) -> i64 {
    env.store("data").add(key, 0).await.unwrap().0
}

#[tokio::test]
async fn queued_fast_get_replays_but_each_delivery_still_meets_admission() {
    let env = env().await;
    let req = request();
    send(&env, &req).await;
    // No worker has polled yet. The gateway's 500 ms hedge timer can expire
    // while local admission/handler time remains zero on the manual clock.
    env.advance(700);
    send(&env, &req).await;
    env.run_app(serve::<FastGetApp>);
    let first = receive(&env).await;
    let replay = receive(&env).await;
    assert_eq!(first.status, 200);
    assert_eq!(replay.body, first.body);
    assert_eq!(count(&env, b"handler_calls").await, 1);
    assert_eq!(count(&env, b"admissions").await, 2);

    env.store("data").put(b"deny", b"yes").await.unwrap();
    send(&env, &req).await;
    assert_eq!(
        receive(&env).await.status,
        429,
        "cache must not bypass admission"
    );
    env.store("data").delete(b"deny").await.unwrap();
    send(&env, &req).await;
    assert_eq!(
        receive(&env).await.body,
        first.body,
        "refusal must not replace the reply"
    );
    assert_eq!(count(&env, b"handler_calls").await, 1);
    assert_eq!(count(&env, b"admissions").await, 4);
    env.shutdown().await;
}

async fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let length = stream.read_u32_le().await?;
    assert!(length < 1_000_000);
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(bytes).await
}

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl io::Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// The fault variant asks the real Forge service for an invalid operation,
// yielding a definite remote error rather than a fabricated application reply.
async fn held_queue_call(
    env: &TestEnv,
    service: &str,
    operation: &'static str,
    fail: bool,
) -> (
    AppContext,
    Arc<Notify>,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
) {
    let mut payload = env.payload().clone();
    let member = &mut payload.services.get_mut(service).unwrap().shards[0].members[0];
    let target = member.client_addr;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    member.client_addr = listener.local_addr().unwrap();
    let publishing = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let ready = publishing.clone();
    let gate = release.clone();
    // Hold the first actual SDK queue publication before forwarding it to
    // Forge. Store calls and handlers remain real; no reply is fabricated.
    let proxy = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut upstream = TcpStream::connect(target).await.unwrap();
        let mut held = false;
        while let Ok(bytes) = read_frame(&mut client).await {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if !held && value["op"] == operation {
                held = true;
                ready.notify_one();
                gate.notified().await;
                if fail {
                    value["op"] = "q.invalid-test-operation".into();
                }
            }
            write_frame(&mut upstream, &serde_json::to_vec(&value).unwrap())
                .await
                .unwrap();
            let reply = read_frame(&mut upstream).await.unwrap();
            if write_frame(&mut client, &reply).await.is_err() {
                break;
            }
        }
    });
    let ctx = AppContext::with_clock(payload, env.clock());
    (ctx, publishing, release, proxy)
}

async fn slow_event(log: &CapturedLog) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
            if text.contains("slow local request") {
                break text;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn fast_get_replays_when_reply_publication_triggers_a_hedge() {
    let env = env().await;
    let (ctx, publishing, release, proxy) =
        held_queue_call(&env, "observed", "q.publish", false).await;
    let log = CapturedLog::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    let app = tokio::spawn(serve::<FastGetApp>(ctx).with_subscriber(subscriber));
    let req = request();
    send(&env, &req).await;
    tokio::time::timeout(Duration::from_secs(5), publishing.notified())
        .await
        .unwrap();
    assert_eq!(count(&env, b"handler_calls").await, 1);
    env.advance(700);
    send(&env, &req).await;
    release.notify_one();
    let first = receive(&env).await;
    let replay = receive(&env).await;
    assert_eq!(first.status, 200);
    assert_eq!(replay.body, first.body);
    assert_eq!(count(&env, b"handler_calls").await, 1);
    assert_eq!(count(&env, b"admissions").await, 2);
    let text = slow_event(&log).await;
    assert_eq!(text.matches("slow local request").count(), 1);
    assert!(text.contains("cid=same-gateway-delivery"));
    assert!(text.contains("publish_ms=700"));
    assert!(text.contains("total_local_ms=700"));
    assert!(!text.contains("handler call"));
    assert!(!text.contains("/fast"));
    app.abort();
    let _ = app.await;
    proxy.abort();
    let _ = proxy.await;
    env.shutdown().await;
}

#[tokio::test]
async fn slow_publish_and_ack_errors_are_traced_without_changing_settlement() {
    for (service, operation, phase) in [
        ("observed", "q.publish", "publish"),
        ("requests", "q.ack", "ack"),
    ] {
        let env = env().await;
        let (ctx, reached, release, proxy) = held_queue_call(&env, service, operation, true).await;
        let log = CapturedLog::default();
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish();
        let app = tokio::spawn(serve::<FastGetApp>(ctx).with_subscriber(subscriber));
        send(&env, &request()).await;
        tokio::time::timeout(Duration::from_secs(5), reached.notified())
            .await
            .unwrap();
        env.advance(700);
        release.notify_one();
        let text = slow_event(&log).await;
        assert_eq!(text.matches("slow local request").count(), 1);
        assert!(
            text.contains(&format!("failed_phase=\"{phase}\"")),
            "{text}"
        );
        assert!(text.contains(&format!("{phase}_ms=700")), "{text}");
        assert!(!text.contains("handler call"));
        assert!(!text.contains("/fast"));
        if phase == "ack" {
            assert_eq!(
                receive(&env).await.status,
                200,
                "reply is published before failed ack"
            );
            assert!(tokio::time::timeout(Duration::from_secs(5), app)
                .await
                .unwrap()
                .unwrap()
                .is_err());
        } else {
            assert!(
                !app.is_finished(),
                "failed publication leaves the serve loop running"
            );
            assert!(env.queue("observed").poll_wait(1).await.unwrap().is_none());
            app.abort();
            let _ = app.await;
        }
        proxy.abort();
        let _ = proxy.await;
        env.shutdown().await;
    }
}

struct GatedGetApp;

impl AlloyApp for GatedGetApp {
    const BUILD: &'static str = "gated-get-hedge";
    const SHELL: &'static str = "";

    async fn seed(_ctx: &AppContext) -> Result<()> {
        Ok(())
    }

    async fn answer(ctx: &AppContext, req: &IngressRequest) -> Result<IngressReply> {
        if req.method == "STREAM_CLOSE" {
            return Ok(IngressReply::to(req, 204, b"closed".to_vec()));
        }
        if req.path == "/set-cookie" {
            ctx.store("data").unwrap().add(b"cookie_calls", 1).await.unwrap();
            let mut reply = IngressReply::to(req, 200, b"minted".to_vec());
            reply
                .headers
                .push(("set-cookie".into(), "__Host-session=secret; Secure; Path=/".into()));
            return Ok(reply);
        }
        let cookie = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| v.as_str());
        if cookie != Some("session=alice") {
            return Ok(IngressReply::to(req, 401, b"unauthorized".to_vec()));
        }
        let (calls, _) = ctx
            .store("data")
            .unwrap()
            .add(b"auth_calls", 1)
            .await
            .unwrap();
        Ok(IngressReply::to(
            req,
            200,
            format!("alice secret {calls}").into_bytes(),
        ))
    }
}

#[tokio::test]
async fn hedge_memory_binds_caller_envelope_and_skips_cookies_empty_cids_and_lifecycle() {
    let env = TestHarness::new()
        .with_queue("requests")
        .with_queue("replies")
        .with_queue("observed")
        .with_queue("attacker")
        .with_store("cache")
        .with_store("data")
        .with_ape("tags")
        .manual_clock(100_000)
        .build()
        .await;
    env.run_app(serve::<GatedGetApp>);

    let mut authed = ingress::get("/private");
    authed.correlation_id = "cid-1".into();
    authed.reply_to = "observed".into();
    authed.headers.push(("cookie".into(), "session=alice".into()));
    send(&env, &authed).await;
    let first = receive(&env).await;
    assert_eq!(first.status, 200);

    // Unauthenticated request reusing cid-1 must NOT recall Alice's reply.
    let mut unauthed = ingress::get("/private");
    unauthed.correlation_id = "cid-1".into();
    unauthed.reply_to = "observed".into();
    send(&env, &unauthed).await;
    let denied = receive(&env).await;
    assert_eq!(denied.status, 401, "unauthenticated reuse of cid-1 must not replay Alice's 200");

    // Different reply_to queue reusing cid-1 even with matching headers must NOT recall.
    let mut wrong_queue = authed.clone();
    wrong_queue.reply_to = "attacker".into();
    send(&env, &wrong_queue).await;
    let mut attacker_q = env.queue("attacker");
    let lease = tokio::time::timeout(Duration::from_secs(5), attacker_q.poll_wait(1_000))
        .await
        .unwrap()
        .unwrap()
        .expect("attacker reply");
    let wrong_q_reply: IngressReply = serde_json::from_slice(&lease.payload).unwrap();
    attacker_q.ack(lease.token).await.unwrap();
    assert_eq!(count(&env, b"auth_calls").await, 2, "different reply_to must run handler rather than recall");
    assert_eq!(wrong_q_reply.status, 200);

    // Lifecycle frame reusing cid-1 must NOT recall the GET reply.
    let mut close_frame = authed.clone();
    close_frame.method = "STREAM_CLOSE".into();
    send(&env, &close_frame).await;
    let closed = receive(&env).await;
    assert_eq!(closed.status, 204, "STREAM_CLOSE must reach A::answer rather than HedgeMemory");

    // Empty correlation_id must NEVER be cached or recalled.
    let mut empty_cid = ingress::get("/private");
    empty_cid.correlation_id = String::new();
    empty_cid.reply_to = "observed".into();
    empty_cid.headers.push(("cookie".into(), "session=alice".into()));
    send(&env, &empty_cid).await;
    assert_eq!(receive(&env).await.status, 200);
    let mut empty_cid_anon = ingress::get("/private");
    empty_cid_anon.correlation_id = String::new();
    empty_cid_anon.reply_to = "observed".into();
    send(&env, &empty_cid_anon).await;
    assert_eq!(receive(&env).await.status, 401);

    // Replies carrying Set-Cookie must NEVER be cached in HedgeMemory.
    let mut cookie_req = ingress::get("/set-cookie");
    cookie_req.correlation_id = "cid-cookie".into();
    cookie_req.reply_to = "observed".into();
    send(&env, &cookie_req).await;
    assert_eq!(receive(&env).await.status, 200);
    send(&env, &cookie_req).await;
    assert_eq!(receive(&env).await.status, 200);
    assert_eq!(count(&env, b"cookie_calls").await, 2, "Set-Cookie replies must not be cached in HedgeMemory");

    env.shutdown().await;
}
