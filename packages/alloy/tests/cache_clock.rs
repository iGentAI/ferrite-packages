use ferrite_alloy_harness::alloy::{
    cache::{cache_key, CacheEnvelope},
    ctx::{fill_key, lease_key},
    CacheLife, CacheStore, TagStore,
};
use ferrite_app_test::{TestEnv, TestHarness};
use std::sync::atomic::{AtomicUsize, Ordering};

async fn env() -> TestEnv {
    TestHarness::new()
        .with_store("cache")
        .with_ape("tags")
        .manual_clock(100_000)
        .build()
        .await
}

fn cache(env: &TestEnv, clocked: bool) -> CacheStore {
    let cache = CacheStore::new(env.store("cache"), TagStore::new(env.ape("tags")));
    if clocked {
        let ctx = env.context();
        cache.with_clock(move || ctx.now_ms())
    } else {
        cache
    }
}

async fn envelope(env: &TestEnv) -> CacheEnvelope {
    let bytes = env
        .store("cache")
        .get(cache_key("slow-fill", b"cart").as_bytes())
        .await
        .unwrap()
        .unwrap();
    CacheEnvelope::decode(&bytes).unwrap()
}

#[tokio::test]
async fn slow_cold_fill_uses_completion_clock_while_timestamp_only_api_is_unchanged() {
    for clocked in [false, true] {
        let env = env().await;
        let calls = AtomicUsize::new(0);
        cache(&env, clocked)
            .get(
                "slow-fill",
                b"cart",
                &["cart-test".into()],
                CacheLife::Seconds,
                env.now_ms(),
                || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    env.advance(1_500);
                    Ok(1_u64)
                },
            )
            .await
            .unwrap();
        let stored = envelope(&env).await;
        assert_eq!(
            stored.created_at_ms,
            if clocked { 101_500 } else { 100_000 }
        );
        let second = cache(&env, clocked)
            .get(
                "slow-fill",
                b"cart",
                &["cart-test".into()],
                CacheLife::Seconds,
                env.now_ms(),
                || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(2_u64)
                },
            )
            .await
            .unwrap();
        assert_eq!(second.value, if clocked { 1 } else { 2 });
        assert_eq!(calls.load(Ordering::SeqCst), if clocked { 1 } else { 2 });
        env.shutdown().await;
    }
}

#[tokio::test]
async fn stale_refresh_and_expired_fill_each_start_a_new_fresh_window() {
    for age in [1_500, 60_001] {
        let env = env().await;
        cache(&env, true)
            .get(
                "slow-fill",
                b"cart",
                &["cart-test".into()],
                CacheLife::Seconds,
                env.now_ms(),
                || async { Ok(1_u64) },
            )
            .await
            .unwrap();
        env.advance(age);
        cache(&env, true)
            .get(
                "slow-fill",
                b"cart",
                &["cart-test".into()],
                CacheLife::Seconds,
                env.now_ms(),
                || async {
                    env.advance(1_500);
                    Ok(2_u64)
                },
            )
            .await
            .unwrap();
        let stored = envelope(&env).await;
        assert_eq!(stored.created_at_ms, env.now_ms());
        assert_eq!(stored.stale_at_ms, env.now_ms() + 1_000);
        assert_eq!(stored.expire_at_ms, env.now_ms() + 60_000);
        let next = cache(&env, true)
            .get(
                "slow-fill",
                b"cart",
                &["cart-test".into()],
                CacheLife::Seconds,
                env.now_ms(),
                || async {
                    panic!("immediate read repeated a completed fill");
                    #[allow(unreachable_code)]
                    Ok(3_u64)
                },
            )
            .await
            .unwrap();
        assert_eq!(next.value, 2);
        env.shutdown().await;
    }
}

#[tokio::test]
async fn completion_timestamp_never_recaptures_tags_changed_during_load() {
    let env = env().await;
    let tags = vec!["cart-test".into()];
    cache(&env, true)
        .get(
            "slow-fill",
            b"cart",
            &tags,
            CacheLife::Seconds,
            env.now_ms(),
            || async {
                env.advance(1_500);
                TagStore::new(env.ape("tags")).advance(&tags).await.unwrap();
                Ok(1_u64)
            },
        )
        .await
        .unwrap();
    let next = cache(&env, true)
        .get(
            "slow-fill",
            b"cart",
            &tags,
            CacheLife::Seconds,
            env.now_ms(),
            || async { Ok(2_u64) },
        )
        .await
        .unwrap();
    assert_eq!(
        next.value, 2,
        "new timestamp must not bless data observed before invalidation"
    );
    env.shutdown().await;
}

#[tokio::test]
async fn fill_and_refresh_leases_start_at_acquisition_and_expire_during_slow_load() {
    for refresh in [false, true] {
        let env = env().await;
        if refresh {
            cache(&env, true)
                .get(
                    "slow-fill",
                    b"cart",
                    &[],
                    CacheLife::Seconds,
                    env.now_ms(),
                    || async { Ok(1_u64) },
                )
                .await
                .unwrap();
        }
        let old_request_time = env.now_ms();
        env.advance(if refresh { 1_500 } else { 9_000 });
        let key = cache_key("slow-fill", b"cart");
        let lease = if refresh {
            lease_key(&key)
        } else {
            fill_key(&key)
        };
        let before_expiry = if refresh { 29_000 } else { 2_000 };
        let remaining = if refresh { 1_001 } else { 8_001 };
        cache(&env, true)
            .get(
                "slow-fill",
                b"cart",
                &[],
                CacheLife::Seconds,
                old_request_time,
                || async {
                    env.advance(before_expiry);
                    assert!(
                        env.store("cache")
                            .get(lease.as_bytes())
                            .await
                            .unwrap()
                            .is_some(),
                        "lease must use acquisition clock, not stale request time"
                    );
                    env.advance(remaining);
                    assert!(
                        env.store("cache")
                            .get(lease.as_bytes())
                            .await
                            .unwrap()
                            .is_none(),
                        "slow load must not extend its lease"
                    );
                    Ok(2_u64)
                },
            )
            .await
            .unwrap();
        env.shutdown().await;
    }
}
