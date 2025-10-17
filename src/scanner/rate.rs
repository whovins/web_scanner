// src/rate.rs
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::{Semaphore, Mutex};
use tokio::time::interval;

/// 글로벌 레이트리밋 + 글로벌 동시성 + 호스트당 동시성
pub struct Limiters {
    token_bucket: Arc<Semaphore>,
    pub global_concurrency: Arc<Semaphore>,
    per_host: Arc<Mutex<HashMap<IpAddr, Arc<Semaphore>>>>,
    per_host_limit: usize,
}

impl Limiters {
    pub fn new(rate_per_sec: u32, global_concurrency: usize, per_host_limit: usize) -> Self {
        let bucket = Arc::new(Semaphore::new(0));
        let g = Arc::new(Semaphore::new(global_concurrency));
        let per = Arc::new(Mutex::new(HashMap::new()));
        let me = Self { token_bucket: bucket.clone(), global_concurrency: g, per_host: per, per_host_limit };
        me.spawn_pump(rate_per_sec);
        me
    }

    fn spawn_pump(&self, rate_per_sec: u32) {
        let bucket = self.token_bucket.clone();
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                bucket.add_permits(rate_per_sec as usize);
            }
        });
    }

    async fn acquire_token(&self) { let _ = self.token_bucket.acquire().await.unwrap(); }

    async fn acquire_per_host(&self, ip: &IpAddr) {
        let sem = {
            let mut map = self.per_host.lock().await;
            map.entry(*ip).or_insert_with(|| Arc::new(Semaphore::new(self.per_host_limit))).clone()
        };
        let _ = sem.acquire().await.unwrap();
    }

    pub async fn acquire(&self, ip: &IpAddr) {
        self.acquire_token().await;
        self.acquire_per_host(ip).await;
    }
}
