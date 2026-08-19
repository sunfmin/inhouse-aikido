//! Workers: the processes that actually run queued Scans.
//!
//! A worker does the slow half of a Scan (clone, Engines) with nothing locked,
//! then takes HQ's write lock only to fold the result in. That is what lets
//! several Scans run at once even though the Store rewrites all of HQ's state on
//! every save.

use crate::cli::open_hq_for;
use crate::queue::{Job, Purpose, Queue, WriteLock};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub database_url: String,
    pub schema: String,
    pub github_backend: String,
    pub intel_backend: String,
    /// How many Scans may run at once.
    pub workers: usize,
    /// How long a claimed job may go without a heartbeat before another worker
    /// may take it. Must outlast the slowest Engine.
    pub lease: Duration,
    /// How long to wait before asking for work again when the queue is empty.
    pub poll: Duration,
}

impl WorkerConfig {
    pub fn queue(&self) -> Queue {
        Queue::new(&self.database_url, &self.schema)
    }
}

/// Run the pool until the queue drains (`drain`) or forever.
///
/// Returns how many jobs this pool finished, which is what `hq work` reports
/// and what tests assert on.
pub fn run_pool(config: WorkerConfig, drain: bool, stop: Option<Arc<AtomicBool>>) -> usize {
    let done = Arc::new(AtomicUsize::new(0));
    let stop = stop.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let mut handles = Vec::new();
    for index in 0..config.workers.max(1) {
        let config = config.clone();
        let done = done.clone();
        let stop = stop.clone();
        handles.push(std::thread::spawn(move || {
            let name = format!("{}-{index}", std::process::id());
            let queue = config.queue();
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                // A worker that died mid-Scan left its job claimed. Hand it back
                // before asking for new work, or the Scan is stranded forever.
                let _ = queue.requeue_stale(config.lease);
                match queue.claim(&name) {
                    Ok(Some(job)) => {
                        let id = job.id;
                        let outcome =
                            with_heartbeat(&queue, id, config.lease, || run_job(&config, &job));
                        match outcome {
                            Ok(Done::Finished(note)) => {
                                let _ = queue.finish(id, "done", Some(&note));
                            }
                            Ok(Done::Discarded(note)) => {
                                let _ = queue.finish(id, "discarded", Some(&note));
                            }
                            Err(e) => {
                                let _ = queue.finish(id, "failed", Some(&e));
                            }
                        }
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => {
                        if drain {
                            break;
                        }
                        std::thread::sleep(config.poll);
                    }
                    Err(_) => std::thread::sleep(config.poll),
                }
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    done.load(Ordering::Relaxed)
}

enum Done {
    Finished(String),
    /// Nothing to do — the Target stopped being Enrolled, say. Not a failure.
    Discarded(String),
}

/// Keep saying the job is alive while `work` runs, so a Scan that legitimately
/// takes ten minutes is not reclaimed out from under it.
fn with_heartbeat<T>(queue: &Queue, id: i64, lease: Duration, work: impl FnOnce() -> T) -> T {
    let stop = Arc::new(AtomicBool::new(false));
    let beat = {
        let stop = stop.clone();
        let queue = Queue::new_like(queue);
        let every = (lease / 3).max(Duration::from_millis(200));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let _ = queue.heartbeat(id);
                let mut waited = Duration::ZERO;
                while waited < every && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(100));
                    waited += Duration::from_millis(100);
                }
            }
        })
    };
    let out = work();
    stop.store(true, Ordering::Relaxed);
    let _ = beat.join();
    out
}

fn run_job(config: &WorkerConfig, job: &Job) -> Result<Done, String> {
    let mut hq = open_hq_for(
        &config.database_url,
        &config.schema,
        &config.github_backend,
        &config.intel_backend,
    )?;
    if !hq.tracks(&job.target) {
        return Ok(Done::Discarded(format!("{} is not Enrolled", job.target)));
    }
    if job.purpose == Purpose::Gate && !hq.baseline_ready(&job.target) {
        return Ok(Done::Discarded(format!(
            "{} has no Baseline yet",
            job.target
        )));
    }
    let names: Vec<&str> = job.engines.iter().map(String::as_str).collect();
    let engines = hq.select_engines(&names);
    // The slow half. Nothing is locked and nothing is written, so other workers
    // are scanning their own Targets at the same time.
    let outcome = hq.observe(&job.target, Some(&job.revision), &engines, None)?;
    drop(hq);

    // The fast half. One writer at a time, across processes.
    let _lock = WriteLock::acquire(&config.database_url, &config.schema)?;
    let mut hq = open_hq_for(
        &config.database_url,
        &config.schema,
        &config.github_backend,
        &config.intel_backend,
    )?;
    if !hq.tracks(&job.target) {
        return Ok(Done::Discarded(format!(
            "{} stopped being Enrolled mid-Scan",
            job.target
        )));
    }
    let note = match job.purpose {
        Purpose::Gate => {
            let pr = job.pr_number.ok_or("gate job has no PR number")?;
            hq.record_gate(&job.target, pr, &job.revision, &outcome)?
        }
        Purpose::Default => {
            if !outcome.failed_engines.is_empty() {
                return Err(format!(
                    "engines failed: {}",
                    outcome.failed_engines.join(",")
                ));
            }
            hq.record(&job.target, Some(&job.revision), &outcome, false)?
        }
    };
    hq.save()?;
    Ok(Done::Finished(note))
}
