//! The Scan queue.
//!
//! A Scan is slow — a clone and a subprocess per Engine — and a webhook has
//! seconds to answer. So a delivery enqueues a job and returns; workers claim
//! jobs and do the work. Claiming uses `FOR UPDATE SKIP LOCKED`, so two workers
//! never get the same job, and a job whose worker died stops being anyone's.

use postgres::{Client, NoTls};
use std::time::Duration;

/// Why a Scan was queued, which decides what HQ does with the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Gate a pull request: post the Check Run when the Scan lands.
    Gate,
    /// Scan the Target's default Revision: update Findings, maybe Remediate.
    Default,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Gate => "gate",
            Purpose::Default => "default",
        }
    }

    pub fn parse(s: &str) -> Purpose {
        match s {
            "gate" => Purpose::Gate,
            _ => Purpose::Default,
        }
    }
}

/// A Scan somebody asked for.
#[derive(Debug, Clone)]
pub struct JobRequest {
    pub target: String,
    pub revision: String,
    pub engines: Vec<String>,
    pub purpose: Purpose,
    pub pr_number: Option<u64>,
    pub base_revision: Option<String>,
}

/// A Scan a worker has claimed.
#[derive(Debug, Clone)]
pub struct Job {
    pub id: i64,
    pub target: String,
    pub revision: String,
    pub engines: Vec<String>,
    pub purpose: Purpose,
    pub pr_number: Option<u64>,
    pub base_revision: Option<String>,
}

/// A job as an Operator sees it.
#[derive(Debug, Clone)]
pub struct JobRow {
    pub id: i64,
    pub target: String,
    pub revision: String,
    pub engines: Vec<String>,
    pub purpose: Purpose,
    pub state: String,
    pub claimed_by: Option<String>,
    pub took_secs: Option<f64>,
    pub waited_secs: Option<f64>,
    pub note: Option<String>,
}

pub struct Queue {
    url: String,
    schema: String,
}

impl Queue {
    pub fn new(url: &str, schema: &str) -> Self {
        Self {
            url: url.to_string(),
            schema: schema.to_string(),
        }
    }

    /// Another handle on the same queue, for a thread that needs its own
    /// connection.
    pub fn new_like(other: &Queue) -> Self {
        Self::new(&other.url, &other.schema)
    }

    fn client(&self) -> Result<Client, String> {
        let mut client = Client::connect(&self.url, NoTls).map_err(|e| format!("postgres: {e}"))?;
        client
            .batch_execute(&format!("SET search_path TO {}", self.schema))
            .map_err(|e| e.to_string())?;
        Ok(client)
    }

    /// Queue a Scan. An identical Scan already waiting is not queued twice — a
    /// PR pushed to three times in a minute is still one Scan of the head.
    pub fn enqueue(&self, request: &JobRequest) -> Result<i64, String> {
        let mut client = self.client()?;
        let engines = request.engines.join(",");
        let pr = request.pr_number.map(|n| n as i64);
        if let Some(row) = client
            .query_opt(
                "SELECT id FROM scan_jobs
                 WHERE state = 'queued' AND target = $1 AND revision = $2
                   AND purpose = $3 AND pr_number IS NOT DISTINCT FROM $4",
                &[
                    &request.target,
                    &request.revision,
                    &request.purpose.as_str(),
                    &pr,
                ],
            )
            .map_err(|e| e.to_string())?
        {
            return Ok(row.get(0));
        }
        let row = client
            .query_one(
                "INSERT INTO scan_jobs (target, revision, engines, purpose, pr_number, base_revision)
                 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
                &[
                    &request.target,
                    &request.revision,
                    &engines,
                    &request.purpose.as_str(),
                    &pr,
                    &request.base_revision,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(row.get(0))
    }

    /// Take the oldest queued job, if there is one. `SKIP LOCKED` is what keeps
    /// two workers off the same job.
    pub fn claim(&self, worker: &str) -> Result<Option<Job>, String> {
        let mut client = self.client()?;
        let row = client
            .query_opt(
                "UPDATE scan_jobs SET state = 'running', claimed_by = $1,
                        started_at = now(), heartbeat = now()
                 WHERE id = (
                   SELECT id FROM scan_jobs WHERE state = 'queued'
                   ORDER BY queued_at, id FOR UPDATE SKIP LOCKED LIMIT 1
                 )
                 RETURNING id, target, revision, engines, purpose, pr_number, base_revision",
                &[&worker],
            )
            .map_err(|e| e.to_string())?;
        Ok(row.map(|r| Job {
            id: r.get(0),
            target: r.get(1),
            revision: r.get(2),
            engines: r
                .get::<_, String>(3)
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            purpose: Purpose::parse(r.get(4)),
            pr_number: r.get::<_, Option<i64>>(5).map(|n| n as u64),
            base_revision: r.get(6),
        }))
    }

    /// Say the worker is still alive, so its job is not reclaimed under it.
    pub fn heartbeat(&self, id: i64) -> Result<(), String> {
        let mut client = self.client()?;
        client
            .execute(
                "UPDATE scan_jobs SET heartbeat = now() WHERE id = $1",
                &[&id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn finish(&self, id: i64, state: &str, note: Option<&str>) -> Result<(), String> {
        let mut client = self.client()?;
        client
            .execute(
                "UPDATE scan_jobs SET state = $2, finished_at = now(), note = $3 WHERE id = $1",
                &[&id, &state, &note],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// A job whose worker stopped reporting becomes claimable again. Without
    /// this, one crashed worker strands a Scan forever.
    pub fn requeue_stale(&self, lease: Duration) -> Result<u64, String> {
        let mut client = self.client()?;
        let seconds = lease.as_secs_f64();
        client
            .execute(
                "UPDATE scan_jobs SET state = 'queued', claimed_by = NULL, started_at = NULL
                 WHERE state = 'running'
                   AND heartbeat < now() - make_interval(secs => $1)",
                &[&seconds],
            )
            .map_err(|e| e.to_string())
    }

    pub fn pending(&self) -> Result<i64, String> {
        let mut client = self.client()?;
        let row = client
            .query_one(
                "SELECT count(*) FROM scan_jobs WHERE state IN ('queued','running')",
                &[],
            )
            .map_err(|e| e.to_string())?;
        Ok(row.get(0))
    }

    pub fn list(&self, limit: i64) -> Result<Vec<JobRow>, String> {
        let mut client = self.client()?;
        let rows = client
            .query(
                "SELECT id, target, revision, engines, purpose, state, claimed_by,
                        extract(epoch from (finished_at - started_at))::float8,
                        extract(epoch from (coalesce(started_at, now()) - queued_at))::float8,
                        note
                 FROM scan_jobs ORDER BY id DESC LIMIT $1",
                &[&limit],
            )
            .map_err(|e| e.to_string())?;
        Ok(rows
            .into_iter()
            .map(|r| JobRow {
                id: r.get(0),
                target: r.get(1),
                revision: r.get(2),
                engines: r
                    .get::<_, String>(3)
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                purpose: Purpose::parse(r.get(4)),
                state: r.get(5),
                claimed_by: r.get(6),
                took_secs: r.get(7),
                waited_secs: r.get(8),
                note: r.get(9),
            })
            .collect())
    }
}

/// Serialises HQ's write path.
///
/// The Store loads all of HQ's state and writes it back, so two writers would
/// clobber each other. Workers do the slow, read-only half in parallel and take
/// this lock only to fold the result in. It is a Postgres advisory lock, so it
/// holds across processes, not just threads.
pub struct WriteLock {
    client: Option<Client>,
    key: i64,
}

impl WriteLock {
    pub fn acquire(url: &str, schema: &str) -> Result<Self, String> {
        let mut client = Client::connect(url, NoTls).map_err(|e| format!("postgres: {e}"))?;
        let key = lock_key(schema);
        client
            .query("SELECT pg_advisory_lock($1)", &[&key])
            .map_err(|e| e.to_string())?;
        Ok(Self {
            client: Some(client),
            key,
        })
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        if let Some(mut client) = self.client.take() {
            let _ = client.query("SELECT pg_advisory_unlock($1)", &[&self.key]);
        }
    }
}

/// One lock per schema, so test schemas never wait on each other.
fn lock_key(schema: &str) -> i64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in schema.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash as i64
}
