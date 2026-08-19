use crate::domain::{
    Finding, FindingKind, FindingState, Fingerprint, LicensePolicy, Observation, Remediation,
    Revision, Scope, Severity, Target, TargetId, TargetKind, Validity,
};
use crate::engine::FakeEngine;
use crate::github::{FakeGithub, Github};
use postgres::{Client, NoTls};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  default_revision TEXT NOT NULL,
  baseline_ready BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS baseline_fps (
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  problem_id TEXT NOT NULL,
  location_key TEXT NOT NULL,
  PRIMARY KEY (target_id, target, problem_id, location_key)
);
CREATE TABLE IF NOT EXISTS findings (
  fp TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  problem_id TEXT NOT NULL,
  location_key TEXT NOT NULL,
  state TEXT NOT NULL,
  kind TEXT NOT NULL,
  last_revision TEXT,
  package TEXT,
  manifest TEXT,
  fixed_version TEXT
);
CREATE TABLE IF NOT EXISTS observations (
  fp TEXT NOT NULL REFERENCES findings(fp) ON DELETE CASCADE,
  engine TEXT NOT NULL,
  problem_id TEXT NOT NULL,
  location_key TEXT NOT NULL,
  kind TEXT NOT NULL,
  package TEXT,
  manifest TEXT,
  fixed_version TEXT,
  message TEXT NOT NULL,
  PRIMARY KEY (fp, engine)
);
CREATE TABLE IF NOT EXISTS remediations (
  id BIGSERIAL PRIMARY KEY,
  target TEXT NOT NULL,
  manifest TEXT NOT NULL,
  package TEXT NOT NULL,
  fixed_version TEXT NOT NULL,
  pr_number BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS remediation_fps (
  remediation_id BIGINT NOT NULL REFERENCES remediations(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  problem_id TEXT NOT NULL,
  location_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS github_checks (
  repo TEXT NOT NULL,
  pr BIGINT NOT NULL,
  conclusion TEXT NOT NULL,
  summary TEXT NOT NULL,
  annotations JSONB NOT NULL DEFAULT '[]',
  PRIMARY KEY (repo, pr)
);
CREATE TABLE IF NOT EXISTS github_prs (
  repo TEXT NOT NULL,
  number BIGINT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  files JSONB NOT NULL DEFAULT '[]',
  PRIMARY KEY (repo, number)
);
CREATE TABLE IF NOT EXISTS github_meta (
  k TEXT PRIMARY KEY,
  v BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS fake_obs (
  scan_key TEXT NOT NULL,
  payload JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS fake_fail (
  scan_key TEXT PRIMARY KEY
);
-- Deliveries HQ has already acted on, so a redelivery is not a second Gate run.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  delivery_id TEXT PRIMARY KEY,
  seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Which installation covers which repo, as the App's installation events report.
CREATE TABLE IF NOT EXISTS app_installations (
  repo TEXT PRIMARY KEY,
  installation_id BIGINT NOT NULL
);
-- Scans waiting for, or held by, a worker.
CREATE TABLE IF NOT EXISTS scan_jobs (
  id BIGSERIAL PRIMARY KEY,
  target TEXT NOT NULL,
  revision TEXT NOT NULL,
  engines TEXT NOT NULL,
  purpose TEXT NOT NULL,
  pr_number BIGINT,
  base_revision TEXT,
  state TEXT NOT NULL DEFAULT 'queued',
  claimed_by TEXT,
  note TEXT,
  queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  heartbeat TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS scan_jobs_queued ON scan_jobs (state, queued_at);
-- Findings HQ has already announced, so a re-Scan does not announce them again.
CREATE TABLE IF NOT EXISTS announced_findings (
  fp TEXT PRIMARY KEY,
  announced_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- What the advisory source said about a package, cached. A NULL advisory_id
-- means "asked, and it is clean" — worth remembering too.
-- What an Operator has decided about licenses.
CREATE TABLE IF NOT EXISTS license_policy (
  rule TEXT NOT NULL,
  license TEXT NOT NULL,
  PRIMARY KEY (rule, license)
);
-- The dependency inventory as of a Target's last Scan, so an SBOM can be
-- written without a checkout.
CREATE TABLE IF NOT EXISTS target_packages (
  target TEXT NOT NULL,
  revision TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT,
  manifest TEXT NOT NULL,
  scope TEXT NOT NULL,
  PRIMARY KEY (target, manifest, name)
);
CREATE TABLE IF NOT EXISTS package_advisories (
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  advisory_id TEXT,
  summary TEXT,
  fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (ecosystem, name)
);
-- Public exploitability intel, cached so one Scan does not fetch per Finding.
CREATE TABLE IF NOT EXISTS cve_intel (
  cve TEXT PRIMARY KEY,
  epss DOUBLE PRECISION,
  percentile DOUBLE PRECISION,
  known_exploited BOOLEAN NOT NULL DEFAULT FALSE,
  fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Added after the first release; run after every CREATE above.
ALTER TABLE observations ADD COLUMN IF NOT EXISTS line INTEGER;
ALTER TABLE github_checks ADD COLUMN IF NOT EXISTS head_sha TEXT NOT NULL DEFAULT '';
ALTER TABLE github_prs ADD COLUMN IF NOT EXISTS head TEXT NOT NULL DEFAULT '';
ALTER TABLE github_prs ADD COLUMN IF NOT EXISTS base TEXT NOT NULL DEFAULT '';
ALTER TABLE observations ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE targets ADD COLUMN IF NOT EXISTS gate_dev_scope BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS epss DOUBLE PRECISION;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS epss_percentile DOUBLE PRECISION;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS known_exploited BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validity TEXT NOT NULL DEFAULT 'unverified';
"#;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub targets: HashMap<String, Target>,
    pub findings: HashMap<String, Finding>,
    pub remediations: Vec<Remediation>,
    pub fake: FakeBundle,
    #[serde(default)]
    pub license_policy: LicensePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FakeBundle {
    pub observations: HashMap<String, Vec<Observation>>,
    pub fail: Vec<String>,
}

impl State {
    pub fn finding(&self, fp: &Fingerprint) -> Option<&Finding> {
        self.findings.get(&fp.display())
    }

    pub fn finding_mut(&mut self, fp: &Fingerprint) -> Option<&mut Finding> {
        self.findings.get_mut(&fp.display())
    }
}

pub struct Store {
    url: String,
    schema: String,
    pub state: State,
}

impl Store {
    pub fn open(url: &str, schema: &str) -> Result<Self, String> {
        validate_ident(schema)?;
        let mut client = connect(url)?;
        client
            .batch_execute(&format!(
                "CREATE SCHEMA IF NOT EXISTS {schema}; SET search_path TO {schema}"
            ))
            .map_err(|e| e.to_string())?;
        client.batch_execute(DDL).map_err(|e| e.to_string())?;
        let state = load(&mut client)?;
        Ok(Self {
            url: url.to_string(),
            schema: schema.to_string(),
            state,
        })
    }

    /// Persist HQ's own state, plus whatever the GitHub backend keeps locally,
    /// in one transaction.
    pub fn save(&self, github: &dyn Github) -> Result<(), String> {
        let mut client = connect(&self.url)?;
        client
            .batch_execute(&format!("SET search_path TO {}", self.schema))
            .map_err(|e| e.to_string())?;
        let mut tx = client.transaction().map_err(|e| e.to_string())?;
        persist(&mut tx, &self.state)?;
        github.persist(&mut tx)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// The fake backend's rows from an earlier invocation. Only the fake backend
    /// has any; a real one reads GitHub instead.
    pub fn load_fake_github(&self) -> Result<FakeGithub, String> {
        let mut client = self.client()?;
        FakeGithub::load(&mut client)
    }

    /// Has HQ already acted on this delivery?
    pub fn delivery_seen(&self, delivery_id: &str) -> Result<bool, String> {
        let mut client = self.client()?;
        let rows = client
            .query(
                "SELECT 1 FROM webhook_deliveries WHERE delivery_id = $1",
                &[&delivery_id],
            )
            .map_err(|e| e.to_string())?;
        Ok(!rows.is_empty())
    }

    /// Record a delivery as handled. Called after the work succeeded, so a
    /// delivery that failed can be retried by GitHub.
    pub fn remember_delivery(&self, delivery_id: &str) -> Result<(), String> {
        let mut client = self.client()?;
        client
            .execute(
                "INSERT INTO webhook_deliveries (delivery_id) VALUES ($1)
                 ON CONFLICT (delivery_id) DO NOTHING",
                &[&delivery_id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn record_installation(&self, repo: &str, installation_id: u64) -> Result<(), String> {
        let mut client = self.client()?;
        client
            .execute(
                "INSERT INTO app_installations (repo, installation_id) VALUES ($1,$2)
                 ON CONFLICT (repo) DO UPDATE SET installation_id = EXCLUDED.installation_id",
                &[&repo, &(installation_id as i64)],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn forget_installation(&self, repo: &str) -> Result<(), String> {
        let mut client = self.client()?;
        client
            .execute("DELETE FROM app_installations WHERE repo = $1", &[&repo])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Repos the App can reach, as its installation events reported them.
    pub fn reachable_repos(&self) -> Result<Vec<(String, u64)>, String> {
        let mut client = self.client()?;
        Ok(client
            .query(
                "SELECT repo, installation_id FROM app_installations ORDER BY repo",
                &[],
            )
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| (r.get(0), r.get::<_, i64>(1) as u64))
            .collect())
    }

    /// Intel HQ has already fetched and that is still fresh. Anything older
    /// than the TTL is not returned, so it is refetched rather than trusted.
    pub fn cached_intel(
        &self,
        cves: &[String],
        ttl: std::time::Duration,
    ) -> Result<HashMap<String, crate::intel::CveIntel>, String> {
        if cves.is_empty() {
            return Ok(HashMap::new());
        }
        let mut client = self.client()?;
        let seconds = ttl.as_secs_f64();
        let rows = client
            .query(
                "SELECT cve, epss, percentile, known_exploited FROM cve_intel
                 WHERE cve = ANY($1) AND fetched_at > now() - make_interval(secs => $2)",
                &[&cves, &seconds],
            )
            .map_err(|e| e.to_string())?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<_, String>(0),
                    crate::intel::CveIntel {
                        epss: r.get(1),
                        percentile: r.get(2),
                        known_exploited: r.get(3),
                    },
                )
            })
            .collect())
    }

    /// Remember what a source said. Not part of HQ's state — it is a cache of
    /// somebody else's facts, and `save` must never truncate it.
    pub fn cache_intel(
        &self,
        intel: &HashMap<String, crate::intel::CveIntel>,
    ) -> Result<(), String> {
        if intel.is_empty() {
            return Ok(());
        }
        let mut client = self.client()?;
        for (cve, data) in intel {
            client
                .execute(
                    "INSERT INTO cve_intel (cve, epss, percentile, known_exploited, fetched_at)
                     VALUES ($1,$2,$3,$4, now())
                     ON CONFLICT (cve) DO UPDATE SET epss = EXCLUDED.epss,
                       percentile = EXCLUDED.percentile,
                       known_exploited = EXCLUDED.known_exploited,
                       fetched_at = EXCLUDED.fetched_at",
                    &[cve, &data.epss, &data.percentile, &data.known_exploited],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Remember what a Target depends on, so an SBOM can be written later
    /// without a checkout. Replaces the previous Scan's inventory wholesale — a
    /// removed dependency must not linger in the SBOM.
    pub fn record_inventory(
        &self,
        target: &str,
        revision: &str,
        packages: &[crate::inventory::Package],
    ) -> Result<(), String> {
        let mut client = self.client()?;
        let mut tx = client.transaction().map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM target_packages WHERE target = $1", &[&target])
            .map_err(|e| e.to_string())?;
        for p in packages {
            tx.execute(
                "INSERT INTO target_packages (target, revision, ecosystem, name, version, manifest, scope)
                 VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (target, manifest, name) DO NOTHING",
                &[
                    &target,
                    &revision,
                    &p.ecosystem,
                    &p.name,
                    &p.version,
                    &p.manifest,
                    &p.scope.as_str(),
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// A Target's inventory as of its last Scan, and which Revision that was.
    pub fn inventory(
        &self,
        target: &str,
    ) -> Result<Option<(String, Vec<crate::inventory::Package>)>, String> {
        let mut client = self.client()?;
        let rows = client
            .query(
                "SELECT revision, ecosystem, name, version, manifest, scope FROM target_packages
                 WHERE target = $1 ORDER BY manifest, name",
                &[&target],
            )
            .map_err(|e| e.to_string())?;
        if rows.is_empty() {
            return Ok(None);
        }
        let revision: String = rows[0].get(0);
        let packages = rows
            .into_iter()
            .map(|r| crate::inventory::Package {
                ecosystem: r.get(1),
                name: r.get(2),
                version: r.get(3),
                manifest: r.get(4),
                scope: Scope::parse(r.get(5)).unwrap_or_default(),
            })
            .collect();
        Ok(Some((revision, packages)))
    }

    /// Postgres' clock, formatted the way an SBOM wants it. HQ has no time
    /// dependency of its own and does not need one for this.
    pub fn now_rfc3339(&self) -> Result<String, String> {
        let mut client = self.client()?;
        let row = client
            .query_one(
                "SELECT to_char(now() at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
                &[],
            )
            .map_err(|e| e.to_string())?;
        Ok(row.get(0))
    }

    /// What HQ already asked about these packages, if the answer is still
    /// fresh. `None` in the map means "asked, and clean".
    pub fn cached_advisories(
        &self,
        ecosystem: &str,
        names: &[String],
        ttl: std::time::Duration,
    ) -> Result<HashMap<String, Option<crate::malicious::Advisory>>, String> {
        if names.is_empty() {
            return Ok(HashMap::new());
        }
        let mut client = self.client()?;
        let seconds = ttl.as_secs_f64();
        let rows = client
            .query(
                "SELECT name, advisory_id, summary FROM package_advisories
                 WHERE ecosystem = $1 AND name = ANY($2)
                   AND fetched_at > now() - make_interval(secs => $3)",
                &[&ecosystem, &names, &seconds],
            )
            .map_err(|e| e.to_string())?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let id: Option<String> = r.get(1);
                let summary: Option<String> = r.get(2);
                (
                    r.get::<_, String>(0),
                    id.map(|id| crate::malicious::Advisory {
                        id,
                        summary: summary.unwrap_or_default(),
                    }),
                )
            })
            .collect())
    }

    pub fn cache_advisories(
        &self,
        ecosystem: &str,
        answers: &HashMap<String, Option<crate::malicious::Advisory>>,
    ) -> Result<(), String> {
        if answers.is_empty() {
            return Ok(());
        }
        let mut client = self.client()?;
        for (name, advisory) in answers {
            let id = advisory.as_ref().map(|a| a.id.clone());
            let summary = advisory.as_ref().map(|a| a.summary.clone());
            client
                .execute(
                    "INSERT INTO package_advisories (ecosystem, name, advisory_id, summary, fetched_at)
                     VALUES ($1,$2,$3,$4, now())
                     ON CONFLICT (ecosystem, name) DO UPDATE SET advisory_id = EXCLUDED.advisory_id,
                       summary = EXCLUDED.summary, fetched_at = EXCLUDED.fetched_at",
                    &[&ecosystem, name, &id, &summary],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Which of these Findings have already been announced. Not part of HQ's
    /// state — announcing twice is the failure mode, and `save` must never
    /// truncate the record that prevents it.
    pub fn already_announced(
        &self,
        fps: &[String],
    ) -> Result<std::collections::HashSet<String>, String> {
        if fps.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let mut client = self.client()?;
        let rows = client
            .query(
                "SELECT fp FROM announced_findings WHERE fp = ANY($1)",
                &[&fps],
            )
            .map_err(|e| e.to_string())?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    pub fn remember_announced(&self, fps: &[String]) -> Result<(), String> {
        let mut client = self.client()?;
        for fp in fps {
            client
                .execute(
                    "INSERT INTO announced_findings (fp) VALUES ($1) ON CONFLICT DO NOTHING",
                    &[fp],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// The Scan queue in this schema.
    pub fn queue(&self) -> crate::queue::Queue {
        crate::queue::Queue::new(&self.url, &self.schema)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    fn client(&self) -> Result<Client, String> {
        let mut client = connect(&self.url)?;
        client
            .batch_execute(&format!("SET search_path TO {}", self.schema))
            .map_err(|e| e.to_string())?;
        Ok(client)
    }

    pub fn fake_engine(&self, name: &str) -> FakeEngine {
        FakeEngine {
            name: name.to_string(),
            by_key: self.state.fake.observations.clone(),
            fail: self.state.fake.fail.iter().cloned().collect(),
        }
    }
}

fn connect(url: &str) -> Result<Client, String> {
    Client::connect(url, NoTls).map_err(|e| format!("postgres: {e}"))
}

fn validate_ident(s: &str) -> Result<(), String> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("bad schema name {s}"));
    }
    Ok(())
}

fn persist(tx: &mut postgres::Transaction<'_>, state: &State) -> Result<(), String> {
    tx.batch_execute(
        "TRUNCATE observations, baseline_fps, remediation_fps, remediations, findings, targets,
                  fake_obs, fake_fail, license_policy CASCADE",
    )
    .map_err(|e| e.to_string())?;

    for (rule, licenses) in [
        ("allow", &state.license_policy.allow),
        ("deny", &state.license_policy.deny),
        ("review", &state.license_policy.review),
    ] {
        for license in licenses {
            tx.execute(
                "INSERT INTO license_policy (rule, license) VALUES ($1,$2)
                 ON CONFLICT DO NOTHING",
                &[&rule, license],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    for t in state.targets.values() {
        tx.execute(
            "INSERT INTO targets (id, kind, default_revision, baseline_ready, gate_dev_scope)
             VALUES ($1,$2,$3,$4,$5)",
            &[
                &t.id.0,
                &kind_str(t.kind),
                &t.default_revision.0,
                &t.baseline_ready,
                &t.gate_dev_scope,
            ],
        )
        .map_err(|e| e.to_string())?;
        for fp in &t.baseline {
            tx.execute(
                "INSERT INTO baseline_fps (target_id, target, problem_id, location_key) VALUES ($1,$2,$3,$4)",
                &[&t.id.0, &fp.target, &fp.problem_id, &fp.location_key],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    for (key, f) in &state.findings {
        tx.execute(
            "INSERT INTO findings (fp, target, problem_id, location_key, state, kind, last_revision, package, manifest, fixed_version,
                                   severity, epss, epss_percentile, known_exploited, validity)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            &[
                key,
                &f.fingerprint.target,
                &f.fingerprint.problem_id,
                &f.fingerprint.location_key,
                &state_str(f.state),
                &fkind_str(f.kind),
                &f.last_revision.as_ref().map(|r| r.0.clone()),
                &f.package,
                &f.manifest,
                &f.fixed_version,
                &f.severity.as_str(),
                &f.epss,
                &f.epss_percentile,
                &f.known_exploited,
                &f.validity.as_str(),
            ],
        )
        .map_err(|e| e.to_string())?;
        for o in &f.observations {
            tx.execute(
                "INSERT INTO observations (fp, engine, problem_id, location_key, kind, package, manifest, fixed_version, message, line, scope, severity)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                &[
                    key,
                    &o.engine,
                    &o.problem_id,
                    &o.location_key,
                    &fkind_str(o.kind),
                    &o.package,
                    &o.manifest,
                    &o.fixed_version,
                    &o.message,
                    &o.line.map(|l| l as i32),
                    &o.scope.as_str(),
                    &o.severity.as_str(),
                ],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    for r in &state.remediations {
        let id: i64 = tx
            .query_one(
                "INSERT INTO remediations (target, manifest, package, fixed_version, pr_number)
                 VALUES ($1,$2,$3,$4,$5) RETURNING id",
                &[
                    &r.target,
                    &r.manifest,
                    &r.package,
                    &r.fixed_version,
                    &(r.pr_number as i64),
                ],
            )
            .map_err(|e| e.to_string())?
            .get(0);
        for fp in &r.finding_fingerprints {
            tx.execute(
                "INSERT INTO remediation_fps (remediation_id, target, problem_id, location_key) VALUES ($1,$2,$3,$4)",
                &[&id, &fp.target, &fp.problem_id, &fp.location_key],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    for (k, obs) in &state.fake.observations {
        for o in obs {
            let payload = serde_json::to_value(o).map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO fake_obs (scan_key, payload) VALUES ($1,$2)",
                &[k, &payload],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    for k in &state.fake.fail {
        tx.execute("INSERT INTO fake_fail (scan_key) VALUES ($1)", &[k])
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn load(client: &mut Client) -> Result<State, String> {
    let mut state = State::default();

    for row in client
        .query(
            "SELECT rule, license FROM license_policy ORDER BY license",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        let license: String = row.get(1);
        match row.get::<_, String>(0).as_str() {
            "allow" => state.license_policy.allow.push(license),
            "deny" => state.license_policy.deny.push(license),
            _ => state.license_policy.review.push(license),
        }
    }

    for row in client
        .query(
            "SELECT id, kind, default_revision, baseline_ready, gate_dev_scope FROM targets",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        let id: String = row.get(0);
        let mut t = Target {
            id: TargetId(id.clone()),
            kind: parse_kind(row.get(1))?,
            default_revision: Revision(row.get(2)),
            baseline_ready: row.get(3),
            baseline: vec![],
            gate_dev_scope: row.get(4),
        };
        for b in client
            .query(
                "SELECT target, problem_id, location_key FROM baseline_fps WHERE target_id = $1",
                &[&id],
            )
            .map_err(|e| e.to_string())?
        {
            t.baseline.push(Fingerprint {
                target: b.get(0),
                problem_id: b.get(1),
                location_key: b.get(2),
            });
        }
        state.targets.insert(id, t);
    }

    for row in client
        .query(
            "SELECT fp, target, problem_id, location_key, state, kind, last_revision, package,
                    manifest, fixed_version, severity, epss, epss_percentile, known_exploited,
                    validity
             FROM findings",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        let fp_key: String = row.get(0);
        let last: Option<String> = row.get(6);
        let mut finding = Finding {
            fingerprint: Fingerprint {
                target: row.get(1),
                problem_id: row.get(2),
                location_key: row.get(3),
            },
            state: parse_state(row.get(4))?,
            kind: parse_fkind(row.get(5))?,
            observations: vec![],
            last_revision: last.map(Revision),
            package: row.get(7),
            manifest: row.get(8),
            fixed_version: row.get(9),
            severity: Severity::parse(row.get(10)).unwrap_or_default(),
            epss: row.get(11),
            epss_percentile: row.get(12),
            known_exploited: row.get(13),
            validity: Validity::parse(row.get(14)).unwrap_or_default(),
        };
        for o in client
            .query(
                "SELECT engine, problem_id, location_key, kind, package, manifest, fixed_version, message, line, scope, severity FROM observations WHERE fp = $1",
                &[&fp_key],
            )
            .map_err(|e| e.to_string())?
        {
            finding.observations.push(Observation {
                engine: o.get(0),
                problem_id: o.get(1),
                location_key: o.get(2),
                kind: parse_fkind(o.get(3))?,
                package: o.get(4),
                manifest: o.get(5),
                fixed_version: o.get(6),
                message: o.get(7),
                line: o.get::<_, Option<i32>>(8).map(|l| l as u32),
                scope: Scope::parse(o.get(9)).unwrap_or_default(),
                severity: Severity::parse(o.get(10)).unwrap_or_default(),
                // The credential itself is never read back: it was never stored.
                secret: None,
            });
        }
        state.findings.insert(fp_key, finding);
    }

    for row in client
        .query(
            "SELECT id, target, manifest, package, fixed_version, pr_number FROM remediations",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        let id: i64 = row.get(0);
        let mut r = Remediation {
            target: row.get(1),
            manifest: row.get(2),
            package: row.get(3),
            fixed_version: row.get(4),
            finding_fingerprints: vec![],
            pr_number: row.get::<_, i64>(5) as u64,
        };
        for f in client
            .query(
                "SELECT target, problem_id, location_key FROM remediation_fps WHERE remediation_id = $1",
                &[&id],
            )
            .map_err(|e| e.to_string())?
        {
            r.finding_fingerprints.push(Fingerprint {
                target: f.get(0),
                problem_id: f.get(1),
                location_key: f.get(2),
            });
        }
        state.remediations.push(r);
    }

    for row in client
        .query("SELECT scan_key, payload FROM fake_obs", &[])
        .map_err(|e| e.to_string())?
    {
        let k: String = row.get(0);
        let payload: serde_json::Value = row.get(1);
        if let Ok(obs) = serde_json::from_value::<Observation>(payload) {
            state.fake.observations.entry(k).or_default().push(obs);
        }
    }
    for row in client
        .query("SELECT scan_key FROM fake_fail", &[])
        .map_err(|e| e.to_string())?
    {
        state.fake.fail.push(row.get(0));
    }
    Ok(state)
}

fn kind_str(k: TargetKind) -> &'static str {
    match k {
        TargetKind::Github => "github",
        TargetKind::Image => "image",
    }
}

fn parse_kind(s: String) -> Result<TargetKind, String> {
    match s.as_str() {
        "github" => Ok(TargetKind::Github),
        "image" => Ok(TargetKind::Image),
        other => Err(format!("bad target kind {other}")),
    }
}

fn state_str(s: FindingState) -> &'static str {
    match s {
        FindingState::Open => "open",
        FindingState::Fixed => "fixed",
        FindingState::Dismissed => "dismissed",
    }
}

fn parse_state(s: String) -> Result<FindingState, String> {
    match s.as_str() {
        "open" => Ok(FindingState::Open),
        "fixed" => Ok(FindingState::Fixed),
        "dismissed" => Ok(FindingState::Dismissed),
        other => Err(format!("bad state {other}")),
    }
}

fn fkind_str(k: FindingKind) -> &'static str {
    match k {
        FindingKind::Sca => "sca",
        FindingKind::Secret => "secret",
        FindingKind::Sast => "sast",
        FindingKind::Iac => "iac",
        FindingKind::License => "license",
        FindingKind::Malicious => "malicious",
    }
}

fn parse_fkind(s: String) -> Result<FindingKind, String> {
    match s.as_str() {
        "sca" => Ok(FindingKind::Sca),
        "secret" => Ok(FindingKind::Secret),
        "sast" => Ok(FindingKind::Sast),
        "iac" => Ok(FindingKind::Iac),
        "license" => Ok(FindingKind::License),
        "malicious" => Ok(FindingKind::Malicious),
        other => Err(format!("bad finding kind {other}")),
    }
}
