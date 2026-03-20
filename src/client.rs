use serde::{Deserialize, Serialize};

use crate::error::{CyberbroError, Result};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AnalyzeRequest<'a> {
    text: &'a str,
    engines: &'a [String],
    ignore_cache: bool,
}

#[derive(Deserialize, Debug)]
pub struct AnalyzeResponse {
    pub analysis_id: String,
    pub link: String,
}

#[derive(Deserialize, Debug)]
pub struct CompleteResponse {
    pub complete: bool,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct CyberbroClient {
    base_url: String,
    api_prefix: String,
    http: reqwest::Client,
}

impl CyberbroClient {
    pub fn new(base_url: &str, api_prefix: &str, verify_tls: bool) -> Result<Self> {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(!verify_tls)
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_prefix: api_prefix.trim_matches('/').to_string(),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}/{}", self.base_url, self.api_prefix, path.trim_start_matches('/'))
    }

    /// Submit observables for analysis. The `text` field accepts one or more
    /// observables; the server extracts and classifies them automatically.
    pub async fn submit(
        &self,
        text: &str,
        engines: &[String],
        ignore_cache: bool,
    ) -> Result<AnalyzeResponse> {
        let body = AnalyzeRequest {
            text,
            engines,
            ignore_cache,
        };

        let resp = self
            .http
            .post(self.url("analyze"))
            .json(&body)
            .send()
            .await?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CyberbroError::ServerError { status, body });
        }

        Ok(resp.json::<AnalyzeResponse>().await?)
    }

    /// Poll whether an analysis is complete.
    pub async fn is_complete(&self, analysis_id: &str) -> Result<bool> {
        let resp = self
            .http
            .get(self.url(&format!("is_analysis_complete/{analysis_id}")))
            .send()
            .await?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CyberbroError::ServerError { status, body });
        }

        let data: CompleteResponse = resp.json().await?;
        Ok(data.complete)
    }

    /// Fetch the results of a completed analysis.
    pub async fn get_results(&self, analysis_id: &str) -> Result<Vec<serde_json::Value>> {
        let resp = self
            .http
            .get(self.url(&format!("results/{analysis_id}")))
            .send()
            .await?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CyberbroError::ServerError { status, body });
        }

        Ok(resp.json::<Vec<serde_json::Value>>().await?)
    }

    /// Submit, then poll until complete or timeout, then return results.
    pub async fn analyze_and_wait(
        &self,
        text: &str,
        engines: &[String],
        ignore_cache: bool,
        timeout_secs: u64,
        poll_interval_secs: u64,
        on_tick: impl Fn(),
    ) -> Result<(String, Vec<serde_json::Value>)> {
        let submission = self.submit(text, engines, ignore_cache).await?;
        let analysis_id = submission.analysis_id.clone();

        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(timeout_secs);

        loop {
            if self.is_complete(&analysis_id).await? {
                break;
            }

            if std::time::Instant::now() >= deadline {
                return Err(CyberbroError::Timeout(timeout_secs));
            }

            on_tick();
            tokio::time::sleep(std::time::Duration::from_secs(poll_interval_secs)).await;
        }

        let results = self.get_results(&analysis_id).await?;
        Ok((analysis_id, results))
    }
}
