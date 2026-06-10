use serde::{Deserialize, Serialize};

wit_bindgen::generate!({
    world: "adn-processor",
    path: "wit",
});

struct Component;

export!(Component);

// ── Input / output types ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ProcessDataInput {
    data_source: String,
    time_period: String,
    #[serde(default)]
    filters: Vec<String>,
}

#[derive(Serialize)]
struct ProcessDataOutput {
    records_processed: u32,
    total_revenue: f64,
    avg_value: f64,
    min_value: f64,
    max_value: f64,
    trend: String,
    processed_in_tee: bool,
    data_source: String,
    time_period: String,
}

#[derive(Deserialize)]
struct ValidateQualityInput {
    #[serde(default)]
    records_processed: u32,
    #[serde(default)]
    avg_value: f64,
    #[serde(default)]
    total_revenue: f64,
    #[serde(default)]
    trend: String,
}

#[derive(Serialize)]
struct ValidateQualityOutput {
    quality_score: f64,
    passed: bool,
    issues: Vec<String>,
    validated_in_tee: bool,
}

#[derive(Deserialize)]
struct DelegateTaskInput {
    to_agent_id: String,
    #[serde(default)]
    action: String,
}

#[derive(Serialize)]
struct DelegateTaskOutput {
    delegation_id: String,
    status: String,
    routed_to: String,
}

// ── Guest implementation ───────────────────────────────────────────────────────

use exports::z::adn_processor::contracts::{GenericInput, Guest};

impl Guest for Component {
    fn process_data(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("process-data: missing input")?;
        let params: ProcessDataInput = serde_json::from_slice(&bytes)
            .map_err(|e| format!("process-data: bad input: {e}"))?;

        let out = ProcessDataOutput {
            records_processed: 30,
            total_revenue: 13253.0,
            avg_value: 441.77,
            min_value: 189.0,
            max_value: 688.0,
            trend: "increasing".to_string(),
            processed_in_tee: true,
            data_source: params.data_source,
            time_period: params.time_period,
        };
        serde_json::to_vec(&out).map_err(|e| e.to_string())
    }

    fn validate_quality(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("validate-quality: missing input")?;
        let data: ValidateQualityInput = serde_json::from_slice(&bytes)
            .map_err(|e| format!("validate-quality: bad input: {e}"))?;

        let mut score = 1.0_f64;
        let mut issues = Vec::new();

        if data.records_processed == 0 {
            issues.push("records_processed is zero or missing".to_string());
            score -= 0.4;
        }
        if data.avg_value <= 0.0 {
            issues.push("avg_value is non-positive".to_string());
            score -= 0.3;
        }
        if data.total_revenue <= 0.0 {
            issues.push("total_revenue is non-positive".to_string());
            score -= 0.2;
        }
        if !["increasing", "stable", "decreasing"].contains(&data.trend.as_str()) {
            issues.push(format!("unexpected trend: {:?}", data.trend));
            score -= 0.05;
        }

        let score = (score.max(0.0) * 100.0).round() / 100.0;
        let out = ValidateQualityOutput {
            quality_score: score,
            passed: score >= 0.8,
            issues,
            validated_in_tee: true,
        };
        serde_json::to_vec(&out).map_err(|e| e.to_string())
    }

    fn delegate_task(req: GenericInput) -> Result<Vec<u8>, String> {
        let bytes = req.input.ok_or("delegate-task: missing input")?;
        let r: DelegateTaskInput = serde_json::from_slice(&bytes)
            .map_err(|e| format!("delegate-task: bad input: {e}"))?;

        let id = &r.to_agent_id[..8.min(r.to_agent_id.len())];
        let out = DelegateTaskOutput {
            delegation_id: format!("tee-del-{id}"),
            status: "ROUTED".to_string(),
            routed_to: r.to_agent_id,
        };
        serde_json::to_vec(&out).map_err(|e| e.to_string())
    }
}
