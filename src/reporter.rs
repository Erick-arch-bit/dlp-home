use crate::db::Database;
use std::sync::Arc;

pub async fn export_csv(db: Arc<Database>) -> Result<String, sqlx::Error> {
    let rows = sqlx::query_as::<_, (i64, chrono::DateTime<chrono::Utc>, String, String, String, Option<String>)>(
        "SELECT id, timestamp, severity, pattern_name, description, context FROM alerts ORDER BY timestamp DESC LIMIT 10000"
    )
    .fetch_all(db.pool())
    .await?;

    let mut csv = String::from("ID,Timestamp,Severity,Pattern,Description,Context\n");
    for (id, ts, severity, pattern, description, context) in rows {
        let ctx = context.unwrap_or_default().replace(',', " ").replace('\n', " ");
        csv.push_str(&format!("{},{},{},{},{},{}\n",
            id, ts.format("%Y-%m-%d %H:%M:%S"), severity, pattern,
            description.replace(',', " ").replace('\n', " "), ctx));
    }

    Ok(csv)
}

#[derive(serde::Serialize)]
pub struct WeeklyReport {
    pub total_scans: i64,
    pub total_alerts: i64,
    pub critical_alerts: i64,
    pub high_alerts: i64,
    pub medium_alerts: i64,
    pub low_alerts: i64,
    pub top_categories: Vec<(String, i64)>,
}

pub async fn generate_weekly_report(db: Arc<Database>) -> Result<WeeklyReport, sqlx::Error> {
    let week_ago = chrono::Utc::now() - chrono::Duration::days(7);

    let total_alerts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE timestamp >= $1"
    )
    .bind(week_ago)
    .fetch_one(db.pool())
    .await?;

    let critical: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE timestamp >= $1 AND severity = 'critical'"
    )
    .bind(week_ago)
    .fetch_one(db.pool())
    .await?;

    let high: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE timestamp >= $1 AND severity = 'high'"
    )
    .bind(week_ago)
    .fetch_one(db.pool())
    .await?;

    let medium: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE timestamp >= $1 AND severity = 'medium'"
    )
    .bind(week_ago)
    .fetch_one(db.pool())
    .await?;

    let low: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE timestamp >= $1 AND severity = 'low'"
    )
    .bind(week_ago)
    .fetch_one(db.pool())
    .await?;

    let total_scans: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM file_scans WHERE timestamp >= $1"
    )
    .bind(week_ago)
    .fetch_one(db.pool())
    .await?;

    let categories: Vec<(String, i64)> = sqlx::query_as(
        "SELECT pattern_name, COUNT(*) as cnt FROM alerts WHERE timestamp >= $1 GROUP BY pattern_name ORDER BY cnt DESC LIMIT 10"
    )
    .bind(week_ago)
    .fetch_all(db.pool())
    .await?;

    Ok(WeeklyReport {
        total_scans,
        total_alerts,
        critical_alerts: critical,
        high_alerts: high,
        medium_alerts: medium,
        low_alerts: low,
        top_categories: categories,
    })
}
