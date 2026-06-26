use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Alert {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub severity: String,
    pub category: String,
    pub source: String,
    pub description: String,
    pub data: Option<String>,
    pub hostname: Option<String>,
    pub pid: Option<i32>,
    pub process_name: Option<String>,
    pub username: Option<String>,
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSummary {
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub unresolved: i64,
    pub by_category: Vec<CategoryCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryCount {
    pub category: String,
    pub count: i64,
}

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn insert_alert(
        &self,
        severity: &str,
        category: &str,
        source: &str,
        description: &str,
        data: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        let hostname = hostname();
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO alerts (severity, category, source, description, data, hostname)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id"
        )
        .bind(severity)
        .bind(category)
        .bind(source)
        .bind(description)
        .bind(data)
        .bind(hostname)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    pub async fn insert_event(
        &self,
        event_type: &str,
        source: &str,
        detail: &str,
        data: Option<&serde_json::Value>,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO events (event_type, source, detail, data) VALUES ($1, $2, $3, $4) RETURNING id"
        )
        .bind(event_type)
        .bind(source)
        .bind(detail)
        .bind(data)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    pub async fn insert_file_scan(
        &self,
        file_path: &str,
        file_size: i64,
        matches_count: i32,
        scan_result: &str,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO file_scans (file_path, file_size, matches_count, scan_result)
             VALUES ($1, $2, $3, $4) RETURNING id"
        )
        .bind(file_path)
        .bind(file_size)
        .bind(matches_count)
        .bind(scan_result)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    pub async fn get_alerts(
        &self,
        limit: i64,
        offset: i64,
        severity: Option<&str>,
        category: Option<&str>,
        source: Option<&str>,
        resolved: Option<bool>,
    ) -> Result<Vec<Alert>, sqlx::Error> {
        let mut query = "SELECT * FROM alerts WHERE 1=1".to_string();
        let mut params: Vec<String> = vec![];

        if let Some(s) = severity {
            params.push(format!("severity = '{}'", s.replace('\'', "''")));
        }
        if let Some(c) = category {
            params.push(format!("category = '{}'", c.replace('\'', "''")));
        }
        if let Some(s) = source {
            params.push(format!("source = '{}'", s.replace('\'', "''")));
        }
        if let Some(r) = resolved {
            params.push(format!("resolved = {}", r));
        }

        if !params.is_empty() {
            query.push_str(" AND ");
            query.push_str(&params.join(" AND "));
        }

        query.push_str(" ORDER BY timestamp DESC LIMIT ");
        query.push_str(&limit.to_string());
        query.push_str(" OFFSET ");
        query.push_str(&offset.to_string());

        sqlx::query_as::<_, Alert>(&query)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn get_alert_summary(&self) -> Result<AlertSummary, sqlx::Error> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts")
            .fetch_one(&self.pool).await?;

        let critical: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE severity = 'critical'")
            .fetch_one(&self.pool).await?;

        let high: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE severity = 'high'")
            .fetch_one(&self.pool).await?;

        let medium: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE severity = 'medium'")
            .fetch_one(&self.pool).await?;

        let low: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE severity = 'low'")
            .fetch_one(&self.pool).await?;

        let unresolved: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE NOT resolved")
            .fetch_one(&self.pool).await?;

        let by_category: Vec<CategoryCount> = sqlx::query_as::<_, (String, i64)>(
            "SELECT category, COUNT(*) as count FROM alerts GROUP BY category ORDER BY count DESC"
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|(category, count)| CategoryCount { category, count })
        .collect();

        Ok(AlertSummary {
            total: total.0,
            critical: critical.0,
            high: high.0,
            medium: medium.0,
            low: low.0,
            unresolved: unresolved.0,
            by_category,
        })
    }

    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }

    pub async fn get_config(&self, key: &str) -> Result<Option<String>, sqlx::Error> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT value FROM config WHERE key = $1"
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn set_config(&self, key: &str, value: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO config (key, value, updated_at) VALUES ($1, $2, NOW())
             ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()"
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_all_config(&self) -> Result<std::collections::HashMap<String, String>, sqlx::Error> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT key, value FROM config ORDER BY key"
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    pub async fn resolve_alert(&self, alert_id: i64) -> Result<bool, sqlx::Error> {
        let r = sqlx::query("UPDATE alerts SET resolved = TRUE WHERE id = $1")
            .bind(alert_id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn get_resolved_alerts(&self, limit: i64, offset: i64) -> Result<Vec<Alert>, sqlx::Error> {
        sqlx::query_as::<_, Alert>(
            "SELECT * FROM alerts WHERE resolved = TRUE ORDER BY timestamp DESC LIMIT $1 OFFSET $2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn block_entity(&self, entity_type: &str, entity_value: &str, reason: &str) -> Result<String, sqlx::Error> {
        let r = sqlx::query(
            "INSERT INTO blocked_entities (entity_type, entity_value, reason) VALUES ($1, $2, $3) ON CONFLICT (entity_type, entity_value) DO UPDATE SET reason = $3"
        )
        .bind(entity_type)
        .bind(entity_value)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        if r.rows_affected() > 0 {
            Ok(format!("Bloqueado: {} = {}", entity_type, entity_value))
        } else {
            Ok("Ya estaba bloqueado.".to_string())
        }
    }

    pub async fn unblock_entity(&self, entity_id: i64) -> Result<bool, sqlx::Error> {
        let r = sqlx::query("DELETE FROM blocked_entities WHERE id = $1")
            .bind(entity_id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn list_blocked(&self) -> Result<Vec<BlockedEntity>, sqlx::Error> {
        sqlx::query_as::<_, BlockedEntity>(
            "SELECT id, entity_type, entity_value, reason, blocked_by, created_at FROM blocked_entities ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await
    }

    pub async fn is_entity_blocked(&self, entity_type: &str, entity_value: &str) -> Result<bool, sqlx::Error> {
        let r: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM blocked_entities WHERE entity_type = $1 AND entity_value = $2"
        )
        .bind(entity_type)
        .bind(entity_value)
        .fetch_optional(&self.pool)
        .await?;
        Ok(r.is_some())
    }

    pub async fn get_top_sources(&self, days: i32) -> Result<Vec<(String, i64)>, sqlx::Error> {
        sqlx::query_as(
            "SELECT source, COUNT(*)::bigint as cnt FROM alerts \
             WHERE timestamp >= NOW() - ($1 || ' days')::interval \
             GROUP BY source ORDER BY cnt DESC LIMIT 10"
        )
        .bind(days.to_string())
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_daily_trends(&self, days: i32) -> Result<Vec<(String, i64)>, sqlx::Error> {
        sqlx::query_as(
            "SELECT to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD') as day, COUNT(*)::bigint as cnt \
             FROM alerts WHERE timestamp >= NOW() - ($1 || ' days')::interval \
             GROUP BY day ORDER BY day"
        )
        .bind(days.to_string())
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_severity_trends(&self, days: i32) -> Result<Vec<(String, String, i64)>, sqlx::Error> {
        sqlx::query_as(
            "SELECT to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD') as day, severity, COUNT(*)::bigint as cnt \
             FROM alerts WHERE timestamp >= NOW() - ($1 || ' days')::interval \
             GROUP BY day, severity ORDER BY day"
        )
        .bind(days.to_string())
        .fetch_all(&self.pool)
        .await
    }
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BlockedEntity {
    pub id: i64,
    pub entity_type: String,
    pub entity_value: String,
    pub reason: Option<String>,
    pub blocked_by: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
