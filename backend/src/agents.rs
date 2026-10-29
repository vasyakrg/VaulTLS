use chrono::Utc;
use rocket::get;
use rocket::post;
use rocket::serde::json::Json;
use rocket_okapi::openapi;
use serde_json::{json, Value};

use crate::auth::session_auth::Authenticated;
use crate::data::api::AgentHeartbeatRequest;
use crate::data::error::ApiError;
use crate::data::objects::{AgentHeartbeatIn, AgentRecord, AgentStatusRow, AppState};
use rocket::State;

/// Порог оффлайна: агент считается пропавшим, если не отмечался дольше
/// max(3×его интервал, 15 минут). Тройной запас покрывает пропущенный тик
/// heartbeat'а; минимум защищает короткие интервалы от секундного джиттера.
fn agent_online(last_seen: i64, interval_sec: i64, now_ms: i64) -> bool {
    let threshold_ms = (interval_sec.max(0) * 3).max(15 * 60) * 1000;
    now_ms.saturating_sub(last_seen) <= threshold_ms
}

/// Отчёт пишется в БД как есть, поэтому строки агента урезаются до разумной
/// длины — прошивка агента не должна раздувать таблицу.
fn clamp_str(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[openapi(tag = "Agents")]
#[post("/agents/heartbeat", format = "json", data = "<payload>")]
/// Приём heartbeat'а агента: последний снимок состояния (версия, домены,
/// ошибки). Только для сервисных токенов — идентичность агента определяется
/// аккаунтом токена; человек с теми же правами чужой агент не представит.
pub(crate) async fn agent_heartbeat(
    state: &State<AppState>,
    auth: Authenticated,
    payload: Json<AgentHeartbeatRequest>,
) -> Result<Json<Value>, ApiError> {
    let Some(service) = auth.claims.service.as_ref() else {
        return Err(ApiError::Forbidden(Some(
            "heartbeat is only accepted from service accounts".to_string(),
        )));
    };
    let req = payload.into_inner();
    let agent_uuid = req.agent_id.trim().to_string();
    if agent_uuid.is_empty() || agent_uuid.len() > 64 {
        return Err(ApiError::BadRequest(
            "agent_id must be 1..=64 characters".to_string(),
        ));
    }

    let now_ms = Utc::now().timestamp_millis();
    // Сводный статус считаем на сервере из отчёта, а не верим полю агента:
    // строка таблицы — то, что видит оператор на дашборде.
    let mut domains = req.domains;
    domains.truncate(200);
    let mut last_error: Option<String> = None;
    let mut last_error_at: Option<i64> = None;
    let mut soonest_expiry_ms: Option<i64> = None;
    for d in &domains {
        if d.status != "ok" {
            let text = format!("{}: {}", clamp_str(&d.name, 100), clamp_str(d.error.as_deref().unwrap_or("unknown error"), 400));
            if last_error.is_none() {
                last_error = Some(text.clone());
                last_error_at = d.last_check_ms.or(Some(now_ms));
            }
        }
        if let (Some(e), true) = (d.expiry_ms, d.status == "ok") {
            soonest_expiry_ms = Some(match soonest_expiry_ms {
                Some(cur) => cur.min(e),
                None => e,
            });
        }
    }
    let error_count = domains.iter().filter(|d| d.status != "ok").count() as i64;
    let status = if error_count > 0 { "error" } else { "ok" }.to_string();
    let domains_json = serde_json::to_string(&domains)
        .map_err(|e| ApiError::Other(format!("serialize domains: {e}")))?;

    let rec = AgentHeartbeatIn {
        account_id: service.account_id,
        agent_uuid,
        hostname: clamp_str(&req.hostname, 100),
        version: clamp_str(&req.version, 32),
        os: clamp_str(&req.os, 32),
        arch: clamp_str(&req.arch, 32),
        schedule: clamp_str(&req.schedule, 64),
        heartbeat_interval_sec: req.heartbeat_interval_sec.clamp(30, i64::MAX),
        status,
        error_count,
        last_error,
        last_error_at,
        soonest_expiry_ms,
        domains_json,
        ip: auth.ip.clone().unwrap_or_default(),
        now_ms,
    };
    state.db.upsert_agent_heartbeat(rec).await?;

    // Ретеншн: агенты, не отмечавшиеся месяц, убираем попутно с входящими
    // heartbeat'ами. Ошибка чистки не должна ронять сам heartbeat.
    if let Err(e) = state.db.prune_stale_agents(now_ms - 30 * 24 * 3600 * 1000).await {
        tracing::warn!("failed pruning stale agents: {e}");
    }
    Ok(Json(json!({ "ok": true })))
}

#[openapi(tag = "Agents")]
#[get("/agents")]
/// Список агентов для дашборда: последний снимок каждого агента плюс
/// вычисленный online. Доступен всем людям (включая обычных пользователей);
/// сервисным токенам запрещён — это людской обзор, не API для машин.
pub(crate) async fn get_agents(
    state: &State<AppState>,
    auth: Authenticated,
) -> Result<Json<Vec<AgentStatusRow>>, ApiError> {
    if auth.claims.is_service() {
        return Err(ApiError::Forbidden(None));
    }
    let now_ms = Utc::now().timestamp_millis();
    let rows = state.db.list_agents().await?;
    let out = rows
        .into_iter()
        .map(|r: AgentRecord| AgentStatusRow {
            online: agent_online(r.last_seen, r.heartbeat_interval_sec, now_ms),
            domains: serde_json::from_str(&r.domains_json)
                .unwrap_or_else(|_| Value::Array(Vec::new())),
            id: r.id,
            agent_uuid: r.agent_uuid,
            hostname: r.hostname,
            version: r.version,
            os: r.os,
            arch: r.arch,
            schedule: r.schedule,
            heartbeat_interval_sec: r.heartbeat_interval_sec,
            status: r.status,
            error_count: r.error_count,
            last_error: r.last_error,
            last_error_at: r.last_error_at,
            soonest_expiry_ms: r.soonest_expiry_ms,
            ip: r.ip,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            account_name: r.account_name,
            owner_login: r.owner_login,
        })
        .collect();
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::agent_online;

    #[test]
    fn online_within_triple_interval() {
        let now = 1_000_000_000_i64 * 1000;
        // interval 5m → порог 15m
        assert!(agent_online(now, 300, now - 15 * 60 * 1000));
        assert!(!agent_online(now, 300, now - 15 * 60 * 1000 - 1));
    }

    #[test]
    fn short_interval_still_gets_fifteen_minute_floor() {
        let now = 1_000_000_000_i64 * 1000;
        // interval 30s: 3×30s = 90s, но минимум 15 минут
        assert!(agent_online(now, 30, now - 14 * 60 * 1000));
        assert!(!agent_online(now, 30, now - 16 * 60 * 1000));
    }

    #[test]
    fn future_last_seen_never_offline() {
        let now = 1_000_000_000_i64 * 1000;
        assert!(agent_online(now, 300, now + 60 * 1000));
    }
}
