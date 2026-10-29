// Один домен в heartbeat-снимке агента: последний результат reconcile
// по этой записи конфига (протокол POST /api/agents/heartbeat).
export interface AgentDomain {
    name: string;
    cert_id: number;
    target: string;
    destination: string;
    status: 'ok' | 'error';
    stage?: string;
    error?: string;
    serial?: string;
    expiry_ms?: number;
    last_check_ms?: number;
}

// Строка GET /api/agents: последний снимок агента + имена аккаунта/владельца
// и вычисленный сервером online.
export interface AgentStatus {
    id: number;
    agent_uuid: string;
    hostname: string;
    version: string;
    os: string;
    arch: string;
    schedule: string;
    heartbeat_interval_sec: number;
    status: 'ok' | 'error';
    online: boolean;
    error_count: number;
    last_error?: string;
    last_error_at?: number;
    soonest_expiry_ms?: number;
    domains: AgentDomain[];
    ip: string;
    first_seen: number;
    last_seen: number;
    account_name: string;
    owner_login: string;
}
