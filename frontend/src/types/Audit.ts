export interface AuditLogRow {
    id: number;
    ts: number;
    actor_id: number | null;
    actor_label: string;
    actor_type: string;
    action: string;
    target_type: string | null;
    target_id: string | null;
    target_label: string | null;
    result: string;
    detail: string | null;
    ip: string | null;
}

export interface AuditPage {
    rows: AuditLogRow[];
    total: number;
}

export interface AuditQuery {
    actor?: number;
    action?: string;
    result?: string;
    from?: number;
    to?: number;
    limit?: number;
    offset?: number;
}
