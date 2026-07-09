import ApiClient from './ApiClient';
import type { AuditPage, AuditQuery } from '@/types/Audit';

export const fetchAudit = async (q: AuditQuery): Promise<AuditPage> =>
    await ApiClient.get<AuditPage>('/audit', q as Record<string, any>);

export const purgeAudit = async (before: number): Promise<number> =>
    await ApiClient.delete<number>('/audit', { params: { before } });
