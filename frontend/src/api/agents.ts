import ApiClient from '@/api/ApiClient.ts';
import type { AgentStatus } from '@/types/Agent';

export const fetchAgents = async (): Promise<AgentStatus[]> => {
    return await ApiClient.get<AgentStatus[]>('/agents');
};
