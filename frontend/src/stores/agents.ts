import { defineStore } from 'pinia';
import type { AgentStatus } from '@/types/Agent';
import { fetchAgents } from '@/api/agents.ts';
import axios from 'axios';

export const useAgentsStore = defineStore('agents', {
    state: () => ({
        agents: new Map<number, AgentStatus>(),
        loading: false,
        error: null as string | null,
    }),

    getters: {
        list: (state) => Array.from(state.agents.values()),
    },

    actions: {
        // Merge-and-prune: безопасно вызывать повторно из polling-таймера.
        async fetchAgents(): Promise<void> {
            this.loading = true;
            this.error = null;
            try {
                const fresh = await fetchAgents();
                for (const a of fresh) {
                    this.agents.set(a.id, a);
                }
                const freshIds = new Set<number>(fresh.map(a => a.id));
                for (const existingId of this.agents.keys()) {
                    if (!freshIds.has(existingId)) {
                        this.agents.delete(existingId);
                    }
                }
            } catch (err) {
                if (axios.isAxiosError(err)) {
                    this.error = 'Failed to fetch agents: ' + err.response?.data?.error;
                } else {
                    this.error = 'Failed to fetch agents';
                }
                console.error(err);
            } finally {
                this.loading = false;
            }
        },
    },
});
