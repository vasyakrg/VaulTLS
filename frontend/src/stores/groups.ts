import { defineStore } from 'pinia';
import type { Group, GroupDetail, GroupRequest } from "@/types/Group.ts";
import {
    fetchGroups, fetchGroup, createGroup, updateGroup, deleteGroup,
    setGroupUsers, setGroupCertificates,
} from "@/api/groups.ts";
import axios from 'axios';

export const useGroupStore = defineStore('group', {
    state: () => ({
        groups: [] as Group[],
        loading: false,
        error: null as string | null,
    }),
    actions: {
        async fetchGroups(force = false): Promise<void> {
            if (this.groups.length === 0 || force) {
                this.loading = true; this.error = null;
                try { this.groups = await fetchGroups(); }
                catch (err) { this.error = axios.isAxiosError(err) ? 'Failed to fetch groups: ' + err.response?.data?.error : 'Failed to fetch groups'; console.error(err); }
                finally { this.loading = false; }
            }
        },
        async fetchGroup(id: number): Promise<GroupDetail | null> {
            try { return await fetchGroup(id); }
            catch (err) { console.error(err); return null; }
        },
        async createGroup(req: GroupRequest): Promise<void> {
            try { await createGroup(req); this.groups = await fetchGroups(); }
            catch (err) { this.error = axios.isAxiosError(err) ? 'Failed to create group: ' + err.response?.data?.error : 'Failed to create group'; console.error(err); }
        },
        async updateGroup(id: number, req: GroupRequest): Promise<void> {
            try { await updateGroup(id, req); this.groups = await fetchGroups(); }
            catch (err) { console.error(err); }
        },
        async deleteGroup(id: number): Promise<void> {
            try { await deleteGroup(id); this.groups = await fetchGroups(); }
            catch (err) { console.error(err); }
        },
        async setGroupUsers(id: number, ids: number[]): Promise<void> { await setGroupUsers(id, ids); },
        async setGroupCertificates(id: number, ids: number[]): Promise<void> { await setGroupCertificates(id, ids); },
    },
});
