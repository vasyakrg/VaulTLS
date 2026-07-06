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
            this.loading = true; this.error = null;
            try { return await fetchGroup(id); }
            catch (err) {
                this.error = axios.isAxiosError(err) ? 'Failed to fetch the group: ' + err.response?.data?.error : 'Failed to fetch the group';
                console.error(err);
                return null;
            }
            finally { this.loading = false; }
        },
        async createGroup(req: GroupRequest): Promise<void> {
            this.loading = true; this.error = null;
            try { await createGroup(req); this.groups = await fetchGroups(); }
            catch (err) { this.error = axios.isAxiosError(err) ? 'Failed to create group: ' + err.response?.data?.error : 'Failed to create group'; console.error(err); }
            finally { this.loading = false; }
        },
        async updateGroup(id: number, req: GroupRequest): Promise<void> {
            this.loading = true; this.error = null;
            try { await updateGroup(id, req); this.groups = await fetchGroups(); }
            catch (err) {
                this.error = axios.isAxiosError(err) ? 'Failed to update the group: ' + err.response?.data?.error : 'Failed to update the group';
                console.error(err);
            }
            finally { this.loading = false; }
        },
        async deleteGroup(id: number): Promise<void> {
            this.loading = true; this.error = null;
            try { await deleteGroup(id); this.groups = await fetchGroups(); }
            catch (err) {
                this.error = axios.isAxiosError(err) ? 'Failed to delete the group: ' + err.response?.data?.error : 'Failed to delete the group';
                console.error(err);
            }
            finally { this.loading = false; }
        },
        async setGroupUsers(id: number, ids: number[]): Promise<void> {
            this.loading = true; this.error = null;
            try { await setGroupUsers(id, ids); }
            catch (err) {
                this.error = axios.isAxiosError(err) ? 'Failed to update the group users: ' + err.response?.data?.error : 'Failed to update the group users';
                console.error(err);
            }
            finally { this.loading = false; }
        },
        async setGroupCertificates(id: number, ids: number[]): Promise<void> {
            this.loading = true; this.error = null;
            try { await setGroupCertificates(id, ids); }
            catch (err) {
                this.error = axios.isAxiosError(err) ? 'Failed to update the group certificates: ' + err.response?.data?.error : 'Failed to update the group certificates';
                console.error(err);
            }
            finally { this.loading = false; }
        },
    },
});
