import ApiClient from './ApiClient';
import type { Group, GroupDetail, GroupRequest } from "@/types/Group.ts";

export const fetchGroups = async (): Promise<Group[]> =>
    await ApiClient.get<Group[]>('/groups');

export const fetchGroup = async (id: number): Promise<GroupDetail> =>
    await ApiClient.get<GroupDetail>(`/groups/${id}`);

export const createGroup = async (req: GroupRequest): Promise<number> =>
    await ApiClient.post<number>('/groups', req);

export const updateGroup = async (id: number, req: GroupRequest): Promise<void> =>
    await ApiClient.put<void>(`/groups/${id}`, req);

export const deleteGroup = async (id: number): Promise<void> =>
    await ApiClient.delete<void>(`/groups/${id}`);

export const setGroupUsers = async (id: number, ids: number[]): Promise<void> =>
    await ApiClient.put<void>(`/groups/${id}/users`, { ids });

export const setGroupCertificates = async (id: number, ids: number[]): Promise<void> =>
    await ApiClient.put<void>(`/groups/${id}/certificates`, { ids });
