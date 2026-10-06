import ApiClient from "@/api/ApiClient.ts";
import type {CA, CAImportUrlRequest, CARequirements} from "@/types/CA.ts";

export const fetchCAs = async (): Promise<CA[]> => {
    return await ApiClient.get<CA[]>(`/certificates/ca`);
};

export const createCA = async (certReq: CARequirements): Promise<number> => {
    return await ApiClient.post<number>('/certificates/ca', certReq);
};

export const downloadCAByID = async (id: number): Promise<void> => {
    return await ApiClient.download(`/certificates/ca/${id}/download`);
};

export const deleteCA = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/ca/${id}`);
};

export const downloadCRL = async (id: number, format: string = 'der'): Promise<void> => {
    await ApiClient.download(`/certificates/ca/${id}/crl?format=${format}`);
};

export const importCa = async (form: FormData): Promise<number> => {
    return await ApiClient.postForm<number>('/certificates/ca/import', form);
};

export const importCaUrl = async (payload: CAImportUrlRequest): Promise<number> => {
    return await ApiClient.post<number>('/certificates/ca/import-url', payload);
};