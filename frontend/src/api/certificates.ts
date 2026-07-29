import ApiClient from './ApiClient';
import type {Certificate} from '@/types/Certificate';
import type {CertificateRequirements} from "@/types/CertificateRequirements.ts";
import type {CertificateVersion} from '@/types/CertificateVersion';

export const fetchCertificates = async (): Promise<Certificate[]> => {
    return await ApiClient.get<Certificate[]>('/certificates');
};

export const fetchCertificatePassword = async (id: number, version?: number): Promise<string> => {
    const query = version === undefined ? '' : `?version=${version}`;
    return await ApiClient.get<string>(`/certificates/${id}/password${query}`);
};

export const downloadCertificate = async (id: number, format?: 'pem', version?: number): Promise<void> => {
    const params = [
        format ? `download_format=${format}` : null,
        version === undefined ? null : `version=${version}`,
    ].filter(Boolean).join('&');
    const url = `/certificates/${id}/download${params ? `?${params}` : ''}`;
    return await ApiClient.download(url);
};

export const fetchCertificateVersions = async (id: number): Promise<CertificateVersion[]> => {
    return await ApiClient.get<CertificateVersion[]>(`/certificates/${id}/versions`);
};

export const updateCertificate = async (id: number, form: FormData): Promise<Certificate> => {
    return await ApiClient.putForm<Certificate>(`/certificates/${id}`, form);
};

export const deleteCertificateVersion = async (id: number, version: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/${id}/versions/${version}`);
};

export const createCertificate = async (certReq: CertificateRequirements): Promise<number> => {
    const cert = await ApiClient.post<Certificate>('/certificates', certReq);
    return cert.id;
};

export const deleteCertificate = async (id: number): Promise<void> => {
    await ApiClient.delete<void>(`/certificates/${id}`);
};

export const revokeCertificate = async (id: number): Promise<void> => {
    await ApiClient.post<void>(`/certificates/${id}/revoke`);
};

export const importCertificate = async (form: FormData): Promise<void> => {
    await ApiClient.postForm<void>('/certificates/import', form);
};
