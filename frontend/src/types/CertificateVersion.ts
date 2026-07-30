export interface CertificateVersion {
    version: number;                  // номер версии, 1 — первая
    version_id: number | null;        // id записи истории; null у текущей версии
    current: boolean;
    created_on: number;               // UNIX ms
    valid_until: number;              // UNIX ms
    serial_hex: string | null;
    fingerprint: string | null;       // SHA-256 в hex
    replaced_at: number | null;       // UNIX ms, когда версия была вытеснена
    replaced_by: number | null;       // id пользователя, выполнившего замену
}
