import type {Name} from "@/types/Name.ts";

export enum CertificateType {
    TLSClient = 0,
    TLSServer = 1,
    SSHClient = 10,
    SSHServer = 11,
}

export enum CertificateRenewMethod {
    None = 0,
    Notify = 1,
    Renew = 2,
    RenewAndNotify = 3
}

export interface Certificate {
    id: number;                           // Unique identifier for the certificate
    name: Name;                           // Certificate name
    created_on: string;                   // Date when the certificate was created (UNIX timestamp in ms)
    password: string;                     // Certificate password
    valid_until: string;                  // Expiration date of the certificate (UNIX timestamp in ms)
    certificate_type: CertificateType;    // Type of the certificate
    user_id: number;                      // User ID who owns the certificate
    renew_method: CertificateRenewMethod; // Method on what to do when the certificate is about to expire
    ca_id: number | null;                 // Cert ID used to create the certificate (null for ACME/LE certs)
    acme_provider_id?: number | null;     // ACME provider ID for LE certs (set when ca_id is null)
    // ВНИМАНИЕ: в СЕКУНДАХ, в отличие от created_on/valid_until выше — они в мс.
    // Пишется как chrono::Utc::now().timestamp() (backend/src/db.rs, revoke_user_cert),
    // читается как OffsetDateTime::from_unix_timestamp (backend/src/certs/tls_cert.rs) —
    // обе стороны на секундах. Для отображения через new Date() нужен множитель * 1000.
    revoked_at?: number;                  // Date when the certificate was revoked (UNIX timestamp in SECONDS)
    version: number;                      // номер текущей версии содержимого
    fingerprint?: string | null;          // SHA-256 текущей версии в hex
    is_imported: boolean;                 // только импортированные можно заменять
}
