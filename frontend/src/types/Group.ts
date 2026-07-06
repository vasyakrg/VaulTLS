export interface Group {
    id: number;
    name: string;
    description?: string | null;
    created_on: number;
}

export interface GroupDetail extends Group {
    user_ids: number[];
    certificate_ids: number[];
}

export interface GroupRequest {
    name: string;
    description?: string | null;
}
