export enum UserRole {
    User = 0,
    Admin = 1
}

export interface User {
    id: number,
    name: string,
    email: string,
    has_password: boolean,
    role: UserRole,
    is_local?: boolean
}

export interface CreateUserRequest {
    user_name: string,
    user_email: string,
    password?: string
    role: UserRole
}