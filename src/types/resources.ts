export interface ResourceMetadata {
    version: 1;
    id: string;
    title: string;
    author: string;
    description: string;
    originalFilename: string;
    uploadedAt: string;
    pathname: string;
}

export interface ResourceItem extends ResourceMetadata {
    url: string;
    downloadUrl: string;
    size: number;
}

export interface ResourceListResponse {
    configured: boolean;
    resources: ResourceItem[];
}

export interface ResourceUploadPayload {
    id: string;
    title: string;
    author: string;
    description: string;
    originalFilename: string;
}

export interface ResourceAuthUser {
    login: string;
    avatarUrl: string;
}

export interface ResourceAuthResponse {
    configured: boolean;
    authenticated: boolean;
    user?: ResourceAuthUser;
}
