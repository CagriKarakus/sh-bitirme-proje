/* API service – communicates with the FastAPI backend */

import type {
    ArtifactInfoResponse,
    RulesResponse,
    ResolveRequest,
    ResolveResult,
    GenerateRequest,
    GenerateResponse,
} from "../types";

const API_BASE = "http://localhost:8001/api";

async function request<T>(url: string, options?: RequestInit): Promise<T> {
    const res = await fetch(url, {
        headers: { "Content-Type": "application/json" },
        ...options,
    });
    if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
    }
    return res.json();
}

export async function fetchRules(os: string): Promise<RulesResponse> {
    return request<RulesResponse>(`${API_BASE}/rules/${os}`);
}

export async function resolveRules(
    os: string,
    ruleIds: string[]
): Promise<ResolveResult> {
    const body: ResolveRequest = { os, rule_ids: ruleIds };
    return request<ResolveResult>(`${API_BASE}/resolve`, {
        method: "POST",
        body: JSON.stringify(body),
    });
}

export async function generateConfig(
    os: string,
    ruleIds: string[],
    format: string = "ansible",
    permanent: boolean = false
): Promise<GenerateResponse> {
    const body: GenerateRequest = { os, rule_ids: ruleIds, format, permanent };
    return request<GenerateResponse>(`${API_BASE}/generate`, {
        method: "POST",
        body: JSON.stringify(body),
    });
}

export async function lookupArtifact(artifactId: string): Promise<ArtifactInfoResponse> {
    return request<ArtifactInfoResponse>(`${API_BASE}/artifact/${artifactId}`);
}

/**
 * Trigger a file download from the backend download endpoint.
 * Opens the URL in a new tab / triggers browser download.
 */
export function downloadArtifact(downloadUrl: string): void {
    const fullUrl = `${API_BASE.replace("/api", "")}${downloadUrl}`;
    const a = document.createElement("a");
    a.href = fullUrl;
    a.download = "";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}
