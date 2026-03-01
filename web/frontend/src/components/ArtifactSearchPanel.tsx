/* ArtifactSearchPanel – search for a previously generated artifact by its 12-char ID */

import { useState, useRef, useEffect } from "react";
import { useLocale } from "../context/LocaleContext";
import { lookupArtifact, downloadArtifact } from "../services/api";
import type { ArtifactInfoResponse } from "../types";

type SearchState = "idle" | "loading" | "found" | "not-found" | "error";

export default function ArtifactSearchPanel() {
    const { t } = useLocale();
    const [input, setInput] = useState("");
    const [searchState, setSearchState] = useState<SearchState>("idle");
    const [result, setResult] = useState<ArtifactInfoResponse | null>(null);
    const abortRef = useRef<AbortController | null>(null);

    // Sanitize input: only alphanumeric, max 12 chars
    function sanitize(raw: string): string {
        return raw.replace(/[^a-zA-Z0-9]/g, "").slice(0, 12);
    }

    async function doSearch(id: string) {
        if (id.length !== 12) return;

        // Cancel any in-flight request
        abortRef.current?.abort();
        abortRef.current = new AbortController();

        setSearchState("loading");
        setResult(null);

        try {
            const data = await lookupArtifact(id);
            setResult(data);
            setSearchState(data.found ? "found" : "not-found");
        } catch {
            setSearchState("error");
        }
    }

    function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
        const clean = sanitize(e.target.value);
        setInput(clean);
        // Reset result when user changes the input
        if (searchState !== "idle") {
            setSearchState("idle");
            setResult(null);
        }
    }

    // Auto-trigger when exactly 12 chars are entered
    useEffect(() => {
        if (input.length === 12) {
            doSearch(input);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [input]);

    function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
        if (e.key === "Enter" && input.length === 12) {
            doSearch(input);
        }
    }

    function handleSearchClick() {
        if (input.length === 12) {
            doSearch(input);
        }
    }

    const isLoading = searchState === "loading";

    return (
        <div className="artifact-search-panel">
            <h3 className="artifact-search__title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z" />
                </svg>
                {t("artifact_search.title")}
            </h3>

            <p className="artifact-search__hint">{t("artifact_search.hint")}</p>

            <div className="artifact-search__input-row">
                <div className="artifact-search__input-wrap">
                    <input
                        className="artifact-search__input"
                        type="text"
                        value={input}
                        onChange={handleChange}
                        onKeyDown={handleKeyDown}
                        placeholder={t("artifact_search.placeholder")}
                        maxLength={12}
                        spellCheck={false}
                        autoComplete="off"
                    />
                    <span className="artifact-search__counter">{input.length}/12</span>
                </div>
                <button
                    className="artifact-search__btn"
                    onClick={handleSearchClick}
                    disabled={input.length !== 12 || isLoading}
                >
                    {isLoading ? (
                        <>
                            <span className="btn__spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />
                            {t("artifact_search.searching")}
                        </>
                    ) : (
                        <>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                                <path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z" />
                            </svg>
                            {t("artifact_search.search_btn")}
                        </>
                    )}
                </button>
            </div>

            {/* Result area */}
            <div className="artifact-search__result">
                {searchState === "found" && result && (
                    <div className="artifact-search__found">
                        <div className="vp-msg vp-msg--success">{t("artifact_search.found")}</div>
                        <div className="vp-file-info">
                            <div className="vp-file-row">
                                <span className="vp-label">Dosya:</span>
                                <code className="vp-value">{result.filename}</code>
                            </div>
                            <div className="vp-file-row">
                                <span className="vp-label">SHA-256:</span>
                                <code className="vp-value vp-sha256">{result.sha256}</code>
                            </div>
                        </div>
                        <button
                            className="vp-btn vp-btn--download"
                            onClick={() => downloadArtifact(result.download_url!)}
                        >
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                                <path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z" />
                            </svg>
                            İndir
                        </button>
                    </div>
                )}

                {searchState === "not-found" && (
                    <div className="vp-msg vp-msg--error">
                        {t("artifact_search.not_found", { id: input })}
                    </div>
                )}

                {searchState === "error" && (
                    <div className="vp-msg vp-msg--error">{t("artifact_search.error")}</div>
                )}
            </div>
        </div>
    );
}
