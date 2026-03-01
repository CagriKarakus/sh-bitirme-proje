/* RuleDetailPage – full-screen overlay with detailed description for a rule */

import { useEffect } from "react";
import type { RuleItem } from "../types";

interface Props {
    rule: RuleItem;
    onClose: () => void;
}

export default function RuleDetailPage({ rule, onClose }: Props) {
    // Close on Escape
    useEffect(() => {
        const handleKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") onClose();
        };
        document.addEventListener("keydown", handleKey);
        return () => document.removeEventListener("keydown", handleKey);
    }, [onClose]);

    return (
        <div className="detail-page detail-page--visible">
            {/* Top bar */}
            <div className="detail-page__topbar">
                <button className="detail-page__back" onClick={onClose}>
                    <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
                        <path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z" />
                    </svg>
                    Geri Dön
                </button>
            </div>

            <div className="detail-page__content">
                {/* Hero */}
                <div className="detail-page__hero">
                    <span className="rule-drawer__rule-id" style={{ fontSize: "1rem" }}>{rule.rule_id}</span>
                    <h1 className="detail-page__title">{rule.title}</h1>

                    {/* Badges */}
                    <div className="rule-card__meta" style={{ marginTop: "var(--sp-md)" }}>
                        {rule.cis_level && (
                            <span className={`rule-card__badge rule-card__badge--level-${rule.cis_level}`}>
                                CIS Level {rule.cis_level}
                            </span>
                        )}
                        <span className={`rule-card__badge ${rule.automated ? "rule-card__badge--automated" : "rule-card__badge--manual"}`}>
                            {rule.automated ? "Otomatik" : "Manuel"}
                        </span>
                        {rule.severity && (
                            <span className={`rule-card__severity rule-card__severity--${rule.severity}`}>
                                {rule.severity}
                            </span>
                        )}
                        {rule.tags?.map((tag) => (
                            <span key={tag} className="detail-page__tag">{tag}</span>
                        ))}
                    </div>
                </div>

                {/* Meta grid */}
                <div className="detail-page__meta-grid">
                    <div className="detail-page__meta-card">
                        <span className="detail-page__meta-label">Bölüm</span>
                        <span className="detail-page__meta-val">{rule.section}</span>
                    </div>
                    {rule.category && (
                        <div className="detail-page__meta-card">
                            <span className="detail-page__meta-label">Kategori</span>
                            <span className="detail-page__meta-val">{rule.category}</span>
                        </div>
                    )}
                    {rule.subcategory && (
                        <div className="detail-page__meta-card">
                            <span className="detail-page__meta-label">Alt Kategori</span>
                            <span className="detail-page__meta-val">{rule.subcategory}</span>
                        </div>
                    )}
                    <div className="detail-page__meta-card">
                        <span className="detail-page__meta-label">İşletim Sistemi</span>
                        <span className="detail-page__meta-val">{rule.os}</span>
                    </div>
                </div>

                {/* Description placeholder */}
                <div className="detail-page__section">
                    <h2 className="detail-page__section-title">Açıklama</h2>
                    <div className="detail-page__placeholder-block">
                        <p>Bu kural için detaylı açıklama henüz eklenmedi.</p>
                    </div>
                </div>

                {/* Rationale placeholder */}
                <div className="detail-page__section">
                    <h2 className="detail-page__section-title">Gerekçe</h2>
                    <div className="detail-page__placeholder-block">
                        <p>Bu kural için gerekçe henüz eklenmedi.</p>
                    </div>
                </div>

                {/* Remediation placeholder */}
                <div className="detail-page__section">
                    <h2 className="detail-page__section-title">Düzeltme Adımları</h2>
                    <div className="detail-page__placeholder-block">
                        <p>Bu kural için düzeltme adımları henüz eklenmedi.</p>
                    </div>
                </div>
            </div>
        </div>
    );
}
