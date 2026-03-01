/* LocaleContext – i18n engine with browser detection and localStorage persistence */

import {
    createContext,
    useContext,
    useState,
    useCallback,
    type ReactNode,
} from "react";
import tr from "../locales/tr.json";
import en from "../locales/en.json";

// ── Types ────────────────────────────────────────────────────────────────────

export type Locale = "tr" | "en";

// Recursive type that produces all dot-separated key paths from a nested object
type DotPaths<T, Prefix extends string = ""> = {
    [K in keyof T]: T[K] extends Record<string, unknown>
        ? DotPaths<T[K], `${Prefix}${string & K}.`>
        : `${Prefix}${string & K}`;
}[keyof T];

export type TranslationKey = DotPaths<typeof tr>;

// ── Locale data ──────────────────────────────────────────────────────────────

const translations: Record<Locale, Record<string, unknown>> = { tr, en };

// ── Helpers ──────────────────────────────────────────────────────────────────

function interpolate(template: string, vars?: Record<string, string | number>): string {
    if (!vars) return template;
    return template.replace(/\{(\w+)\}/g, (_, key) =>
        key in vars ? String(vars[key]) : `{${key}}`
    );
}

function resolve(obj: Record<string, unknown>, path: string): string {
    const parts = path.split(".");
    let current: unknown = obj;
    for (const part of parts) {
        if (current == null || typeof current !== "object") return path;
        current = (current as Record<string, unknown>)[part];
    }
    if (typeof current === "string") return current;
    return path; // fallback: return the key path itself (visible during development)
}

function detectLocale(): Locale {
    const stored = localStorage.getItem("cis_hardening_locale");
    if (stored === "tr" || stored === "en") return stored;
    const browserLang = navigator.language?.split("-")[0];
    if (browserLang === "en") return "en";
    return "tr"; // default
}

// ── Context ──────────────────────────────────────────────────────────────────

interface LocaleContextValue {
    locale: Locale;
    setLocale: (locale: Locale) => void;
    t: (key: TranslationKey, vars?: Record<string, string | number>) => string;
}

const LocaleContext = createContext<LocaleContextValue | null>(null);

// ── Provider ─────────────────────────────────────────────────────────────────

export function LocaleProvider({ children }: { children: ReactNode }) {
    const [locale, setLocaleState] = useState<Locale>(detectLocale);

    const setLocale = useCallback((next: Locale) => {
        localStorage.setItem("cis_hardening_locale", next);
        setLocaleState(next);
    }, []);

    const t = useCallback(
        (key: TranslationKey, vars?: Record<string, string | number>) => {
            const dict = translations[locale] as Record<string, unknown>;
            const raw = resolve(dict, key);
            return interpolate(raw, vars);
        },
        [locale]
    );

    return (
        <LocaleContext.Provider value={{ locale, setLocale, t }}>
            {children}
        </LocaleContext.Provider>
    );
}

// ── Hook ─────────────────────────────────────────────────────────────────────

export function useLocale(): LocaleContextValue {
    const ctx = useContext(LocaleContext);
    if (!ctx) throw new Error("useLocale must be used within LocaleProvider");
    return ctx;
}
