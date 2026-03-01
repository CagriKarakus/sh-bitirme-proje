/* LanguageToggle – segmented button placed at the bottom of the sidebar */

import { useLocale, type Locale } from "../context/LocaleContext";

const LOCALES: { value: Locale; label: string; flag: string }[] = [
    { value: "tr", label: "TR", flag: "🇹🇷" },
    { value: "en", label: "EN", flag: "🇬🇧" },
];

export default function LanguageToggle() {
    const { locale, setLocale } = useLocale();

    return (
        <div className="lang-toggle">
            <div className="lang-toggle__buttons">
                {LOCALES.map(({ value, label, flag }) => (
                    <button
                        key={value}
                        className={`lang-toggle__btn${locale === value ? " lang-toggle__btn--active" : ""}`}
                        onClick={() => setLocale(value)}
                        aria-pressed={locale === value}
                    >
                        <span>{flag}</span>
                        <span>{label}</span>
                    </button>
                ))}
            </div>
        </div>
    );
}
