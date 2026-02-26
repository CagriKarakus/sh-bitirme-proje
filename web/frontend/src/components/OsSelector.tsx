/* OS Selector – toggle between Ubuntu and Windows */

import type { ReactNode } from "react";
import { useHardening, type SelectedOS } from "../context/HardeningContext";

export default function OsSelector() {
    const { state, setOS } = useHardening();

    const options: { os: SelectedOS; label: string; icon: ReactNode }[] = [
        {
            os: "ubuntu",
            label: "Ubuntu",
            icon: (
                <svg className="os-selector__icon" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 2c1.85 0 3.55.63 4.9 1.69L14.5 9.5a4.5 4.5 0 00-5 0L7.1 5.69A7.96 7.96 0 0112 4zM4 12c0-1.85.63-3.55 1.69-4.9L9.5 9.5a4.5 4.5 0 000 5L5.69 16.9A7.96 7.96 0 014 12zm8 8a7.96 7.96 0 01-4.9-1.69L9.5 14.5a4.5 4.5 0 005 0l2.4 3.81A7.96 7.96 0 0112 20zm2.5-8a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0zm3.81 4.9L14.5 14.5a4.5 4.5 0 000-5l3.81-2.4A7.96 7.96 0 0120 12a7.96 7.96 0 01-1.69 4.9z" />
                </svg>
            ),
        },
        {
            os: "windows",
            label: "Windows",
            icon: (
                <svg className="os-selector__icon" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M3 12V6.75l8-1.25V12H3zm0 .5h8v6.5l-8-1.25V12.5zM11.5 5.35l9.5-1.6V12H11.5V5.35zM11.5 12.5H21v7.75l-9.5-1.6V12.5z" />
                </svg>
            ),
        },
    ];

    return (
        <div className="os-selector">
            {options.map((opt) => (
                <button
                    key={opt.os}
                    className={`os-selector__btn${state.selectedOS === opt.os ? " os-selector__btn--active" : ""
                        }`}
                    onClick={() => setOS(opt.os)}
                >
                    {opt.icon}
                    {opt.label}
                </button>
            ))}
        </div>
    );
}
