/* ThemeToggle – sun/moon icon button for dark/light toggle */

import { useTheme } from "../context/ThemeContext";
import { useLocale } from "../context/LocaleContext";

export default function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  const { t } = useLocale();
  const isDark = theme === "dark";

  return (
    <button
      className="theme-toggle"
      onClick={toggleTheme}
      aria-label={isDark ? t("theme.toggle_light") : t("theme.toggle_dark")}
      title={isDark ? t("theme.toggle_light") : t("theme.toggle_dark")}
    >
      {isDark ? (
        /* Sun icon */
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 7a5 5 0 1 0 0 10A5 5 0 0 0 12 7zm0-5a1 1 0 0 1 1 1v2a1 1 0 0 1-2 0V3a1 1 0 0 1 1-1zm0 16a1 1 0 0 1 1 1v2a1 1 0 0 1-2 0v-2a1 1 0 0 1 1-1zm9-9h-2a1 1 0 0 0 0 2h2a1 1 0 0 0 0-2zM5 12a1 1 0 0 1-1 1H2a1 1 0 0 1 0-2h2a1 1 0 0 1 1 1zm12.66-6.66-.71-.71a1 1 0 0 0-1.41 1.41l.71.71a1 1 0 1 0 1.41-1.41zM7.05 17.66l-.71-.71a1 1 0 0 0-1.41 1.41l.71.71a1 1 0 0 0 1.41-1.41zm11.32.7-.71.71a1 1 0 0 1-1.41-1.41l.71-.71a1 1 0 0 1 1.41 1.41zM5.76 6.34 5.05 5.63a1 1 0 0 1 1.41-1.41l.71.71A1 1 0 0 1 5.76 6.34z" />
        </svg>
      ) : (
        /* Moon icon */
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      )}
    </button>
  );
}
