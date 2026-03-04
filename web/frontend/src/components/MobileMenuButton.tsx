/* MobileMenuButton – hamburger toggle for sidebar on mobile */

interface Props {
  isOpen: boolean;
  onToggle: () => void;
}

export default function MobileMenuButton({ isOpen, onToggle }: Props) {
  return (
    <button
      className="mobile-menu-btn"
      onClick={onToggle}
      aria-label={isOpen ? "Menüyü kapat" : "Menüyü aç"}
      aria-expanded={isOpen}
    >
      {isOpen ? (
        /* X icon */
        <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
          <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" />
        </svg>
      ) : (
        /* Hamburger icon */
        <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
          <path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z" />
        </svg>
      )}
    </button>
  );
}
