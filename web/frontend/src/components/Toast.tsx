/* Toast – individual toast notification */

import type { Toast as ToastItem, ToastType } from "../context/ToastContext";
import { useToast } from "../context/ToastContext";

const TYPE_COLORS: Record<ToastType, string> = {
  success: "var(--success)",
  error: "var(--error)",
  warning: "var(--warning)",
  info: "var(--accent)",
};

const TYPE_ICONS: Record<ToastType, string> = {
  success: "✓",
  error: "✕",
  warning: "⚠",
  info: "ℹ",
};

interface Props {
  toast: ToastItem;
}

export default function Toast({ toast }: Props) {
  const { removeToast } = useToast();
  const color = TYPE_COLORS[toast.type];

  return (
    <div className="toast" style={{ borderLeftColor: color }}>
      <span className="toast__icon" style={{ color }}>
        {TYPE_ICONS[toast.type]}
      </span>
      <span className="toast__message">{toast.message}</span>
      <button
        className="toast__dismiss"
        onClick={() => removeToast(toast.id)}
        aria-label="Kapat"
      >
        ✕
      </button>
    </div>
  );
}
