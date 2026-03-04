/* ToastContainer – renders stacked toasts in fixed top-right */

import { useToast } from "../context/ToastContext";
import Toast from "./Toast";

export default function ToastContainer() {
  const { toasts } = useToast();

  if (toasts.length === 0) return null;

  return (
    <div className="toast-container">
      {toasts.map((toast) => (
        <Toast key={toast.id} toast={toast} />
      ))}
    </div>
  );
}
