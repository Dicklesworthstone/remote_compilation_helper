import { useEffect, useRef } from "react";

/**
 * Backs both drawers with a native <dialog>. showModal() provides the focus
 * trap, Esc handling (fires the dialog's cancel event) and top-layer stacking
 * natively; this hook only wires imperative open/close to React state and
 * keeps body scroll locked while open. Focus is restored by the platform when
 * the dialog closes.
 */
export function useDialog(open: boolean) {
  const ref = useRef<HTMLDialogElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  return ref;
}
