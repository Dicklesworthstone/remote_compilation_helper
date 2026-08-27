import { useCallback, useEffect, useRef, type MouseEvent } from "react";

/**
 * Backs both drawers with a native <dialog>. showModal() provides the focus
 * trap, Esc handling (fires the dialog's cancel event) and top-layer stacking
 * natively; this hook wires imperative open/close to React state and keeps
 * body scroll locked while open. Focus is restored by the platform when the
 * dialog closes.
 */
export function useDialog(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDialogElement | null>(null);

  // Routed through a ref so consumers can pass an inline closure without
  // re-running the open/close effect below.
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

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

  /** Native Esc fires the dialog's cancel event; route it through state. */
  const onCancel = useCallback(() => onCloseRef.current(), []);

  /**
   * Clicking the ::backdrop surfaces as a click on the <dialog> itself (the
   * backdrop is its pseudo-element) — but so does a click on the panel's own
   * padding, which would close the drawer while the user is reading. Close
   * only when the click actually landed outside the panel box.
   */
  const onClick = useCallback((e: MouseEvent<HTMLDialogElement>) => {
    const el = ref.current;
    if (!el || e.target !== el) return;
    const r = el.getBoundingClientRect();
    const outside =
      e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    if (outside) onCloseRef.current();
  }, []);

  return { ref, onCancel, onClick };
}
