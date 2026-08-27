import { useEffect, useRef } from "react";

/**
 * Shared dialog behavior for both drawers: lock body scroll while open, move
 * focus into the panel (its close button) on open, and restore focus to
 * whatever held it before — otherwise keyboard and screen-reader users are
 * dumped back at the top of the page when a drawer closes.
 */
export function useDialog(open: boolean) {
  const panelRef = useRef<HTMLElement | null>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restoreRef.current = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    // One frame later the panel is mounted and focusable.
    const raf = requestAnimationFrame(() => {
      panelRef.current?.querySelector<HTMLElement>("button")?.focus();
    });
    return () => {
      cancelAnimationFrame(raf);
      document.body.style.overflow = prevOverflow;
      restoreRef.current?.focus();
    };
  }, [open]);

  return panelRef;
}
