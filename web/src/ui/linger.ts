// useLinger keeps a tooltip open long enough for the pointer to reach it,
// and open while the pointer is on it, so its text can be read, selected
// or clicked. The site's tooltips (heat map, charts) all use it.

import { useCallback, useEffect, useRef, useState } from "react";

/** LINGER_MS: how long a tooltip waits after the pointer leaves its anchor. */
export const LINGER_MS = 280;

export interface Linger<T> {
  /** value is what the tooltip shows; null: closed. */
  value: T | null;
  /** show opens (or moves) the tooltip at once. */
  show: (v: T) => void;
  /** leave closes it after LINGER_MS, unless the pointer comes back. */
  leave: () => void;
  /** hold cancels a pending close: the pointer is on the tooltip. */
  hold: () => void;
  /** close closes it now (Escape, blur, a click that opens a sheet). */
  close: () => void;
}

export function useLinger<T>(ms = LINGER_MS): Linger<T> {
  const [value, setValue] = useState<T | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const hold = useCallback(() => clearTimeout(timer.current), []);
  const show = useCallback((v: T) => {
    clearTimeout(timer.current);
    setValue(v);
  }, []);
  const leave = useCallback(() => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setValue(null), ms);
  }, [ms]);
  const close = useCallback(() => {
    clearTimeout(timer.current);
    setValue(null);
  }, []);
  useEffect(() => () => clearTimeout(timer.current), []);
  return { value, show, leave, hold, close };
}
