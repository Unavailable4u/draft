import { useCallback, useState } from "react";

/** "paper" is the default (a typeset page); "midnight" is the same system for dark rooms and projectors. */
export type Theme = "paper" | "midnight";

const KEY = "minilocker.theme";
const EVENT = "minilocker:theme";

export function getTheme(): Theme {
  try { return localStorage.getItem(KEY) === "midnight" ? "midnight" : "paper"; } catch { return "paper"; }
}

export function applyTheme(t: Theme) {
  document.documentElement.dataset.theme = t;
  window.dispatchEvent(new CustomEvent(EVENT, { detail: t }));
}

/** For things that paint outside CSS (the xterm canvas) and must repaint when the theme changes. */
export function onThemeChange(fn: (t: Theme) => void): () => void {
  const h = (e: Event) => fn((e as CustomEvent<Theme>).detail);
  window.addEventListener(EVENT, h);
  return () => window.removeEventListener(EVENT, h);
}

export function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "midnight" ? "midnight" : "paper";
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(currentTheme);
  const toggle = useCallback(() => {
    const next: Theme = theme === "paper" ? "midnight" : "paper";
    try { localStorage.setItem(KEY, next); } catch { /* private mode: the choice just won't persist */ }
    applyTheme(next);
    setTheme(next);
  }, [theme]);
  return [theme, toggle];
}
