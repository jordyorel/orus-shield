import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";
import { setLangForTests } from "../i18n";

// The tests read the French interface, whatever the test browser's language.
setLangForTests("fr");

// Recent Chromium returns a Promise from scrollTo; jsdom does not implement
// it. Behave like the browser, so an effect returning its result fails here.
window.scrollTo = (() => Promise.resolve()) as unknown as typeof window.scrollTo;

// Unmount what each test rendered and reset the URL, so tests stay independent.
afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});
