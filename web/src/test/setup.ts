import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Unmount what each test rendered and reset the URL, so tests stay independent.
afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});
