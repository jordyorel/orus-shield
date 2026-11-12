import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { AuthProvider } from "./auth";
// Fonts of the mockups, served from our own origin (never Google Fonts:
// that would send every visitor's address to a third party).
import "@fontsource-variable/figtree";
import "@fontsource-variable/bricolage-grotesque";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");

createRoot(root).render(
  <StrictMode>
    <AuthProvider>
      <App />
    </AuthProvider>
  </StrictMode>,
);
