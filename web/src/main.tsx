import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { AuthProvider } from "./auth";
import { LangProvider, Relang } from "./i18n";
// Fonts of the mockups, served from our own origin (never Google Fonts:
// that would send every visitor's address to a third party).
// IBM Plex Sans everywhere (chosen 2026-11-19), served from our origin.
import "@fontsource-variable/ibm-plex-sans";
// IBM Plex Mono for technical names (hosts, addresses, check IDs): two weights only.
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");

createRoot(root).render(
  <StrictMode>
    <LangProvider>
      <AuthProvider>
        <Relang>
          <App />
        </Relang>
      </AuthProvider>
    </LangProvider>
  </StrictMode>,
);
