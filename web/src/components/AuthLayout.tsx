import type { ReactNode } from "react";
import { Link } from "../router";
import { Logo } from "./Logo";

/** AuthLayout is the centered card of the sign-in pages. */
export function AuthLayout({ children, wide = false }: { children: ReactNode; wide?: boolean }) {
  return (
    <main className="auth">
      <Link className="brand" to="/">
        <Logo />
        <span className="brand-name">Orus Shield</span>
      </Link>
      <div className={wide ? "auth-card wide" : "auth-card"}>{children}</div>
      <p className="auth-footer">Audit de sécurité continu pour les PME</p>
    </main>
  );
}

export function Alert({ kind, children }: { kind: "error" | "notice" | "warning"; children: ReactNode }) {
  return (
    <p className={`alert alert-${kind}`} role={kind === "error" ? "alert" : "status"}>
      {children}
    </p>
  );
}
