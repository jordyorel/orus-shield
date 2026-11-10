import type { Me, Membership } from "../api/types";
import { useAuth } from "../auth";
import { AppShell } from "../components/AppShell";
import { AuthLayout } from "../components/AuthLayout";
import { sections } from "../components/nav";
import { Link, navigate } from "../router";

/** What each screen not built yet will show, from docs/ui-adaptation.md. */
const upcoming: Record<string, string> = {
  surface: "Vos domaines, adresses IP, certificats et services exposés, avec leur couverture par les modules de scan.",
  priorisation: "Vos vulnérabilités classées selon le risque réel : exposition, exploitation active et protections en place.",
  vulnerabilites: "Toutes les vulnérabilités détectées, avec leur explication, les étapes de correction et la preuve technique.",
  posture: "Le score de posture par catégorie (emails, web, TLS, réseau) et les contrôles réussis ou échoués.",
  gouvernance: "L’évolution des vulnérabilités ouvertes et corrigées, et vos délais de correction dans le temps.",
  actifs: "Vos domaines, leur vérification de propriété par enregistrement DNS et les actifs découverts.",
  scans: "Le lancement des scans, leur historique et leur configuration (modules, fréquence, exclusions).",
  parametres: "Votre équipe, vos alertes et vos préférences.",
};

export function ComingSoonPage({ me, org, section }: { me: Me; org: Membership; section: string }) {
  const s = sections.find((x) => x.path === section);
  return (
    <AppShell me={me} org={org} section={section} title={s?.label ?? ""}>
      <section className="card empty">
        <h2>Bientôt disponible</h2>
        <p>{upcoming[section]}</p>
      </section>
    </AppShell>
  );
}

export function NotFoundPage() {
  return (
    <AuthLayout>
      <div className="stack">
        <h1>Page introuvable</h1>
        <p className="muted">Cette page n’existe pas, ou vous n’y avez pas accès.</p>
        <Link className="btn btn-secondary" to="/">
          Retour à l’accueil
        </Link>
      </div>
    </AuthLayout>
  );
}

export function NoOrgPage({ me }: { me: Me }) {
  const { signOut } = useAuth();
  return (
    <AuthLayout>
      <div className="stack">
        <h1>Aucune organisation</h1>
        <p className="muted">Votre compte ({me.email}) n’est rattaché à aucune organisation pour l’instant. Demandez à votre administrateur de vous y ajouter.</p>
        <p className="small">
          <button type="button" className="link-button" onClick={() => void signOut().then(() => navigate("/login?ok=logout", { replace: true }))}>
            Se déconnecter
          </button>
        </p>
      </div>
    </AuthLayout>
  );
}
