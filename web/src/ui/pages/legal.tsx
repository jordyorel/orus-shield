// Legal pages: terms (conditions), privacy policy (confidentialite) and
// data processing agreement (traitement-des-donnees). Drafts written from
// what the platform really does; what is not decided yet stays in
// [brackets]. They must be reviewed by a lawyer before the launch.

import type { ReactNode } from "react";
import { Link } from "../../router";
import { useBodyClass } from "../ui";
import { PubFoot, PubHead } from "./public";

const VERSION = "Version de travail du 12 novembre 2026, à faire valider par un juriste avant toute mise en service.";

function LegalPage({ title, intro, children }: { title: string; intro: string; children: ReactNode }) {
  useBodyClass(["public"]);
  return (
    <main>
      <div className="view">
        <PubHead cur="legal" />
        <section className="phead">
          <h1>{title}</h1>
          <p className="herosub">{intro}</p>
          <p className="sub" style={{ marginTop: 12 }}>
            {VERSION}
          </p>
        </section>
        <div className="faq" style={{ maxWidth: 760 }}>
          {children}
        </div>
        <PubFoot />
      </div>
    </main>
  );
}

function Article({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="band" style={{ marginTop: 36 }}>
      <h2 style={{ fontSize: 22 }}>{title}</h2>
      <div className="legaltext">{children}</div>
    </section>
  );
}

export function ConditionsPage() {
  return (
    <LegalPage
      title="Conditions d’utilisation"
      intro="Les règles d’utilisation d’Orus Shield, le service de surveillance de la sécurité de ce que votre entreprise expose sur internet."
    >
      <Article title="1. Qui fournit le service">
        <p>
          Orus Shield est édité par [raison sociale], [forme juridique] au capital de [montant], immatriculée sous le numéro [numéro] au [registre], dont le siège
          est situé [adresse]. Contact : [adresse email de contact].
        </p>
      </Article>
      <Article title="2. Ce que fait le service">
        <p>
          Orus Shield découvre les noms de domaine, sous-domaines, serveurs et services que votre entreprise expose sur internet, les vérifie, et vous indique
          les problèmes trouvés, leur gravité et comment les corriger. Selon votre offre, il réalise :
        </p>
        <ul>
          <li>des contrôles passifs, à partir d’informations publiques (DNS, certificats, réponses des sites) ;</li>
          <li>
            des contrôles actifs, qui envoient des requêtes à vos serveurs : recherche de ports et services ouverts, de vulnérabilités connues, et, avec le
            profil approfondi, des tests applicatifs de vos sites et API ;
          </li>
          <li>des scans authentifiés, si vous fournissez un compte de test ;</li>
          <li>des analyses de vos réseaux internes, si vous installez un agent.</li>
        </ul>
        <p>Le service est une aide à la sécurité. Il ne garantit pas l’absence de faille et ne remplace pas les autres mesures de sécurité de votre entreprise.</p>
      </Article>
      <Article title="3. Vous ne testez que ce qui vous appartient">
        <p>
          Vous ne pouvez faire analyser que des domaines, serveurs, applications et réseaux que vous possédez ou que vous êtes autorisé à faire tester. Avant
          tout contrôle actif, Orus Shield vous demande de prouver que le domaine vous appartient (enregistrement DNS) et vérifie que chaque serveur testé
          appartient bien à ce domaine. Vous restez responsable de disposer des autorisations nécessaires, notamment de votre hébergeur si son contrat
          l’exige.
        </p>
        <p>
          Le profil approfondi et les scans authentifiés demandent votre accord explicite. Les tests peuvent ralentir un serveur ancien ou fragile : utilisez
          si possible un environnement de test, et des comptes de test, jamais des comptes d’administrateur.
        </p>
      </Article>
      <Article title="4. Votre compte">
        <p>
          Vous êtes responsable des accès à votre espace : choisissez un mot de passe solide, activez la double authentification (obligatoire pour les
          administrateurs) et retirez l’accès des personnes qui quittent votre entreprise. Chaque scan est enregistré dans un journal : qui l’a lancé, sur
          quoi, et quand.
        </p>
      </Article>
      <Article title="5. Offres, essai et paiement">
        <p>
          Les offres et leurs limites sont décrites sur la page <Link to="/tarifs">Tarifs</Link>. Une nouvelle organisation bénéficie d’un essai gratuit de 14
          jours. Les abonnements payants sont réglés par carte bancaire, par l’intermédiaire de [prestataire de paiement] : Orus Shield ne voit ni ne conserve
          votre numéro de carte. L’abonnement est sans engagement : il s’arrête à la fin de la période payée. [Conditions de remboursement, TVA et devise à
          préciser.]
        </p>
      </Article>
      <Article title="6. Disponibilité et responsabilité">
        <p>
          Nous faisons nos meilleurs efforts pour que le service soit disponible et que ses résultats soient exacts, sans pouvoir le garantir en
          permanence. [Engagement de disponibilité éventuel, limitation de responsabilité et plafond à préciser.]
        </p>
      </Article>
      <Article title="7. Données">
        <p>
          Le traitement de vos données est décrit dans la <Link to="/confidentialite">politique de confidentialité</Link> et, pour les données de vos systèmes que
          nous traitons pour votre compte, dans l’<Link to="/traitement-des-donnees">accord de traitement des données</Link>.
        </p>
      </Article>
      <Article title="8. Fin du contrat">
        <p>
          Vous pouvez arrêter à tout moment. Nous pouvons suspendre un compte qui utilise le service pour tester des systèmes sans autorisation. À la fin du
          contrat, vos données sont supprimées dans les délais indiqués dans la politique de confidentialité. [Modalités d’export à préciser.]
        </p>
      </Article>
      <Article title="9. Droit applicable">
        <p>[Droit applicable et juridiction compétente à préciser selon le pays de la société.]</p>
      </Article>
    </LegalPage>
  );
}

export function ConfidentialitePage() {
  return (
    <LegalPage title="Politique de confidentialité" intro="Quelles données Orus Shield traite, pourquoi, combien de temps, et vos droits.">
      <Article title="1. Responsable du traitement">
        <p>
          [Raison sociale], [adresse], est responsable du traitement des données de vos comptes. Pour les données de vos systèmes que nous analysons pour votre
          compte, votre entreprise est responsable du traitement et nous agissons comme sous-traitant (voir l’
          <Link to="/traitement-des-donnees">accord de traitement des données</Link>). Contact : [adresse email du délégué ou du contact données].
        </p>
      </Article>
      <Article title="2. Les données que nous traitons">
        <ul>
          <li>Compte : adresse email, nom si vous le renseignez, rôle, organisation.</li>
          <li>Sécurité du compte : mot de passe haché (jamais en clair), secret de double authentification chiffré, codes de secours hachés.</li>
          <li>Connexions : sessions, adresse IP, navigateur, journal des connexions et des actions de sécurité.</li>
          <li>Journal d’audit : qui a lancé quel scan, sur quel domaine, et quand ; modifications des réglages.</li>
          <li>
            Résultats des analyses : noms de domaine, sous-domaines, adresses IP, ports, services, technologies et versions détectées, certificats, problèmes
            trouvés et leurs preuves techniques.
          </li>
          <li>Comptes de test que vous fournissez : chiffrés avec une clé dédiée, jamais réaffichés, utilisés seulement pendant les scans.</li>
          <li>Paiement : géré par [prestataire de paiement] ; nous ne recevons pas votre numéro de carte.</li>
        </ul>
      </Article>
      <Article title="3. Pourquoi">
        <ul>
          <li>Fournir le service que vous avez demandé (exécution du contrat).</li>
          <li>Protéger les comptes et la plateforme, et garder la trace des scans (intérêt légitime, obligations de sécurité).</li>
          <li>Vous envoyer les emails du service : alertes, invitations, réinitialisation du mot de passe.</li>
          <li>Facturer (obligations légales).</li>
        </ul>
        <p>Nous ne vendons pas vos données et ne les utilisons pas pour de la publicité.</p>
      </Article>
      <Article title="4. Qui les reçoit">
        <ul>
          <li>[Hébergeur], qui héberge la plateforme, [pays].</li>
          <li>[Relais email], qui achemine les emails du service.</li>
          <li>[Prestataire de paiement], pour les paiements par carte.</li>
          <li>
            crt.sh, service public des journaux de certificats : pour découvrir vos sous-domaines, le nom de vos domaines y est recherché. Aucune autre donnée
            n’y est envoyée.
          </li>
        </ul>
        <p>[Transferts hors du pays ou de l’Union européenne et garanties à préciser.]</p>
      </Article>
      <Article title="5. Combien de temps">
        <ul>
          <li>Compte et résultats : tant que votre abonnement est actif, puis [durée] après sa fin.</li>
          <li>Journal d’audit et journal des connexions : [durée].</li>
          <li>Comptes de test : jusqu’à ce que vous les supprimiez, ou avec le domaine concerné.</li>
          <li>Factures : la durée imposée par la loi, [durée].</li>
        </ul>
      </Article>
      <Article title="6. Cookies et stockage">
        <p>
          Un seul cookie : celui de votre session, indispensable pour rester connecté. Votre navigateur garde aussi votre choix de thème (clair ou sombre).
          Pas de cookie publicitaire ni de mesure d’audience ; les polices sont servies par nos serveurs, sans appel à un service tiers.
        </p>
      </Article>
      <Article title="7. Sécurité">
        <p>
          Isolation des données de chaque organisation au niveau de la base de données, mots de passe hachés (argon2id), secrets chiffrés (AES-256-GCM),
          double authentification, journal d’audit, scans soumis à la preuve de propriété, à vos exclusions et à une limite de débit.
        </p>
      </Article>
      <Article title="8. Vos droits">
        <p>
          Vous pouvez accéder à vos données, les rectifier, les supprimer, les recevoir dans un format lisible, et vous opposer à certains traitements, en
          écrivant à [adresse email]. Vous pouvez aussi saisir [autorité de protection des données compétente].
        </p>
      </Article>
    </LegalPage>
  );
}

export function TraitementPage() {
  return (
    <LegalPage
      title="Accord de traitement des données"
      intro="Ce que nous faisons, comme sous-traitant, des données de vos systèmes que nous analysons pour votre compte."
    >
      <Article title="1. Objet">
        <p>
          Votre entreprise (le client) est responsable du traitement des données de ses systèmes. [Raison sociale] (Orus Shield) les traite pour son compte, comme
          sous-traitant, dans le seul but de fournir le service décrit dans les <Link to="/conditions">conditions d’utilisation</Link>.
        </p>
      </Article>
      <Article title="2. Données et durée">
        <p>
          Données techniques de vos domaines, serveurs, applications, API et réseaux internes, preuves des problèmes trouvés (qui peuvent contenir des extraits
          de réponses de vos systèmes), comptes de test fournis. Durée : celle du contrat, puis [durée] avant suppression.
        </p>
      </Article>
      <Article title="3. Nos engagements">
        <ul>
          <li>Ne traiter ces données que sur vos instructions, c’est-à-dire pour réaliser les analyses que vous configurez.</li>
          <li>Limiter l’accès aux personnes qui en ont besoin, tenues à la confidentialité.</li>
          <li>Appliquer les mesures de sécurité décrites dans la politique de confidentialité.</li>
          <li>Vous informer de toute violation de données vous concernant dans les [délai] heures après en avoir eu connaissance.</li>
          <li>Vous aider à répondre aux demandes des personnes concernées et aux contrôles, dans la limite du raisonnable.</li>
          <li>Supprimer ou vous restituer les données à la fin du contrat, selon votre choix.</li>
        </ul>
      </Article>
      <Article title="4. Sous-traitants ultérieurs">
        <p>
          [Hébergeur] (hébergement), [relais email] (emails du service). Nous vous informons avant d’en ajouter un nouveau ; vous pouvez vous y opposer.
          [Liste et procédure à préciser.]
        </p>
      </Article>
      <Article title="5. Audits">
        <p>[Modalités d’audit et de documentation à préciser.]</p>
      </Article>
    </LegalPage>
  );
}
