// Legal pages: terms (conditions), privacy policy (confidentialite) and
// data processing agreement (traitement-des-donnees). Drafts written from
// what the platform really does; what is not decided yet stays in
// [brackets]. They must be reviewed by a lawyer before the launch.
//
// Each page is written in French and in English, as whole texts side by
// side rather than sentence by sentence: legal wording reads as a whole.
// The French text prevails; the English one says so.

import { Children, isValidElement, type ReactNode } from "react";
import { tr, useLang } from "../../i18n";
import { Link, useLocation } from "../../router";
import { useBodyClass } from "../ui";
import { slug, Toc } from "./article";
import { PubFoot, PubHead } from "./public";

const version = () =>
  tr(
    "Version de travail du 12 novembre 2026, à faire valider par un juriste avant toute mise en service.",
    "Working draft of 12 November 2026, to be reviewed by a lawyer before the service opens. This English version is a translation: in case of difference, the French text prevails.",
  );

/** LEGAL lists the three texts, for the tabs at the top of each. */
const LEGAL: [string, () => string][] = [
  ["/conditions", () => tr("Conditions d’utilisation", "Terms of use")],
  ["/confidentialite", () => tr("Confidentialité", "Privacy")],
  ["/traitement-des-donnees", () => tr("Traitement des données", "Data processing")],
];

function LegalPage({ title, intro, children }: { title: string; intro: string; children: ReactNode }) {
  useBodyClass(["public"]);
  const { path } = useLocation();
  // The table of contents is the articles' titles, in order.
  const titles = Children.toArray(children).flatMap((c) => (isValidElement<{ title?: string }>(c) && c.props.title ? [c.props.title] : []));
  return (
    <main>
      <div className="view">
        <PubHead cur="legal" />
        <section className="lhead">
          <p className="kicker">{tr("Légal", "Legal")}</p>
          <h1>{title}</h1>
          <p className="herosub">{intro}</p>
          <p className="draftnote">
            <span aria-hidden="true">!</span>
            {version()}
          </p>
        </section>
        <nav className="legaltabs" aria-label={tr("Textes légaux", "Legal texts")}>
          {LEGAL.map(([to, name]) => (
            <Link key={to} to={to} aria-current={path === to ? "page" : undefined}>
              {name()}
            </Link>
          ))}
        </nav>
        <div className="artlayout">
          <aside>
            <Toc titles={titles} />
          </aside>
          <div className="artbody">{children}</div>
        </div>
        <PubFoot />
      </div>
    </main>
  );
}

function Article({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="lart" id={slug(title)}>
      <h2>{title}</h2>
      <div className="legaltext">{children}</div>
    </section>
  );
}

function ConditionsFR() {
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
          Les offres et leurs limites sont décrites sur la page <Link to="/tarifs">Tarifs</Link>. L’offre Gratuit est un audit unique d’un domaine : un
          scan, dont les résultats restent consultables ; les scans suivants, dont la vérification des corrections, demandent une offre payante. Les offres
          Essentiel et Pro commencent par un essai gratuit
          de 14 jours, une fois par organisation : le moyen de paiement est demandé au début de l’essai, et le premier prélèvement a lieu à sa fin, sauf
          annulation avant. Les abonnements payants sont vendus et encaissés par Paddle (Paddle.com Market Limited), notre revendeur officiel : la commande, le paiement
          par carte ou PayPal, les taxes et les factures relèvent de Paddle, selon ses propres conditions. Orus Shield ne voit ni ne conserve votre numéro de
          carte. L’abonnement est sans engagement : il s’arrête à la fin de la période payée ; vous le gérez depuis le portail Paddle (Réglages, Abonnement).
          [Conditions de remboursement à préciser.]
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

function ConfidentialiteFR() {
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
          <li>Paiement : géré par Paddle, notre revendeur ; nous recevons l’état de votre abonnement et un identifiant client, jamais votre numéro de carte.</li>
          <li>
            Test public d’un domaine, sans compte : le domaine testé, l’adresse IP qui l’a demandé et le résultat. Si vous demandez le rapport : votre adresse
            email, et votre accord éventuel pour recevoir nos conseils et offres.
          </li>
        </ul>
      </Article>
      <Article title="3. Pourquoi">
        <ul>
          <li>Fournir le service que vous avez demandé (exécution du contrat).</li>
          <li>Protéger les comptes et la plateforme, et garder la trace des scans (intérêt légitime, obligations de sécurité).</li>
          <li>Vous envoyer les emails du service : alertes, invitations, réinitialisation du mot de passe.</li>
          <li>Facturer (obligations légales).</li>
          <li>Empêcher les abus du test public : limites par adresse IP (intérêt légitime) ; vous envoyer le rapport demandé.</li>
          <li>Seulement avec votre accord : vous envoyer nos conseils et offres. Vous pouvez retirer cet accord à tout moment, en un clic.</li>
        </ul>
        <p>Nous ne vendons pas vos données et ne les utilisons pas pour de la publicité.</p>
      </Article>
      <Article title="4. Qui les reçoit">
        <ul>
          <li>[Hébergeur], qui héberge la plateforme, [pays].</li>
          <li>[Relais email], qui achemine les emails du service.</li>
          <li>Paddle (Paddle.com Market Limited), revendeur des abonnements : commande, paiement, taxes et factures.</li>
          <li>
            crt.sh, service public des journaux de certificats : pour découvrir vos sous-domaines, le nom de vos domaines y est recherché. Aucune autre donnée
            n’y est envoyée.
          </li>
          <li>
            XposedOrNot (xposedornot.com), service de notification des fuites de données : pour savoir si les adresses email de vos domaines vérifiés (celles
            des membres de votre équipe sur ces domaines et celles que vous déclarez) figurent dans des fuites connues, chaque adresse y est recherchée. Nous
            n’en conservons que le nom des fuites, leur date et les types de données exposées, jamais de mot de passe. [Accord de licence et clauses de
            sous-traitance à valider.]
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
          <li>Tests publics (domaine, adresse IP, résultat) : 30 jours. Adresses laissées pour un rapport : [durée], ou jusqu’à votre désinscription.</li>
        </ul>
      </Article>
      <Article title="6. Cookies et stockage">
        <p>
          Un seul cookie : celui de votre session, indispensable pour rester connecté. Votre navigateur garde aussi votre choix de thème (clair ou sombre), de langue et d’affichage du menu, et, le temps de vous inscrire, le domaine que vous avez testé.
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

function TraitementFR() {
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
          [Hébergeur] (hébergement), [relais email] (emails du service), XposedOrNot (recherche des adresses email de vos domaines dans les fuites de
          données connues). Nous vous informons avant d’en ajouter un nouveau ; vous pouvez vous y opposer.
          [Liste et procédure à préciser.]
        </p>
      </Article>
      <Article title="5. Audits">
        <p>[Modalités d’audit et de documentation à préciser.]</p>
      </Article>
    </LegalPage>
  );
}

export function ConditionsPage() {
  return useLang().lang === "en" ? <ConditionsEN /> : <ConditionsFR />;
}

export function ConfidentialitePage() {
  return useLang().lang === "en" ? <ConfidentialiteEN /> : <ConfidentialiteFR />;
}

export function TraitementPage() {
  return useLang().lang === "en" ? <TraitementEN /> : <TraitementFR />;
}

function ConditionsEN() {
  return (
    <LegalPage title="Terms of use" intro="The rules for using Orus Shield, the service that monitors the security of what your business exposes on the internet.">
      <Article title="1. Who provides the service">
        <p>
          Orus Shield is published by [company name], [legal form] with a share capital of [amount], registered under number [number] with [registry], whose
          registered office is at [address]. Contact: [contact email address].
        </p>
      </Article>
      <Article title="2. What the service does">
        <p>
          Orus Shield discovers the domain names, subdomains, servers and services your business exposes on the internet, checks them, and tells you the
          problems found, how serious they are and how to fix them. Depending on your plan, it performs:
        </p>
        <ul>
          <li>passive checks, based on public information (DNS, certificates, website responses);</li>
          <li>
            active checks, which send requests to your servers: searching for open ports and services, known vulnerabilities and, with the deep profile,
            application tests of your websites and APIs;
          </li>
          <li>authenticated scans, if you provide a test account;</li>
          <li>scans of your internal networks, if you install an agent.</li>
        </ul>
        <p>The service is a security aid. It does not guarantee the absence of flaws and does not replace your business’s other security measures.</p>
      </Article>
      <Article title="3. You only test what belongs to you">
        <p>
          You may only have domains, servers, applications and networks scanned that you own or are authorized to have tested. Before any active check,
          Orus Shield asks you to prove that the domain is yours (a DNS record) and checks that every server tested really belongs to that domain. You remain
          responsible for holding the necessary authorizations, in particular from your hosting provider if its contract requires it.
        </p>
        <p>
          The deep profile and authenticated scans require your explicit consent. Tests can slow down an old or fragile server: where possible, use a test
          environment and test accounts, never administrator accounts.
        </p>
      </Article>
      <Article title="4. Your account">
        <p>
          You are responsible for access to your workspace: choose a strong password, turn on two-factor authentication (mandatory for administrators) and
          remove access for people who leave your business. Every scan is recorded in a log: who started it, on what, and when.
        </p>
      </Article>
      <Article title="5. Plans, trial and payment">
        <p>
          Plans and their limits are described on the <Link to="/tarifs">Pricing</Link> page. The Free plan is a single audit of one domain: one scan, whose
          results remain available; later scans, including the verification of fixes, require a paid plan. The Essential and Pro plans start with a 14-day
          free trial, once per organization: a payment method is requested at the start of the trial, and the first charge takes place at its end, unless
          cancelled before. Paid subscriptions are sold and collected by Paddle (Paddle.com Market Limited), our authorized reseller: the order, payment by
          card or PayPal, taxes and invoices are handled by Paddle, under its own terms. Orus Shield never sees or keeps your card number. The subscription
          has no commitment: it ends at the end of the paid period; you manage it from the Paddle portal (Settings, Subscription). [Refund terms to be
          specified.]
        </p>
      </Article>
      <Article title="6. Availability and liability">
        <p>
          We make our best efforts to keep the service available and its results accurate, without being able to guarantee this at all times. [Possible
          availability commitment, limitation of liability and cap to be specified.]
        </p>
      </Article>
      <Article title="7. Data">
        <p>
          The processing of your data is described in the <Link to="/confidentialite">privacy policy</Link> and, for the data of your systems we process on
          your behalf, in the <Link to="/traitement-des-donnees">data processing agreement</Link>.
        </p>
      </Article>
      <Article title="8. End of the contract">
        <p>
          You can stop at any time. We may suspend an account that uses the service to test systems without authorization. At the end of the contract, your
          data is deleted within the periods stated in the privacy policy. [Export terms to be specified.]
        </p>
      </Article>
      <Article title="9. Governing law">
        <p>[Governing law and competent courts to be specified according to the company’s country.]</p>
      </Article>
    </LegalPage>
  );
}

function ConfidentialiteEN() {
  return (
    <LegalPage title="Privacy policy" intro="What data Orus Shield processes, why, for how long, and your rights.">
      <Article title="1. Data controller">
        <p>
          [Company name], [address], is the controller of your account data. For the data of your systems we scan on your behalf, your business is the
          controller and we act as processor (see the <Link to="/traitement-des-donnees">data processing agreement</Link>). Contact: [email address of the
          data protection officer or data contact].
        </p>
      </Article>
      <Article title="2. The data we process">
        <ul>
          <li>Account: email address, name if you provide it, role, organization.</li>
          <li>Account security: hashed password (never in clear text), encrypted two-factor secret, hashed recovery codes.</li>
          <li>Sign-ins: sessions, IP address, browser, log of sign-ins and security actions.</li>
          <li>Audit log: who started which scan, on which domain, and when; changes to settings.</li>
          <li>
            Scan results: domain names, subdomains, IP addresses, ports, services, detected technologies and versions, certificates, problems found and their
            technical evidence.
          </li>
          <li>Test accounts you provide: encrypted with a dedicated key, never shown again, used only during scans.</li>
          <li>Payment: handled by Paddle, our reseller; we receive the state of your subscription and a customer identifier, never your card number.</li>
          <li>
            Public test of a domain, without an account: the domain tested, the IP address that asked for it and the result. If you ask for the report: your
            email address, and your optional consent to receive our tips and offers.
          </li>
        </ul>
      </Article>
      <Article title="3. Why">
        <ul>
          <li>To provide the service you asked for (performance of the contract).</li>
          <li>To protect accounts and the platform, and keep a record of scans (legitimate interest, security obligations).</li>
          <li>To send you the service’s emails: alerts, invitations, password resets.</li>
          <li>To invoice (legal obligations).</li>
          <li>To prevent abuse of the public test: limits per IP address (legitimate interest); to send you the report you asked for.</li>
          <li>Only with your consent: to send you our tips and offers. You can withdraw it at any time, in one click.</li>
        </ul>
        <p>We do not sell your data and do not use it for advertising.</p>
      </Article>
      <Article title="4. Who receives it">
        <ul>
          <li>[Hosting provider], which hosts the platform, [country].</li>
          <li>[Email relay], which delivers the service’s emails.</li>
          <li>Paddle (Paddle.com Market Limited), reseller of the subscriptions: order, payment, taxes and invoices.</li>
          <li>
            crt.sh, the public certificate log service: to discover your subdomains, the names of your domains are searched there. No other data is sent to
            it.
          </li>
          <li>
            XposedOrNot (xposedornot.com), a data breach notification service: to know whether the email addresses of your verified domains (your team
            members’ addresses on those domains and the ones you declare) appear in known breaches, each address is looked up there. We keep only the
            breaches’ names, dates and the kinds of data exposed, never a password. [Licence agreement and sub-processing terms to be confirmed.]
          </li>
        </ul>
        <p>[Transfers outside the country or the European Union and safeguards to be specified.]</p>
      </Article>
      <Article title="5. How long">
        <ul>
          <li>Account and results: as long as your subscription is active, then [period] after it ends.</li>
          <li>Audit log and sign-in log: [period].</li>
          <li>Test accounts: until you delete them, or with the domain concerned.</li>
          <li>Invoices: the period required by law, [period].</li>
          <li>Public tests (domain, IP address, result): 30 days. Addresses left for a report: [period], or until you unsubscribe.</li>
        </ul>
      </Article>
      <Article title="6. Cookies and storage">
        <p>
          A single cookie: your session cookie, needed to stay signed in. Your browser also keeps your choice of theme (light or dark), of language and of how the menu is shown, and, while you sign up, the domain you tested. No
          advertising cookie and no audience measurement; fonts are served by our servers, without calling a third-party service.
        </p>
      </Article>
      <Article title="7. Security">
        <p>
          Isolation of each organization’s data at the database level, hashed passwords (argon2id), encrypted secrets (AES-256-GCM), two-factor
          authentication, audit log, scans subject to proof of ownership, to your exclusions and to a rate limit.
        </p>
      </Article>
      <Article title="8. Your rights">
        <p>
          You can access your data, correct it, delete it, receive it in a readable format, and object to certain processing, by writing to [email address].
          You can also contact [competent data protection authority].
        </p>
      </Article>
    </LegalPage>
  );
}

function TraitementEN() {
  return (
    <LegalPage title="Data processing agreement" intro="What we do, as processor, with the data of your systems we scan on your behalf.">
      <Article title="1. Purpose">
        <p>
          Your business (the customer) is the controller of the data of its systems. [Company name] (Orus Shield) processes it on the customer’s behalf, as
          processor, for the sole purpose of providing the service described in the <Link to="/conditions">terms of use</Link>.
        </p>
      </Article>
      <Article title="2. Data and duration">
        <p>
          Technical data of your domains, servers, applications, APIs and internal networks, evidence of the problems found (which may contain extracts of
          your systems’ responses), test accounts provided. Duration: that of the contract, then [period] before deletion.
        </p>
      </Article>
      <Article title="3. Our commitments">
        <ul>
          <li>Process this data only on your instructions, that is, to run the scans you configure.</li>
          <li>Limit access to the people who need it, bound by confidentiality.</li>
          <li>Apply the security measures described in the privacy policy.</li>
          <li>Inform you of any data breach concerning you within [period] hours of becoming aware of it.</li>
          <li>Help you answer requests from data subjects and audits, within reason.</li>
          <li>Delete or return the data to you at the end of the contract, as you choose.</li>
        </ul>
      </Article>
      <Article title="4. Sub-processors">
        <p>
          [Hosting provider] (hosting), [email relay] (service emails), XposedOrNot (lookup of your domains’ email addresses in known data breaches). We
          inform you before adding a new one; you may object. [List and procedure to be
          specified.]
        </p>
      </Article>
      <Article title="5. Audits">
        <p>[Audit and documentation terms to be specified.]</p>
      </Article>
    </LegalPage>
  );
}
