// Guides (/guides): practical pages on what the public test checks, to be
// found by search engines and to lead to the test. Each guide is written
// whole in French and in English (like the legal pages): a guide reads as a
// whole, and its examples differ little between languages.
//
// They state only what is true of the protocols and of what Orus Shield
// checks; commands and records are standard (dig, openssl, DNS TXT).

import { useEffect, useState, type ReactNode } from "react";
import { useAuth } from "../../auth";
import { tr, useLang } from "../../i18n";
import { Link, navigate } from "../../router";
import { cleanDomain } from "../prefill";
import { useBodyClass } from "../ui";
import { G, Glyph } from "../glyphs";
import { slug, Toc } from "./article";
import { PubFoot, PubHead } from "./public";

interface GuideText {
  title: string;
  /** description: one or two sentences, for the index and search engines. */
  description: string;
  intro: ReactNode;
  sections: [string, ReactNode][];
}

interface Guide {
  slug: string;
  minutes: number;
  fr: GuideText;
  en: GuideText;
}

const Code = ({ children }: { children: string }) => <pre className="guidecode">{children}</pre>;

const GUIDES: Guide[] = [
  {
    slug: "dmarc",
    minutes: 6,
    fr: {
      title: "Vérifier et configurer DMARC pour protéger vos emails",
      description: "DMARC empêche qu’on envoie des emails frauduleux en votre nom. Comment vérifier votre enregistrement et le mettre en place pas à pas.",
      intro: (
        <p>
          N’importe qui peut envoyer un email qui prétend venir de <b>contact@votre-entreprise.cg</b>. Sans protection, vos clients le reçoivent : c’est la base de
          l’hameçonnage et des fausses factures. DMARC dit aux messageries quoi faire d’un email qui se fait passer pour vous.
        </p>
      ),
      sections: [
        [
          "Ce que fait DMARC",
          <>
            <p>
              DMARC s’appuie sur deux autres protections : SPF (les serveurs autorisés à envoyer vos emails) et DKIM (une signature ajoutée à chaque email). Il
              publie, dans votre DNS, votre politique pour les emails qui échouent à ces vérifications :
            </p>
            <ul>
              <li>
                <b>p=none</b> : ne rien bloquer, seulement envoyer des rapports. C’est l’étape d’observation.
              </li>
              <li>
                <b>p=quarantine</b> : mettre ces emails en indésirables.
              </li>
              <li>
                <b>p=reject</b> : les refuser. C’est la protection complète.
              </li>
            </ul>
          </>,
        ],
        [
          "Vérifier votre domaine",
          <>
            <p>Le plus simple : lancez notre test gratuit, il lit votre enregistrement DMARC et vous dit ce qui manque. Vous pouvez aussi le lire vous-même :</p>
            <Code>dig +short TXT _dmarc.votre-entreprise.cg</Code>
            <p>
              Aucune réponse : vous n’avez pas de DMARC. Une réponse commence par <b>v=DMARC1</b> et contient votre politique (<b>p=</b>).
            </p>
          </>,
        ],
        [
          "Le mettre en place, pas à pas",
          <>
            <p>
              <b>1. Vérifiez d’abord SPF et DKIM</b> chez votre fournisseur d’emails (Google Workspace, Microsoft 365, votre hébergeur…) : DMARC ne sert à rien sans
              eux.
            </p>
            <p>
              <b>2. Publiez un enregistrement d’observation.</b> Dans la zone DNS de votre domaine, ajoutez un enregistrement TXT nommé <b>_dmarc</b> :
            </p>
            <Code>v=DMARC1; p=none; rua=mailto:dmarc@votre-entreprise.cg</Code>
            <p>
              <b>3. Lisez les rapports pendant deux à quatre semaines.</b> L’adresse de <b>rua</b> reçoit chaque jour des rapports des grandes messageries : ils
              montrent qui envoie des emails en votre nom, y compris vos outils légitimes (facturation, newsletter) oubliés dans SPF.
            </p>
            <p>
              <b>4. Durcissez</b> quand tous vos envois légitimes passent : <b>p=quarantine</b>, puis <b>p=reject</b>.
            </p>
            <Code>v=DMARC1; p=reject; rua=mailto:dmarc@votre-entreprise.cg</Code>
          </>,
        ],
        [
          "Les erreurs courantes",
          <ul>
            <li>Rester en p=none pour toujours : vous observez, mais personne n’est protégé.</li>
            <li>Publier deux enregistrements DMARC : les messageries ignorent alors les deux.</li>
            <li>Passer directement à p=reject sans observer : vos propres emails de facturation ou de newsletter peuvent être bloqués.</li>
            <li>Oublier rua : sans rapports, impossible de savoir qui envoie en votre nom.</li>
          </ul>,
        ],
      ],
    },
    en: {
      title: "Check and set up DMARC to protect your email",
      description: "DMARC stops fraudulent email sent in your name. How to check your record and set it up step by step.",
      intro: (
        <p>
          Anyone can send an email claiming to come from <b>contact@your-company.com</b>. Without protection, your customers receive it: that is how phishing and
          fake invoices work. DMARC tells mail providers what to do with an email that pretends to be you.
        </p>
      ),
      sections: [
        [
          "What DMARC does",
          <>
            <p>
              DMARC relies on two other protections: SPF (the servers allowed to send your email) and DKIM (a signature added to each email). It publishes, in
              your DNS, your policy for emails that fail these checks:
            </p>
            <ul>
              <li>
                <b>p=none</b>: block nothing, only send reports. This is the observation step.
              </li>
              <li>
                <b>p=quarantine</b>: send these emails to spam.
              </li>
              <li>
                <b>p=reject</b>: refuse them. This is full protection.
              </li>
            </ul>
          </>,
        ],
        [
          "Check your domain",
          <>
            <p>The simplest way: run our free test, it reads your DMARC record and tells you what is missing. You can also read it yourself:</p>
            <Code>dig +short TXT _dmarc.your-company.com</Code>
            <p>
              No answer: you have no DMARC. An answer starts with <b>v=DMARC1</b> and contains your policy (<b>p=</b>).
            </p>
          </>,
        ],
        [
          "Set it up, step by step",
          <>
            <p>
              <b>1. Check SPF and DKIM first</b> with your email provider (Google Workspace, Microsoft 365, your host…): DMARC is useless without them.
            </p>
            <p>
              <b>2. Publish an observation record.</b> In your domain’s DNS zone, add a TXT record named <b>_dmarc</b>:
            </p>
            <Code>v=DMARC1; p=none; rua=mailto:dmarc@your-company.com</Code>
            <p>
              <b>3. Read the reports for two to four weeks.</b> The <b>rua</b> address receives daily reports from the large mail providers: they show who sends
              email in your name, including legitimate tools (billing, newsletter) missing from SPF.
            </p>
            <p>
              <b>4. Tighten</b> once all your legitimate sending passes: <b>p=quarantine</b>, then <b>p=reject</b>.
            </p>
            <Code>v=DMARC1; p=reject; rua=mailto:dmarc@your-company.com</Code>
          </>,
        ],
        [
          "Common mistakes",
          <ul>
            <li>Staying at p=none forever: you observe, but nobody is protected.</li>
            <li>Publishing two DMARC records: mail providers then ignore both.</li>
            <li>Going straight to p=reject without observing: your own billing or newsletter emails may be blocked.</li>
            <li>Forgetting rua: without reports, you cannot know who sends in your name.</li>
          </ul>,
        ],
      ],
    },
  },
  {
    slug: "spf",
    minutes: 5,
    fr: {
      title: "SPF : déclarer qui a le droit d’envoyer vos emails",
      description: "Un enregistrement SPF liste les serveurs autorisés à envoyer les emails de votre domaine. Comment le vérifier, l’écrire et éviter les erreurs.",
      intro: (
        <p>
          SPF est un enregistrement DNS qui dit au monde : « seuls ces serveurs envoient des emails pour mon domaine ». Les messageries s’en servent pour repérer
          les emails usurpés, et DMARC en a besoin.
        </p>
      ),
      sections: [
        [
          "Vérifier votre domaine",
          <>
            <p>Lancez notre test gratuit, ou lisez l’enregistrement vous-même :</p>
            <Code>dig +short TXT votre-entreprise.cg</Code>
            <p>
              Cherchez une ligne qui commence par <b>v=spf1</b>. Il ne doit y en avoir <b>qu’une seule</b>.
            </p>
          </>,
        ],
        [
          "Écrire votre enregistrement",
          <>
            <p>Listez tout ce qui envoie des emails pour vous, puis publiez un enregistrement TXT sur le domaine lui-même. Par exemple, avec Google Workspace :</p>
            <Code>v=spf1 include:_spf.google.com -all</Code>
            <p>Avec Microsoft 365 :</p>
            <Code>v=spf1 include:spf.protection.outlook.com -all</Code>
            <p>
              Ajoutez un <b>include:</b> par outil qui envoie en votre nom (outil de facturation, newsletter…) : leur documentation donne la valeur exacte.
            </p>
          </>,
        ],
        [
          "La fin de l’enregistrement compte",
          <ul>
            <li>
              <b>-all</b> : tout autre serveur est refusé. Le plus sûr, une fois la liste complète.
            </li>
            <li>
              <b>~all</b> : tout autre serveur est suspect. Acceptable pendant une transition.
            </li>
            <li>
              <b>?all</b> : aucun avis. Ne protège rien.
            </li>
            <li>
              <b>+all</b> : tout le monde est autorisé. Dangereux : à corriger immédiatement.
            </li>
          </ul>,
        ],
        [
          "Les erreurs courantes",
          <ul>
            <li>Deux enregistrements SPF : SPF échoue entièrement. Fusionnez-les en un seul.</li>
            <li>Plus de 10 consultations DNS (chaque include en compte au moins une) : SPF échoue. Retirez les outils que vous n’utilisez plus.</li>
            <li>Oublier un outil d’envoi : ses emails seront marqués comme suspects.</li>
          </ul>,
        ],
      ],
    },
    en: {
      title: "SPF: declare who may send your email",
      description: "An SPF record lists the servers allowed to send your domain’s email. How to check it, write it and avoid mistakes.",
      intro: (
        <p>
          SPF is a DNS record that tells the world: “only these servers send email for my domain”. Mail providers use it to spot spoofed email, and DMARC needs
          it.
        </p>
      ),
      sections: [
        [
          "Check your domain",
          <>
            <p>Run our free test, or read the record yourself:</p>
            <Code>dig +short TXT your-company.com</Code>
            <p>
              Look for a line starting with <b>v=spf1</b>. There must be <b>only one</b>.
            </p>
          </>,
        ],
        [
          "Write your record",
          <>
            <p>List everything that sends email for you, then publish a TXT record on the domain itself. For example, with Google Workspace:</p>
            <Code>v=spf1 include:_spf.google.com -all</Code>
            <p>With Microsoft 365:</p>
            <Code>v=spf1 include:spf.protection.outlook.com -all</Code>
            <p>
              Add one <b>include:</b> per tool that sends in your name (billing tool, newsletter…): their documentation gives the exact value.
            </p>
          </>,
        ],
        [
          "The end of the record matters",
          <ul>
            <li>
              <b>-all</b>: any other server is refused. The safest, once the list is complete.
            </li>
            <li>
              <b>~all</b>: any other server is suspicious. Acceptable during a transition.
            </li>
            <li>
              <b>?all</b>: no opinion. Protects nothing.
            </li>
            <li>
              <b>+all</b>: everyone is allowed. Dangerous: fix it at once.
            </li>
          </ul>,
        ],
        [
          "Common mistakes",
          <ul>
            <li>Two SPF records: SPF fails entirely. Merge them into one.</li>
            <li>More than 10 DNS lookups (each include counts at least one): SPF fails. Remove the tools you no longer use.</li>
            <li>Forgetting a sending tool: its emails will be marked as suspicious.</li>
          </ul>,
        ],
      ],
    },
  },
  {
    slug: "certificat-tls",
    minutes: 5,
    fr: {
      title: "Tester le certificat SSL/TLS de votre site",
      description: "Un certificat expiré ou mal installé affiche une alerte de sécurité à vos visiteurs. Comment le vérifier et le garder valide sans effort.",
      intro: (
        <p>
          Le certificat de votre site prouve aux navigateurs qu’ils parlent bien à vous, et chiffre ce qui s’échange. Expiré, mal installé ou trop ancien, il
          affiche une alerte qui fait fuir vos visiteurs, et il peut exposer leurs données.
        </p>
      ),
      sections: [
        [
          "Ce qu’il faut vérifier",
          <ul>
            <li>Qu’il n’est pas expiré, et qu’il ne le sera pas dans les prochaines semaines.</li>
            <li>Qu’il couvre bien votre nom, avec et sans www.</li>
            <li>Qu’il est reconnu par les navigateurs : émis par une autorité connue, avec ses certificats intermédiaires.</li>
            <li>Que le serveur refuse les anciennes versions de TLS (1.0 et 1.1) : seules TLS 1.2 et 1.3 sont sûres.</li>
          </ul>,
        ],
        [
          "Vérifier votre site",
          <>
            <p>Notre test gratuit vérifie tout cela sur votre domaine et son www. En ligne de commande :</p>
            <Code>{"openssl s_client -connect votre-entreprise.cg:443 -servername votre-entreprise.cg </dev/null | openssl x509 -noout -dates -subject"}</Code>
            <p>
              <b>notAfter</b> donne la date d’expiration.
            </p>
          </>,
        ],
        [
          "Corriger",
          <>
            <p>
              <b>Expiré ou bientôt expiré :</b> le plus durable est un certificat gratuit Let’s Encrypt renouvelé automatiquement. La plupart des hébergeurs le
              proposent en un clic ; sur votre propre serveur, l’outil certbot s’en charge.
            </p>
            <p>
              <b>Non reconnu :</b> installez la chaîne complète (le fichier « fullchain »), pas seulement votre certificat. C’est l’oubli le plus fréquent.
            </p>
            <p>
              <b>Anciennes versions de TLS :</b> limitez le serveur à TLS 1.2 et 1.3. Avec nginx :
            </p>
            <Code>ssl_protocols TLSv1.2 TLSv1.3;</Code>
          </>,
        ],
      ],
    },
    en: {
      title: "Test your website’s SSL/TLS certificate",
      description: "An expired or badly installed certificate shows your visitors a security warning. How to check it and keep it valid without effort.",
      intro: (
        <p>
          Your site’s certificate proves to browsers that they are really talking to you, and encrypts what is exchanged. Expired, badly installed or outdated,
          it shows a warning that drives visitors away, and it can expose their data.
        </p>
      ),
      sections: [
        [
          "What to check",
          <ul>
            <li>That it has not expired, and will not in the coming weeks.</li>
            <li>That it covers your name, with and without www.</li>
            <li>That browsers trust it: issued by a known authority, with its intermediate certificates.</li>
            <li>That the server refuses old TLS versions (1.0 and 1.1): only TLS 1.2 and 1.3 are safe.</li>
          </ul>,
        ],
        [
          "Check your site",
          <>
            <p>Our free test checks all of this on your domain and its www. From the command line:</p>
            <Code>{"openssl s_client -connect your-company.com:443 -servername your-company.com </dev/null | openssl x509 -noout -dates -subject"}</Code>
            <p>
              <b>notAfter</b> gives the expiry date.
            </p>
          </>,
        ],
        [
          "Fix it",
          <>
            <p>
              <b>Expired or about to expire:</b> the most durable fix is a free Let’s Encrypt certificate renewed automatically. Most hosts offer it in one click;
              on your own server, the certbot tool handles it.
            </p>
            <p>
              <b>Not trusted:</b> install the full chain (the “fullchain” file), not only your certificate. It is the most common slip.
            </p>
            <p>
              <b>Old TLS versions:</b> limit the server to TLS 1.2 and 1.3. With nginx:
            </p>
            <Code>ssl_protocols TLSv1.2 TLSv1.3;</Code>
          </>,
        ],
      ],
    },
  },
  {
    slug: "securiser-site",
    minutes: 7,
    fr: {
      title: "Sécuriser son site : HTTPS, HSTS et en-têtes de sécurité",
      description: "Quelques lignes de configuration protègent vos visiteurs : redirection HTTPS, HSTS et en-têtes de sécurité. Lesquelles, et comment les ajouter.",
      intro: (
        <p>
          Un certificat valide ne suffit pas : encore faut-il que vos visiteurs arrivent en HTTPS, et que leur navigateur sache se protéger. Cela tient à
          quelques lignes de configuration de votre serveur ou de votre hébergeur.
        </p>
      ),
      sections: [
        [
          "Les réglages qui comptent",
          <ul>
            <li>
              <b>Redirection HTTP vers HTTPS</b> : une adresse tapée sans « https » doit être redirigée, de façon permanente (code 301).
            </li>
            <li>
              <b>HSTS</b> : dit au navigateur de n’utiliser que HTTPS pour votre site, même si on tape http.
            </li>
            <li>
              <b>Content-Security-Policy</b> : limite d’où viennent les scripts de vos pages, contre l’injection de code.
            </li>
            <li>
              <b>X-Content-Type-Options: nosniff</b> : empêche le navigateur de deviner le type d’un fichier.
            </li>
            <li>
              <b>frame-ancestors</b> (ou X-Frame-Options) : empêche d’autres sites d’afficher vos pages dans un cadre, contre le « clickjacking ».
            </li>
            <li>Ne pas afficher les versions de vos logiciels : elles aident un attaquant à choisir sa faille.</li>
          </ul>,
        ],
        [
          "Vérifier votre site",
          <>
            <p>Notre test gratuit vérifie tous ces points. Pour voir les en-têtes vous-même :</p>
            <Code>curl -sI https://votre-entreprise.cg</Code>
          </>,
        ],
        [
          "Les ajouter avec nginx",
          <>
            <Code>
              {`server {
    listen 80;
    server_name votre-entreprise.cg www.votre-entreprise.cg;
    return 301 https://$host$request_uri;
}

# dans le bloc server en 443 :
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "frame-ancestors 'self'" always;
server_tokens off;`}
            </Code>
            <p>
              Commencez la Content-Security-Policy par frame-ancestors, puis resserrez-la page par page : une politique trop stricte d’emblée peut casser votre
              site.
            </p>
          </>,
        ],
        [
          "Les ajouter avec Apache",
          <Code>
            {`Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "frame-ancestors 'self'"
ServerTokens Prod
ServerSignature Off`}
          </Code>,
        ],
        [
          "Sur un hébergement mutualisé ou un CMS",
          <p>
            Beaucoup d’hébergeurs proposent « Forcer HTTPS » et HSTS dans leur panneau. Sur WordPress, une extension de sécurité reconnue peut ajouter les
            en-têtes. Dans le doute, envoyez ce guide à votre hébergeur : ce sont des réglages standards.
          </p>,
        ],
      ],
    },
    en: {
      title: "Secure your website: HTTPS, HSTS and security headers",
      description: "A few lines of configuration protect your visitors: HTTPS redirect, HSTS and security headers. Which ones, and how to add them.",
      intro: (
        <p>
          A valid certificate is not enough: your visitors must also arrive over HTTPS, and their browser must know how to protect itself. It takes a few lines
          of configuration on your server or with your host.
        </p>
      ),
      sections: [
        [
          "The settings that matter",
          <ul>
            <li>
              <b>HTTP to HTTPS redirect</b>: an address typed without “https” must be redirected, permanently (code 301).
            </li>
            <li>
              <b>HSTS</b>: tells the browser to use only HTTPS for your site, even if someone types http.
            </li>
            <li>
              <b>Content-Security-Policy</b>: limits where your pages’ scripts come from, against code injection.
            </li>
            <li>
              <b>X-Content-Type-Options: nosniff</b>: stops the browser from guessing a file’s type.
            </li>
            <li>
              <b>frame-ancestors</b> (or X-Frame-Options): stops other sites from showing your pages in a frame, against clickjacking.
            </li>
            <li>Do not show your software versions: they help an attacker pick a flaw.</li>
          </ul>,
        ],
        [
          "Check your site",
          <>
            <p>Our free test checks all of these. To see the headers yourself:</p>
            <Code>curl -sI https://your-company.com</Code>
          </>,
        ],
        [
          "Add them with nginx",
          <>
            <Code>
              {`server {
    listen 80;
    server_name your-company.com www.your-company.com;
    return 301 https://$host$request_uri;
}

# in the server block on 443:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "frame-ancestors 'self'" always;
server_tokens off;`}
            </Code>
            <p>Start the Content-Security-Policy with frame-ancestors, then tighten it page by page: a policy too strict at once can break your site.</p>
          </>,
        ],
        [
          "Add them with Apache",
          <Code>
            {`Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set Content-Security-Policy "frame-ancestors 'self'"
ServerTokens Prod
ServerSignature Off`}
          </Code>,
        ],
        [
          "On shared hosting or a CMS",
          <p>
            Many hosts offer “Force HTTPS” and HSTS in their panel. On WordPress, a well-known security plugin can add the headers. When in doubt, send this guide
            to your host: these are standard settings.
          </p>,
        ],
      ],
    },
  },
];

/** useMeta sets the page's title and description (search engines, shared
 * links), and puts the previous ones back when the page closes. */
function useMeta(title: string, description: string) {
  useEffect(() => {
    const prevTitle = document.title;
    let meta = document.querySelector<HTMLMetaElement>('meta[name="description"]');
    const created = !meta;
    if (!meta) {
      meta = document.createElement("meta");
      meta.name = "description";
      document.head.appendChild(meta);
    }
    const prevDesc = meta.content;
    document.title = title + " · Orus Shield";
    meta.content = description;
    return () => {
      document.title = prevTitle;
      if (created) meta?.remove();
      else if (meta) meta.content = prevDesc;
    };
  }, [title, description]);
}

/** TestBox leads a reader to the public test (visitors only, as on the
 * home page; a signed-in customer goes to their dashboard). */
function TestBox() {
  const { state } = useAuth();
  const [d, setD] = useState("");
  if (state.status === "signed-in") {
    return (
      <div className="rpanel guidebox">
        <p className="mt">{tr("Vos domaines sont vérifiés chaque semaine.", "Your domains are checked every week.")}</p>
        <Link className="btn" to="/app">
          {tr("Aller à mon tableau de bord", "Go to my dashboard")}
        </Link>
      </div>
    );
  }
  return (
    <form
      className="rpanel guidebox"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        const c = cleanDomain(d);
        navigate(c ? `/test?domaine=${encodeURIComponent(c)}` : "/test");
      }}
    >
      <p className="mt">{tr("Testez votre domaine gratuitement, sans compte, en 20 secondes.", "Test your domain for free, without an account, in 20 seconds.")}</p>
      <div className="addrow">
        <label className="vh" htmlFor="guide-domain">
          {tr("Votre nom de domaine", "Your domain name")}
        </label>
        <input
          id="guide-domain"
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          placeholder={tr("votre-entreprise.cg", "your-company.com")}
          value={d}
          onChange={(e) => setD(e.target.value)}
        />
        <button className="btn" type="submit">
          {tr("Tester mon domaine", "Test my domain")}
        </button>
      </div>
    </form>
  );
}

/** CATEGORIES group the guides, with their icon. */
type Category = "email" | "tls" | "web";
const CATEGORIES: [Category, () => string, string][] = [
  ["email", () => tr("Emails", "Email"), G.mail],
  ["tls", () => tr("Certificats", "Certificates"), G.lock],
  ["web", () => tr("Sites web", "Websites"), G.globe],
];
const CATEGORY_OF: Record<string, Category> = { dmarc: "email", spf: "email", "certificat-tls": "tls", "securiser-site": "web" };
const category = (slug: string) => CATEGORIES.find(([k]) => k === CATEGORY_OF[slug]) ?? CATEGORIES[0]!;

/** GuideCard is a guide in a list: its category, title, summary and length. */
function GuideCard({ g, compact }: { g: Guide; compact?: boolean }) {
  const { lang } = useLang();
  const t = lang === "en" ? g.en : g.fr;
  const [, cat, icon] = category(g.slug);
  return (
    <Link className={"gcard" + (compact ? " compact" : "")} to={`/guides/${g.slug}`}>
      <span className="gcardtop">
        <span className="capicon">
          <Glyph d={icon} />
        </span>
        <small>{cat()}</small>
      </span>
      <b>{t.title}</b>
      {!compact && <span className="gdesc">{t.description}</span>}
      <span className="gfoot">
        <span>{tr(`${g.minutes} min de lecture`, `${g.minutes} min read`)}</span>
        <span className="gread">
          {tr("Lire", "Read")} <Glyph d={G.arrow} size={16} />
        </span>
      </span>
    </Link>
  );
}

export function GuidesIndexPage() {
  useBodyClass(["public"]);
  const [cat, setCat] = useState<Category | "">("");
  useMeta(
    tr("Guides de sécurité pour les entreprises", "Security guides for businesses"),
    tr(
      "Guides pratiques pour protéger vos emails, votre certificat et votre site : DMARC, SPF, TLS, HTTPS et en-têtes de sécurité.",
      "Practical guides to protect your email, your certificate and your website: DMARC, SPF, TLS, HTTPS and security headers.",
    ),
  );
  const shown = GUIDES.filter((g) => !cat || CATEGORY_OF[g.slug] === cat);
  return (
    <main>
      <div className="view">
        <PubHead cur="guides" />
        <section className="lhead center">
          <p className="kicker">{tr("Ressources", "Resources")}</p>
          <h1>{tr("Guides de sécurité", "Security guides")}</h1>
          <p className="herosub">
            {tr(
              "Ce qu’il faut vérifier sur vos emails, votre certificat et votre site, et comment le corriger, étape par étape. Sans jargon.",
              "What to check on your email, your certificate and your website, and how to fix it, step by step. Without jargon.",
            )}
          </p>
          <div className="chips" role="group" aria-label={tr("Catégories", "Categories")}>
            <button type="button" aria-pressed={cat === ""} onClick={() => setCat("")}>
              {tr("Tous", "All")} <small>{GUIDES.length}</small>
            </button>
            {CATEGORIES.map(([k, name]) => (
              <button key={k} type="button" aria-pressed={cat === k} onClick={() => setCat(k)}>
                {name()} <small>{GUIDES.filter((g) => CATEGORY_OF[g.slug] === k).length}</small>
              </button>
            ))}
          </div>
        </section>
        <ul className="ggrid">
          {shown.map((g) => (
            <li key={g.slug}>
              <GuideCard g={g} />
            </li>
          ))}
        </ul>
        <section className="hfinal gfinal">
          <h2>{tr("Où en est votre domaine ?", "How is your domain doing?")}</h2>
          <p className="herosub">{tr("Notre test vérifie tout ce que décrivent ces guides, en 20 secondes.", "Our test checks everything these guides describe, in 20 seconds.")}</p>
          <TestBox />
        </section>
        <PubFoot />
      </div>
    </main>
  );
}

export function GuidePage({ slug: guideSlug }: { slug: string }) {
  useBodyClass(["public"]);
  const { lang } = useLang();
  const g = GUIDES.find((x) => x.slug === guideSlug);
  const t = g ? (lang === "en" ? g.en : g.fr) : null;
  useMeta(t?.title ?? tr("Guide introuvable", "Guide not found"), t?.description ?? "");
  const [, cat, icon] = category(guideSlug);
  return (
    <main>
      <div className="view">
        <PubHead cur="guides" />
        {!g || !t ? (
          <section className="phead">
            <h1>{tr("Ce guide n’existe pas.", "This guide does not exist.")}</h1>
            <p className="herosub">
              <Link to="/guides">{tr("Voir tous les guides", "See all guides")}</Link>
            </p>
          </section>
        ) : (
          <article className="guide2">
            <header className="ghead">
              <nav className="crumbs" aria-label={tr("Fil d’Ariane", "Breadcrumb")}>
                <Link to="/guides">{tr("Guides", "Guides")}</Link>
                <span aria-hidden="true">/</span>
                <span>{cat()}</span>
              </nav>
              <h1>{t.title}</h1>
              <p className="gmeta">
                <span className="gcat">
                  <Glyph d={icon} size={16} />
                  {cat()}
                </span>
                <span>{tr(`${g.minutes} min de lecture`, `${g.minutes} min read`)}</span>
              </p>
            </header>
            <div className="artlayout tocright">
              <div className="artbody">
                <div className="guidetext guideintro">{t.intro}</div>
                <TestBox />
                {t.sections.map(([h, body]) => (
                  <section key={h} id={slug(h)} className="gsec">
                    <h2>{h}</h2>
                    <div className="guidetext">{body}</div>
                  </section>
                ))}
              </div>
              <aside>
                <Toc titles={t.sections.map(([h]) => h)} />
              </aside>
            </div>
            <section className="gmore">
              <h2>{tr("Les autres guides", "The other guides")}</h2>
              <ul className="ggrid three">
                {GUIDES.filter((x) => x.slug !== guideSlug).map((x) => (
                  <li key={x.slug}>
                    <GuideCard g={x} compact />
                  </li>
                ))}
              </ul>
            </section>
          </article>
        )}
        <PubFoot />
      </div>
    </main>
  );
}

/** GUIDE_SLUGS lists the guides, for the router and the tests. */
export const GUIDE_SLUGS = GUIDES.map((g) => g.slug);
