// The home page (/). Its structure follows what established security
// products do (decided 2026-11-19, after studying them): a hero with the
// real product, what we check, three feature blocks with screenshots, a
// grid of capabilities, how to start, integrations, the trust we earn,
// prices, questions, a closing call. Nothing is invented: no customer
// logos, ratings or reviews until real ones exist; the screenshots are the
// real dashboard on an example domain.

import { useState, type ReactNode } from "react";
import { useAuth } from "../../auth";
import { tr } from "../../i18n";
import { Link, navigate } from "../../router";
import { MODS, ModIcon, Soon, Tick } from "../icons";
import { money } from "../model";
import { cleanDomain } from "../prefill";
import { useBodyClass } from "../ui";
import { MyPerimeter, price, PubFoot, PubHead, usePlans } from "./public";

/** Glyph draws the small line icons of the capability grid. */
function Glyph({ d }: { d: string }) {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}

const G = {
  mail: "M3 6h18v12H3zM3 7l9 6 9-6",
  lock: "M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18",
  server: "M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01",
  bug: "M12 3 2 20h20zM12 10v4M12 17h.01",
  bolt: "M13 2 4 14h7l-1 8 9-12h-7z",
  code: "M8 8l-4 4 4 4M16 8l4 4-4 4M14 5l-4 14",
  key: "M7 14a3 3 0 1 0 0 .01M9.5 12.5 19 3M15 7l2 2",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",
  net: "M12 3v6M5 21v-4h14v4M12 9a2 2 0 1 0 0 .01M12 11v6",
  file: "M6 3h9l4 4v14H6zM14 3v5h5M9 13h6M9 17h6",
  bell: "M6 16V11a6 6 0 0 1 12 0v5l2 2H4zM10 21h4",
};

/** Shot is a product screenshot in a window frame. */
function Shot({ src, alt, eager = false }: { src: string; alt: string; eager?: boolean }) {
  return (
    <figure className="shot">
      <span className="shotbar" aria-hidden="true">
        <i />
        <i />
        <i />
      </span>
      <img src={src} alt={alt} width={1600} height={1000} loading={eager ? "eager" : "lazy"} decoding="async" />
    </figure>
  );
}

function Feature({ kicker, title, text, points, img, alt, flip, link }: { kicker: string; title: string; text: string; points: string[]; img: string; alt: string; flip?: boolean; link?: ReactNode }) {
  return (
    <section className={"hfeat" + (flip ? " flip" : "")}>
      <div className="hfeattext">
        <p className="kicker">{kicker}</p>
        <h2>{title}</h2>
        <p className="herosub">{text}</p>
        <ul className="ticks">
          {points.map((p) => (
            <li key={p}>
              <i aria-hidden="true">
                <Tick size={12} width={3.4} />
              </i>
              {p}
            </li>
          ))}
        </ul>
        {link}
      </div>
      <Shot src={img} alt={alt} />
    </section>
  );
}

export function AccueilPage() {
  useBodyClass(["public"]);
  const plans = usePlans();
  const by = (id: string) => plans.find((p) => p.id === id);
  const [demo, setDemo] = useState("");
  const { state } = useAuth();
  const signedIn = state.status === "signed-in";
  const first = state.status === "signed-in" ? state.me.name.split(/\s+/)[0] : "";
  const test = (e: React.FormEvent) => {
    e.preventDefault();
    const d = cleanDomain(demo);
    navigate(d ? `/test?domaine=${encodeURIComponent(d)}` : "/test");
  };
  const testForm = (id: string, label: string) => (
    <form className="addrow herotest" noValidate onSubmit={test}>
      <label className="vh" htmlFor={id}>
        {label}
      </label>
      <input id={id} type="text" inputMode="url" autoComplete="off" spellCheck={false} placeholder={tr("votre-entreprise.cg", "your-company.com")} value={demo} onChange={(e) => setDemo(e.target.value)} />
      <button className="btn" type="submit">
        {tr("Tester mon domaine", "Test my domain")}
      </button>
    </form>
  );

  const caps: [string, string, string, string][] = [
    [G.mail, tr("Emails", "Email"), tr("SPF, DKIM et DMARC : personne n’envoie en votre nom.", "SPF, DKIM and DMARC: nobody sends in your name."), "/guides/dmarc"],
    [G.lock, tr("Certificats", "Certificates"), tr("Expiration, chaîne de confiance, versions de TLS.", "Expiry, chain of trust, TLS versions."), "/guides/certificat-tls"],
    [G.globe, tr("Sites web", "Websites"), tr("HTTPS imposé, HSTS, en-têtes de sécurité.", "HTTPS enforced, HSTS, security headers."), "/guides/securiser-site"],
    [G.server, tr("Ports et services", "Ports and services"), tr("Bases de données, accès distants et services oubliés.", "Databases, remote access and forgotten services."), "/tarifs"],
    [G.bug, tr("Vulnérabilités connues", "Known vulnerabilities"), tr("Les CVE de vos logiciels exposés, classées par risque réel.", "The CVEs of your exposed software, ranked by real risk."), "/tarifs"],
    [G.bolt, tr("Menaces émergentes", "Emerging threats"), tr("Une faille publiée aujourd’hui : nous revérifions aussitôt.", "A flaw published today: we check again at once."), "/tarifs"],
    [G.code, tr("Tests applicatifs", "Application tests"), tr("Injections, XSS et failles exploitables de vos sites.", "Injections, XSS and exploitable flaws in your sites."), "/tarifs"],
    [G.key, tr("Sécurité des API", "API security"), tr("Vos API OpenAPI ou GraphQL, testées comme un attaquant.", "Your OpenAPI or GraphQL APIs, tested like an attacker would."), "/tarifs"],
    [G.user, tr("Scans authentifiés", "Authenticated scans"), tr("Ce qui se cache derrière la connexion, avec un compte de test.", "What hides behind the login, with a test account."), "/tarifs"],
    [G.net, tr("Réseaux internes", "Internal networks"), tr("Un agent sur votre réseau, sans port à ouvrir.", "An agent on your network, no port to open."), "/tarifs"],
    [G.file, tr("Rapports PDF", "PDF reports"), tr("Un rapport Direction sans jargon, un rapport Technique complet.", "A plain executive report, a complete technical one."), "/tarifs"],
    [G.bell, tr("Alertes", "Alerts"), tr("Un email dès qu’un problème grave apparaît.", "An email as soon as a serious problem appears."), "/tarifs"],
  ];

  return (
    <main>
      <div className="view">
        <PubHead cur="accueil" />

        <section className="hhero">
          <div className="hherotext">
            <p className="eyebrow">{signedIn ? tr("Votre espace", "Your space") : tr("Surveillance continue de votre sécurité", "Continuous security monitoring")}</p>
            <h1>
              {signedIn
                ? first
                  ? tr(`Bon retour, ${first}.`, `Welcome back, ${first}.`)
                  : tr("Bon retour.", "Welcome back.")
                : tr("Trouvez vos failles avant les pirates.", "Find your security gaps before attackers do.")}
            </h1>
            <p className="herosub">
              {signedIn
                ? tr("Votre score, vos problèmes ouverts, et ce qu’il faut faire aujourd’hui.", "Your score, your open problems, and what to do today.")
                : tr(
                    "Orus Shield surveille vos domaines, vos emails et vos serveurs, puis vous dit quoi corriger en premier, étape par étape et sans jargon.",
                    "Orus Shield monitors your domains, your email and your servers, then tells you what to fix first, step by step and without jargon.",
                  )}
            </p>
            {signedIn ? (
              <div className="actions">
                <Link className="btn" to="/app">
                  {tr("Aller à mon tableau de bord", "Go to my dashboard")}
                </Link>
              </div>
            ) : (
              <>
                {testForm("demo-in", tr("Votre nom de domaine", "Your domain name"))}
                <p className="heronote">
                  <span>{tr("Gratuit, sans compte", "Free, no account")}</span>
                  <span>{tr("Résultat en 20 secondes", "Result in 20 seconds")}</span>
                  <span>
                    <Link to="/inscription">{tr("Ou essayez 14 jours", "Or try it for 14 days")}</Link>
                  </span>
                </p>
              </>
            )}
          </div>
          <div className="hherovis">
            {signedIn ? <MyPerimeter /> : <Shot src="/screens/aujourdhui.jpg" alt={tr("Le tableau de bord Orus Shield : score, problèmes ouverts et actions du jour", "The Orus Shield dashboard: score, open problems and today’s actions")} eager />}
          </div>
        </section>

        <section className="hstrip" aria-label={tr("Ce que nous vérifions", "What we check")}>
          <p>{tr("Ce que nous vérifions, chaque semaine", "What we check, every week")}</p>
          <ul>
            {MODS.map((m) => (
              <li key={m.key}>
                <ModIcon>{m.icon}</ModIcon>
                {m.title}
                {m.module === null && <Soon />}
              </li>
            ))}
          </ul>
        </section>

        <Feature
          kicker={tr("Voir", "See")}
          title={tr("Tout ce que vous exposez, au même endroit.", "Everything you expose, in one place.")}
          text={tr(
            "Nous trouvons vos sous-domaines, vos serveurs et leurs services, puis nous les vérifions tous. Un nouvel actif apparaît ? Il est surveillé aussitôt.",
            "We find your subdomains, your servers and their services, then check them all. A new asset appears? It is monitored at once.",
          )}
          points={[
            tr("Découverte par les journaux de certificats et le DNS", "Discovery through certificate logs and DNS"),
            tr("Technologies et versions détectées", "Technologies and versions detected"),
            tr("Chaque actif classé selon son problème le plus grave", "Each asset ranked by its most serious problem"),
          ]}
          img="/screens/actifs.jpg"
          alt={tr("L’inventaire des actifs d’un domaine", "A domain’s asset inventory")}
        />
        <Feature
          flip
          kicker={tr("Prioriser", "Prioritize")}
          title={tr("Sachez quoi corriger en premier.", "Know what to fix first.")}
          text={tr(
            "Pas une liste de 200 alertes : les trois actions qui vous protègent le plus aujourd’hui, avec le temps qu’elles prennent et les points qu’elles vous font gagner.",
            "Not a list of 200 alerts: the three actions that protect you most today, with the time they take and the points they win you.",
          )}
          points={[
            tr("Un score sur 100, expliqué en une phrase", "A score out of 100, explained in one sentence"),
            tr("Les vulnérabilités déjà exploitées passent en tête", "Already exploited vulnerabilities come first"),
            tr("Vos progrès, semaine après semaine", "Your progress, week after week"),
          ]}
          img="/screens/aujourdhui.jpg"
          alt={tr("Les actions du jour et le score", "Today’s actions and the score")}
        />
        <Feature
          kicker={tr("Corriger", "Fix")}
          title={tr("Corrigez vous-même, ou envoyez à votre prestataire.", "Fix it yourself, or send it to your provider.")}
          text={tr(
            "Chaque problème vient avec son explication et ses étapes. Votre agence web s’en occupe ? Envoyez-lui tout, par email ou WhatsApp. Cochez quand c’est fait : nous vérifions aussitôt.",
            "Every problem comes with its explanation and its steps. Your web agency handles it? Send them everything, by email or WhatsApp. Tick when it is done: we check at once.",
          )}
          points={[
            tr("Étapes claires, en français ou en anglais", "Clear steps, in French or English"),
            tr("La preuve technique pour votre informaticien", "The technical evidence for your IT person"),
            tr("Une vérification automatique après chaque correction", "An automatic check after every fix"),
          ]}
          img="/screens/problemes.jpg"
          alt={tr("La fiche d’un problème avec ses étapes de correction", "A problem’s sheet with its steps to fix it")}
        />

        <section className="hsection">
          <div className="hsectionhead">
            <p className="kicker">{tr("Plateforme", "Platform")}</p>
            <h2>{tr("Une seule plateforme pour toute votre surface d’attaque.", "One platform for your whole attack surface.")}</h2>
          </div>
          <ul className="capgrid">
            {caps.map(([d, t, x, to]) => (
              <li key={t}>
                <Link to={to}>
                  <span className="capicon">
                    <Glyph d={d} />
                  </span>
                  <b>{t}</b>
                  <span>{x}</span>
                </Link>
              </li>
            ))}
          </ul>
        </section>

        <section className="hsection">
          <div className="hsectionhead">
            <p className="kicker">{tr("Démarrage", "Getting started")}</p>
            <h2>{tr("Opérationnel en 5 minutes.", "Up and running in 5 minutes.")}</h2>
          </div>
          <ol className="hsteps">
            <li>
              <span>1</span>
              <b>{tr("Ajoutez votre domaine", "Add your domain")}</b>
              <p>{tr("Nous trouvons vos sous-domaines et vos serveurs.", "We find your subdomains and your servers.")}</p>
            </li>
            <li>
              <span>2</span>
              <b>{tr("Prouvez qu’il est à vous", "Prove it is yours")}</b>
              <p>{tr("Un enregistrement DNS, et le premier scan démarre.", "One DNS record, and the first scan starts.")}</p>
            </li>
            <li>
              <span>3</span>
              <b>{tr("Corrigez, nous vérifions", "Fix it, we check")}</b>
              <p>{tr("Chaque problème avec ses étapes, revérifié après correction.", "Every problem with its steps, checked again after the fix.")}</p>
            </li>
          </ol>
          {!signedIn && (
            <div className="actions" style={{ justifyContent: "center" }}>
              <Link className="btn" to="/inscription">
                {tr("Commencer gratuitement", "Start for free")}
              </Link>
            </div>
          )}
        </section>

        <section className="hsection">
          <div className="hsectionhead">
            <p className="kicker">{tr("Intégrations", "Integrations")}</p>
            <h2>{tr("Branché sur vos outils.", "Connected to your tools.")}</h2>
            <p className="herosub">{tr("Une API, des webhooks signés, et vos outils d’automatisation.", "An API, signed webhooks, and your automation tools.")}</p>
          </div>
          <ul className="intgrid">
            {(
              [
                ["API", tr("Lisez vos résultats, lancez des scans.", "Read your results, start scans."), "/docs/api", false],
                ["Webhooks", tr("Chaque événement, signé, dans vos outils.", "Every event, signed, in your tools."), "/docs/api", false],
                ["Zapier · Make · n8n", tr("Par les webhooks, sans code.", "Through webhooks, no code."), "/docs/api", false],
                ["WhatsApp", tr("Envoyez un problème à votre prestataire.", "Send a problem to your provider."), "/tarifs", false],
                ["Slack", tr("Les alertes dans vos canaux.", "Alerts in your channels."), "", true],
                ["Microsoft Teams", tr("Les alertes dans vos équipes.", "Alerts in your teams."), "", true],
              ] as const
            ).map(([n, d, to, soon]) => (
              <li key={n} className={soon ? "is-soon" : ""}>
                {to ? (
                  <Link to={to}>
                    <b>{n}</b>
                    <span>{d}</span>
                  </Link>
                ) : (
                  <div>
                    <b>
                      {n} <Soon />
                    </b>
                    <span>{d}</span>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </section>

        <section className="band dark htrust">
          <h2>{tr("Nous ne testons que ce qui vous appartient.", "We only test what belongs to you.")}</h2>
          <ul className="trust">
            <li>
              <b>{tr("Propriété prouvée", "Proven ownership")}</b>
              <span>{tr("Aucun test actif sans preuve que le domaine et le serveur sont à vous.", "No active test without proof that the domain and the server are yours.")}</span>
            </li>
            <li>
              <b>{tr("Vos limites respectées", "Your limits respected")}</b>
              <span>{tr("Vous choisissez la vitesse, les horaires et ce qu’on ne touche pas.", "You choose the speed, the hours and what we leave alone.")}</span>
            </li>
            <li>
              <b>{tr("Tout est tracé", "Everything is logged")}</b>
              <span>{tr("Chaque scan est enregistré : qui l’a lancé, sur quoi, et quand.", "Every scan is recorded: who started it, on what, and when.")}</span>
            </li>
            <li>
              <b>{tr("Vos secrets chiffrés", "Your secrets encrypted")}</b>
              <span>{tr("Mots de passe hachés, comptes de test chiffrés, double authentification.", "Hashed passwords, encrypted test accounts, two-factor authentication.")}</span>
            </li>
          </ul>
        </section>

        <section className="hsection">
          <div className="hsectionhead">
            <p className="kicker">{tr("Tarifs", "Pricing")}</p>
            <h2>{tr("Un prix simple, sans engagement.", "A simple price, no commitment.")}</h2>
          </div>
          <ul className="hprices">
            {(
              [
                ["discovery", tr("Gratuit", "Free"), tr("Un audit pour voir où vous en êtes.", "One audit to see where you stand.")],
                ["sme", tr("Essentiel", "Essential"), tr("La surveillance chaque semaine pour une PME.", "Weekly monitoring for a small business.")],
                ["pro", "Pro", tr("Tests applicatifs, API, scans quotidiens.", "Application tests, APIs, daily scans.")],
              ] as const
            ).map(([id, n, d]) => (
              <li key={id} className={id === "sme" ? "star" : ""}>
                <b>{n}</b>
                <p className="hprice">
                  {id === "discovery" ? money(0) : price(by(id), "mois")}
                  <small>{id === "discovery" ? tr("un audit", "one audit") : tr("par mois", "a month")}</small>
                </p>
                <span>{d}</span>
              </li>
            ))}
          </ul>
          <div className="actions" style={{ justifyContent: "center" }}>
            <Link className="btn ghost" to="/tarifs">
              {tr("Comparer les offres", "Compare the plans")}
            </Link>
          </div>
        </section>

        <section className="hsection">
          <div className="hsectionhead">
            <p className="kicker">{tr("Questions", "Questions")}</p>
            <h2>{tr("Questions fréquentes", "Frequently asked questions")}</h2>
          </div>
          <div className="faq hfaq">
            {(
              [
                [
                  tr("Est-ce que vos tests peuvent casser mon site ?", "Can your tests break my site?"),
                  tr(
                    "Non dans la plupart des cas : les contrôles de base lisent des données publiques, et les tests actifs respectent la vitesse que vous choisissez. Le profil approfondi, plus poussé, demande votre accord explicite.",
                    "Not in most cases: the basic checks read public data, and active tests respect the speed you choose. The deep profile, more thorough, needs your explicit consent.",
                  ),
                ],
                [
                  tr("Je n’ai pas d’informaticien. Est-ce pour moi ?", "I have no IT person. Is it for me?"),
                  tr(
                    "Oui : chaque problème est expliqué simplement avec ses étapes, et vous pouvez l’envoyer en un clic à votre agence web ou votre hébergeur.",
                    "Yes: every problem is explained simply with its steps, and you can send it in one click to your web agency or your host.",
                  ),
                ],
                [
                  tr("Pourquoi prouver que le domaine est à moi ?", "Why prove the domain is mine?"),
                  tr(
                    "Parce que nous ne testons jamais ce qui ne vous appartient pas. Un enregistrement DNS suffit, et il ne donne accès à rien.",
                    "Because we never test what does not belong to you. One DNS record is enough, and it gives access to nothing.",
                  ),
                ],
                [
                  tr("Comment se passe l’essai ?", "How does the trial work?"),
                  tr(
                    "14 jours avec tout ce que comprend l’offre. Rien n’est prélevé avant la fin, et vous annulez en un clic.",
                    "14 days with everything the plan includes. Nothing is charged before the end, and you cancel in one click.",
                  ),
                ],
                [
                  tr("Comment puis-je payer ?", "How can I pay?"),
                  tr("Par carte ou PayPal, au mois ou à l’année.", "By card or PayPal, monthly or yearly."),
                ],
              ] as const
            ).map(([q, a]) => (
              <details key={q}>
                <summary>{q}</summary>
                <p>{a}</p>
              </details>
            ))}
          </div>
        </section>

        {!signedIn && (
          <section className="hfinal">
            <h2>{tr("Où en est la sécurité de votre entreprise ?", "How secure is your business?")}</h2>
            <p className="herosub">{tr("Votre score sur 100 en 20 secondes, gratuitement.", "Your score out of 100 in 20 seconds, for free.")}</p>
            {testForm("final-in", tr("Le domaine à tester", "The domain to test"))}
          </section>
        )}
        <PubFoot />
      </div>
    </main>
  );
}
