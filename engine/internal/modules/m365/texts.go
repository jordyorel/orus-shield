package m365

import (
	"fmt"

	"github.com/jordyorel/orus-shield/engine/internal/finding"
)

// check is one catalog entry with its finding texts, in English and French.
// finding and findingFR may take the arguments build receives.
type check struct {
	severity            finding.Severity
	title, titleFR      string // what is checked (catalog)
	finding, findingFR  string // the finding's title
	description, descFR string
	steps, stepsFR      []string
	references          []string
}

// checkOrder is the catalog's order: the most serious first.
var checkOrder = []string{
	CheckAdminMFA, CheckBaseline, CheckLegacyAuth, CheckForward, CheckUserMFA,
	CheckTooManyAdmins, CheckUserConsent, CheckSingleAdmin, CheckGuestInvites,
	CheckAppRegistration, CheckInactive,
}

const cisM365 = "https://www.cisecurity.org/benchmark/microsoft_365"

var catalog = map[string]check{
	CheckAdminMFA: {
		severity: finding.SeverityCritical,
		title:    "Every global administrator has multi-factor authentication", titleFR: "Chaque administrateur général a la double authentification",
		finding: "Global administrator without multi-factor authentication", findingFR: "Administrateur général sans double authentification",
		description: "This account can change everything in the tenant: users, mail, security settings. Protected by a password alone, one phishing email or one leaked password is enough to take over the whole organization.",
		descFR:      "Ce compte peut tout modifier dans le tenant : utilisateurs, messagerie, réglages de sécurité. Protégé par un seul mot de passe, un e-mail d’hameçonnage ou un mot de passe fuité suffit pour prendre le contrôle de toute l’organisation.",
		steps: []string{
			"Sign in with this account and register Microsoft Authenticator, or a security key, at https://aka.ms/mysecurityinfo.",
			"Require multi-factor authentication for administrators: turn on security defaults, or a conditional access policy for the administrator roles.",
			"Use this account for administration only, and a separate everyday account for mail and documents.",
		},
		stepsFR: []string{
			"Connectez-vous avec ce compte et enregistrez Microsoft Authenticator, ou une clé de sécurité, sur https://aka.ms/mysecurityinfo.",
			"Exigez la double authentification pour les administrateurs : activez les paramètres de sécurité par défaut, ou une stratégie d’accès conditionnel pour les rôles d’administrateur.",
			"Réservez ce compte à l’administration, et utilisez un autre compte au quotidien pour la messagerie et les documents.",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks", cisM365},
	},
	CheckUserMFA: {
		severity: finding.SeverityHigh,
		title:    "Every account has multi-factor authentication", titleFR: "Chaque compte a la double authentification",
		finding: "Account without multi-factor authentication", findingFR: "Compte sans double authentification",
		description: "No second factor is registered for this account. A stolen or guessed password gives access to its mailbox and files, and attackers use such mailboxes to send convincing fraud to customers and suppliers.",
		descFR:      "Aucun second facteur n’est enregistré pour ce compte. Un mot de passe volé ou deviné donne accès à sa messagerie et à ses fichiers, et les attaquants se servent de ces boîtes pour envoyer des fraudes crédibles aux clients et aux fournisseurs.",
		steps: []string{
			"Ask the person to register Microsoft Authenticator at https://aka.ms/mysecurityinfo.",
			"Make multi-factor authentication mandatory for everyone (security defaults, or conditional access), so that new accounts cannot skip it.",
		},
		stepsFR: []string{
			"Demandez à la personne d’enregistrer Microsoft Authenticator sur https://aka.ms/mysecurityinfo.",
			"Rendez la double authentification obligatoire pour tous (paramètres de sécurité par défaut, ou accès conditionnel), pour que les nouveaux comptes ne puissent pas s’en passer.",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks", cisM365},
	},
	CheckBaseline: {
		severity: finding.SeverityHigh,
		title:    "Multi-factor authentication is required for all users", titleFR: "La double authentification est exigée pour tous les utilisateurs",
		finding: "Nothing requires multi-factor authentication in the tenant", findingFR: "Rien n’exige la double authentification dans le tenant",
		description: "Security defaults are off and no conditional access policy requires multi-factor authentication for all users. Each account is protected only if its owner chose to register a second factor.",
		descFR:      "Les paramètres de sécurité par défaut sont désactivés et aucune stratégie d’accès conditionnel n’exige la double authentification pour tous. Chaque compte n’est protégé que si son titulaire a choisi d’enregistrer un second facteur.",
		steps: []string{
			"In the Microsoft Entra admin center, Identity > Overview > Properties > Manage security defaults: turn them on. They are free and require MFA for everyone.",
			"With Microsoft Entra ID P1 (Microsoft 365 Business Premium), use conditional access instead: a policy for all users and all cloud apps granting access only with MFA, excluding one emergency account.",
		},
		stepsFR: []string{
			"Dans le centre d’administration Microsoft Entra, Identité > Vue d’ensemble > Propriétés > Gérer les paramètres de sécurité par défaut : activez-les. Ils sont gratuits et exigent la double authentification pour tous.",
			"Avec Microsoft Entra ID P1 (Microsoft 365 Business Premium), utilisez plutôt l’accès conditionnel : une stratégie pour tous les utilisateurs et toutes les applications cloud qui n’accorde l’accès qu’avec la double authentification, en excluant un compte d’urgence.",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults", cisM365},
	},
	CheckLegacyAuth: {
		severity: finding.SeverityHigh,
		title:    "Legacy authentication is blocked", titleFR: "L’authentification héritée est bloquée",
		finding: "Legacy authentication is not blocked", findingFR: "L’authentification héritée n’est pas bloquée",
		description: "Old mail protocols (IMAP, POP, SMTP authentication, Exchange ActiveSync with basic sign-in) cannot ask for a second factor. Attackers use them to try leaked passwords at scale and get around multi-factor authentication.",
		descFR:      "Les anciens protocoles de messagerie (IMAP, POP, authentification SMTP, Exchange ActiveSync en connexion simple) ne savent pas demander de second facteur. Les attaquants s’en servent pour essayer en masse des mots de passe fuités et contourner la double authentification.",
		steps: []string{
			"Turn on security defaults: they block legacy authentication.",
			"Or, with conditional access, create a policy for all users whose client apps are \"Exchange ActiveSync clients\" and \"Other clients\", with Block access.",
			"Before that, check in the sign-in logs that no printer or old application still depends on these protocols.",
		},
		stepsFR: []string{
			"Activez les paramètres de sécurité par défaut : ils bloquent l’authentification héritée.",
			"Ou, avec l’accès conditionnel, créez une stratégie pour tous les utilisateurs dont les applications clientes sont « Clients Exchange ActiveSync » et « Autres clients », avec Bloquer l’accès.",
			"Avant cela, vérifiez dans les journaux de connexion qu’aucune imprimante ni ancienne application ne dépend encore de ces protocoles.",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication", cisM365},
	},
	CheckTooManyAdmins: {
		severity: finding.SeverityMedium,
		title:    "Fewer than five global administrators", titleFR: "Moins de cinq administrateurs généraux",
		finding: "%d global administrators", findingFR: "%d administrateurs généraux",
		description: "Each global administrator can take over the whole tenant. Microsoft recommends fewer than five: every extra one is another account an attacker can phish.",
		descFR:      "Chaque administrateur général peut prendre le contrôle de tout le tenant. Microsoft en recommande moins de cinq : chacun de plus est un compte de plus qu’un attaquant peut hameçonner.",
		steps: []string{
			"Review the list: keep two to four global administrators.",
			"Give the others a narrower role for what they actually do (User Administrator, Exchange Administrator, Helpdesk Administrator).",
		},
		stepsFR: []string{
			"Revoyez la liste : gardez deux à quatre administrateurs généraux.",
			"Donnez aux autres un rôle plus restreint, adapté à ce qu’ils font réellement (administrateur des utilisateurs, administrateur Exchange, administrateur du support technique).",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices", cisM365},
	},
	CheckSingleAdmin: {
		severity: finding.SeverityLow,
		title:    "At least two global administrators", titleFR: "Au moins deux administrateurs généraux",
		finding: "Only one global administrator", findingFR: "Un seul administrateur général",
		description: "If this one account is locked, lost or its owner leaves, nobody can manage the tenant any more, and recovering it through Microsoft support takes days.",
		descFR:      "Si ce compte unique est bloqué, perdu, ou si son titulaire part, plus personne ne peut gérer le tenant, et le récupérer auprès du support Microsoft prend des jours.",
		steps: []string{
			"Create a second global administrator, an emergency account not used day to day, with a long password kept in a safe place and its own second factor.",
		},
		stepsFR: []string{
			"Créez un second administrateur général, un compte d’urgence qui ne sert pas au quotidien, avec un mot de passe long conservé en lieu sûr et son propre second facteur.",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access", cisM365},
	},
	CheckUserConsent: {
		severity: finding.SeverityMedium,
		title:    "Users cannot consent to any application", titleFR: "Les utilisateurs ne peuvent pas autoriser n’importe quelle application",
		finding: "Users can give any application access to their data", findingFR: "Les utilisateurs peuvent donner à n’importe quelle application l’accès à leurs données",
		description: "Any user can accept an application's request to read their mail and files. Attackers send such requests by email (consent phishing): once accepted, the application keeps its access even after a password change.",
		descFR:      "N’importe quel utilisateur peut accepter la demande d’une application de lire sa messagerie et ses fichiers. Les attaquants envoient ces demandes par e-mail (hameçonnage par consentement) : une fois acceptée, l’application garde son accès même après un changement de mot de passe.",
		steps: []string{
			"In the Microsoft Entra admin center, Enterprise applications > Consent and permissions: allow user consent only for verified publishers and low-risk permissions, or not at all.",
			"Turn on the admin consent workflow, so that users can ask an administrator instead.",
			"Review the applications already authorized in Enterprise applications.",
		},
		stepsFR: []string{
			"Dans le centre d’administration Microsoft Entra, Applications d’entreprise > Consentement et autorisations : n’autorisez le consentement des utilisateurs que pour les éditeurs vérifiés et les autorisations à faible risque, ou pas du tout.",
			"Activez le flux de demande de consentement administrateur, pour que les utilisateurs puissent demander à un administrateur.",
			"Passez en revue les applications déjà autorisées dans Applications d’entreprise.",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent", cisM365},
	},
	CheckGuestInvites: {
		severity: finding.SeverityLow,
		title:    "Guest invitations are restricted", titleFR: "Les invitations d’invités sont limitées",
		finding: "Anyone, guests included, can invite outside users", findingFR: "Tout le monde, invités compris, peut inviter des personnes extérieures",
		description: "Every account, including guests, can invite people from outside into the tenant, where they may reach Teams, SharePoint and shared files.",
		descFR:      "Chaque compte, invités compris, peut faire entrer des personnes extérieures dans le tenant, où elles peuvent accéder à Teams, à SharePoint et aux fichiers partagés.",
		steps: []string{
			"In the Microsoft Entra admin center, External Identities > External collaboration settings: limit guest invitations to members, or to administrators and the Guest Inviter role.",
		},
		stepsFR: []string{
			"Dans le centre d’administration Microsoft Entra, Identités externes > Paramètres de collaboration externe : limitez les invitations aux membres, ou aux administrateurs et au rôle Inviteur.",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure", cisM365},
	},
	CheckAppRegistration: {
		severity: finding.SeverityLow,
		title:    "Users cannot register applications", titleFR: "Les utilisateurs ne peuvent pas inscrire d’applications",
		finding: "Any user can register applications", findingFR: "Tout utilisateur peut inscrire des applications",
		description: "Any user can create an application identity in the tenant. A compromised account can use one to keep access discreetly.",
		descFR:      "Tout utilisateur peut créer une identité d’application dans le tenant. Un compte compromis peut s’en servir pour garder un accès discret.",
		steps: []string{
			"In the Microsoft Entra admin center, Users > User settings: set \"Users can register applications\" to No, and give the Application Developer role to those who need it.",
		},
		stepsFR: []string{
			"Dans le centre d’administration Microsoft Entra, Utilisateurs > Paramètres utilisateur : réglez « Les utilisateurs peuvent inscrire des applications » sur Non, et donnez le rôle Développeur d’applications à ceux qui en ont besoin.",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-app-roles", cisM365},
	},
	CheckInactive: {
		severity: finding.SeverityLow,
		title:    "No enabled account unused for 90 days", titleFR: "Aucun compte actif inutilisé depuis 90 jours",
		finding: "Account enabled but unused for over 90 days", findingFR: "Compte actif mais inutilisé depuis plus de 90 jours",
		description: "Nobody has signed in with this account for over 90 days, but it still works. Forgotten accounts (former staff, old projects) are a favourite way in: nobody notices when someone else uses them.",
		descFR:      "Personne ne s’est connecté avec ce compte depuis plus de 90 jours, mais il fonctionne toujours. Les comptes oubliés (anciens salariés, anciens projets) sont une porte d’entrée prisée : personne ne remarque quand quelqu’un d’autre s’en sert.",
		steps: []string{
			"Check with its manager whether the account is still needed.",
			"If not, block its sign-in, then delete it once its mail and files have been kept or handed over.",
		},
		stepsFR: []string{
			"Vérifiez avec son responsable si le compte est encore utile.",
			"Sinon, bloquez sa connexion, puis supprimez-le une fois sa messagerie et ses fichiers conservés ou transmis.",
		},
		references: []string{"https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts", cisM365},
	},
	CheckForward: {
		severity: finding.SeverityHigh,
		title:    "No inbox rule forwards mail outside the organization", titleFR: "Aucune règle de boîte ne transfère le courrier hors de l’organisation",
		finding: "Inbox rule forwarding mail outside the organization", findingFR: "Règle de boîte qui transfère le courrier hors de l’organisation",
		description: "An enabled rule in this mailbox sends incoming mail to an outside address. It may be legitimate, but it is also the first thing an attacker sets up after taking over a mailbox, to read everything silently.",
		descFR:      "Une règle active de cette boîte envoie le courrier reçu vers une adresse extérieure. Elle peut être légitime, mais c’est aussi la première chose qu’installe un attaquant après avoir pris une boîte, pour tout lire en silence.",
		steps: []string{
			"Ask the mailbox owner whether they created this rule and know the address.",
			"If not: delete the rule, change the account's password, sign it out of every session and check its multi-factor methods.",
			"Block automatic external forwarding for everyone in the outbound spam policy of Microsoft Defender, with exceptions only where needed.",
		},
		stepsFR: []string{
			"Demandez au titulaire de la boîte s’il a créé cette règle et s’il connaît l’adresse.",
			"Sinon : supprimez la règle, changez le mot de passe du compte, déconnectez toutes ses sessions et vérifiez ses méthodes de double authentification.",
			"Bloquez le transfert externe automatique pour tous dans la stratégie anti-spam sortante de Microsoft Defender, avec des exceptions seulement là où c’est nécessaire.",
		},
		references: []string{"https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding", cisM365},
	},
}

// build makes the finding of check on asset. args fill the finding's title.
func build(domain, id, asset string, sev finding.Severity, evidence string, args ...any) finding.Finding {
	c := catalog[id]
	title, titleFR := c.finding, c.findingFR
	if len(args) > 0 {
		title, titleFR = fmt.Sprintf(title, args...), fmt.Sprintf(titleFR, args...)
	}
	return finding.Finding{
		SchemaVersion: finding.SchemaVersion,
		ID:            finding.NewID(ID, id, domain, asset),
		ModuleID:      ID,
		CheckID:       id,
		Target:        domain,
		Asset:         asset,
		Severity:      sev,
		Title:         title,
		Description:   c.description,
		Evidence:      finding.TruncateEvidence("Source: Microsoft Graph\n" + evidence),
		Remediation:   c.steps,
		References:    c.references,
		Translations:  map[string]finding.Text{"fr": {Title: titleFR, Description: c.descFR, Remediation: c.stepsFR}},
	}
}
