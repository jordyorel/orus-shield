// Messages shown to the user. Every wrong password gets the same one,
// whatever the reason: the page never tells whether an account exists.

import { ApiError } from "./api/client";
import { tr } from "./i18n";

export const msg = {
  get badCredentials() {
    return tr("Adresse e-mail ou mot de passe incorrect.", "Incorrect email address or password.");
  },
  get badPassword() {
    return tr("Mot de passe incorrect.", "Incorrect password.");
  },
  get rateLimited() {
    return tr("Trop de tentatives échouées. Réessayez dans 15 minutes.", "Too many failed attempts. Try again in 15 minutes.");
  },
  get resetRateLimited() {
    return tr("Trop de demandes de réinitialisation. Réessayez dans une heure.", "Too many reset requests. Try again in an hour.");
  },
  get signupRateLimited() {
    return tr("Trop de demandes d’inscription. Réessayez dans une heure.", "Too many sign-up requests. Try again in an hour.");
  },
  get signupInvalid() {
    return tr("Vérifiez l’adresse e-mail et le nom de l’organisation.", "Check the email address and the organization name.");
  },
  get signupClosed() {
    return tr("Les inscriptions sont fermées pour le moment : demandez une invitation à votre administrateur.", "Sign-up is closed for now: ask your administrator for an invitation.");
  },
  get signupLink() {
    return tr("Ce lien d’inscription est invalide, expiré ou déjà utilisé. Recommencez l’inscription pour en recevoir un nouveau.", "This sign-up link is invalid, expired or already used. Sign up again to receive a new one.");
  },
  get accountExists() {
    return tr("Un compte existe déjà pour cette adresse : connectez-vous, ou utilisez « Mot de passe oublié ».", "An account already exists for this address: sign in, or use “Forgot password”.");
  },
  get badCode() {
    return tr("Code incorrect. Vérifiez l’heure de votre téléphone et saisissez le code affiché maintenant.", "Incorrect code. Check your phone's time and enter the code shown now.");
  },
  get badRecovery() {
    return tr("Code incorrect, ou déjà utilisé.", "Incorrect code, or already used.");
  },
  get loginExpired() {
    return tr("La vérification a expiré. Saisissez à nouveau votre mot de passe.", "The verification expired. Enter your password again.");
  },
  get setupToken() {
    return tr("Ce code ou ce lien est invalide, expiré ou déjà utilisé. Demandez un nouveau lien (Mot de passe oublié) ou un nouveau code à votre administrateur.", "This code or link is invalid, expired or already used. Ask for a new link (Forgot password) or a new code from your administrator.");
  },
  get passwordShort() {
    return tr("Le mot de passe doit contenir au moins 12 caractères.", "The password must be at least 12 characters long.");
  },
  get passwordMatch() {
    return tr("Les deux mots de passe ne correspondent pas.", "The two passwords do not match.");
  },
  get adminNeedsMfa() {
    return tr("Votre rôle d’administrateur exige la double authentification. Activez-la pour accéder à votre organisation.", "Your administrator role requires two-factor authentication. Turn it on to access your organization.");
  },
  get cookieRefused() {
    return tr("Votre navigateur a refusé le cookie de session, la connexion ne peut pas tenir. Sur Safari, ouvrez le tableau de bord en HTTPS (ou utilisez un autre navigateur en local).", "Your browser refused the session cookie, so the sign-in cannot hold. On Safari, open the dashboard over HTTPS (or use another browser locally).");
  },
  get unexpected() {
    return tr("Une erreur inattendue s’est produite. Réessayez dans quelques instants.", "An unexpected error occurred. Try again in a moment.");
  },
  get offline() {
    return tr("Le serveur ne répond pas. Vérifiez votre connexion et réessayez.", "The server is not answering. Check your connection and try again.");
  },
};

/** Notices after a redirect, keyed by ?ok=: fixed texts, never text from the URL. */
export const notices: Record<string, string> = {
  get password() {
    return tr("Votre mot de passe est enregistré. Vous pouvez vous connecter.", "Your password is saved. You can sign in.");
  },
  get logout() {
    return tr("Vous êtes déconnecté.", "You are signed out.");
  },
  get signup() {
    return tr("Votre compte est créé. Connectez-vous : vous activerez ensuite la double authentification.", "Your account is created. Sign in: you will then turn on two-factor authentication.");
  },
};

/** PASSWORD_MIN_LENGTH mirrors the engine's password.MinLength. */
export const PASSWORD_MIN_LENGTH = 12;

/** fallback is the message of an error a page does not handle itself. */
export function fallback(e: unknown): string {
  if (!(e instanceof ApiError)) return msg.offline; // network error
  if (e.status === 429) return msg.rateLimited;
  // 502 to 504: a proxy (Vite in development, the reverse proxy in
  // production) could not reach the API.
  if (e.status >= 502 && e.status <= 504) return msg.offline;
  return msg.unexpected;
}
