// Messages shown to the user. Every wrong password gets the same one,
// whatever the reason: the page never tells whether an account exists.

import { ApiError } from "../api/client";

export const msg = {
  badCredentials: "Adresse e-mail ou mot de passe incorrect.",
  badPassword: "Mot de passe incorrect.",
  rateLimited: "Trop de tentatives échouées. Réessayez dans 15 minutes.",
  resetRateLimited: "Trop de demandes de réinitialisation. Réessayez dans une heure.",
  signupRateLimited: "Trop de demandes d’inscription. Réessayez dans une heure.",
  signupInvalid: "Vérifiez l’adresse e-mail et le nom de l’organisation.",
  signupClosed: "Les inscriptions sont fermées pour le moment : demandez une invitation à votre administrateur.",
  signupLink: "Ce lien d’inscription est invalide, expiré ou déjà utilisé. Recommencez l’inscription pour en recevoir un nouveau.",
  accountExists: "Un compte existe déjà pour cette adresse : connectez-vous, ou utilisez « Mot de passe oublié ».",
  badCode: "Code incorrect. Vérifiez l’heure de votre téléphone et saisissez le code affiché maintenant.",
  badRecovery: "Code incorrect, ou déjà utilisé.",
  loginExpired: "La vérification a expiré. Saisissez à nouveau votre mot de passe.",
  setupToken: "Ce code ou ce lien est invalide, expiré ou déjà utilisé. Demandez un nouveau lien (Mot de passe oublié) ou un nouveau code à votre administrateur.",
  passwordShort: "Le mot de passe doit contenir au moins 12 caractères.",
  passwordMatch: "Les deux mots de passe ne correspondent pas.",
  adminNeedsMfa: "Votre rôle d’administrateur exige la double authentification. Activez-la pour accéder à votre organisation.",
  unexpected: "Une erreur inattendue s’est produite. Réessayez dans quelques instants.",
  offline: "Le serveur ne répond pas. Vérifiez votre connexion et réessayez.",
};

/** Notices after a redirect, keyed by ?ok=: fixed texts, never text from the URL. */
export const notices: Record<string, string> = {
  password: "Votre mot de passe est enregistré. Vous pouvez vous connecter.",
  logout: "Vous êtes déconnecté.",
  signup: "Votre compte est créé. Connectez-vous : vous activerez ensuite la double authentification.",
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
