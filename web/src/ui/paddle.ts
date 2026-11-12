// Paddle.js, loaded only on the payment page: Paddle's checkout shows the
// card (or PayPal) form in its own frame, so card numbers never reach our
// servers. The transaction is created by our API (POST /checkout) and
// carries the organization, so a payment can only ever change it.
//
// Production CSP for the payment page: script-src https://cdn.paddle.com;
// frame-src https://*.paddle.com; connect-src https://*.paddle.com.

interface PaddleCheckoutSettings {
  displayMode: "inline" | "overlay";
  frameTarget?: string;
  frameInitialHeight?: number;
  frameStyle?: string;
  locale?: string;
  successUrl?: string;
}

interface PaddleJS {
  Environment: { set: (env: string) => void };
  Initialize: (o: { token: string }) => void;
  Checkout: { open: (o: { transactionId: string; settings: PaddleCheckoutSettings; customer?: { email: string } }) => void };
}

declare global {
  interface Window {
    Paddle?: PaddleJS;
  }
}

const SRC = "https://cdn.paddle.com/paddle/v2/paddle.js";
let loading: Promise<PaddleJS> | null = null;

/** loadPaddle adds Paddle.js once and resolves when it is ready. */
export function loadPaddle(): Promise<PaddleJS> {
  if (window.Paddle) return Promise.resolve(window.Paddle);
  if (loading) return loading;
  loading = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = SRC;
    s.async = true;
    s.onload = () => (window.Paddle ? resolve(window.Paddle) : reject(new Error("Paddle.js did not load")));
    s.onerror = () => {
      loading = null;
      reject(new Error("Paddle.js did not load"));
    };
    document.head.appendChild(s);
  });
  return loading;
}

let initialized = "";

/** openCheckout shows Paddle's checkout for a transaction. */
export async function openCheckout(o: { transactionId: string; clientToken: string; environment: string; email: string; inlineTarget?: string }) {
  const paddle = await loadPaddle();
  if (initialized !== o.clientToken) {
    if (o.environment === "sandbox") paddle.Environment.set("sandbox");
    paddle.Initialize({ token: o.clientToken });
    initialized = o.clientToken;
  }
  const settings: PaddleCheckoutSettings = {
    displayMode: o.inlineTarget ? "inline" : "overlay",
    locale: "fr",
    successUrl: `${window.location.origin}/paiement?statut=ok`,
  };
  if (o.inlineTarget) {
    settings.frameTarget = o.inlineTarget;
    settings.frameInitialHeight = 450;
    settings.frameStyle = "width:100%;min-width:286px;background-color:transparent;border:none;";
  }
  paddle.Checkout.open({ transactionId: o.transactionId, settings, customer: { email: o.email } });
}
