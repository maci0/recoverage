import { Icon } from "./Icon";
import "./ProviderIcon.css";

export type ProviderName = "password" | "google" | "github" | "gitlab" | "oidc";

/** Provider marks are decorative; the adjacent button names the method. */
export function ProviderIcon({ provider, assetBase }: { provider: ProviderName; assetBase: string }) {
  if (provider === "password" || provider === "oidc") {
    return <Icon name={provider === "password" ? "user" : "shield-check"} size="md" />;
  }

  if (provider === "github") {
    return <span aria-hidden="true" data-provider-icon={provider} />;
  }

  return <span data-provider-icon={provider} aria-hidden="true">
    <img src={`${assetBase}/${provider === "google" ? "google.png" : "gitlab.svg"}`} alt="" width="20" height="20" />
  </span>;
}
