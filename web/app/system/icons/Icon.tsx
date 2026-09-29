/* One icon from the relumea set (docs/brand/BRAND.md "Icons"). The drawing
   comes from ./paths.ts, generated from ./svg/*.svg by `bun run icons`; the
   stroke comes from the `[data-icon]` rule in ../tokens.css. Other repos copy
   this file, paths.ts and tokens.css unchanged.

   The markup uses only attributes React and Preact spell the same way, so the
   file compiles under either JSX runtime. Colour is `currentColor`: set the
   text colour on the element around it.

   An icon is always decorative and hidden from assistive technology. The
   control or text beside it carries the name: a visible label, or
   `aria-label` on an icon-only button. */
import { ICON_PATHS, type IconName } from "./paths";

/** Rendered sizes in px. sm sits in a line of 14-16px text, md in a control,
    lg alone. The stroke stays 1.7px at all three. */
const ICON_SIZE = { sm: 16, md: 20, lg: 24 };

export interface IconProps {
  name: IconName;
  size?: keyof typeof ICON_SIZE;
}

export function Icon({ name, size = "sm" }: IconProps) {
  const px = ICON_SIZE[size];

  return (
    <svg data-icon={name} viewBox="0 0 24 24" width={px} height={px} aria-hidden="true">
      <path d={ICON_PATHS[name]} />
    </svg>
  );
}
