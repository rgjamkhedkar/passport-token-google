import pkginfo from "pkginfo";
import Strategy from "./strategy";

const version = pkginfo("version").version;

export { version, Strategy };
