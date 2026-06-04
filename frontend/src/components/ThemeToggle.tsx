import * as React from "react";
import { Moon, Sun } from "lucide-react";
import { Button } from "./ui";

export function useTheme() {
  const [dark, setDark] = React.useState(() => localStorage.getItem("theme") === "dark");
  React.useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("theme", dark ? "dark" : "light");
  }, [dark]);
  return { dark, toggle: () => setDark((d) => !d) };
}

export function ThemeToggle() {
  const { dark, toggle } = useTheme();
  return (
    <Button variant="ghost" size="icon" onClick={toggle} title="切换主题">
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </Button>
  );
}
