import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import Dashboard from "./pages/Dashboard";
import ThreatLog from "./pages/ThreatLog";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  // useEffect to apply the theme class to the document
  useEffect(() => {
    const root = window.document.documentElement;
    root.classList.remove("light", "dark");
    root.classList.add(theme);
  }, [theme]);

  // Function to toggle the theme
  const toggleTheme = () => {
    setTheme(theme === "dark" ? "light" : "dark");
  };

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Dashboard theme={theme} toggleTheme={toggleTheme} />} />
            <Route
              path="/threats"
              element={<ThreatLog theme={theme} toggleTheme={toggleTheme} />}
            />
            {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  );
};

export default App;
