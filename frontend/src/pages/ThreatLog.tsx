import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { ThreatLogTable } from "@/components/ThreatLogTable";
import { Shield, ArrowLeft, RefreshCw } from "lucide-react";
import { useNavigate } from "react-router-dom";

// Define the Threat interface. This is the single source of truth.
export interface Threat {
  id: number;
  timestamp: number;
  source_ip: string;
  dest_ip: string;
  threat_type: string;
  details: string;
  blocked: boolean;
  confidence: number;
}

const ThreatLog = () => {
  const navigate = useNavigate();
  const [threats, setThreats] = useState<Threat[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const fetchThreats = async () => {
    setIsLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:5000/api/threats");
      const data = await response.json();
      if (response.ok) {
        const sortedThreats = data.threats.sort((a: Threat, b: Threat) => b.timestamp - a.timestamp);
        setThreats(sortedThreats);
      } else {
        console.error("Error fetching threats:", data.error);
      }
    } catch (error) {
      console.error("API call failed:", error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(() => {
      fetchThreats();
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = () => {
    fetchThreats();
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-card">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate("/")}
                className="mr-2"
              >
                <ArrowLeft className="h-4 w-4 mr-1" />
                Back
              </Button>
              <Shield className="h-8 w-8 text-primary" />
              <h1 className="text-2xl font-bold">Threat Detection Log</h1>
            </div>
            <Button
              onClick={handleRefresh}
              disabled={isLoading}
              variant="outline"
              size="sm"
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-card rounded-lg p-4 border">
              <div className="text-2xl font-bold text-primary">{threats.length}</div>
              <div className="text-sm text-muted-foreground">Total Threats</div>
            </div>
            <div className="bg-card rounded-lg p-4 border">
              <div className="text-2xl font-bold text-destructive">
                {threats.filter(t => t.blocked).length}
              </div>
              <div className="text-sm text-muted-foreground">Blocked</div>
            </div>
            <div className="bg-card rounded-lg p-4 border">
              <div className="text-2xl font-bold text-primary">
                {threats.filter(t => t.threat_type === "ai_detection").length}
              </div>
              <div className="text-sm text-muted-foreground">AI Detected</div>
            </div>
            <div className="bg-card rounded-lg p-4 border">
              <div className="text-2xl font-bold text-secondary-foreground">
                {threats.filter(t => t.threat_type === "signature").length}
              </div>
              <div className="text-sm text-muted-foreground">Signature Based</div>
            </div>
          </div>

          {/* Threat Log Table */}
          {isLoading ? (
            <div className="text-center text-muted-foreground">Loading threat log...</div>
          ) : (
            <ThreatLogTable threats={threats} />
          )}
        </div>
      </main>
    </div>
  );
};

export default ThreatLog;