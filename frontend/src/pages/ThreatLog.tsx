import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { ThreatLogTable } from "@/components/ThreatLogTable";
import { Shield, ArrowLeft, RefreshCw } from "lucide-react";
import { useNavigate } from "react-router-dom";

// Mock data interface
interface Threat {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  threatType: "Signature" | "AI";
  description: string;
  blocked: boolean;
}

const ThreatLog = () => {
  const navigate = useNavigate();
  const [threats, setThreats] = useState<Threat[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  // Mock data generation
  const generateMockThreats = (): Threat[] => {
    const mockThreats: Threat[] = [
      {
        id: "1",
        timestamp: "2024-01-15 14:30:25",
        sourceIp: "192.168.1.100",
        destinationIp: "10.0.0.5",
        threatType: "Signature",
        description: "SQL Injection attempt detected",
        blocked: true
      },
      {
        id: "2",
        timestamp: "2024-01-15 14:28:12",
        sourceIp: "203.0.113.45",
        destinationIp: "10.0.0.10",
        threatType: "AI",
        description: "Suspicious network pattern - potential data exfiltration",
        blocked: true
      },
      {
        id: "3",
        timestamp: "2024-01-15 14:25:03",
        sourceIp: "198.51.100.78",
        destinationIp: "10.0.0.20",
        threatType: "Signature",
        description: "Port scanning activity from external source",
        blocked: false
      },
      {
        id: "4",
        timestamp: "2024-01-15 14:22:45",
        sourceIp: "172.16.0.55",
        destinationIp: "10.0.0.15",
        threatType: "AI",
        description: "Anomalous traffic volume detected",
        blocked: true
      },
      {
        id: "5",
        timestamp: "2024-01-15 14:20:18",
        sourceIp: "203.0.113.99",
        destinationIp: "10.0.0.25",
        threatType: "Signature",
        description: "Cross-site scripting (XSS) attempt blocked",
        blocked: true
      }
    ];
    return mockThreats;
  };

  const fetchThreats = async () => {
    setIsLoading(true);
    // TODO: Call API endpoint /api/threats
    // Simulate API call delay
    setTimeout(() => {
      setThreats(generateMockThreats());
      setIsLoading(false);
    }, 1000);
  };

  useEffect(() => {
    fetchThreats();
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
                {threats.filter(t => t.threatType === "AI").length}
              </div>
              <div className="text-sm text-muted-foreground">AI Detected</div>
            </div>
            <div className="bg-card rounded-lg p-4 border">
              <div className="text-2xl font-bold text-secondary-foreground">
                {threats.filter(t => t.threatType === "Signature").length}
              </div>
              <div className="text-sm text-muted-foreground">Signature Based</div>
            </div>
          </div>

          {/* Threat Log Table */}
          <ThreatLogTable threats={threats} />
        </div>
      </main>
    </div>
  );
};

export default ThreatLog;