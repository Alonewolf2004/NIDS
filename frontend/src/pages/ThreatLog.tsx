import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { ThreatLogTable } from "@/components/ThreatLogTable";
import { Shield, ArrowLeft, RefreshCw, Download, RotateCcw, Sun, Moon } from "lucide-react";
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

interface ThreatLogProps {
  theme: 'dark' | 'light';
  toggleTheme: () => void;
}

const ThreatLog = ({ theme, toggleTheme }: ThreatLogProps) => {
  const navigate = useNavigate();
  const [threats, setThreats] = useState<Threat[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const fetchThreats = async () => {
    setIsLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:5000/api/threats");
      const data = await response.json();
      if (response.ok) {
        // The backend already sorts the threats, so no need to sort here.
        setThreats(data.threats);
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

  const handleRestart = async () => {
    // eslint-disable-next-line no-alert
    if (window.confirm("Are you sure you want to restart the NIDS? This will delete all threat logs and reset all counters.")) {
      try {
        const response = await fetch("http://127.0.0.1:5000/api/restart", {
          method: "POST",
        });
        if (response.ok) {
          alert("NIDS has been restarted. All logs and counters are cleared.");
          fetchThreats(); // Refresh the log to show it's empty
        } else {
          const errorData = await response.json();
          alert(`Failed to restart NIDS: ${errorData.message}`);
        }
      } catch (error) {
        console.error("API call to restart failed:", error);
        alert("An error occurred while trying to restart the NIDS.");
      }
    }
  };

  // Function to convert data to CSV and trigger download
  const handleDownloadExcel = () => {
    if (!threats || threats.length === 0) {
      alert("No threat data to download.");
      return;
    }

    // Define CSV headers - matching the Threat interface keys
    const headers = [
      "ID",
      "Timestamp",
      "Source IP",
      "Destination IP",
      "Threat Type",
      "Details",
      "Blocked",
      "Confidence",
    ];

    // Format data for CSV
    const csvRows = threats.map((threat) => {
      // Convert timestamp to human-readable date/time string
      const formattedTimestamp = new Date(threat.timestamp * 1000).toLocaleString();
      // Convert boolean to "Yes"/"No"
      const blockedStatus = threat.blocked ? "Yes" : "No";

      // Escape CSV values: double quotes around fields containing commas,
      // double quotes, or newlines. Double any existing double quotes.
      const escapeCsvValue = (value: any) => {
        if (value === null || value === undefined) return "";
        let stringValue = String(value);
        if (stringValue.includes(",") || stringValue.includes('"') || stringValue.includes("\n")) {
          return `"${stringValue.replace(/"/g, '""')}"`;
        }
        return stringValue;
      };

      return [
        escapeCsvValue(threat.id), escapeCsvValue(formattedTimestamp), escapeCsvValue(threat.source_ip),
        escapeCsvValue(threat.dest_ip), escapeCsvValue(threat.threat_type), escapeCsvValue(threat.details),
        escapeCsvValue(blockedStatus), escapeCsvValue(threat.confidence)
      ].join(",");
    });

    const csvContent = [headers.join(","), ...csvRows].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `nids_threat_log_${new Date().toISOString().slice(0, 10)}.csv`);
    link.click();
    URL.revokeObjectURL(url); // Clean up the URL object
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
            <div className="flex items-center space-x-2">
              <Button
                onClick={handleRefresh}
                disabled={isLoading}
                variant="outline"
                size="sm"
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
                Refresh
              </Button>
              <Button
                variant="outline"
                size="icon"
                onClick={toggleTheme}
                className="border-primary/30 bg-background/50 hover:bg-primary/10 hover:border-primary/50"
              >
                <Sun className="h-[1.2rem] w-[1.2rem] rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
                <Moon className="absolute h-[1.2rem] w-[1.2rem] rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
                <span className="sr-only">Toggle theme</span>
              </Button>
              <Button
                onClick={handleRestart}
                variant="destructive"
                size="sm"
              >
                <RotateCcw className="h-4 w-4 mr-2" />
                Restart
              </Button>
              <Button
                onClick={handleDownloadExcel}
                disabled={isLoading || threats.length === 0}
                variant="secondary"
                size="sm"
              >
                <Download className="h-4 w-4 mr-2" />
                Download to Excel
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid  gap-4">
            <div className="bg-card rounded-lg p-4 border">
              <div className="text-2xl font-bold text-primary">{threats.length}</div>
              <div className="text-sm text-muted-foreground">Total Threats</div>
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