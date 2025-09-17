import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { MetricCard } from "@/components/MetricCard";
import { StatusIndicator } from "@/components/StatusIndicator";
import { ConfigurationPanel } from "@/components/ConfigurationPanel";
import { Activity, Shield, ShieldAlert, Users, FileText } from "lucide-react";
import { useNavigate } from "react-router-dom";


// Define a type for the NIDS status object from the backend
interface NidsStatus {
  running: boolean;
  packet_count: number;
  flow_count: number;
  threat_count: number;
  blocked_ips: string[];
}

const Dashboard = () => {
  const navigate = useNavigate();

  // State for NIDS status and metrics, fetched from the API
  const [nidsStatus, setNidsStatus] = useState<NidsStatus | null>(null);

  // Configuration state
  const [interfaces, setInterfaces] = useState<string[]>(["Loading..."]);
  const [selectedInterface, setSelectedInterface] = useState("eth0");
  const [enableBlocking, setEnableBlocking] = useState(true);
  const [aiThreshold, setAiThreshold] = useState(0.7); // Changed to number for API consistency
  const [isInitializing, setIsInitializing] = useState(false);

  // Helper function to fetch NIDS status
  const fetchStatus = async () => {
    try {
      const response = await fetch("http://127.0.0.1:5000/api/status");
      if (response.ok) {
        const data = await response.json();
        setNidsStatus(data);
      }
    } catch (error) {
      console.error("Error fetching status:", error);
    }
  };

  // Helper function to fetch available interfaces
  const fetchInterfaces = async () => {
    try {
      const response = await fetch("http://127.0.0.1:5000/api/interfaces");
      if (response.ok) {
        const data = await response.json();
        setInterfaces(data.interfaces);
        if (data.interfaces.length > 0) {
          setSelectedInterface(data.interfaces[0]);
        }
      }
    } catch (error) {
      console.error("Error fetching interfaces:", error);
    }
  };

  // useEffect to handle initial data fetch and polling
  useEffect(() => {
    fetchInterfaces();
    fetchStatus();

    const interval = setInterval(() => {
      fetchStatus();
    }, 5000); // Poll every 5 seconds

    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    setIsInitializing(true);
    console.log("Starting NIDS with configuration...");
    try {
      const response = await fetch("http://127.0.0.1:5000/api/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          interface: selectedInterface,
          enableBlocking: enableBlocking,
          aiConfidence: aiThreshold,
        }),
      });
      if (response.ok) {
        console.log("NIDS started successfully.");
        // The polling useEffect will now pick up the running status
      } else {
        const errorData = await response.json();
        console.error("Failed to start NIDS:", errorData.message);
      }
    } catch (error) {
      console.error("API call failed:", error);
    } finally {
      setIsInitializing(false);
    }
  };

  const handleStop = async () => {
    console.log("Stopping NIDS...");
    try {
      const response = await fetch("http://127.0.0.1:5000/api/stop", {
        method: "POST",
      });
      if (response.ok) {
        console.log("NIDS stopped successfully.");
        // The polling useEffect will now pick up the stopped status
      } else {
        const errorData = await response.json();
        console.error("Failed to stop NIDS:", errorData.message);
      }
    } catch (error) {
      console.error("API call failed:", error);
    }
  };
  
  // Replace mock data with state data
  const packetsProcessed = nidsStatus?.packet_count?.toLocaleString() || "0";
  const threatsDetected = nidsStatus?.threat_count?.toLocaleString() || "0";
  const blockedIps = nidsStatus?.blocked_ips?.length.toLocaleString() || "0";
  const isRunning = nidsStatus?.running || false;

  return (
    <div className="min-h-screen bg-background relative overflow-hidden">
      {/* Matrix rain effect */}
      <div className="fixed inset-0 pointer-events-none opacity-20">
        {[...Array(20)].map((_, i) => (
          <div
            key={i}
            className="absolute text-primary font-mono text-xs animate-matrix-rain"
            style={{
              left: `${i * 5}%`,
              animationDelay: `${i * 0.1}s`,
              animationDuration: `${3 + Math.random() * 2}s`
            }}
          >
            {Math.random().toString(36).substring(2, 15)}
          </div>
        ))}
      </div>

      {/* Header */}
      <header className="relative border-b border-primary/20 bg-card/30 backdrop-blur-sm">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-primary animate-cyber-pulse glow" />
              <h1 className="text-2xl font-bold font-mono uppercase tracking-wider glow-text">
                NIDS Dashboard
              </h1>
            </div>
            <div className="flex items-center space-x-4">
              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate("/threats")}
                className="flex items-center space-x-2 border-primary/30 bg-background/50 hover:bg-primary/10 hover:border-primary/50 font-mono transition-all duration-300"
              >
                <FileText className="h-4 w-4" />
                <span>View Threat Log</span>
              </Button>
              <div className="text-sm text-muted-foreground/60 font-mono">
                <span className="text-primary">[</span>Network Intrusion Detection System<span className="text-primary">]</span>
              </div>
            </div>
          </div>
        </div>
        {/* Scan line effect */}
        <div className="absolute bottom-0 left-0 w-full h-0.5 bg-gradient-to-r from-transparent via-primary to-transparent animate-data-flow"></div>
      </header>

      <main className="relative container mx-auto px-4 py-8">
        <div className="space-y-8">
          {/* Terminal-style header */}
          <div className="bg-card/20 border border-primary/20 rounded-lg p-4 font-mono text-sm backdrop-blur-sm">
            <div className="flex items-center space-x-2 mb-2">
              <div className="w-3 h-3 rounded-full bg-destructive"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-primary"></div>
              <span className="text-muted-foreground/60 ml-4">root@nids-terminal:~$</span>
            </div>
            <div className="text-primary/80">
              <span className="text-primary">&gt;</span> Initializing Network Intrusion Detection System...
              <span className="animate-terminal-cursor"></span>
            </div>
          </div>

          {/* Metrics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <MetricCard
              title="Packets Processed"
              value={packetsProcessed}
              icon={<Activity className="h-5 w-5" />}
              trend="up"
            />
            <MetricCard
              title="Threats Detected"
              value={threatsDetected}
              icon={<ShieldAlert className="h-5 w-5" />}
              trend="down"
            />
            <MetricCard
              title="Blocked IPs"
              value={blockedIps}
              icon={<Users className="h-5 w-5" />}
              trend="neutral"
            />
          </div>

          {/* Status and Configuration */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <StatusIndicator
              isRunning={isRunning}
              lastUpdate={isRunning ? new Date().toLocaleString() : undefined}
            />
            <ConfigurationPanel
              networkInterface={selectedInterface}
              setNetworkInterface={setSelectedInterface}
              enableBlocking={enableBlocking}
              setEnableBlocking={setEnableBlocking}
              aiThreshold={aiThreshold}
              setAiThreshold={setAiThreshold}
              interfaces={interfaces} // Pass the fetched interfaces to the component
            />
          </div>

          {/* Control Buttons */}
          <div className="flex justify-center space-x-4">
            <Button
              onClick={handleStart}
              disabled={isRunning || isInitializing}
              size="lg"
              className="min-w-[140px] font-mono uppercase tracking-wider bg-primary hover:bg-primary/80 text-black border border-primary hover:glow transition-all duration-300 "
            >
              <span className="mr-2">▶</span>
              {isInitializing ? "Initializing..." : "Initialize"}
            </Button>
            <Button
              onClick={handleStop}
              disabled={!isRunning || isInitializing}
              variant="destructive"
              size="lg"
              className="min-w-[140px] font-mono uppercase tracking-wider bg-destructive hover:bg-destructive/80 border border-destructive transition-all duration-300"
            >
              <span className="mr-2">■</span>
              Terminate
            </Button>
          </div>

          {/* Status line */}
          <div className="text-center">
            <div className="inline-flex items-center space-x-2 text-xs font-mono text-muted-foreground/60">
              <span className="text-primary">[</span>
              <span>System Status: {isRunning ? "ACTIVE" : "STANDBY"}</span>
              <span className="text-primary">]</span>
              <div className="w-2 h-2 rounded-full bg-primary animate-pulse"></div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;