import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface StatusIndicatorProps {
  isRunning: boolean;
  lastUpdate?: string;
}

export const StatusIndicator = ({ isRunning, lastUpdate }: StatusIndicatorProps) => {
  return (
    <Card className="relative border-primary/20 bg-card/50 backdrop-blur-sm animate-fade-in scanlines">
      <CardHeader>
        <CardTitle className="text-lg font-mono uppercase tracking-wider flex items-center">
          <span className="animate-neon-flicker">System Status</span>
          <div className="ml-2 w-2 h-2 rounded-full bg-primary animate-cyber-pulse"></div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium font-mono">NIDS Status:</span>
          <Badge 
            variant={isRunning ? "default" : "destructive"}
            className={`${
              isRunning 
                ? "bg-primary hover:bg-primary/80 animate-cyber-pulse border border-primary glow" 
                : "bg-destructive hover:bg-destructive/80 animate-glitch"
            } text-black font-mono uppercase tracking-wider`}
          >
            <div className={`w-2 h-2 rounded-full mr-2 ${
              isRunning ? "bg-black animate-pulse" : "bg-black"
            }`} />
            {isRunning ? "ONLINE" : "OFFLINE"}
          </Badge>
        </div>
        {lastUpdate && (
          <div className="text-xs text-muted-foreground/60 font-mono">
            <span className="text-primary">&gt;</span> Last updated: {lastUpdate}
          </div>
        )}
        <div className="text-xs text-muted-foreground/40 font-mono">
          <span className="text-primary">&gt;</span> Monitoring network traffic...
          <span className="animate-terminal-cursor"></span>
        </div>
      </CardContent>
    </Card>
  );
};