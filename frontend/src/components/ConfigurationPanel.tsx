import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// Update the interface to accept the 'interfaces' prop
interface ConfigurationPanelProps {
  networkInterface: string;
  setNetworkInterface: (value: string) => void;
  enableBlocking: boolean;
  setEnableBlocking: (value: boolean) => void;
  aiThreshold: number;
  setAiThreshold: (value: number) => void;
  interfaces: string[]; // <--- ADDED THIS LINE
}

export const ConfigurationPanel = ({
  networkInterface,
  setNetworkInterface,
  enableBlocking,
  setEnableBlocking,
  aiThreshold,
  setAiThreshold,
  interfaces, // <--- ADDED THIS LINE
}: ConfigurationPanelProps) => {
  return (
    <Card className="relative border-primary/20 bg-card/50 backdrop-blur-sm animate-fade-in">
      <CardHeader>
        <CardTitle className="text-lg font-mono uppercase tracking-wider">Configuration</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="network-interface" className="font-mono text-xs uppercase tracking-wider">Network Interface</Label>
          <Select value={networkInterface} onValueChange={setNetworkInterface}>
            <SelectTrigger id="network-interface" className="border-primary/20 bg-background/50 font-mono">
              <SelectValue placeholder="Select interface" />
            </SelectTrigger>
            <SelectContent className="border-primary/20 bg-card backdrop-blur-sm">
              {/* Dynamically render SelectItems from the interfaces prop */}
              {interfaces.length > 0 ? (
                interfaces.map((iface) => (
                  <SelectItem key={iface} value={iface} className="font-mono">
                    {iface}
                  </SelectItem>
                ))
              ) : (
                <SelectItem value="no-interfaces" disabled>
                  No interfaces found
                </SelectItem>
              )}
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center justify-between p-3 border border-primary/20 rounded bg-background/20">
          <Label htmlFor="enable-blocking" className="font-mono text-xs uppercase tracking-wider">
            Enable Blocking
          </Label>
          <Switch
            id="enable-blocking"
            checked={enableBlocking}
            onCheckedChange={setEnableBlocking}
            className="data-[state=checked]:bg-primary"
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="ai-threshold" className="font-mono text-xs uppercase tracking-wider">AI Confidence Threshold (%)</Label>
          <div className="relative">
            <Input
              id="ai-threshold"
              type="number"
              min="0"
              max="100"
              value={aiThreshold}
              onChange={(e) => setAiThreshold(Number(e.target.value))}
              className="w-full border-primary/20 bg-background/50 font-mono text-primary glow-text"
            />
            <div className="absolute top-1/2 right-3 transform -translate-y-1/2 text-primary/60 font-mono text-xs">
              {aiThreshold}%
            </div>
          </div>
          <div className="w-full h-1 bg-background/30 rounded overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-destructive via-yellow-500 to-primary transition-all duration-300"
              style={{ width: `${aiThreshold}%` }}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
};