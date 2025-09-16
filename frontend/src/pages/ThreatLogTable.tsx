import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";

// Import the Threat interface from the ThreatLog component
import { Threat } from "../pages/ThreatLog"; // Adjust the path as needed

// This interface now correctly uses the imported Threat type
interface ThreatLogTableProps {
  threats: Threat[];
}

export const ThreatLogTable = ({ threats }: ThreatLogTableProps) => {
  if (!threats || threats.length === 0) {
    return (
      <div className="text-center text-muted-foreground p-8 border rounded-lg">
        No threats detected yet.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow className="border-primary/20">
            <TableHead className="text-primary font-mono text-xs uppercase">Timestamp</TableHead>
            <TableHead className="text-primary font-mono text-xs uppercase">Source IP</TableHead>
            <TableHead className="text-primary font-mono text-xs uppercase">Destination IP</TableHead>
            <TableHead className="text-primary font-mono text-xs uppercase">Type</TableHead>
            <TableHead className="text-primary font-mono text-xs uppercase">Details</TableHead>
            <TableHead className="text-primary font-mono text-xs uppercase">Status</TableHead>
            <TableHead className="text-primary font-mono text-xs uppercase text-right">Confidence</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {threats.map((threat) => (
            <TableRow key={threat.id} className="border-primary/10 transition-all hover:bg-card/30">
              <TableCell className="font-mono text-xs text-muted-foreground/80">
                {format(new Date(threat.timestamp * 1000), 'yyyy-MM-dd HH:mm:ss')}
              </TableCell>
              <TableCell className="font-mono text-sm text-primary">{threat.source_ip}</TableCell>
              <TableCell className="font-mono text-sm text-primary/80">{threat.dest_ip}</TableCell>
              <TableCell>
                <Badge 
                  variant="outline" 
                  className={`font-mono ${
                    threat.threat_type === 'signature' 
                      ? 'border-destructive text-destructive' 
                      : 'border-yellow-500 text-yellow-500'
                  }`}
                >
                  {threat.threat_type === 'signature' ? 'Signature' : 'AI'}
                </Badge>
              </TableCell>
              <TableCell className="text-sm">{threat.details}</TableCell>
              <TableCell>
                {threat.blocked ? (
                  <Badge className="bg-destructive hover:bg-destructive/80 font-mono">Blocked</Badge>
                ) : (
                  <Badge className="bg-primary/50 hover:bg-primary/30 text-white font-mono">Monitored</Badge>
                )}
              </TableCell>
              <TableCell className="font-mono text-sm text-right">{threat.confidence?.toFixed(2) || 'N/A'}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
};