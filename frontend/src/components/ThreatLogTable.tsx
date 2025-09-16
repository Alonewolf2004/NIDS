import { useState } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ChevronUp, ChevronDown } from "lucide-react";

interface Threat {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  threatType: "Signature" | "AI";
  description: string;
  blocked: boolean;
}

interface ThreatLogTableProps {
  threats: Threat[];
}

type SortField = keyof Threat;
type SortDirection = "asc" | "desc";

export const ThreatLogTable = ({ threats }: ThreatLogTableProps) => {
  const [sortField, setSortField] = useState<SortField>("timestamp");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");

  const handleSort = (field: SortField) => {
    if (field === sortField) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection("asc");
    }
  };

  const sortedThreats = [...threats].sort((a, b) => {
    const aValue = a[sortField];
    const bValue = b[sortField];
    
    if (aValue < bValue) return sortDirection === "asc" ? -1 : 1;
    if (aValue > bValue) return sortDirection === "asc" ? 1 : -1;
    return 0;
  });

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null;
    return sortDirection === "asc" ? 
      <ChevronUp className="h-4 w-4 ml-1" /> : 
      <ChevronDown className="h-4 w-4 ml-1" />;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Threat Detection Log</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead 
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => handleSort("timestamp")}
                >
                  <div className="flex items-center">
                    Timestamp
                    <SortIcon field="timestamp" />
                  </div>
                </TableHead>
                <TableHead 
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => handleSort("sourceIp")}
                >
                  <div className="flex items-center">
                    Source IP
                    <SortIcon field="sourceIp" />
                  </div>
                </TableHead>
                <TableHead 
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => handleSort("destinationIp")}
                >
                  <div className="flex items-center">
                    Destination IP
                    <SortIcon field="destinationIp" />
                  </div>
                </TableHead>
                <TableHead 
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => handleSort("threatType")}
                >
                  <div className="flex items-center">
                    Threat Type
                    <SortIcon field="threatType" />
                  </div>
                </TableHead>
                <TableHead 
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => handleSort("description")}
                >
                  <div className="flex items-center">
                    Description
                    <SortIcon field="description" />
                  </div>
                </TableHead>
                <TableHead 
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => handleSort("blocked")}
                >
                  <div className="flex items-center">
                    Blocked
                    <SortIcon field="blocked" />
                  </div>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sortedThreats.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No threats detected
                  </TableCell>
                </TableRow>
              ) : (
                sortedThreats.map((threat) => (
                  <TableRow key={threat.id} className="hover:bg-muted/50">
                    <TableCell className="font-mono text-sm">
                      {threat.timestamp}
                    </TableCell>
                    <TableCell className="font-mono">
                      {threat.sourceIp}
                    </TableCell>
                    <TableCell className="font-mono">
                      {threat.destinationIp}
                    </TableCell>
                    <TableCell>
                      <Badge 
                        variant={threat.threatType === "AI" ? "default" : "secondary"}
                        className={threat.threatType === "AI" ? "bg-primary hover:bg-primary/80" : ""}
                      >
                        {threat.threatType}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-xs truncate" title={threat.description}>
                      {threat.description}
                    </TableCell>
                    <TableCell>
                      <Badge 
                        variant={threat.blocked ? "destructive" : "outline"}
                        className={threat.blocked ? "bg-destructive hover:bg-destructive/80" : ""}
                      >
                        {threat.blocked ? "Yes" : "No"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
};