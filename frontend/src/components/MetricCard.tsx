import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: "up" | "down" | "neutral";
}

export const MetricCard = ({ title, value, icon, trend = "neutral" }: MetricCardProps) => {
  const getTrendColor = () => {
    switch (trend) {
      case "up":
        return "text-primary";
      case "down":
        return "text-destructive";
      default:
        return "text-muted-foreground";
    }
  };

  return (
    <Card className="relative hover:shadow-lg transition-all duration-300 border-primary/20 bg-card/50 backdrop-blur-sm hover:border-primary/50 hover:bg-card/70 animate-fade-in group overflow-hidden">
      {/* Animated border effect */}
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-primary/10 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-1000"></div>
      
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 relative z-10">
        <CardTitle className="text-sm font-medium text-muted-foreground/80 font-mono uppercase tracking-wider">
          {title}
        </CardTitle>
        <div className={`${getTrendColor()} animate-cyber-pulse`}>{icon}</div>
      </CardHeader>
      <CardContent className="relative z-10">
        <div className="text-2xl font-bold font-mono tracking-wider glow-text">
          {value}
        </div>
        <div className="absolute bottom-1 left-4 w-8 h-0.5 bg-primary/30 animate-data-flow"></div>
      </CardContent>
    </Card>
  );
};