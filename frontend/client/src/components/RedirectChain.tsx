import { motion, Variants } from "framer-motion";
import { ShieldAlert, ShieldCheck, AlertTriangle, ArrowDown, Clock, Link as LinkIcon, Server } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";

export interface RedirectHop {
  step: number;
  url: string;
  status: number;
  time_ms: number;
  flags: string[];
}

export interface RedirectChainData {
  initial_url: string;
  final_url: string;
  total_redirects: number;
  risk_level: string;
  chain: RedirectHop[];
}

interface RedirectChainProps {
  data: RedirectChainData;
}

export function RedirectChain({ data }: RedirectChainProps) {
  if (!data || !data.chain || data.chain.length === 0) return null;

  const containerVariants: Variants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.15, delayChildren: 0.2 },
    },
  };

  const itemVariants: Variants = {
    hidden: { opacity: 0, x: -20, y: 10 },
    visible: {
      opacity: 1,
      x: 0,
      y: 0,
      transition: { type: "spring", stiffness: 120, damping: 15 },
    },
  };

  const getStatusColor = (status: number, isError: boolean) => {
    if (isError || status === 0) return "bg-red-500/10 text-red-500 border-red-500/20";
    if (status >= 300 && status < 400) return "bg-orange-500/10 text-orange-500 border-orange-500/20";
    if (status === 200) return "bg-green-500/10 text-green-500 border-green-500/20";
    return "bg-secondary text-secondary-foreground border-border";
  };

  const isSuspicious = data.risk_level === "High" || data.risk_level === "Medium";

  return (
    <Card className="mt-8 border-border/50 bg-card/60 backdrop-blur-2xl shadow-xl rounded-2xl overflow-hidden relative">
      {/* Top Threat Indicator Bar */}
      <div className={`absolute top-0 left-0 w-full h-1.5 ${
        data.risk_level === "High" ? "bg-red-500" :
        data.risk_level === "Medium" ? "bg-orange-500" : "bg-green-500"
      }`} />

      <CardContent className="p-6 sm:p-8">
        <div className="flex items-center gap-3 mb-8">
          <div className={`p-2 rounded-xl flex items-center justify-center ${
            isSuspicious ? "bg-red-500/20 text-red-500" : "bg-primary/20 text-primary"
          }`}>
            <Server className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-xl font-bold font-sans tracking-tight">Redirect Chain Analysis</h3>
            <p className="text-sm text-muted-foreground">
              Traced <span className="font-semibold text-foreground">{data.total_redirects}</span> hops to final destination. 
              {isSuspicious && " Suspicious behavior detected."}
            </p>
          </div>
        </div>

        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="relative space-y-0"
        >
          {/* Vertical Connecting Line */}
          <div className="absolute left-[27px] sm:left-[35px] top-6 bottom-6 w-0.5 bg-border/60 z-0" />

          {data.chain.map((hop, index) => {
            const isLast = index === data.chain.length - 1;
            const hasThreats = hop.flags.length > 0;
            const isError = hop.status === 0;

            return (
              <motion.div
                key={hop.step}
                variants={itemVariants}
                className="relative z-10 flex gap-4 sm:gap-6 pb-8 last:pb-0"
              >
                {/* Step Connector Column */}
                <div className="flex flex-col items-center">
                  <div className={`w-14 h-14 sm:w-16 sm:h-16 rounded-2xl flex items-center justify-center border-2 shadow-sm bg-background transition-colors ${
                    hasThreats || isError 
                      ? "border-red-500/50 text-red-500 shadow-red-500/20" 
                      : index === 0 
                        ? "border-primary/50 text-primary" 
                        : isLast
                          ? "border-green-500/50 text-green-500"
                          : "border-orange-500/50 text-orange-500"
                  }`}>
                    {hasThreats || isError ? (
                      <AlertTriangle className="w-6 h-6 sm:w-7 sm:h-7" />
                    ) : index === 0 ? (
                      <LinkIcon className="w-6 h-6 sm:w-7 sm:h-7" />
                    ) : isLast ? (
                      <ShieldCheck className="w-6 h-6 sm:w-7 sm:h-7" />
                    ) : (
                      <ArrowDown className="w-6 h-6 sm:w-7 sm:h-7" />
                    )}
                  </div>
                </div>

                {/* Content Column */}
                <div className="flex-1 min-w-0 pt-1">
                  <div className={`p-4 sm:p-5 rounded-2xl border bg-background/50 backdrop-blur-sm shadow-sm transition-all hover:bg-background/80 ${
                    hasThreats || isError ? "border-red-500/30" : "border-border/50"
                  }`}>
                    
                    {/* Header Row: Status & Timing */}
                    <div className="flex flex-wrap items-center gap-3 mb-3">
                      <Badge variant="outline" className={`font-mono text-xs px-2.5 py-0.5 rounded-lg border ${getStatusColor(hop.status, isError)}`}>
                        {isError ? "ERROR" : `${hop.status} ${hop.status >= 300 && hop.status < 400 ? 'Redirect' : 'OK'}`}
                      </Badge>
                      
                      <div className="flex items-center text-xs font-medium text-muted-foreground bg-secondary/50 px-2 py-1 rounded-md">
                        <Clock className="w-3.5 h-3.5 mr-1.5 opacity-70" />
                        {hop.time_ms}ms
                      </div>

                      <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground ml-auto opacity-70">
                        Hop {hop.step}
                      </div>
                    </div>

                    {/* URL String */}
                    <div className="bg-secondary/30 p-3 rounded-xl border border-border/40 overflow-hidden mb-4">
                      <p className="font-mono text-sm break-all leading-relaxed text-foreground/90 selection:bg-primary/20">
                        {hop.url}
                      </p>
                    </div>

                    {/* Threat Badges (The "Wow" factor) */}
                    {hasThreats && (
                      <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-border/50">
                        {hop.flags.map((flag, i) => (
                          <Badge 
                            key={i} 
                            variant="destructive" 
                            className="bg-red-500/15 hover:bg-red-500/25 text-red-500 border border-red-500/30 px-3 py-1 text-xs font-semibold gap-1.5 shadow-sm rounded-lg"
                          >
                            <ShieldAlert className="w-3.5 h-3.5" />
                            {flag}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </motion.div>
      </CardContent>
    </Card>
  );
}
