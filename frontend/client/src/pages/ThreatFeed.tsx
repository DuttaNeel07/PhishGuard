import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, AlertTriangle, Clock, RefreshCw, ArrowLeft } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useLocation } from "wouter";

interface ThreatEntry {
  domain: string;
  score: number;
  tactics: string[];
  scanned_at: string;
  risk_level: "dangerous" | "suspicious";
}

export default function ThreatFeed() {
  const [, navigate] = useLocation();
  const [feed, setFeed] = useState<ThreatEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [newEntries, setNewEntries] = useState<Set<string>>(new Set());

  const fetchFeed = async (silent = false) => {
    if (!silent) setIsLoading(true);
    try {
      const res = await fetch("http://localhost:8000/analyze/threat-feed");
      const data = await res.json();
      const incoming: ThreatEntry[] = data.feed ?? [];

      if (feed.length > 0) {
        const existingDomains = new Set(feed.map(f => f.domain + f.scanned_at));
        const fresh = new Set(
          incoming
            .filter(e => !existingDomains.has(e.domain + e.scanned_at))
            .map(e => e.domain + e.scanned_at)
        );
        setNewEntries(fresh);
        setTimeout(() => setNewEntries(new Set()), 3000);
      }

      setFeed(incoming);
      setLastUpdated(new Date());
    } catch (e) {
      console.error("Threat feed error:", e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchFeed();
    const interval = setInterval(() => fetchFeed(true), 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col items-center pt-16 px-4 font-sans relative overflow-hidden">
      {/* Background blob */}
      <div className="absolute top-0 inset-x-0 h-full w-full pointer-events-none z-0 flex justify-center">
        <div className="absolute top-[-10%] w-[80vw] max-w-[800px] h-[400px] bg-primary/10 blur-[120px] rounded-full opacity-50" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-2xl z-10 space-y-6"
      >
        {/* Back button */}
        <button
          onClick={() => navigate("/")}
          className="flex items-center gap-2 text-sm text-muted-foreground hover:text-primary transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Scanner
        </button>

        {/* Page header */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-secondary/80 border border-border/50 mb-2 shadow-inner">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-foreground">
            Threat Intelligence
          </h1>
          <p className="text-muted-foreground text-lg max-w-lg mx-auto">
            Live feed of phishing domains detected by PhishGuard users in real-time.
          </p>
        </div>

        {/* Header controls */}
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            Live Threat Feed
          </h2>
          <div className="flex items-center gap-3">
            {lastUpdated && (
              <span className="text-[11px] text-muted-foreground">
                Updated {lastUpdated.toLocaleTimeString()}
              </span>
            )}
            <button
              onClick={() => fetchFeed()}
              className="p-1.5 rounded-lg hover:bg-secondary transition-colors"
              title="Refresh"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-muted-foreground ${isLoading ? "animate-spin" : ""}`} />
            </button>
            <span className="text-xs text-green-500 font-medium flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse inline-block" />
              Live
            </span>
          </div>
        </div>

        {/* Stats bar */}
        {feed.length > 0 && (
          <div className="grid grid-cols-3 gap-2">
            <div className="rounded-xl bg-card/60 border border-border/50 p-3 text-center">
              <p className="text-2xl font-bold text-foreground">{feed.length}</p>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Threats</p>
            </div>
            <div className="rounded-xl bg-card/60 border border-border/50 p-3 text-center">
              <p className="text-2xl font-bold text-red-500">
                {feed.filter(f => f.risk_level === "dangerous").length}
              </p>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Dangerous</p>
            </div>
            <div className="rounded-xl bg-card/60 border border-border/50 p-3 text-center">
              <p className="text-2xl font-bold text-orange-500">
                {feed.filter(f => f.risk_level === "suspicious").length}
              </p>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Suspicious</p>
            </div>
          </div>
        )}

        {/* Feed list */}
        {isLoading && feed.length === 0 ? (
          <div className="flex items-center justify-center py-12">
            <RefreshCw className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : feed.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 space-y-2">
            <Shield className="w-10 h-10 text-muted-foreground/30" />
            <p className="text-muted-foreground text-sm">No threats detected yet.</p>
            <p className="text-muted-foreground/60 text-xs">Threats appear here as users scan suspicious URLs.</p>
          </div>
        ) : (
          <div className="space-y-2 pb-10">
            <AnimatePresence>
              {feed.map((entry, i) => {
                const isNew = newEntries.has(entry.domain + entry.scanned_at);
                return (
                  <motion.div
                    key={entry.domain + entry.scanned_at}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 10 }}
                    transition={{ delay: i * 0.02 }}
                  >
                    <Card className={`border-border/50 bg-card/60 backdrop-blur-sm transition-all ${
                      isNew ? "ring-1 ring-primary/50 bg-primary/5" : ""
                    }`}>
                      <CardContent className="p-3 flex items-center justify-between gap-4">
                        <div className="flex items-center gap-3 min-w-0">
                          <AlertTriangle className={`w-4 h-4 flex-shrink-0 ${
                            entry.risk_level === "dangerous" ? "text-red-500" : "text-orange-500"
                          }`} />
                          <div className="min-w-0">
                            <p className="text-sm font-mono font-medium truncate">
                              {entry.domain}
                              {isNew && (
                                <span className="ml-2 text-[10px] text-primary font-sans font-semibold">NEW</span>
                              )}
                            </p>
                            <div className="flex flex-wrap gap-1 mt-0.5">
                              {(entry.tactics ?? []).slice(0, 2).map((t, j) => (
                                <span key={j} className="text-[10px] text-muted-foreground">
                                  {t}{j < Math.min((entry.tactics ?? []).length, 2) - 1 ? " ·" : ""}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 flex-shrink-0">
                          <Badge
                            variant="outline"
                            className={`text-xs font-bold ${
                              entry.risk_level === "dangerous"
                                ? "bg-red-500/10 text-red-500 border-red-500/20"
                                : "bg-orange-500/10 text-orange-500 border-orange-500/20"
                            }`}
                          >
                            {entry.score}/100
                          </Badge>
                          <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(entry.scanned_at).toLocaleTimeString()}
                          </span>
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        )}
      </motion.div>
    </div>
  );
}