import { useState, useRef, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Loader2, ShieldAlert, ShieldCheck, Languages, ArrowRight, Upload, X, QrCode, Link, Shield, ChevronDown, Globe, Activity, AlertTriangle, Wifi, Camera, Monitor } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useLocation } from "wouter";
import { RedirectChain } from "@/components/RedirectChain";
import { LiveSandbox } from "@/components/LiveSandbox";

export default function Home() {
  const [, navigate] = useLocation();
  const [url, setUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [lang, setLang] = useState<"en" | "hi">("en");
  const [inputMode, setInputMode] = useState<"url" | "file">("url");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filePreview, setFilePreview] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [screenshot, setScreenshot] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});
  const [showLiveView, setShowLiveView] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const toggleSection = (key: string) =>
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));

  const formatDomainAge = (days: number | string | undefined) => {
    if (days === undefined || days === "unknown") return "Unknown";
    const d = Number(days);
    if (d < 0) return "Unknown";
    if (d < 30) return `${d} days (⚠️ Very New)`;
    if (d < 365) return `${Math.floor(d / 30)} months`;
    return `${(d / 365).toFixed(1)} years`;
  };

  useEffect(() => {
    if (!selectedFile) {
      setFilePreview(null);
      return;
    }
    const objectUrl = URL.createObjectURL(selectedFile);
    setFilePreview(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [selectedFile]);

  const handleFileSelect = useCallback((file: File) => {
    if (file.type.startsWith("image/")) {
      setSelectedFile(file);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelect(file);
  }, [handleFileSelect]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleFileAnalyze = async () => {
    if (!selectedFile) return;
    setIsLoading(true);
    setResult(null);
    setScreenshot(null);

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

    const response = await fetch("/analyze/qr", {
      method: "POST",
      body: formData,
    });

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error('Python backend is not running. Start it on port 8000.');
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Analysis failed (${response.status})`);
      }

      const data = await response.json();
      console.log("PhishGuard QR Response:", data);

      const qrResult = data.qr_results?.[0];

      if (!qrResult) {
        throw new Error("No QR code found in image.");
      }

    // If QR contains a URL → forward to analyze endpoint for full analysis
    if (qrResult.type === "url" && qrResult.url_for_analysis) {
      const analyzeResponse = await fetch("/analyze/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: qrResult.url_for_analysis }),
      });

        if (!analyzeResponse.ok) {
          const err = await analyzeResponse.json().catch(() => ({}));
          throw new Error(err.detail || `URL analysis failed (${analyzeResponse.status})`);
        }

        const urlData = await analyzeResponse.json();
        console.log("PhishGuard QR→URL Response:", urlData);
        setResult({ ...urlData, tactics: urlData.tactics ?? [] });
        if (urlData.screenshot_b64) {
          setScreenshot(`data:image/png;base64,${urlData.screenshot_b64}`);
        }
        return;
      }

      if (qrResult.type === "upi") {
        setResult({
          score: qrResult.score ?? (
            qrResult.risk_level === "dangerous" ? 80 :
              qrResult.risk_level === "suspicious" ? 50 : 10
          ),
          verdict_en: qrResult.flags?.length
            ? `UPI QR: ${qrResult.flags.join(". ")}`
            : `UPI payment to ${qrResult.payee_name || qrResult.payee_vpa} — no threats detected.`,
          verdict_hi: `UPI विश्लेषण: ${qrResult.payee_name || qrResult.payee_vpa} — ${qrResult.risk_level === "safe" ? "कोई खतरा नहीं" : "संदिग्ध गतिविधि"}`,
          tactics: qrResult.flags ?? [],
        });
        return;
      }

      setResult({
        score: 0,
        verdict_en: `QR decoded (text): ${qrResult.decoded}`,
        verdict_hi: `QR विश्लेषण: ${qrResult.decoded}`,
        tactics: [],
      });

    } catch (error: any) {
      console.error("PhishGuard File Error:", error);
      setResult({
        score: 0,
        verdict_en: `Error: ${error.message || "Could not reach the analysis server."}`,
        verdict_hi: `त्रुटि: ${error.message || "विश्लेषण सर्वर तक नहीं पहुँच सका।"}`,
        tactics: [],
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setIsLoading(true);
    setResult(null);
    setScreenshot(null);

  try {
    const response = await fetch("/analyze/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error('Python backend is not running. Start it on port 8000.');
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Analysis failed (${response.status})`);
      }

      const data = await response.json();
      console.log("PhishGuard API Response:", data);
      setResult(data);

      // Use screenshot from the main analysis response (captured by Playwright sandbox)
      if (data.screenshot_b64) {
        setScreenshot(`data:image/png;base64,${data.screenshot_b64}`);
      }

    } catch (error: any) {
      console.error("PhishGuard Error:", error);
      setResult({
        score: 0,
        verdict_en: `Error: ${error.message || "Could not reach the analysis server."}`,
        verdict_hi: `त्रुटि: ${error.message || "विश्लेषण सर्वर तक नहीं पहुँच सका।"}`,
        tactics: []
      });
    } finally {
      setIsLoading(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 70) return "text-red-500";
    if (score >= 40) return "text-orange-500";
    return "text-green-500";
  };

  const getStrokeColor = (score: number) => {
    if (score >= 70) return "stroke-red-500";
    if (score >= 40) return "stroke-orange-500";
    return "stroke-green-500";
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col items-center pt-20 px-4 font-sans selection:bg-primary/30 selection:text-primary-foreground relative overflow-hidden bg-grid">
      {/* Ambient background effects */}
      <div className="absolute top-0 inset-x-0 h-full w-full pointer-events-none z-0">
        <div className="absolute top-[-15%] left-1/2 -translate-x-1/2 w-[90vw] max-w-[900px] h-[500px] bg-primary/8 blur-[150px] rounded-full" />
        <div className="absolute top-[30%] right-[-10%] w-[400px] h-[400px] bg-cyan-500/5 blur-[120px] rounded-full" />
        <div className="absolute bottom-[10%] left-[-5%] w-[300px] h-[300px] bg-primary/5 blur-[100px] rounded-full" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-2xl z-10 space-y-10"
      >
        <div className="text-center space-y-5">
          <div className="relative inline-flex items-center justify-center">
            <div className="absolute w-16 h-16 bg-primary/20 rounded-full pulse-ring" />
            <div className="relative p-4 rounded-2xl bg-secondary/80 border border-primary/20 shadow-lg shadow-primary/10">
              <ShieldAlert className="w-8 h-8 text-primary" />
            </div>
          </div>
          <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight">
            <span className="gradient-text">PhishGuard</span>
          </h1>
          <p className="text-muted-foreground text-lg max-w-lg mx-auto leading-relaxed">
            Advanced threat intelligence for phishing detection, domain analysis, and credential harvesting prevention.
          </p>
          <button
            onClick={() => navigate("/threats")}
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-primary transition-all duration-300 mt-1 group"
          >
            <Shield className="w-4 h-4 group-hover:scale-110 transition-transform" />
            View Live Threat Intelligence Feed
            <ArrowRight className="w-3 h-3 opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all" />
          </button>
        </div>

        <Card className="border-border/50 bg-card/60 backdrop-blur-2xl shadow-2xl overflow-hidden rounded-2xl glow-border">
          <CardContent className="p-2 sm:p-4">
            <Tabs value={inputMode} onValueChange={(v) => setInputMode(v as "url" | "file")} className="w-full">
              <TabsList className="w-full mb-3 bg-background/50 border border-border/50 rounded-xl h-12 p-1">
                <TabsTrigger
                  value="url"
                  className="flex-1 h-full rounded-lg text-sm font-semibold gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground transition-all"
                  data-testid="tab-url"
                >
                  <Link className="w-4 h-4" />
                  Paste URL
                </TabsTrigger>
                <TabsTrigger
                  value="file"
                  className="flex-1 h-full rounded-lg text-sm font-semibold gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground transition-all"
                  data-testid="tab-file"
                >
                  <QrCode className="w-4 h-4" />
                  Upload QR
                </TabsTrigger>
              </TabsList>

              {/* URL Tab */}
              <TabsContent value="url" className="mt-0">
                <form onSubmit={handleAnalyze} className="relative flex flex-col sm:flex-row gap-3">
                  <div className="relative flex-1">
                    <Input
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="https://example.com/login"
                      className="w-full h-14 pl-5 text-lg bg-background/50 border-border focus-visible:ring-primary/50 rounded-xl"
                      data-testid="input-url"
                      required
                      type="url"
                    />
                  </div>
                  <Button
                    type="submit"
                    disabled={isLoading || !url}
                    className="h-14 px-8 rounded-xl font-medium text-base shadow-lg transition-all w-full sm:w-auto"
                    data-testid="button-analyze"
                  >
                    {isLoading ? (
                      <Loader2 className="w-5 h-5 animate-spin" />
                    ) : (
                      <>Analyze <ArrowRight className="ml-2 w-5 h-5" /></>
                    )}
                  </Button>
                </form>
              </TabsContent>

              {/* File Upload Tab */}
              <TabsContent value="file" className="mt-0">
                <div className="space-y-3">
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/png,image/jpeg,image/webp,image/gif"
                    className="hidden"
                    data-testid="input-file"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleFileSelect(file);
                    }}
                  />

                  <AnimatePresence mode="wait">
                    {!selectedFile ? (
                      <motion.div
                        key="dropzone"
                        initial={{ opacity: 0, scale: 0.97 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.97 }}
                        transition={{ duration: 0.2 }}
                        onDrop={handleDrop}
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onClick={() => fileInputRef.current?.click()}
                        className={`relative flex flex-col items-center justify-center gap-3 p-8 sm:p-10 rounded-xl border-2 border-dashed cursor-pointer transition-all duration-200 ${isDragging
                          ? "border-primary bg-primary/10 scale-[1.01]"
                          : "border-border/60 bg-background/30 hover:border-primary/50 hover:bg-primary/5"
                          }`}
                        data-testid="dropzone"
                      >
                        <div className={`p-4 rounded-2xl transition-colors ${isDragging ? "bg-primary/20" : "bg-secondary/80"}`}>
                          <Upload className={`w-8 h-8 transition-colors ${isDragging ? "text-primary" : "text-muted-foreground"}`} />
                        </div>
                        <div className="text-center space-y-1">
                          <p className="text-sm font-medium text-foreground">
                            {isDragging ? "Drop your file here" : "Drag & drop an image here"}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            or click to browse · PNG, JPG, WebP, GIF
                          </p>
                        </div>
                        <p className="text-[10px] text-muted-foreground/60 uppercase tracking-widest font-semibold">
                          QR codes · Screenshots · Suspicious images
                        </p>
                      </motion.div>
                    ) : (
                      <motion.div
                        key="preview"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        transition={{ duration: 0.25 }}
                        className="relative flex items-center gap-4 p-4 rounded-xl bg-background/50 border border-border/50"
                      >
                        {filePreview && (
                          <div className="relative w-16 h-16 rounded-lg overflow-hidden border border-border/50 flex-shrink-0 bg-secondary/50">
                            <img src={filePreview} alt="Preview" className="w-full h-full object-cover" />
                          </div>
                        )}
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate text-foreground">{selectedFile.name}</p>
                          <p className="text-xs text-muted-foreground">{(selectedFile.size / 1024).toFixed(1)} KB</p>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedFile(null);
                            if (fileInputRef.current) fileInputRef.current.value = "";
                          }}
                          className="p-2 rounded-lg hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
                          data-testid="button-remove-file"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  <Button
                    type="button"
                    onClick={handleFileAnalyze}
                    disabled={isLoading || !selectedFile}
                    className="h-14 w-full rounded-xl font-medium text-base shadow-lg transition-all"
                    data-testid="button-analyze-file"
                  >
                    {isLoading ? (
                      <Loader2 className="w-5 h-5 animate-spin" />
                    ) : (
                      <>Analyze File <ArrowRight className="ml-2 w-5 h-5" /></>
                    )}
                  </Button>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {isLoading && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="flex flex-col items-center justify-center py-16 space-y-6"
          >
            <div className="relative">
              <div className="w-20 h-20 rounded-full border-2 border-primary/20 flex items-center justify-center">
                <div className="w-16 h-16 rounded-full border-2 border-t-primary border-r-primary border-b-transparent border-l-transparent animate-spin" />
              </div>
              <div className="absolute inset-0 flex items-center justify-center">
                <Shield className="w-6 h-6 text-primary" />
              </div>
            </div>
            <div className="text-center space-y-2">
              <p className="text-foreground font-semibold text-lg">Analyzing Threat Vectors</p>
              <p className="text-muted-foreground text-sm">Domain intelligence · Sandbox · Network analysis</p>
            </div>
            <div className="flex gap-3">
              {["Domain", "Sandbox", "NLP", "AI Verdict"].map((step, i) => (
                <motion.div
                  key={step}
                  initial={{ opacity: 0.3 }}
                  animate={{ opacity: [0.3, 1, 0.3] }}
                  transition={{ duration: 1.5, repeat: Infinity, delay: i * 0.3 }}
                  className="flex items-center gap-1.5"
                >
                  <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                  <span className="text-xs text-muted-foreground font-medium">{step}</span>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}

        {result && !isLoading && (
          <motion.div
            initial={{ opacity: 0, y: 30, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ type: "spring", bounce: 0.4, duration: 0.6 }}
          >
            <Card className={`overflow-hidden border-border/50 bg-card/60 backdrop-blur-2xl shadow-2xl relative rounded-2xl ${
              result.score >= 70
                ? 'shadow-red-500/10'
                : result.score >= 40
                  ? 'shadow-orange-500/10'
                  : 'shadow-primary/10'
            }`}>
              <div className={`absolute top-0 left-0 w-full h-1 ${
                result.score >= 70
                  ? 'bg-gradient-to-r from-red-500/0 via-red-500 to-red-500/0'
                  : result.score >= 40
                    ? 'bg-gradient-to-r from-orange-500/0 via-orange-500 to-orange-500/0'
                    : 'bg-gradient-to-r from-primary/0 via-primary to-primary/0'
              }`} />

              <CardContent className="p-6 sm:p-8">
                <div className="grid grid-cols-1 md:grid-cols-[auto_1fr] gap-8 sm:gap-10 items-center">

                  {/* Gauge */}
                  <div className="flex flex-col items-center justify-center">
                    <div className="relative flex items-center justify-center w-44 h-44">
                      <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
                        <circle cx="80" cy="80" r="68" className="fill-transparent" stroke="hsl(222 30% 12%)" strokeWidth="10" />
                        <motion.circle
                          cx="80" cy="80" r="68"
                          className={`fill-transparent ${getStrokeColor(result.score)}`}
                          strokeWidth="10"
                          strokeDasharray={2 * Math.PI * 68}
                          initial={{ strokeDashoffset: 2 * Math.PI * 68 }}
                          animate={{ strokeDashoffset: (2 * Math.PI * 68) - ((result.score / 100) * (2 * Math.PI * 68)) }}
                          transition={{ duration: 1.5, ease: "easeOut" }}
                          strokeLinecap="round"
                          filter="url(#glow)"
                        />
                        <defs>
                          <filter id="glow">
                            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                            <feMerge>
                              <feMergeNode in="coloredBlur" />
                              <feMergeNode in="SourceGraphic" />
                            </feMerge>
                          </filter>
                        </defs>
                      </svg>
                      <div className="absolute flex flex-col items-center justify-center">
                        <motion.span
                          className={`text-5xl font-extrabold tracking-tighter ${getScoreColor(result.score)}`}
                          initial={{ scale: 0 }}
                          animate={{ scale: 1 }}
                          transition={{ type: "spring", bounce: 0.5, delay: 0.2 }}
                        >
                          {result.score}
                        </motion.span>
                        <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-[0.2em] mt-1">
                          Risk Score
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Details */}
                  <div className="space-y-6">
                    <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-4">
                      <h3 className="text-2xl font-bold flex items-center gap-2.5">
                        {result.score >= 70 ? (
                          <><ShieldAlert className="w-7 h-7 text-red-500" /> Critical Threat</>
                        ) : result.score >= 40 ? (
                          <><ShieldAlert className="w-7 h-7 text-orange-500" /> Suspicious</>
                        ) : (
                          <><ShieldCheck className="w-7 h-7 text-green-500" /> Safe</>
                        )}
                      </h3>
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => setLang(l => l === "en" ? "hi" : "en")}
                        className="rounded-full h-9 px-4 text-xs font-semibold hover:bg-secondary/80 border border-border/50 transition-colors"
                        data-testid="button-toggle-lang"
                      >
                        <Languages className="w-4 h-4 mr-2" />
                        {lang === "en" ? "हिंदी में देखें" : "View in English"}
                      </Button>
                    </div>

                    <div className="p-5 rounded-xl bg-background/40 border border-border/50 shadow-inner">
                      <p className="text-lg leading-relaxed font-medium">
                        {lang === "en" ? result.verdict_en : result.verdict_hi}
                      </p>
                    </div>

                    <div className="space-y-3">
                      <p className="text-[11px] font-bold text-muted-foreground uppercase tracking-[0.15em]">
                        Detected Tactics
                      </p>
                      <div className="flex flex-wrap gap-2.5">
                        {(result.tactics ?? []).map((tactic: string, i: number) => (
                          <Badge
                            key={i}
                            variant="outline"
                            className={`px-3 py-1 text-sm rounded-lg font-medium border ${result.score >= 70
                                ? 'bg-red-500/10 text-red-500 border-red-500/20'
                                : result.score >= 40
                                  ? 'bg-orange-500/10 text-orange-500 border-orange-500/20'
                                  : 'bg-green-500/10 text-green-500 border-green-500/20'
                              }`}
                          >
                            {tactic}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* ──── PROFESSIONAL SECURITY REPORT ──── */}
                <div className="mt-8 space-y-3">
                  <p className="text-[11px] font-bold text-muted-foreground uppercase tracking-[0.15em] mb-4">
                    Detailed Security Report
                  </p>

                  {/* 1. Domain Intelligence */}
                  {result.domain_signals && (
                    <div className="rounded-xl border border-border/50 overflow-hidden bg-background/30">
                      <button
                        onClick={() => toggleSection("domain")}
                        className="w-full flex items-center justify-between px-5 py-4 hover:bg-secondary/30 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-lg ${result.domain_signals.impersonating ? 'bg-red-500/10' : 'bg-green-500/10'}`}>
                            <Globe className={`w-4 h-4 ${result.domain_signals.impersonating ? 'text-red-500' : 'text-green-500'}`} />
                          </div>
                          <span className="font-semibold text-sm">Domain Intelligence</span>
                          {result.domain_signals.impersonating && (
                            <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20 text-[10px]">
                              Impersonation Detected
                            </Badge>
                          )}
                        </div>
                        <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform duration-200 ${expandedSections.domain ? 'rotate-180' : ''}`} />
                      </button>
                      <AnimatePresence>
                        {expandedSections.domain && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.2 }}
                            className="overflow-hidden"
                          >
                            <div className="px-5 pb-5 grid grid-cols-1 sm:grid-cols-2 gap-3">
                              <div className="p-3 rounded-lg bg-secondary/30 border border-border/30">
                                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">Domain Age</p>
                                <p className={`text-sm font-bold mt-1 ${
                                  result.domain_signals.domain_age_days !== undefined &&
                                  Number(result.domain_signals.domain_age_days) < 30
                                    ? 'text-red-500' : 'text-foreground'
                                }`}>
                                  {formatDomainAge(result.domain_signals.domain_age_days)}
                                </p>
                              </div>
                              <div className="p-3 rounded-lg bg-secondary/30 border border-border/30">
                                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">TLD</p>
                                <p className="text-sm font-bold mt-1">{result.domain_signals.tld || "N/A"}</p>
                              </div>
                              {result.domain_signals.registrar && (
                                <div className="p-3 rounded-lg bg-secondary/30 border border-border/30 sm:col-span-2">
                                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">Registrar</p>
                                  <p className="text-sm font-bold mt-1">{result.domain_signals.registrar}</p>
                                </div>
                              )}
                              {result.domain_signals.impersonating && (
                                <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20 sm:col-span-2">
                                  <p className="text-[10px] uppercase tracking-wider text-red-500 font-semibold">⚠ Impersonating</p>
                                  <p className="text-sm font-bold mt-1 text-red-500">{result.domain_signals.impersonating}</p>
                                </div>
                              )}
                              {result.domain_signals.virustotal && (
                                <div className="p-3 rounded-lg bg-secondary/30 border border-border/30 sm:col-span-2">
                                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">VirusTotal</p>
                                  <p className="text-sm font-bold mt-1">
                                    {typeof result.domain_signals.virustotal === 'object'
                                      ? `${result.domain_signals.virustotal.malicious || 0} engines flagged`
                                      : String(result.domain_signals.virustotal)
                                    }
                                  </p>
                                </div>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}

                  {/* 2. Sandbox Analysis */}
                  {result.visual_signals && (
                    <div className="rounded-xl border border-border/50 overflow-hidden bg-background/30">
                      <button
                        onClick={() => toggleSection("sandbox")}
                        className="w-full flex items-center justify-between px-5 py-4 hover:bg-secondary/30 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-lg ${
                            (result.visual_signals.suspicious_form_targets?.length > 0 || result.visual_signals.suspicious_network_requests?.length > 0)
                              ? 'bg-red-500/10' : 'bg-green-500/10'
                          }`}>
                            <Activity className={`w-4 h-4 ${
                              (result.visual_signals.suspicious_form_targets?.length > 0 || result.visual_signals.suspicious_network_requests?.length > 0)
                                ? 'text-red-500' : 'text-green-500'
                            }`} />
                          </div>
                          <span className="font-semibold text-sm">Sandbox Analysis</span>
                          {result.visual_signals.timeout && (
                            <Badge variant="outline" className="bg-orange-500/10 text-orange-500 border-orange-500/20 text-[10px]">
                              Timed Out
                            </Badge>
                          )}
                        </div>
                        <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform duration-200 ${expandedSections.sandbox ? 'rotate-180' : ''}`} />
                      </button>
                      <AnimatePresence>
                        {expandedSections.sandbox && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.2 }}
                            className="overflow-hidden"
                          >
                            <div className="px-5 pb-5 space-y-3">
                              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div className="p-3 rounded-lg bg-secondary/30 border border-border/30">
                                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">HTTP Status</p>
                                  <p className={`text-sm font-bold mt-1 ${
                                    result.visual_signals.http_status && result.visual_signals.http_status >= 400
                                      ? 'text-red-500' : 'text-foreground'
                                  }`}>
                                    {result.visual_signals.http_status ?? "N/A"}
                                  </p>
                                </div>
                                <div className="p-3 rounded-lg bg-secondary/30 border border-border/30">
                                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">Page Title</p>
                                  <p className="text-sm font-bold mt-1 truncate">{result.visual_signals.page_title || "N/A"}</p>
                                </div>
                              </div>
                              {result.visual_signals.final_url && (
                                <div className="p-3 rounded-lg bg-secondary/30 border border-border/30">
                                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">Final URL (after redirects)</p>
                                  <p className="text-xs font-medium mt-1 text-muted-foreground break-all">{result.visual_signals.final_url}</p>
                                </div>
                              )}
                              {result.visual_signals.dom_signals && Object.keys(result.visual_signals.dom_signals).length > 0 && (
                                <div className="p-3 rounded-lg bg-orange-500/5 border border-orange-500/20">
                                  <p className="text-[10px] uppercase tracking-wider text-orange-500 font-semibold">DOM Signals Detected</p>
                                  <div className="flex flex-wrap gap-2 mt-2">
                                    {Object.entries(result.visual_signals.dom_signals).map(([selector, count]: [string, any]) => (
                                      <Badge key={selector} variant="outline" className="bg-orange-500/10 text-orange-500 border-orange-500/20 text-[10px]">
                                        {selector} × {count}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {result.visual_signals.suspicious_form_targets?.length > 0 && (
                                <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20">
                                  <p className="text-[10px] uppercase tracking-wider text-red-500 font-semibold">⚠ Suspicious Form Targets</p>
                                  {result.visual_signals.suspicious_form_targets.map((target: string, i: number) => (
                                    <p key={i} className="text-xs font-medium mt-1 text-red-400 break-all">{target}</p>
                                  ))}
                                </div>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}

                  {/* 3. Attack Scenario */}
                  {result.scam_arc && result.score >= 40 && (
                    <div className="rounded-xl border border-red-500/30 overflow-hidden bg-red-500/5">
                      <button
                        onClick={() => toggleSection("attack")}
                        className="w-full flex items-center justify-between px-5 py-4 hover:bg-red-500/10 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded-lg bg-red-500/10">
                            <AlertTriangle className="w-4 h-4 text-red-500" />
                          </div>
                          <span className="font-semibold text-sm text-red-500">Attack Scenario — What Would Happen</span>
                        </div>
                        <ChevronDown className={`w-4 h-4 text-red-400 transition-transform duration-200 ${expandedSections.attack ? 'rotate-180' : ''}`} />
                      </button>
                      <AnimatePresence>
                        {expandedSections.attack && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.2 }}
                            className="overflow-hidden"
                          >
                            <div className="px-5 pb-5">
                              <p className="text-sm leading-relaxed text-red-300/90 whitespace-pre-line">{result.scam_arc}</p>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}

                  {/* 4. Network Activity */}
                  {result.visual_signals && (result.visual_signals.suspicious_network_requests?.length > 0 || result.visual_signals.network_requests?.length > 0) && (
                    <div className="rounded-xl border border-border/50 overflow-hidden bg-background/30">
                      <button
                        onClick={() => toggleSection("network")}
                        className="w-full flex items-center justify-between px-5 py-4 hover:bg-secondary/30 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-lg ${
                            result.visual_signals.suspicious_network_requests?.length > 0
                              ? 'bg-red-500/10' : 'bg-green-500/10'
                          }`}>
                            <Wifi className={`w-4 h-4 ${
                              result.visual_signals.suspicious_network_requests?.length > 0
                                ? 'text-red-500' : 'text-green-500'
                            }`} />
                          </div>
                          <span className="font-semibold text-sm">Network Activity</span>
                          <Badge variant="outline" className="bg-secondary/50 text-muted-foreground border-border/50 text-[10px]">
                            {result.visual_signals.network_requests?.length ?? 0} requests
                          </Badge>
                          {result.visual_signals.suspicious_network_requests?.length > 0 && (
                            <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20 text-[10px]">
                              {result.visual_signals.suspicious_network_requests.length} suspicious
                            </Badge>
                          )}
                        </div>
                        <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform duration-200 ${expandedSections.network ? 'rotate-180' : ''}`} />
                      </button>
                      <AnimatePresence>
                        {expandedSections.network && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.2 }}
                            className="overflow-hidden"
                          >
                            <div className="px-5 pb-5 space-y-3">
                              {result.visual_signals.suspicious_network_requests?.length > 0 && (
                                <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20">
                                  <p className="text-[10px] uppercase tracking-wider text-red-500 font-semibold mb-2">⚠ Data Exfiltration — External POST Requests</p>
                                  <div className="space-y-2 max-h-40 overflow-y-auto">
                                    {result.visual_signals.suspicious_network_requests.map((req: any, i: number) => (
                                      <div key={i} className="flex items-start gap-2 text-xs">
                                        <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20 text-[9px] shrink-0">
                                          {req.method}
                                        </Badge>
                                        <span className="text-red-400 break-all">{req.url}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {result.mitm_summary && result.mitm_summary.blocked_requests?.length > 0 && (
                                <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20">
                                  <p className="text-[10px] uppercase tracking-wider text-red-500 font-semibold mb-2">MITM Proxy — Blocked Requests</p>
                                  <div className="space-y-2 max-h-40 overflow-y-auto">
                                    {result.mitm_summary.blocked_requests.map((req: any, i: number) => (
                                      <div key={i} className="flex items-start gap-2 text-xs">
                                        <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20 text-[9px] shrink-0">
                                          {req.reason}
                                        </Badge>
                                        <span className="text-red-400 break-all">{req.url}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              <div className="p-3 rounded-lg bg-secondary/30 border border-border/30">
                                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">Total Network Requests</p>
                                <p className="text-sm font-bold mt-1">{result.visual_signals.network_requests?.length ?? 0}</p>
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}

                  {/* 5. Live Sandbox View / Screenshot */}
                  <div className="rounded-xl border border-border/50 overflow-hidden bg-background/30">
                    <button
                      onClick={() => toggleSection("screenshot")}
                      className="w-full flex items-center justify-between px-5 py-4 hover:bg-secondary/30 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-blue-500/10">
                          <Monitor className="w-4 h-4 text-blue-500" />
                        </div>
                        <span className="font-semibold text-sm">Live Sandbox View</span>
                      </div>
                      <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform duration-200 ${expandedSections.screenshot ? 'rotate-180' : ''}`} />
                    </button>
                    <AnimatePresence>
                      {expandedSections.screenshot && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.2 }}
                          className="overflow-hidden"
                        >
                          <div className="px-5 pb-5 space-y-4">
                            {!showLiveView ? (
                              <div className="flex flex-col items-center gap-4 py-6">
                                {screenshot && (
                                  <img
                                    src={screenshot}
                                    alt="Website screenshot"
                                    className="w-full rounded-lg border border-border/30 shadow-lg opacity-60"
                                  />
                                )}
                                <button
                                  onClick={() => setShowLiveView(true)}
                                  className="flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-xl font-semibold text-sm hover:bg-primary/90 transition-all shadow-lg shadow-primary/20"
                                >
                                  <Monitor className="w-4 h-4" />
                                  Launch Live Interactive View
                                </button>
                                <p className="text-[11px] text-muted-foreground text-center max-w-sm">
                                  Browse the website in an isolated sandbox. Your data stays safe — all interaction happens in a sandboxed browser.
                                </p>
                              </div>
                            ) : (
                              <LiveSandbox
                                url={url || result?.redirect_chain?.final_url || ''}
                                onClose={() => setShowLiveView(false)}
                              />
                            )}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>

              </CardContent>
            </Card>
            {/* Render Redirect Chain if data is available */}
            {result.redirect_chain && result.redirect_chain.chain.length > 0 && (
              <RedirectChain data={result.redirect_chain} />
            )}
          </motion.div>
        )}
      </motion.div>

      {/* Footer */}
      <footer className="w-full max-w-2xl z-10 mt-16 mb-8 text-center">
        <div className="h-px bg-gradient-to-r from-transparent via-border to-transparent mb-6" />
        <p className="text-xs text-muted-foreground/50">
          PhishGuard — Advanced Threat Intelligence Platform
        </p>
      </footer>
    </div>
  );
}