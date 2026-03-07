import { useState, useRef, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Loader2, ShieldAlert, ShieldCheck, Languages, ArrowRight, Upload, X, FileImage, Link, Shield } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { RedirectChain } from "@/components/RedirectChain";
import { useLocation } from "wouter";

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
  const fileInputRef = useRef<HTMLInputElement>(null);

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

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

      const response = await fetch('http://localhost:8000/analyze/qr', {
        method: 'POST',
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

      if (qrResult.type === "url" && qrResult.url_for_analysis) {
        const analyzeResponse = await fetch('http://localhost:8000/analyze/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: qrResult.url_for_analysis }),
        });

        if (!analyzeResponse.ok) {
          const err = await analyzeResponse.json().catch(() => ({}));
          throw new Error(err.detail || `URL analysis failed (${analyzeResponse.status})`);
        }

        const urlData = await analyzeResponse.json();
        setResult({ ...urlData, tactics: urlData.tactics ?? [] });
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
      const response = await fetch('http://localhost:8000/analyze/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
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

      // Fetch screenshot in background — skip for dangerous URLs
      if (data.score < 70) {
        fetch(`http://localhost:8000/analyze/screenshot?url=${encodeURIComponent(url)}`)
          .then(r => r.json())
          .then(s => { if (s.screenshot) setScreenshot(s.screenshot); })
          .catch(() => { });
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
    <div className="min-h-screen bg-background text-foreground flex flex-col items-center pt-24 px-4 font-sans selection:bg-primary selection:text-primary-foreground relative overflow-hidden">
      {/* Background glowing blobs */}
      <div className="absolute top-0 inset-x-0 h-full w-full pointer-events-none z-0 flex justify-center">
        <div className="absolute top-[-10%] w-[80vw] max-w-[800px] h-[400px] bg-primary/10 blur-[120px] rounded-full opacity-50" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-2xl z-10 space-y-10"
      >
        <div className="text-center space-y-4">
          <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-secondary/80 border border-border/50 mb-2 shadow-inner">
            <ShieldAlert className="w-8 h-8 text-primary" />
          </div>
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-foreground">
            Phishing URL Analyzer
          </h1>
          <p className="text-muted-foreground text-lg max-w-lg mx-auto">
            Detect malicious intent, spoofed domains, and credential harvesting in real-time.
          </p>
          {/* Threat Feed link */}
          <button
            onClick={() => navigate("/threats")}
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-primary transition-colors mt-1"
          >
            <Shield className="w-4 h-4" />
            View Live Threat Intelligence Feed →
          </button>
        </div>

        <Card className="border-border/50 bg-card/60 backdrop-blur-2xl shadow-2xl overflow-hidden rounded-2xl">
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
                  <FileImage className="w-4 h-4" />
                  Upload File
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
            className="flex flex-col items-center justify-center py-16 space-y-5"
          >
            <Loader2 className="w-12 h-12 animate-spin text-primary" />
            <p className="text-muted-foreground font-medium animate-pulse text-lg">Running heuristic analysis...</p>
          </motion.div>
        )}

        {result && !isLoading && (
          <motion.div
            initial={{ opacity: 0, y: 30, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ type: "spring", bounce: 0.4, duration: 0.6 }}
          >
            <Card className="overflow-hidden border-border/50 bg-card/60 backdrop-blur-2xl shadow-2xl relative rounded-2xl">
              <div className={`absolute top-0 left-0 w-full h-1.5 ${result.score >= 70 ? 'bg-red-500' : result.score >= 40 ? 'bg-orange-500' : 'bg-green-500'}`} />

              <CardContent className="p-6 sm:p-8">
                <div className="grid grid-cols-1 md:grid-cols-[auto_1fr] gap-8 sm:gap-10 items-center">

                  {/* Gauge */}
                  <div className="flex flex-col items-center justify-center">
                    <div className="relative flex items-center justify-center w-40 h-40">
                      <svg className="w-full h-full transform -rotate-90 drop-shadow-lg">
                        <circle cx="80" cy="80" r="72" className="stroke-secondary fill-transparent" strokeWidth="12" />
                        <motion.circle
                          cx="80" cy="80" r="72"
                          className={`fill-transparent ${getStrokeColor(result.score)}`}
                          strokeWidth="12"
                          strokeDasharray={2 * Math.PI * 72}
                          initial={{ strokeDashoffset: 2 * Math.PI * 72 }}
                          animate={{ strokeDashoffset: (2 * Math.PI * 72) - ((result.score / 100) * (2 * Math.PI * 72)) }}
                          transition={{ duration: 1.5, ease: "easeOut" }}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute flex flex-col items-center justify-center">
                        <span className={`text-5xl font-bold tracking-tighter ${getScoreColor(result.score)}`}>
                          {result.score}
                        </span>
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

                {/* Screenshot Preview */}
                {screenshot && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    className="mt-6 rounded-xl overflow-hidden border border-border/50"
                  >
                    <p className="text-[11px] font-bold text-muted-foreground uppercase tracking-[0.15em] px-1 py-3">
                      Page Preview
                    </p>
                    <img
                      src={screenshot}
                      alt="Website screenshot"
                      className="w-full object-cover max-h-64 rounded-lg"
                    />
                  </motion.div>
                )}
              </CardContent>
            </Card>

            {/* Render Redirect Chain if data is available */}
            {result.redirect_chain && result.redirect_chain.chain.length > 0 && (
              <RedirectChain data={result.redirect_chain} />
            )}
          </motion.div>
        )}
      </motion.div>
    </div>
  );
}