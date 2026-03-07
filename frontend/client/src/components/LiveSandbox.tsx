import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Monitor, X, ArrowLeft, ArrowRight, RotateCw, Timer, Shield, Loader2 } from "lucide-react";

interface LiveSandboxProps {
  url: string;
  onClose: () => void;
}

export function LiveSandbox({ url, onClose }: LiveSandboxProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const imgRef = useRef<HTMLImageElement | null>(null);

  const [status, setStatus] = useState<"connecting" | "connected" | "closed" | "error">("connecting");
  const [currentUrl, setCurrentUrl] = useState(url);
  const [pageTitle, setPageTitle] = useState("Loading...");
  const [errorMsg, setErrorMsg] = useState("");
  const [timeLeft, setTimeLeft] = useState(120);

  // Scale factor for coordinate mapping
  const REMOTE_WIDTH = 1280;
  const REMOTE_HEIGHT = 800;

  // Countdown timer
  useEffect(() => {
    if (status !== "connected") return;
    const interval = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          clearInterval(interval);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [status]);

  // WebSocket connection
  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/sandbox/live?url=${encodeURIComponent(url)}`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    // Preload image element for drawing frames
    imgRef.current = new Image();

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        switch (msg.type) {
          case "frame": {
            const canvas = canvasRef.current;
            const ctx = canvas?.getContext("2d");
            const img = imgRef.current;
            if (!canvas || !ctx || !img) return;

            img.onload = () => {
              canvas.width = img.width;
              canvas.height = img.height;
              ctx.drawImage(img, 0, 0);
            };
            img.src = `data:image/jpeg;base64,${msg.data}`;
            break;
          }
          case "url":
            setCurrentUrl(msg.url);
            break;
          case "title":
            setPageTitle(msg.title);
            break;
          case "status":
            setStatus(msg.status);
            break;
          case "error":
            setStatus("error");
            setErrorMsg(msg.message);
            break;
          case "timeout":
            setStatus("closed");
            setErrorMsg(msg.message);
            break;
        }
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      if (status !== "error") {
        setStatus("closed");
      }
    };

    ws.onerror = () => {
      setStatus("error");
      setErrorMsg("WebSocket connection failed");
    };

    return () => {
      ws.close();
    };
  }, [url]);

  // Send message helper
  const send = useCallback((msg: object) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(msg));
    }
  }, []);

  // Map canvas coordinates to remote viewport
  const mapCoords = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return { x: 0, y: 0 };
      const rect = canvas.getBoundingClientRect();
      const scaleX = REMOTE_WIDTH / rect.width;
      const scaleY = REMOTE_HEIGHT / rect.height;
      return {
        x: Math.round((e.clientX - rect.left) * scaleX),
        y: Math.round((e.clientY - rect.top) * scaleY),
      };
    },
    []
  );

  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const { x, y } = mapCoords(e);
      send({ type: "click", x, y, button: e.button === 2 ? "right" : "left" });
    },
    [mapCoords, send]
  );

  const handleScroll = useCallback(
    (e: React.WheelEvent<HTMLCanvasElement>) => {
      const { x, y } = mapCoords(e);
      send({ type: "scroll", x, y, deltaX: e.deltaX, deltaY: e.deltaY });
    },
    [mapCoords, send]
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      // Throttle: only send every 50ms
      const { x, y } = mapCoords(e);
      send({ type: "mousemove", x, y });
    },
    [mapCoords, send]
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      e.preventDefault();
      if (e.key.length === 1) {
        send({ type: "type", text: e.key });
      } else {
        send({ type: "keypress", key: e.key });
      }
    },
    [send]
  );

  const formatTime = (s: number) =>
    `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className="w-full rounded-2xl overflow-hidden border border-border/50 bg-card/80 backdrop-blur-2xl shadow-2xl"
    >
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 bg-background/80 border-b border-border/50">
        {/* Navigation buttons */}
        <button
          onClick={() => send({ type: "back" })}
          className="p-1.5 rounded-lg hover:bg-muted/50 transition-colors text-muted-foreground hover:text-foreground"
          title="Back"
        >
          <ArrowLeft className="w-4 h-4" />
        </button>
        <button
          onClick={() => send({ type: "forward" })}
          className="p-1.5 rounded-lg hover:bg-muted/50 transition-colors text-muted-foreground hover:text-foreground"
          title="Forward"
        >
          <ArrowRight className="w-4 h-4" />
        </button>
        <button
          onClick={() => send({ type: "refresh" })}
          className="p-1.5 rounded-lg hover:bg-muted/50 transition-colors text-muted-foreground hover:text-foreground"
          title="Refresh"
        >
          <RotateCw className="w-4 h-4" />
        </button>

        {/* URL bar */}
        <div className="flex-1 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-muted/30 border border-border/30 text-xs font-mono text-muted-foreground truncate">
          <Shield className="w-3 h-3 text-primary flex-shrink-0" />
          <span className="truncate">{currentUrl}</span>
        </div>

        {/* Timer */}
        <div className="flex items-center gap-1 text-xs font-mono text-muted-foreground">
          <Timer className="w-3 h-3" />
          <span className={timeLeft <= 30 ? "text-red-400" : ""}>{formatTime(timeLeft)}</span>
        </div>

        {/* Close */}
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg hover:bg-red-500/20 transition-colors text-muted-foreground hover:text-red-400"
          title="Close live view"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Sandbox badge */}
      <div className="flex items-center justify-center gap-2 py-1.5 bg-primary/10 border-b border-primary/20">
        <Shield className="w-3 h-3 text-primary" />
        <span className="text-[10px] font-bold text-primary uppercase tracking-widest">
          Isolated Sandbox — Your data is safe
        </span>
      </div>

      {/* Canvas / Status */}
      <div className="relative bg-black" style={{ aspectRatio: "1280 / 800" }}>
        {status === "connecting" && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3">
            <Loader2 className="w-8 h-8 text-primary animate-spin" />
            <p className="text-sm text-muted-foreground">Launching sandbox browser...</p>
          </div>
        )}

        {(status === "closed" || status === "error") && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3">
            <Monitor className="w-8 h-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              {errorMsg || "Session ended"}
            </p>
            <button
              onClick={onClose}
              className="px-4 py-2 text-xs font-semibold bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
            >
              Close
            </button>
          </div>
        )}

        <canvas
          ref={canvasRef}
          className="w-full h-full cursor-pointer"
          style={{ display: status === "connected" ? "block" : "none" }}
          onClick={handleClick}
          onContextMenu={(e) => {
            e.preventDefault();
            handleClick(e);
          }}
          onWheel={handleScroll}
          onMouseMove={handleMouseMove}
          onKeyDown={handleKeyDown}
          tabIndex={0}
        />
      </div>

      {/* Bottom bar */}
      <div className="px-3 py-1.5 bg-background/80 border-t border-border/50 flex items-center justify-between">
        <span className="text-[10px] text-muted-foreground truncate max-w-[60%]">{pageTitle}</span>
        <span className="text-[10px] text-muted-foreground">
          {status === "connected" ? "🟢 Live" : status === "connecting" ? "🟡 Connecting" : "🔴 Disconnected"}
        </span>
      </div>
    </motion.div>
  );
}
