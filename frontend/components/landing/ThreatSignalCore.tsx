"use client";

import React, { useEffect, useRef, useState } from "react";
import { Activity, ShieldAlert, Cpu, Radio } from "lucide-react";

interface Node {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
  glowColor: string;
  pulsePhase: number;
  pulseSpeed: number;
  isThreat?: boolean;
}

interface Packet {
  fromNode: number;
  toNode: number;
  progress: number;
  speed: number;
  color: string;
  isThreat?: boolean;
}

interface Ripple {
  x: number;
  y: number;
  radius: number;
  maxRadius: number;
  alpha: number;
}

export default function ThreatSignalCore() {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [hudState, setHudState] = useState({
    activeSignals: 14,
    threatLevel: "87%",
    pattern: "URGENCY_SPOOF",
  });

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let isVisible = true;
    let width = 0;
    let height = 0;

    // Check reduced motion
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // Adaptive node count based on screen width
    const isMobile = window.innerWidth < 768;
    const NODE_COUNT = isMobile ? 12 : 20;
    const MAX_DISTANCE = isMobile ? 110 : 145;

    let nodes: Node[] = [];
    const packets: Packet[] = [];
    const ripples: Ripple[] = [];
    let radarAngle = 0;

    // Mouse coordinates relative to canvas
    const mouse = { x: -1000, y: -1000, active: false, radius: 100 };

    const resize = () => {
      if (!container || !canvas) return;
      const rect = container.getBoundingClientRect();
      width = rect.width;
      height = rect.height;

      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.scale(dpr, dpr);

      initNodes();
    };

    const initNodes = () => {
      nodes = [];
      const cx = width / 2;
      const cy = height / 2;

      // Color palette: Cyber cyan (#22D3EE), Electric violet (#8B5CF6), Signal blue (#3B82F6), Threat crimson (#F43F5E)
      const colors = [
        { c: "#22D3EE", g: "rgba(34, 211, 238, 0.4)" },
        { c: "#8B5CF6", g: "rgba(139, 92, 246, 0.4)" },
        { c: "#3B82F6", g: "rgba(59, 130, 246, 0.4)" },
        { c: "#22D3EE", g: "rgba(34, 211, 238, 0.4)" },
        { c: "#F43F5E", g: "rgba(244, 63, 94, 0.5)" }, // Threat node
      ];

      for (let i = 0; i < NODE_COUNT; i++) {
        // Distribute in a ring-network around center
        const angle = (i / NODE_COUNT) * Math.PI * 2 + (Math.random() * 0.4 - 0.2);
        const distance = Math.min(width, height) * (0.22 + Math.random() * 0.24);
        const isThreatNode = i === 3 || i === 8;

        const colorObj = isThreatNode ? colors[4] : colors[i % (colors.length - 1)];

        nodes.push({
          x: cx + Math.cos(angle) * distance,
          y: cy + Math.sin(angle) * distance,
          vx: (Math.random() - 0.5) * 0.4,
          vy: (Math.random() - 0.5) * 0.4,
          radius: isThreatNode ? 3.5 : 2.5 + Math.random() * 1.5,
          color: colorObj.c,
          glowColor: colorObj.g,
          pulsePhase: Math.random() * Math.PI * 2,
          pulseSpeed: 0.03 + Math.random() * 0.02,
          isThreat: isThreatNode,
        });
      }
    };

    // Spawn packets
    let packetTimer = 0;
    const maybeSpawnPacket = () => {
      packetTimer++;
      if (packetTimer > 35 && packets.length < 8) {
        packetTimer = 0;
        if (nodes.length < 2) return;
        const from = Math.floor(Math.random() * nodes.length);
        // Find a nearby node
        const nearby: number[] = [];
        for (let j = 0; j < nodes.length; j++) {
          if (j !== from) {
            const dx = nodes[from].x - nodes[j].x;
            const dy = nodes[from].y - nodes[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < MAX_DISTANCE) nearby.push(j);
          }
        }
        if (nearby.length > 0) {
          const to = nearby[Math.floor(Math.random() * nearby.length)];
          const isThreat = nodes[from].isThreat || nodes[to].isThreat;
          packets.push({
            fromNode: from,
            toNode: to,
            progress: 0,
            speed: 0.012 + Math.random() * 0.015,
            color: isThreat ? "#F43F5E" : Math.random() > 0.5 ? "#22D3EE" : "#8B5CF6",
            isThreat,
          });
        }
      }
    };

    // Interaction handlers
    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
      mouse.active = true;
    };

    const handleMouseLeave = () => {
      mouse.active = false;
      mouse.x = -1000;
      mouse.y = -1000;
    };

    const handleClick = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;

      ripples.push({
        x: clickX,
        y: clickY,
        radius: 5,
        maxRadius: 180,
        alpha: 0.8,
      });

      // Disperse nodes slightly
      nodes.forEach((n) => {
        const dx = n.x - clickX;
        const dy = n.y - clickY;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 180 && dist > 1) {
          const force = (180 - dist) / 180;
          n.vx += (dx / dist) * force * 1.5;
          n.vy += (dy / dist) * force * 1.5;
        }
      });
    };

    // Touch support for mobile
    const handleTouchMove = (e: TouchEvent) => {
      if (e.touches.length > 0) {
        const rect = canvas.getBoundingClientRect();
        mouse.x = e.touches[0].clientX - rect.left;
        mouse.y = e.touches[0].clientY - rect.top;
        mouse.active = true;
      }
    };

    const handleTouchEnd = () => {
      mouse.active = false;
      mouse.x = -1000;
      mouse.y = -1000;
    };

    canvas.addEventListener("mousemove", handleMouseMove);
    canvas.addEventListener("mouseleave", handleMouseLeave);
    canvas.addEventListener("click", handleClick);
    canvas.addEventListener("touchmove", handleTouchMove, { passive: true });
    canvas.addEventListener("touchend", handleTouchEnd, { passive: true });

    // Pause when off-screen via IntersectionObserver
    const observer = new IntersectionObserver(
      (entries) => {
        isVisible = entries[0]?.isIntersecting ?? true;
      },
      { threshold: 0.05 }
    );
    observer.observe(container);

    // Initial sizing
    resize();
    window.addEventListener("resize", resize);

    // Main animation loop
    const render = () => {
      if (!isVisible) {
        animationFrameId = requestAnimationFrame(render);
        return;
      }

      ctx.clearRect(0, 0, width, height);

      const cx = width / 2;
      const cy = height / 2;

      // 1. Draw subtle background coordinate grid
      ctx.strokeStyle = "rgba(255, 255, 255, 0.02)";
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // 2. Central Threat Signal Core (Orbiting rings + pulsating core)
      if (!prefersReducedMotion) {
        radarAngle += 0.015;
      }

      // Ambient radial core glow
      const coreGlow = ctx.createRadialGradient(cx, cy, 10, cx, cy, 140);
      coreGlow.addColorStop(0, "rgba(34, 211, 238, 0.12)");
      coreGlow.addColorStop(0.4, "rgba(139, 92, 246, 0.06)");
      coreGlow.addColorStop(1, "transparent");
      ctx.fillStyle = coreGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, 140, 0, Math.PI * 2);
      ctx.fill();

      // Outer concentric ring
      ctx.strokeStyle = "rgba(255, 255, 255, 0.06)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, 95, 0, Math.PI * 2);
      ctx.stroke();

      // Dashed orbital ring
      ctx.save();
      ctx.strokeStyle = "rgba(34, 211, 238, 0.25)";
      ctx.lineWidth = 1.2;
      ctx.setLineDash([4, 8]);
      ctx.beginPath();
      ctx.arc(cx, cy, 68, radarAngle, radarAngle + Math.PI * 2);
      ctx.stroke();
      ctx.restore();

      // Counter-rotating inner ring
      ctx.save();
      ctx.strokeStyle = "rgba(139, 92, 246, 0.3)";
      ctx.lineWidth = 1.2;
      ctx.setLineDash([6, 12]);
      ctx.beginPath();
      ctx.arc(cx, cy, 46, -radarAngle * 1.5, -radarAngle * 1.5 + Math.PI * 2);
      ctx.stroke();
      ctx.restore();

      // Central Shield / Core Dot
      const coreRadius = 14 + Math.sin(radarAngle * 2) * 2;
      const innerCoreGlow = ctx.createRadialGradient(cx, cy, 2, cx, cy, coreRadius);
      innerCoreGlow.addColorStop(0, "#ffffff");
      innerCoreGlow.addColorStop(0.4, "#22D3EE");
      innerCoreGlow.addColorStop(1, "rgba(34, 211, 238, 0.1)");
      ctx.fillStyle = innerCoreGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, coreRadius, 0, Math.PI * 2);
      ctx.fill();

      // Radar scanning beam
      ctx.save();
      const radarSweep = ctx.createRadialGradient(cx, cy, 5, cx, cy, 130);
      radarSweep.addColorStop(0, "rgba(34, 211, 238, 0.2)");
      radarSweep.addColorStop(1, "transparent");
      ctx.fillStyle = radarSweep;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, 130, radarAngle, radarAngle + 0.35);
      ctx.closePath();
      ctx.fill();
      ctx.restore();

      // 3. Update & Draw Ripples
      for (let i = ripples.length - 1; i >= 0; i--) {
        const r = ripples[i];
        r.radius += 3.5;
        r.alpha -= 0.018;

        if (r.alpha <= 0 || r.radius >= r.maxRadius) {
          ripples.splice(i, 1);
        } else {
          ctx.strokeStyle = `rgba(34, 211, 238, ${r.alpha})`;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(r.x, r.y, r.radius, 0, Math.PI * 2);
          ctx.stroke();
        }
      }

      // 4. Update & Draw Nodes
      nodes.forEach((node) => {
        if (!prefersReducedMotion) {
          node.x += node.vx;
          node.y += node.vy;
          node.pulsePhase += node.pulseSpeed;

          // Boundary bounce with soft padding
          const padding = 20;
          if (node.x < padding || node.x > width - padding) node.vx *= -1;
          if (node.y < padding || node.y > height - padding) node.vy *= -1;

          // Mouse proximity reaction
          if (mouse.active) {
            const mdx = node.x - mouse.x;
            const mdy = node.y - mouse.y;
            const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
            if (mdist < mouse.radius && mdist > 0) {
              const repel = (mouse.radius - mdist) / mouse.radius;
              node.x += (mdx / mdist) * repel * 2;
              node.y += (mdy / mdist) * repel * 2;
            }
          }
        }

        // Connect node to central core with subtle line
        const coreDist = Math.sqrt((node.x - cx) ** 2 + (node.y - cy) ** 2);
        if (coreDist < 160) {
          const coreAlpha = (1 - coreDist / 160) * 0.18;
          ctx.strokeStyle = node.isThreat
            ? `rgba(244, 63, 94, ${coreAlpha})`
            : `rgba(34, 211, 238, ${coreAlpha})`;
          ctx.lineWidth = 0.8;
          ctx.beginPath();
          ctx.moveTo(cx, cy);
          ctx.lineTo(node.x, node.y);
          ctx.stroke();
        }

        // Draw node glow
        const currentRadius = node.radius + Math.sin(node.pulsePhase) * 0.8;
        ctx.fillStyle = node.glowColor;
        ctx.beginPath();
        ctx.arc(node.x, node.y, currentRadius * 2.4, 0, Math.PI * 2);
        ctx.fill();

        // Draw node solid center
        ctx.fillStyle = node.color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, currentRadius, 0, Math.PI * 2);
        ctx.fill();
      });

      // 5. Draw Network Connections
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < MAX_DISTANCE) {
            let lineAlpha = (1 - dist / MAX_DISTANCE) * 0.25;

            // Brighten lines near cursor
            if (mouse.active) {
              const midX = (nodes[i].x + nodes[j].x) / 2;
              const midY = (nodes[i].y + nodes[j].y) / 2;
              const mdist = Math.sqrt((midX - mouse.x) ** 2 + (midY - mouse.y) ** 2);
              if (mdist < 100) {
                lineAlpha = Math.min(1, lineAlpha + (1 - mdist / 100) * 0.5);
              }
            }

            const hasThreat = nodes[i].isThreat || nodes[j].isThreat;
            ctx.strokeStyle = hasThreat
              ? `rgba(244, 63, 94, ${lineAlpha * 1.2})`
              : `rgba(139, 92, 246, ${lineAlpha})`;
            ctx.lineWidth = hasThreat ? 1.2 : 0.8;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }

      // 6. Spawn & Draw Moving Data Packets
      if (!prefersReducedMotion) {
        maybeSpawnPacket();

        for (let i = packets.length - 1; i >= 0; i--) {
          const p = packets[i];
          p.progress += p.speed;

          if (p.progress >= 1 || !nodes[p.fromNode] || !nodes[p.toNode]) {
            packets.splice(i, 1);
          } else {
            const n1 = nodes[p.fromNode];
            const n2 = nodes[p.toNode];
            const px = n1.x + (n2.x - n1.x) * p.progress;
            const py = n1.y + (n2.y - n1.y) * p.progress;

            // Glowing packet
            ctx.fillStyle = p.color;
            ctx.shadowColor = p.color;
            ctx.shadowBlur = 8;
            ctx.beginPath();
            ctx.arc(px, py, p.isThreat ? 3 : 2, 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0; // reset
          }
        }
      }

      if (!prefersReducedMotion) {
        animationFrameId = requestAnimationFrame(render);
      }
    };

    render();

    // Subtle interval updating HUD telemetry stats for cyber immersion
    const hudInterval = setInterval(() => {
      setHudState((prev) => ({
        ...prev,
        activeSignals: 12 + Math.floor(Math.random() * 5),
        threatLevel: Math.random() > 0.7 ? "92%" : "87%",
        pattern: Math.random() > 0.5 ? "COERCIVE_URGENCY" : "IMPERSONATION_GATEWAY",
      }));
    }, 4000);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", resize);
      clearInterval(hudInterval);
      observer.disconnect();
      if (canvas) {
        canvas.removeEventListener("mousemove", handleMouseMove);
        canvas.removeEventListener("mouseleave", handleMouseLeave);
        canvas.removeEventListener("click", handleClick);
        canvas.removeEventListener("touchmove", handleTouchMove);
        canvas.removeEventListener("touchend", handleTouchEnd);
      }
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className="relative w-full h-[380px] sm:h-[440px] lg:h-[500px] flex items-center justify-center select-none overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-b from-[#0a0b12]/90 via-[#07080d] to-[#05060a] shadow-[0_0_50px_rgba(0,0,0,0.8)]"
      aria-label="Interactive Threat Signal Network Visualization"
    >
      {/* 2D Canvas */}
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full cursor-crosshair"
      />

      {/* Ambient Corner Accents */}
      <div className="absolute top-2 left-2 text-[9px] font-mono text-cyan-400/50 uppercase tracking-wider flex items-center gap-1.5 pointer-events-none">
        <span className="inline-block w-1 h-1 rounded-full bg-cyan-400 animate-ping" />
        LIVE_THREAT_SCANNER // [D-04]
      </div>

      <div className="absolute bottom-2 right-2 text-[9px] font-mono text-zinc-600 uppercase tracking-widest pointer-events-none">
        INTERACTION: HOVER / CLICK TO PULSE
      </div>

      {/* Floating Cyber Telemetry Metadata Labels */}
      
      {/* Label 1: THREAT ENGINE ACTIVE */}
      <div className="absolute top-6 right-6 hidden sm:flex items-center gap-2.5 rounded-lg border border-cyan-500/25 bg-[#07080d]/85 px-3 py-1.5 backdrop-blur-md shadow-lg pointer-events-none transition-transform duration-500 hover:scale-105">
        <div className="flex h-6 w-6 items-center justify-center rounded bg-cyan-500/10 text-cyan-400">
          <Activity className="h-3.5 w-3.5 animate-pulse" />
        </div>
        <div>
          <div className="text-[10px] font-mono font-bold tracking-wider text-cyan-300 uppercase">
            THREAT ENGINE
          </div>
          <div className="text-[9px] font-mono text-emerald-400 flex items-center gap-1">
            <span className="h-1 w-1 rounded-full bg-emerald-400 inline-block" />
            ACTIVE // {hudState.activeSignals} SIGNALS
          </div>
        </div>
      </div>

      {/* Label 2: RISK ALERT */}
      <div className="absolute bottom-6 left-6 flex items-center gap-2.5 rounded-lg border border-rose-500/30 bg-[#07080d]/85 px-3 py-1.5 backdrop-blur-md shadow-lg pointer-events-none">
        <div className="flex h-6 w-6 items-center justify-center rounded bg-rose-500/10 text-rose-400">
          <ShieldAlert className="h-3.5 w-3.5" />
        </div>
        <div>
          <div className="text-[10px] font-mono font-bold tracking-wider text-rose-300 uppercase flex items-center gap-1.5">
            RISK // {hudState.threatLevel}
            <span className="text-[8px] bg-rose-500/20 text-rose-300 px-1 py-0.2 rounded font-sans">CRITICAL</span>
          </div>
          <div className="text-[9px] font-mono text-zinc-400">
            PATTERN: {hudState.pattern}
          </div>
        </div>
      </div>

      {/* Label 3: SIGNAL ANALYZING */}
      <div className="absolute bottom-6 right-6 hidden md:flex items-center gap-2 rounded-lg border border-white/[0.08] bg-[#07080d]/80 px-2.5 py-1 text-[9px] font-mono text-zinc-400 backdrop-blur-sm pointer-events-none">
        <Cpu className="h-3 w-3 text-violet-400" />
        <span>BEDROCK FUSION: SYNCED</span>
      </div>

      {/* Label 4: SCANNING BADGE Top Left */}
      <div className="absolute top-6 left-6 hidden md:flex items-center gap-2 rounded-lg border border-white/[0.08] bg-[#07080d]/80 px-2.5 py-1 text-[9px] font-mono text-zinc-400 backdrop-blur-sm pointer-events-none">
        <Radio className="h-3 w-3 text-cyan-400 animate-pulse" />
        <span>REALTIME DECODE</span>
      </div>
    </div>
  );
}
