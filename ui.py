import pygame
import math
import time
from typing import List, Optional, Dict, Tuple

from network import NetworkNode, Firewall, IDS, NodeStatus, PortStatus, AlertSeverity
from attacker_ai import AttackerAI, AttackPhase, Difficulty, Packet
from defender_actions import DefenderController, ScoreTracker


# ---------------------------------------------------------------------------
# Colour Palette
# ---------------------------------------------------------------------------

BLACK       = (0,    0,    0)
DARK_BG     = (10,   12,   18)
PANEL_BG    = (15,   20,   30)
PANEL_BORDER= (30,   60,   90)
WHITE       = (255, 255,  255)
GREY        = (120, 130,  140)
LIGHT_GREY  = (180, 190,  200)

# Node status colours
COL_SECURE       = (0,   200,  100)   # Green
COL_SCANNING     = (255, 200,   50)   # Yellow
COL_VULNERABLE   = (255, 140,    0)   # Orange
COL_UNDER_ATTACK = (255,  69,    0)   # Red-Orange
COL_COMPROMISED  = (220,  20,   60)   # Crimson
COL_PATCHED      = (100, 200,  255)   # Cyan
COL_SERVER       = (180,  80,  255)   # Purple

# UI accent colours
ACCENT_BLUE  = (30,  144, 255)
ACCENT_GREEN = (0,   200, 100)
ACCENT_RED   = (220,  20,  60)
ACCENT_ORANGE= (255, 165,   0)

# Alert severity colours
ALERT_COLORS = {
    AlertSeverity.INFO:     (100, 200, 255),
    AlertSeverity.WARNING:  (255, 200,  50),
    AlertSeverity.CRITICAL: (255,  50,  50),
}


# ---------------------------------------------------------------------------
# Font Helper
# ---------------------------------------------------------------------------

class Fonts:
    """Lazy-loaded font cache."""
    _cache: Dict[Tuple, pygame.font.Font] = {}

    @classmethod
    def get(cls, size: int, bold: bool = False) -> pygame.font.Font:
        key = (size, bold)
        if key not in cls._cache:
            try:
                name = "Courier New" if not bold else "Courier New"
                cls._cache[key] = pygame.font.SysFont(name, size, bold=bold)
            except Exception:
                cls._cache[key] = pygame.font.Font(None, size)
        return cls._cache[key]


def draw_text(surface: pygame.Surface, text: str, x: int, y: int,
              color: Tuple = WHITE, size: int = 14, bold: bool = False,
              anchor: str = "topleft") -> pygame.Rect:
    """Render anti-aliased text at (x, y) with given anchor point."""
    font = Fonts.get(size, bold)
    surf = font.render(text, True, color)
    rect = surf.get_rect()
    setattr(rect, anchor, (x, y))
    surface.blit(surf, rect)
    return rect


def draw_rounded_rect(surface: pygame.Surface, color: Tuple,
                      rect: pygame.Rect, radius: int = 8,
                      border_color: Optional[Tuple] = None,
                      border_width: int = 1):
    """Draw a filled rounded rectangle with optional border."""
    pygame.draw.rect(surface, color, rect, border_radius=radius)
    if border_color:
        pygame.draw.rect(surface, border_color, rect,
                         border_width, border_radius=radius)


def draw_progress_bar(surface: pygame.Surface, x: int, y: int,
                      w: int, h: int, fraction: float,
                      fg_color: Tuple, bg_color: Tuple = (40, 40, 60),
                      border_color: Tuple = PANEL_BORDER,
                      radius: int = 4):
    """Draw a horizontal progress / health bar."""
    bg_rect = pygame.Rect(x, y, w, h)
    draw_rounded_rect(surface, bg_color, bg_rect, radius)
    if fraction > 0:
        fg_rect = pygame.Rect(x, y, int(w * fraction), h)
        draw_rounded_rect(surface, fg_color, fg_rect, radius)
    pygame.draw.rect(surface, border_color, bg_rect, 1, border_radius=radius)


# ---------------------------------------------------------------------------
# Node Status → Display Mapping
# ---------------------------------------------------------------------------

STATUS_COLOR = {
    NodeStatus.SECURE:       COL_SECURE,
    NodeStatus.SCANNING:     COL_SCANNING,
    NodeStatus.VULNERABLE:   COL_VULNERABLE,
    NodeStatus.UNDER_ATTACK: COL_UNDER_ATTACK,
    NodeStatus.COMPROMISED:  COL_COMPROMISED,
    NodeStatus.PATCHED:      COL_PATCHED,
}


# ---------------------------------------------------------------------------
# Main UI Renderer
# ---------------------------------------------------------------------------

class GameUI:
    """
    Pygame-based rendering engine for the simulation.

    Layout (1100 × 700 px):
    ┌────────────────────────────────────────────┬───────────┐
    │  NETWORK DIAGRAM (topology + packets)      │  LOG      │
    │  760 × 560 px                              │  PANEL    │
    ├────────────────────────────────────────────┤  340 px   │
    │  ACTION BAR (defender buttons)             │           │
    └────────────────────────────────────────────┴───────────┘
    """

    WIDTH  = 1100
    HEIGHT = 700

    # Layout zones
    NET_W  = 760    # Network diagram width
    NET_H  = 540    # Network diagram height
    LOG_W  = 340    # Log panel width
    BTN_H  = 155    # Action bar height

    # Positioning offsets
    NET_X  = 0
    NET_Y  = 0
    LOG_X  = 760
    LOG_Y  = 0
    LOG_H  = HEIGHT
    BTN_X  = 0
    BTN_Y  = NET_H

    NODE_RADIUS   = 28
    SERVER_RADIUS = 36

    def __init__(self):
        pygame.init()
        # The actual resizable window
        self.window = pygame.display.set_mode((self.WIDTH, self.HEIGHT), pygame.RESIZABLE)
        # The fixed logical virtual screen where drawing happens
        self.screen = pygame.Surface((self.WIDTH, self.HEIGHT))
        pygame.display.set_caption("Hacker vs Defender — Network Security Simulation")
        self.clock  = pygame.time.Clock()
        self._tick  = 0  # Frame counter for animations

        # Hover / click state
        self._hovered_node: Optional[NetworkNode] = None

        # Floating notification queue
        self._notifications: List[Dict] = []

    # ------------------------------------------------------------------
    # Main Render Entry
    # ------------------------------------------------------------------

    def render(self, nodes: List[NetworkNode], server: NetworkNode,
               firewall: Firewall, ids: IDS,
               attacker: AttackerAI, defender: DefenderController,
               score: ScoreTracker):
        """
        Full-frame render. Called every game tick from main.py.
        """
        self._tick += 1
        self.screen.fill(DARK_BG)

        self._draw_network_diagram(nodes, server, attacker, firewall)
        self._draw_hud(server, firewall, attacker, score)
        self._draw_action_bar(defender)
        self._draw_log_panel(ids, attacker, score)
        self._draw_notifications()

        self._flip_display()
        self.clock.tick(60)

    # ------------------------------------------------------------------
    # Network Diagram
    # ------------------------------------------------------------------

    def _draw_network_diagram(self, nodes: List[NetworkNode],
                               server: NetworkNode, attacker: AttackerAI,
                               firewall: Firewall):
        """Render the main network topology view."""
        # Background panel
        net_rect = pygame.Rect(self.NET_X, self.NET_Y, self.NET_W, self.NET_H)
        draw_rounded_rect(self.screen, PANEL_BG, net_rect, 0,
                          PANEL_BORDER, 1)

        # Grid lines (subtle)
        for x in range(0, self.NET_W, 80):
            pygame.draw.line(self.screen, (20, 28, 40),
                             (x, 0), (x, self.NET_H))
        for y in range(0, self.NET_H, 80):
            pygame.draw.line(self.screen, (20, 28, 40),
                             (0, y), (self.NET_W, y))

        # Draw edges (connections to server)
        for node in nodes:
            if not node.is_server:
                self._draw_connection(node, server, firewall)

        # Draw attacker position indicator
        ax, ay = attacker.ATTACKER_POS
        if ax < self.NET_W:  # Only if in diagram area
            self._draw_attacker_icon(ax, ay, attacker)

        # Draw packets
        for pkt in attacker.packets:
            self._draw_packet(pkt)

        # Draw nodes
        for node in nodes:
            self._draw_node(node)

        # Firewall visual between boundary
        self._draw_firewall_barrier(firewall)

        # Panel title
        draw_text(self.screen, "NETWORK TOPOLOGY", 10, 8,
                  ACCENT_BLUE, 13, bold=True)
        draw_text(self.screen, f"Nodes: {len(nodes)}", 200, 8, GREY, 12)

    def _draw_connection(self, node: NetworkNode, server: NetworkNode,
                          firewall: Firewall):
        """Draw a line between a node and the server."""
        color = (30, 50, 70)
        if node.status == NodeStatus.COMPROMISED:
            color = (80, 10, 20)
        elif node.status in (NodeStatus.UNDER_ATTACK, NodeStatus.SCANNING):
            # Pulsing orange
            pulse = abs(math.sin(self._tick * 0.06))
            r = int(80 + 80 * pulse)
            color = (r, 40, 10)
        pygame.draw.line(self.screen, color,
                         node.position, server.position, 1)

    def _draw_node(self, node: NetworkNode):
        """Render a single network node with status indicators."""
        x, y = node.position
        radius = self.SERVER_RADIUS if node.is_server else self.NODE_RADIUS
        color  = STATUS_COLOR.get(node.status, COL_SECURE)

        # Pulsing glow for nodes under attack
        if node.status in (NodeStatus.UNDER_ATTACK, NodeStatus.COMPROMISED):
            pulse = abs(math.sin(self._tick * 0.08)) * 0.6
            glow_r = int(radius + 12 * pulse)
            glow_surf = pygame.Surface((glow_r*2, glow_r*2), pygame.SRCALPHA)
            glow_col  = (*color, int(60 * pulse))
            pygame.draw.circle(glow_surf, glow_col, (glow_r, glow_r), glow_r)
            self.screen.blit(glow_surf, (x - glow_r, y - glow_r))

        # Outer ring
        pygame.draw.circle(self.screen, color, (x, y), radius, 2)
        # Inner fill
        inner_col = tuple(int(c * 0.25) for c in color)
        pygame.draw.circle(self.screen, inner_col, (x, y), radius - 3)

        # Server: special icon
        if node.is_server:
            # Draw server racks icon
            for i in range(3):
                ry = y - 8 + i * 8
                pygame.draw.rect(self.screen, color,
                                 pygame.Rect(x - 10, ry - 2, 20, 5), 1)
                pygame.draw.circle(self.screen, color, (x + 7, ry), 2)
        else:
            # Draw computer icon
            pygame.draw.rect(self.screen, color,
                             pygame.Rect(x - 8, y - 7, 16, 11), 1, 2)
            pygame.draw.line(self.screen, color, (x, y + 4), (x, y + 8))
            pygame.draw.line(self.screen, color, (x - 5, y + 8), (x + 5, y + 8))

        # Health bar (small, below node)
        bar_w = radius * 2
        health_frac = node.health / 100
        hbar_color = (
            COL_SECURE if health_frac > 0.6 else
            COL_VULNERABLE if health_frac > 0.3 else
            COL_COMPROMISED
        )
        draw_progress_bar(
            self.screen,
            x - radius, y + radius + 4,
            bar_w, 4, health_frac,
            hbar_color, (20, 20, 35)
        )

        # Hostname label
        draw_text(self.screen, node.hostname,
                  x, y + radius + 12, LIGHT_GREY, 10,
                  bold=node.is_server, anchor="midtop")
        draw_text(self.screen, node.ip_address,
                  x, y + radius + 23, GREY, 9, anchor="midtop")

        # Port count badge
        open_c = len(node.open_ports)
        if open_c > 0:
            badge_col = COL_UNDER_ATTACK if open_c >= 3 else ACCENT_ORANGE
            pygame.draw.circle(self.screen, badge_col,
                               (x + radius - 4, y - radius + 4), 8)
            draw_text(self.screen, str(open_c),
                      x + radius - 4, y - radius + 4,
                      WHITE, 9, bold=True, anchor="center")

        # Selected highlight
        if self._hovered_node == node:
            pygame.draw.circle(self.screen, WHITE, (x, y), radius + 4, 1)

    def _draw_packet(self, pkt: Packet):
        """Render an animated network packet as a small glowing dot."""
        px, py = int(pkt.current_pos[0]), int(pkt.current_pos[1])
        alpha = int(200 * (1.0 - pkt.progress * 0.4))
        size = 5 if pkt.packet_type == "attack" else 4
        glow = pygame.Surface((size*4, size*4), pygame.SRCALPHA)
        glow_col = (*pkt.color, alpha // 2)
        pygame.draw.circle(glow, glow_col, (size*2, size*2), size*2)
        self.screen.blit(glow, (px - size*2, py - size*2))
        pygame.draw.circle(self.screen, pkt.color, (px, py), size)

    def _draw_attacker_icon(self, x: int, y: int, attacker: AttackerAI):
        """Render the external attacker node at the right edge."""
        pulse = abs(math.sin(self._tick * 0.05))
        col = attacker.threat_color
        # Outer glow
        glow_r = int(20 + 8 * pulse)
        glow_s = pygame.Surface((glow_r*2, glow_r*2), pygame.SRCALPHA)
        pygame.draw.circle(glow_s, (*col, 60), (glow_r, glow_r), glow_r)
        self.screen.blit(glow_s, (x - glow_r, y - glow_r))
        # Icon
        pygame.draw.circle(self.screen, col, (x, y), 22, 2)
        # Skull symbol
        pygame.draw.circle(self.screen, col, (x, y - 3), 9, 1)
        pygame.draw.circle(self.screen, col, (x - 4, y + 3), 3, 1)
        pygame.draw.circle(self.screen, col, (x + 4, y + 3), 3, 1)
        draw_text(self.screen, "ATTACKER", x, y + 28,
                  col, 10, bold=True, anchor="midtop")
        draw_text(self.screen, attacker.ip_address, x, y + 39,
                  GREY, 9, anchor="midtop")

    def _draw_firewall_barrier(self, firewall: Firewall):
        """Draw a visual firewall line near the right edge of the diagram."""
        fw_x = self.NET_W - 55
        if firewall.active:
            pulse = abs(math.sin(self._tick * 0.07))
            col = (0, int(180 + 75 * pulse), int(80 + 50 * pulse))
            for i in range(0, self.NET_H, 12):
                seg_len = 6 + int(4 * math.sin(i * 0.3 + self._tick * 0.1))
                pygame.draw.line(self.screen, col,
                                 (fw_x, i), (fw_x, i + seg_len), 2)
            draw_text(self.screen, "🔥 FIREWALL",
                      fw_x, 8, ACCENT_GREEN, 11, bold=True, anchor="midtop")
        else:
            pygame.draw.line(self.screen, (40, 50, 65),
                             (fw_x, 0), (fw_x, self.NET_H), 1)
            draw_text(self.screen, "FW OFF",
                      fw_x, 8, GREY, 10, anchor="midtop")

    # ------------------------------------------------------------------
    # HUD (top of diagram)
    # ------------------------------------------------------------------

    def _draw_hud(self, server: NetworkNode, firewall: Firewall,
                  attacker: AttackerAI, score: ScoreTracker):
        """Draw the heads-up display overlaid on the diagram."""
        # Server health bar
        bar_x, bar_y = 10, self.NET_H + 5
        draw_text(self.screen, "SERVER INTEGRITY", bar_x, bar_y,
                  COL_SERVER, 11, bold=True)
        health_frac = server.health / 100
        bar_col = (
            COL_SECURE if health_frac > 0.6 else
            COL_VULNERABLE if health_frac > 0.3 else
            COL_COMPROMISED
        )
        draw_progress_bar(self.screen, bar_x, bar_y + 14,
                          220, 12, health_frac, bar_col)
        draw_text(self.screen, f"{server.health}%",
                  bar_x + 225, bar_y + 14, LIGHT_GREY, 11)

        # Threat level
        tl_x = 320
        draw_text(self.screen, "THREAT:", tl_x, bar_y, GREY, 11)
        draw_text(self.screen, attacker.threat_level,
                  tl_x + 55, bar_y, attacker.threat_color, 12, bold=True)
        draw_text(self.screen, f"Phase: {attacker.phase_label}",
                  tl_x, bar_y + 14, GREY, 10)

        # Wave counter
        wv_x = 520
        draw_text(self.screen, f"WAVE  {attacker.wave_number}",
                  wv_x, bar_y, ACCENT_ORANGE, 12, bold=True)
        draw_text(self.screen, f"Exploits: {attacker.total_exploits}",
                  wv_x, bar_y + 14, GREY, 10)

        # Score
        sc_x = 650
        grade_col = (
            ACCENT_GREEN if score.total_score >= 500 else
            ACCENT_ORANGE if score.total_score >= 0 else
            ACCENT_RED
        )
        draw_text(self.screen, f"SCORE  {score.total_score:+d}",
                  sc_x, bar_y, grade_col, 13, bold=True)
        draw_text(self.screen, f"Grade: {score.get_grade()}",
                  sc_x, bar_y + 14, GREY, 10)

    # ------------------------------------------------------------------
    # Action Bar
    # ------------------------------------------------------------------

    def _draw_action_bar(self, defender: DefenderController):
        """Render the defender action buttons at the bottom."""
        bar_rect = pygame.Rect(self.BTN_X, self.BTN_Y, self.NET_W, self.BTN_H)
        draw_rounded_rect(self.screen, (12, 16, 26), bar_rect, 0,
                          PANEL_BORDER, 1)

        draw_text(self.screen, "DEFENDER ACTIONS", 10, self.BTN_Y + 6,
                  ACCENT_BLUE, 12, bold=True)
        draw_text(self.screen,
                  "Click or press key to activate  |  "
                  "Grey = on cooldown",
                  200, self.BTN_Y + 6, GREY, 10)

        btn_x  = 8
        btn_y  = self.BTN_Y + 24
        btn_w  = 118
        btn_h  = 110
        gap    = 10

        for key, action in defender.actions.items():
            ready = action.is_ready
            base_col = action.color if ready else (50, 55, 65)
            border_col = action.color if ready else (70, 75, 85)

            rect = pygame.Rect(btn_x, btn_y, btn_w, btn_h)
            draw_rounded_rect(self.screen, base_col, rect, 8, border_col, 1)

            # Darken fill
            dark = tuple(int(c * 0.2) for c in base_col)
            inner = pygame.Rect(btn_x + 1, btn_y + 1, btn_w - 2, btn_h - 2)
            draw_rounded_rect(self.screen, dark, inner, 7)
            pygame.draw.rect(self.screen, border_col, rect, 1, border_radius=8)

            # Key badge
            kb_rect = pygame.Rect(btn_x + 4, btn_y + 4, 20, 16)
            draw_rounded_rect(self.screen, border_col, kb_rect, 4)
            draw_text(self.screen, f"[{action.key}]",
                      btn_x + 14, btn_y + 12, WHITE, 10, bold=True,
                      anchor="center")

            # Action name
            draw_text(self.screen, action.name,
                      btn_x + btn_w // 2, btn_y + 28,
                      WHITE if ready else GREY, 11, bold=True,
                      anchor="midtop")

            # Cooldown bar
            cd_frac = action.cooldown_fraction
            cd_col  = action.color if ready else (80, 90, 100)
            draw_progress_bar(
                self.screen,
                btn_x + 4, btn_y + 48,
                btn_w - 8, 6,
                cd_frac, cd_col
            )

            if not ready:
                draw_text(self.screen,
                          f"{action.cooldown_remaining:.1f}s",
                          btn_x + btn_w // 2, btn_y + 58,
                          GREY, 9, anchor="midtop")
            else:
                draw_text(self.screen, "READY",
                          btn_x + btn_w // 2, btn_y + 58,
                          ACCENT_GREEN, 9, bold=True, anchor="midtop")

            # Description (wrapped roughly)
            desc_words = action.description.split()
            line, lines = "", []
            for w in desc_words:
                if len(line + w) > 17:
                    lines.append(line.strip())
                    line = w + " "
                else:
                    line += w + " "
            if line:
                lines.append(line.strip())
            for i, ln in enumerate(lines[:3]):
                draw_text(self.screen, ln,
                          btn_x + btn_w // 2,
                          btn_y + 70 + i * 12,
                          (140, 150, 160) if not ready else GREY, 9,
                          anchor="midtop")

            # Store rect for click detection
            action.rect = rect

            btn_x += btn_w + gap

    # ------------------------------------------------------------------
    # Log Panel
    # ------------------------------------------------------------------

    def _draw_log_panel(self, ids: IDS, attacker: AttackerAI,
                         score: ScoreTracker):
        """Render the IDS alert log and attack stats on the right panel."""
        px = self.LOG_X
        panel = pygame.Rect(px, 0, self.LOG_W, self.LOG_H)
        draw_rounded_rect(self.screen, PANEL_BG, panel, 0, PANEL_BORDER, 1)

        # Title
        draw_text(self.screen, "IDS / SECURITY LOG",
                  px + 10, 8, ACCENT_BLUE, 13, bold=True)
        pygame.draw.line(self.screen, PANEL_BORDER,
                         (px, 25), (px + self.LOG_W, 25), 1)

        # Stats strip
        sy = 30
        stats = [
            ("SCANS",    attacker.total_scans,    ACCENT_ORANGE),
            ("ATTACKS",  attacker.total_attacks,  ACCENT_RED),
            ("EXPLOITS", attacker.total_exploits, (200, 0, 200)),
            ("BLOCKED",  len(attacker.packets) and
                         attacker.total_attacks - attacker.total_exploits,
             ACCENT_GREEN),
        ]
        col_w = self.LOG_W // len(stats)
        for i, (label, val, col) in enumerate(stats):
            cx = px + i * col_w + col_w // 2
            draw_text(self.screen, str(val), cx, sy,
                      col, 16, bold=True, anchor="midtop")
            draw_text(self.screen, label, cx, sy + 18,
                      GREY, 9, anchor="midtop")

        pygame.draw.line(self.screen, PANEL_BORDER,
                         (px, sy + 32), (px + self.LOG_W, sy + 32), 1)

        # Alert log
        log_y = sy + 38
        alerts = ids.recent_alerts(24)
        for alert in reversed(alerts):
            if log_y > self.LOG_H - 180:
                break
            col = ALERT_COLORS.get(alert.severity, WHITE)

            # Severity tag
            sev_tag = f"[{alert.severity.value[:4]}]"
            draw_text(self.screen, sev_tag, px + 6, log_y,
                      col, 10, bold=True)
            draw_text(self.screen, alert.formatted_time(),
                      px + 50, log_y, GREY, 10)

            # Message (clipped to panel width)
            msg = alert.message[:45] + ("…" if len(alert.message) > 45 else "")
            draw_text(self.screen, msg, px + 6, log_y + 11,
                      LIGHT_GREY, 10)

            log_y += 24

        pygame.draw.line(self.screen, PANEL_BORDER,
                         (px, self.LOG_H - 170),
                         (px + self.LOG_W, self.LOG_H - 170), 1)

        # Score history (bottom section)
        draw_text(self.screen, "RECENT SCORE EVENTS",
                  px + 10, self.LOG_H - 165, ACCENT_BLUE, 11, bold=True)
        ey = self.LOG_H - 148
        for ev in reversed(score.recent_events(6)):
            col = ACCENT_GREEN if ev.points >= 0 else ACCENT_RED
            sign = "+" if ev.points >= 0 else ""
            draw_text(self.screen, f"{sign}{ev.points}",
                      px + 10, ey, col, 11, bold=True)
            draw_text(self.screen, ev.description[:28],
                      px + 55, ey, LIGHT_GREY, 10)
            ey += 20

        # Honeypot indicator
        draw_text(self.screen, "CONTROLS: S/C/F/P/H/L  |  Click node to select",
                  px + 10, self.LOG_H - 14, GREY, 9)

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    def push_notification(self, text: str,
                          color: Tuple = WHITE, duration: float = 2.5):
        """Add a floating notification to the queue."""
        self._notifications.append({
            "text":    text,
            "color":   color,
            "expires": time.time() + duration,
            "y_off":   0.0
        })

    def _draw_notifications(self):
        """Render active floating notification popups."""
        now = time.time()
        alive = []
        y = 80
        for n in self._notifications:
            if n["expires"] > now:
                alpha = min(255, int(255 * (n["expires"] - now) / 1.0))
                surf = Fonts.get(14, bold=True).render(n["text"], True, n["color"])
                surf.set_alpha(alpha)
                rx = (self.NET_W - surf.get_width()) // 2
                self.screen.blit(surf, (rx, y))
                y += 22
                alive.append(n)
        self._notifications = alive

    # ------------------------------------------------------------------
    # Menu Screens
    # ------------------------------------------------------------------

    def draw_main_menu(self) -> List[pygame.Rect]:
        """
        Render the main menu screen.
        Returns list of button rects: [easy, medium, hard, quit]
        """
        self.screen.fill(DARK_BG)

        # Title
        draw_text(self.screen, "HACKER vs DEFENDER",
                  self.WIDTH // 2, 80, ACCENT_BLUE, 52, bold=True,
                  anchor="midtop")
        draw_text(self.screen, "Network Security Simulation",
                  self.WIDTH // 2, 145, GREY, 18, anchor="midtop")
        draw_text(self.screen,
                  "Defend your network against an AI-driven attacker",
                  self.WIDTH // 2, 170, GREY, 14, anchor="midtop")

        # Decorative grid
        for i in range(0, self.WIDTH, 60):
            pygame.draw.line(self.screen, (18, 24, 36),
                             (i, 0), (i, self.HEIGHT))
        for i in range(0, self.HEIGHT, 60):
            pygame.draw.line(self.screen, (18, 24, 36),
                             (0, i), (self.WIDTH, i))

        # Difficulty buttons
        difficulties = [
            ("EASY",   Difficulty.EASY,   COL_SECURE,      "Slow attacks, single target"),
            ("MEDIUM", Difficulty.MEDIUM, ACCENT_ORANGE,   "Faster, dual target"),
            ("HARD",   Difficulty.HARD,   ACCENT_RED,      "Aggressive multi-vector"),
        ]

        btns = []
        bw, bh = 240, 80
        total_w = len(difficulties) * bw + (len(difficulties) - 1) * 30
        start_x = (self.WIDTH - total_w) // 2
        by = 250

        draw_text(self.screen, "SELECT DIFFICULTY",
                  self.WIDTH // 2, by - 30, LIGHT_GREY, 15,
                  bold=True, anchor="midtop")

        for i, (label, diff, col, desc) in enumerate(difficulties):
            bx = start_x + i * (bw + 30)
            rect = pygame.Rect(bx, by, bw, bh)
            dark = tuple(int(c * 0.15) for c in col)
            draw_rounded_rect(self.screen, dark, rect, 10, col, 2)
            draw_text(self.screen, label,
                      bx + bw // 2, by + 14,
                      col, 22, bold=True, anchor="midtop")
            draw_text(self.screen, desc,
                      bx + bw // 2, by + 50,
                      GREY, 11, anchor="midtop")
            btns.append(rect)

        # Objectives (Left Column)
        oy = 370
        draw_text(self.screen, "OBJECTIVES", 80, oy,
                  ACCENT_BLUE, 14, bold=True, anchor="topleft")
        objectives = [
            "◉  Detect and block AI-driven scans and exploits",
            "◉  Protect the MAIN-SERVER from being compromised",
            "◉  Use firewall, patches, and lockdowns strategically",
            "◉  Survive escalating waves to maximize your score",
        ]
        for i, obj in enumerate(objectives):
            draw_text(self.screen, obj, 80, oy + 25 + i * 20,
                      LIGHT_GREY, 12, anchor="topleft")

        # Controls (Left Column)
        cy = 485
        draw_text(self.screen, "CONTROLS", 80, cy,
                  ACCENT_BLUE, 14, bold=True, anchor="topleft")
        controls = [
            "[S] Scan Network    [C] Close Port        [F] Toggle Firewall",
            "[P] Patch Node      [H] Deploy Honeypot   [L] Emergency Lockdown",
            "Click a node to select it as the target for your next action",
        ]
        for i, ln in enumerate(controls):
            draw_text(self.screen, ln, 80, cy + 25 + i * 18,
                      GREY, 11, anchor="topleft")

        # High Scores (Right Column)
        hx = 680
        draw_text(self.screen, "BEST SCORES", hx, oy,
                  ACCENT_BLUE, 14, bold=True, anchor="topleft")
        
        from high_scores import load_high_scores
        scores = load_high_scores()
        if not scores:
            draw_text(self.screen, "No scores recorded yet.", hx, oy + 28,
                      GREY, 12, anchor="topleft")
        else:
            for idx, s in enumerate(scores):
                info = f"#{idx+1}  {s['score']:+d} ({s['difficulty']}) - {s['grade']}"
                date_str = s['date'].split()[0]
                draw_text(self.screen, info, hx, oy + 28 + idx * 22,
                          LIGHT_GREY, 12, anchor="topleft")
                draw_text(self.screen, date_str, 1020, oy + 28 + idx * 22,
                          GREY, 11, anchor="topright")

        # How to Play & Quit buttons (Bottom Center)
        by = self.HEIGHT - 55
        bh = 38
        bw = 140

        # How to Play Button (index 3)
        hpr = pygame.Rect(self.WIDTH // 2 - 150, by, bw, bh)
        draw_rounded_rect(self.screen, (15, 30, 45), hpr, 8, ACCENT_BLUE, 1)
        draw_text(self.screen, "HOW TO PLAY", self.WIDTH // 2 - 80, by + 19,
                  ACCENT_BLUE, 12, bold=True, anchor="center")
        btns.append(hpr)

        # Quit Button (index 4)
        qr = pygame.Rect(self.WIDTH // 2 + 10, by, bw, bh)
        draw_rounded_rect(self.screen, (50, 20, 20), qr, 8, ACCENT_RED, 1)
        draw_text(self.screen, "QUIT", self.WIDTH // 2 + 80, by + 19,
                  ACCENT_RED, 12, bold=True, anchor="center")
        btns.append(qr)

        self._flip_display()
        return btns

    def draw_game_over(self, won: bool, score: ScoreTracker,
                       attacker: AttackerAI) -> List[pygame.Rect]:
        """
        Render the game-over / victory screen.
        Returns [play_again_rect, quit_rect].
        """
        self.screen.fill(DARK_BG)

        if won:
            title     = "NETWORK SECURED!"
            title_col = ACCENT_GREEN
            sub       = "You successfully defended the network against the attack."
        else:
            title     = "NETWORK BREACHED!"
            title_col = ACCENT_RED
            sub       = "The attacker compromised your server. Better luck next time."

        draw_text(self.screen, title,
                  self.WIDTH // 2, 100, title_col, 48, bold=True, anchor="midtop")
        draw_text(self.screen, sub,
                  self.WIDTH // 2, 165, LIGHT_GREY, 16, anchor="midtop")

        # Stats
        stats = [
            ("Final Score",       f"{score.total_score:+d}",    ACCENT_BLUE),
            ("Grade",             score.get_grade(),             ACCENT_ORANGE),
            ("Attack Waves",      str(attacker.wave_number),     ACCENT_RED),
            ("Nodes Compromised", str(attacker.nodes_compromised), ACCENT_RED),
            ("Total Exploits",    str(attacker.total_exploits),  (200, 0, 200)),
        ]
        sw = 180
        total_sw = len(stats) * sw
        sx = (self.WIDTH - total_sw) // 2
        sy = 220

        for label, val, col in stats:
            draw_text(self.screen, val, sx + sw // 2, sy,
                      col, 28, bold=True, anchor="midtop")
            draw_text(self.screen, label, sx + sw // 2, sy + 36,
                      GREY, 11, anchor="midtop")
            sx += sw

        # Buttons
        btns = []
        for i, (label, col) in enumerate([
            ("PLAY AGAIN", ACCENT_GREEN),
            ("QUIT",       ACCENT_RED)
        ]):
            bx = self.WIDTH // 2 - 140 + i * 180
            by = 360
            rect = pygame.Rect(bx - 70, by, 140, 46)
            dark = tuple(int(c * 0.2) for c in col)
            draw_rounded_rect(self.screen, dark, rect, 10, col, 2)
            draw_text(self.screen, label, bx, by + 23,
                      col, 16, bold=True, anchor="center")
            btns.append(rect)

        # High Scores List (Game Over Screen)
        hy = 440
        draw_text(self.screen, "BEST SCORES", self.WIDTH // 2, hy,
                  ACCENT_BLUE, 14, bold=True, anchor="midtop")

        from high_scores import load_high_scores
        scores = load_high_scores()
        if not scores:
            draw_text(self.screen, "No scores recorded yet.", self.WIDTH // 2, hy + 25,
                      GREY, 12, anchor="midtop")
        else:
            for idx, s in enumerate(scores):
                info = f"#{idx+1}  {s['score']:+d} ({s['difficulty']}) - {s['grade']}"
                date_str = s['date'].split()[0]
                draw_text(self.screen, info, self.WIDTH // 2 - 180, hy + 25 + idx * 22,
                          LIGHT_GREY, 12, anchor="topleft")
                draw_text(self.screen, date_str, self.WIDTH // 2 + 180, hy + 25 + idx * 22,
                          GREY, 11, anchor="topright")

        self._flip_display()
        return btns

    def draw_how_to_play(self, page: int) -> dict:
        """
        Render the How to Play tutorial screen.
        Returns a dict of button rects: {"back": Rect, "skip": Rect, "next": Rect}
        """
        self.screen.fill(DARK_BG)

        # Decorative grid
        for i in range(0, self.WIDTH, 60):
            pygame.draw.line(self.screen, (18, 24, 36),
                             (i, 0), (i, self.HEIGHT))
        for i in range(0, self.HEIGHT, 60):
            pygame.draw.line(self.screen, (18, 24, 36),
                             (0, i), (self.WIDTH, i))

        # Centered tutorial dialog box
        box_rect = pygame.Rect(150, 80, 800, 480)
        draw_rounded_rect(self.screen, PANEL_BG, box_rect, 12, PANEL_BORDER, 2)

        # Header Title
        draw_text(self.screen, "HOW TO PLAY", self.WIDTH // 2, 40,
                  ACCENT_BLUE, 36, bold=True, anchor="midtop")

        # Subheading showing page number
        draw_text(self.screen, f"Page {page + 1} of 3", self.WIDTH // 2, 95,
                  GREY, 12, anchor="midtop")

        content_y = 135
        left_margin = 190

        if page == 0:
            # Page 1: Objectives & Enemies
            draw_text(self.screen, "1. OBJECTIVES & THREAT LANDSCAPE", left_margin, content_y,
                      ACCENT_GREEN, 18, bold=True)

            bullets = [
                ("THE MISSION", "Protect MAIN-SERVER. If health drops to 0%, you lose."),
                ("THE THREAT", "AI automatically scans, exploits, and attacks nodes."),
                ("KILL CHAIN", "Recon ➔ Scanning ➔ Exploitation ➔ Lateral Movement."),
                ("WIN CONDITION", "Survive target wave count without server compromise."),
                ("", "• EASY: 3 Waves  • MEDIUM: 5 Waves  • HARD: 7 Waves"),
            ]

            y_offset = content_y + 35
            for title, desc in bullets:
                if title:
                    draw_text(self.screen, f"■ {title}:", left_margin, y_offset, ACCENT_BLUE, 12, bold=True)
                    draw_text(self.screen, desc, left_margin + 130, y_offset, LIGHT_GREY, 12)
                    y_offset += 26
                else:
                    draw_text(self.screen, desc, left_margin + 130, y_offset, ACCENT_ORANGE, 12, bold=True)
                    y_offset += 28

        elif page == 1:
            # Page 2: Node States Legend
            draw_text(self.screen, "2. UNDERSTAND NODE STATES", left_margin, content_y,
                      ACCENT_GREEN, 18, bold=True)

            states = [
                (COL_SECURE, "SECURE", "Safe. No attacker activity detected. (Priority: Low)"),
                (COL_SCANNING, "SCANNING", "Attacker is scanning node ports. Monitor closely. (Priority: Low)"),
                (COL_VULNERABLE, "VULNERABLE", "Open ports discovered. Exploit is imminent! (Priority: Medium)"),
                (COL_UNDER_ATTACK, "UNDER ATTACK", "Active exploitation. Node taking damage! (Priority: High)"),
                (COL_COMPROMISED, "COMPROMISED", "Taken over. Serves as pivot to attack server. (Priority: Critical!)"),
                (COL_PATCHED, "PATCHED", "Vulnerabilities sealed and health restored. (Priority: Safe)"),
            ]

            y_offset = content_y + 35
            for color, label, desc in states:
                # Draw color indicator circle
                pygame.draw.circle(self.screen, color, (left_margin + 10, y_offset + 6), 7)
                # Inner glow
                dark = tuple(int(c * 0.25) for c in color)
                pygame.draw.circle(self.screen, dark, (left_margin + 10, y_offset + 6), 4)

                draw_text(self.screen, label, left_margin + 30, y_offset, color, 12, bold=True)
                draw_text(self.screen, desc, left_margin + 160, y_offset, LIGHT_GREY, 11)
                y_offset += 32

        elif page == 2:
            # Page 3: Defender Actions
            draw_text(self.screen, "3. DEPLOY COUNTERMEASURES", left_margin, content_y,
                      ACCENT_GREEN, 18, bold=True)

            actions = [
                ("S", "Scan Network", "Perform network scan to reveal attacker activities (8s CD)."),
                ("C", "Close Port", "Seal the most vulnerable open port on the selected node (5s CD)."),
                ("F", "Toggle Firewall", "Block attacker IP traffic at perimeter firewall (15s CD)."),
                ("P", "Patch Node", "Patch node: restore health and close one open port (12s CD)."),
                ("H", "Deploy Honeypot", "Deploy decoy: slow attacker scan/attack by 2.5x for 10s (25s CD)."),
                ("L", "Emergency Lockdown", "Emergency lockdown: seal all open ports across network (40s CD)."),
            ]

            y_offset = content_y + 30
            for key, name, desc in actions:
                # Draw key badge
                kb_rect = pygame.Rect(left_margin, y_offset - 2, 22, 18)
                draw_rounded_rect(self.screen, PANEL_BORDER, kb_rect, 4)
                draw_text(self.screen, key, left_margin + 11, y_offset + 7, WHITE, 10, bold=True, anchor="center")

                draw_text(self.screen, name, left_margin + 35, y_offset, ACCENT_BLUE, 12, bold=True)
                draw_text(self.screen, desc, left_margin + 175, y_offset, LIGHT_GREY, 11)
                y_offset += 30

        # Draw Bottom Buttons
        btns = {}
        by = 500
        bh = 42
        bw = 120

        # Back Button (only shown if page > 0)
        if page > 0:
            back_rect = pygame.Rect(180, by, bw, bh)
            draw_rounded_rect(self.screen, (30, 40, 50), back_rect, 8, PANEL_BORDER, 1)
            draw_text(self.screen, "BACK", 240, by + 21, WHITE, 14, bold=True, anchor="center")
            btns["back"] = back_rect

        # Skip Button
        skip_rect = pygame.Rect(490, by, bw, bh)
        draw_rounded_rect(self.screen, (50, 20, 20), skip_rect, 8, ACCENT_RED, 1)
        draw_text(self.screen, "SKIP", 550, by + 21, ACCENT_RED, 14, bold=True, anchor="center")
        btns["skip"] = skip_rect

        # Next / Done Button
        next_rect = pygame.Rect(800, by, bw, bh)
        next_label = "DONE" if page == 2 else "NEXT"
        next_col = ACCENT_GREEN if page == 2 else ACCENT_BLUE
        draw_rounded_rect(self.screen, tuple(int(c * 0.2) for c in next_col), next_rect, 8, next_col, 2)
        draw_text(self.screen, next_label, 860, by + 21, next_col, 14, bold=True, anchor="center")
        btns["next"] = next_rect

        self._flip_display()
        return btns

    # ------------------------------------------------------------------
    # Hit Testing
    # ------------------------------------------------------------------

    def get_node_at(self, pos: Tuple[int, int],
                    nodes: List[NetworkNode]) -> Optional[NetworkNode]:
        """Return the node under the mouse cursor, or None."""
        mx, my = pos
        for node in nodes:
            nx, ny = node.position
            r = self.SERVER_RADIUS if node.is_server else self.NODE_RADIUS
            if (mx - nx) ** 2 + (my - ny) ** 2 <= (r + 6) ** 2:
                return node
        return None

    def get_action_at(self, pos: Tuple[int, int],
                      defender: DefenderController) -> Optional[str]:
        """Return the action key of the button under the cursor, or None."""
        for key, action in defender.actions.items():
            rect = action.rect
            if rect and rect.collidepoint(pos):
                return key
        return None

    def set_hovered_node(self, node: Optional[NetworkNode]):
        self._hovered_node = node

    def _flip_display(self):
        """Scale the virtual screen to fit the resizable window and flip."""
        win_w, win_h = self.window.get_size()
        scaled = pygame.transform.smoothscale(self.screen, (win_w, win_h))
        self.window.blit(scaled, (0, 0))
        pygame.display.flip()

    def scale_mouse_pos(self, pos: Tuple[int, int]) -> Tuple[int, int]:
        """Scale mouse coordinates from resizable window space to 1100x700 virtual space."""
        win_w, win_h = self.window.get_size()
        if win_w <= 0 or win_h <= 0:
            return pos
        vx = int(pos[0] * self.WIDTH / win_w)
        vy = int(pos[1] * self.HEIGHT / win_h)
        return (vx, vy)
