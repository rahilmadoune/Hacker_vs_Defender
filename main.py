import sys
import time
import pygame

from network import build_network
from attacker_ai import AttackerAI, Difficulty
from defender_actions import DefenderController, ScoreTracker
from ui import GameUI, ACCENT_GREEN, ACCENT_RED, ACCENT_ORANGE


# ---------------------------------------------------------------------------
# Game State
# ---------------------------------------------------------------------------

class GameState:
    MENU      = "menu"
    PLAYING   = "playing"
    GAME_OVER = "game_over"
    HOW_TO_PLAY = "how_to_play"


# ---------------------------------------------------------------------------
# Key → Action Mapping
# ---------------------------------------------------------------------------

KEY_ACTION_MAP = {
    pygame.K_s: "scan",
    pygame.K_c: "close_port",
    pygame.K_f: "firewall",
    pygame.K_p: "patch",
    pygame.K_h: "honeypot",
    pygame.K_l: "lockdown",
}


# ---------------------------------------------------------------------------
# Main Game Class
# ---------------------------------------------------------------------------

class HackerVsDefender:
    """
    Top-level game controller.

    Manages the game state machine and orchestrates all subsystems:
    network simulation, AI attacker, defender actions, and UI rendering.
    """

    def __init__(self):
        self.ui           = GameUI()
        
        # Check first-run tutorial trigger
        from high_scores import load_tutorial_flag
        if not load_tutorial_flag():
            self.state = GameState.HOW_TO_PLAY
        else:
            self.state = GameState.MENU
            
        self._tutorial_page = 0
        self.difficulty   = Difficulty.MEDIUM
 
        # Will be initialised on game start
        self.network      = None
        self.attacker     = None
        self.defender     = None
        self.score        = None
 
        # Game result
        self.won          = False
 
        # Menu button rects (stored for click handling)
        self._menu_btns   = []
        self._over_btns   = []
        self._tutorial_btns = {}

    # ------------------------------------------------------------------
    # Game Lifecycle
    # ------------------------------------------------------------------

    def start_game(self, difficulty: Difficulty):
        """Initialise a fresh game with the selected difficulty."""
        self.difficulty = difficulty

        # Build network
        self.network = build_network()
        nodes    = self.network["nodes"]
        server   = self.network["server"]
        firewall = self.network["firewall"]
        ids      = self.network["ids"]

        # Create score tracker
        self.score = ScoreTracker()

        # Create defender controller
        self.defender = DefenderController(nodes, firewall, ids, self.score)

        # Create and start AI attacker
        self.attacker = AttackerAI(difficulty=difficulty)
        self.attacker.start()

        self.state = GameState.PLAYING
        self.won   = False

        self.ui.push_notification(
            f"Game started — {difficulty.value.upper()} difficulty",
            ACCENT_ORANGE, 3.0
        )

    def end_game(self, won: bool):
        """End the game, saving the score."""
        self.won = won
        target_waves = self._get_target_waves()
        if won:
            self.score.add("game_won", f"Survived all {target_waves} waves! Victory!")
        else:
            self.score.add("server_compromised", "Server compromised — GAME OVER")
        self.state = GameState.GAME_OVER

        # Save score
        from high_scores import save_high_score
        save_high_score(
            score=self.score.total_score,
            difficulty=self.difficulty.value.upper(),
            grade=self.score.get_grade()
        )

    def _get_target_waves(self) -> int:
        """Get wave limit for current difficulty."""
        return {
            Difficulty.EASY: 3,
            Difficulty.MEDIUM: 5,
            Difficulty.HARD: 7
        }.get(self.difficulty, 5)

    def reset(self):
        """Return to the main menu."""
        self.state = GameState.MENU

    # ------------------------------------------------------------------
    # Main Loop
    # ------------------------------------------------------------------

    def run(self):
        """Main application loop."""
        running = True

        while running:
            # --- Event Processing ---
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False

                elif event.type == pygame.KEYDOWN:
                    running = self._handle_key(event.key)

                elif event.type == pygame.MOUSEMOTION:
                    logical_pos = self.ui.scale_mouse_pos(event.pos)
                    self._handle_mouse_motion(logical_pos)

                elif event.type == pygame.MOUSEBUTTONDOWN:
                    if event.button == 1:
                        logical_pos = self.ui.scale_mouse_pos(event.pos)
                        running = self._handle_click(logical_pos)

            # --- State Dispatch ---
            if self.state == GameState.MENU:
                self._menu_btns = self.ui.draw_main_menu()

            elif self.state == GameState.PLAYING:
                self._update_game()
                self._render_game()

            elif self.state == GameState.GAME_OVER:
                self._over_btns = self.ui.draw_game_over(
                    self.won, self.score, self.attacker
                )

            elif self.state == GameState.HOW_TO_PLAY:
                self._tutorial_btns = self.ui.draw_how_to_play(self._tutorial_page)

        pygame.quit()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Game Update
    # ------------------------------------------------------------------

    def _update_game(self):
        """Run one simulation tick."""
        nodes    = self.network["nodes"]
        firewall = self.network["firewall"]
        ids      = self.network["ids"]

        # Run attacker AI tick with honeypot slowdown
        slowdown = self.defender.honeypot_slowdown
        new_alerts = self.attacker.update(nodes, firewall, ids, speed_multiplier=slowdown)

        # Push critical alerts as on-screen notifications
        from network import AlertSeverity
        for alert in new_alerts:
            if alert.severity == AlertSeverity.CRITICAL:
                self.ui.push_notification(
                    alert.message[:60], ACCENT_RED, 3.0
                )

        # Score deductions for server damage
        server = self.network["server"]
        if server.health < 100:
            # Track last health to detect new damage
            prev = getattr(self, "_last_server_health", 100)
            if server.health < prev:
                damage = prev - server.health
                self.score.add("server_damaged",
                               f"Server took {damage} damage!")
            self._last_server_health = server.health

        # Score deductions for newly compromised nodes
        for node in nodes:
            if node.is_compromised and not node.score_tracked:
                self.score.add("node_compromised",
                               f"{node.hostname} compromised!")
                node.score_tracked = True

        # Wave survival bonus
        prev_wave = getattr(self, "_last_wave", 1)
        if self.attacker.wave_number > prev_wave:
            self.score.add("wave_survived",
                           f"Survived attack wave {prev_wave}!")
            self._last_wave = self.attacker.wave_number
            self.ui.push_notification(
                f"Wave {prev_wave} survived! +100 pts", ACCENT_GREEN, 2.5
            )

        # --- Win / Loss Check ---
        target_waves = self._get_target_waves()

        if self.attacker.phase.value == "succeeded" or \
                self.defender.check_loss_condition():
            self.end_game(won=False)
        elif self.defender.check_win_condition(self.attacker.wave_number, target_waves):
            self.end_game(won=True)

    def _render_game(self):
        """Render the current game frame."""
        self.ui.render(
            nodes    = self.network["nodes"],
            server   = self.network["server"],
            firewall = self.network["firewall"],
            ids      = self.network["ids"],
            attacker = self.attacker,
            defender = self.defender,
            score    = self.score,
        )

    # ------------------------------------------------------------------
    # Input Handlers
    # ------------------------------------------------------------------

    def _handle_key(self, key: int) -> bool:
        """Handle keyboard input. Returns False if app should quit."""
        if key == pygame.K_ESCAPE:
            if self.state == GameState.PLAYING:
                self.reset()
            elif self.state == GameState.HOW_TO_PLAY:
                self._exit_tutorial()
            else:
                return False

        elif self.state == GameState.PLAYING:
            action_key = KEY_ACTION_MAP.get(key)
            if action_key:
                self._execute_action(action_key)

        elif self.state == GameState.HOW_TO_PLAY:
            if key in (pygame.K_RIGHT, pygame.K_SPACE, pygame.K_RETURN):
                if self._tutorial_page < 2:
                    self._tutorial_page += 1
                else:
                    self._exit_tutorial()
            elif key == pygame.K_LEFT:
                if self._tutorial_page > 0:
                    self._tutorial_page -= 1

        return True

    def _handle_mouse_motion(self, pos):
        """Update node hover state."""
        if self.state == GameState.PLAYING:
            node = self.ui.get_node_at(pos, self.network["nodes"])
            self.ui.set_hovered_node(node)

    def _handle_click(self, pos) -> bool:
        """Handle mouse click. Returns False if app should quit."""
        if self.state == GameState.MENU:
            return self._handle_menu_click(pos)

        elif self.state == GameState.PLAYING:
            self._handle_game_click(pos)

        elif self.state == GameState.GAME_OVER:
            return self._handle_over_click(pos)

        elif self.state == GameState.HOW_TO_PLAY:
            self._handle_tutorial_click(pos)

        return True

    def _handle_menu_click(self, pos) -> bool:
        """Process main menu button clicks."""
        if not self._menu_btns:
            return True

        diff_map = [Difficulty.EASY, Difficulty.MEDIUM, Difficulty.HARD]
        for i, rect in enumerate(self._menu_btns):
            if rect.collidepoint(pos):
                if i < len(diff_map):
                    self.start_game(diff_map[i])
                elif i == 3:  # How to Play
                    self.state = GameState.HOW_TO_PLAY
                    self._tutorial_page = 0
                elif i == 4:  # Quit
                    return False
        return True

    def _handle_tutorial_click(self, pos):
        """Process tutorial screen clicks (Next, Back, Skip)."""
        if not hasattr(self, "_tutorial_btns") or not self._tutorial_btns:
            return

        # Check Back
        back_rect = self._tutorial_btns.get("back")
        if back_rect and back_rect.collidepoint(pos) and self._tutorial_page > 0:
            self._tutorial_page -= 1

        # Check Skip
        skip_rect = self._tutorial_btns.get("skip")
        if skip_rect and skip_rect.collidepoint(pos):
            self._exit_tutorial()

        # Check Next
        next_rect = self._tutorial_btns.get("next")
        if next_rect and next_rect.collidepoint(pos):
            if self._tutorial_page < 2:
                self._tutorial_page += 1
            else:
                self._exit_tutorial()

    def _exit_tutorial(self):
        """Exit the tutorial screen, setting the has_seen flag."""
        from high_scores import save_tutorial_flag
        save_tutorial_flag(True)
        self.state = GameState.MENU

    def _handle_game_click(self, pos):
        """Process in-game click: node selection or action button."""
        nodes  = self.network["nodes"]
        node   = self.ui.get_node_at(pos, nodes)

        if node:
            # Select this node as the defender's target
            self.defender.selected_node = node
            self.ui.push_notification(
                f"Selected: {node.hostname} ({node.ip_address})",
                (100, 200, 255), 1.5
            )
        else:
            # Check action bar clicks
            action_key = self.ui.get_action_at(pos, self.defender)
            if action_key:
                self._execute_action(action_key)

    def _handle_over_click(self, pos) -> bool:
        """Process game-over screen button clicks."""
        if not self._over_btns:
            return True
        labels = ["play_again", "quit"]
        for i, rect in enumerate(self._over_btns):
            if rect.collidepoint(pos):
                if labels[i] == "play_again":
                    self.start_game(self.difficulty)
                else:
                    return False
        return True

    # ------------------------------------------------------------------
    # Action Dispatch
    # ------------------------------------------------------------------

    def _execute_action(self, action_key: str):
        """
        Execute a defender action by key string.
        Routes to the correct DefenderController method and shows feedback.
        """
        defender = self.defender
        action   = defender.actions.get(action_key)

        if not action:
            return

        if not action.is_ready:
            self.ui.push_notification(
                f"{action.name} — cooldown {action.cooldown_remaining:.1f}s",
                (150, 150, 150), 1.0
            )
            return

        # Dispatch
        result = None
        if action_key == "scan":
            result = defender.scan_network()
        elif action_key == "close_port":
            result = defender.close_port()
        elif action_key == "firewall":
            result = defender.toggle_firewall()
        elif action_key == "patch":
            result = defender.patch_node()
        elif action_key == "honeypot":
            result = defender.deploy_honeypot()
        elif action_key == "lockdown":
            result = defender.emergency_lockdown()

        if result:
            self.ui.push_notification(
                result.message[:55], ACCENT_GREEN, 2.0
            )
        else:
            self.ui.push_notification(
                f"{action.name}: No valid target found.",
                (150, 120, 60), 1.5
            )


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    game = HackerVsDefender()
    game.run()
