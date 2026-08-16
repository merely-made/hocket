//! Hocket's genet desktop host (genet-host refactor).
//!
//! A winit window presenting the Hocket view tree: `GenetAppRunner` diffs
//! the views into a `ScriptedDom`, a retained `IncrementalLayout` lays it
//! out, the paint list lowers to a `netrender::Scene`, and
//! `genet-winit-host`'s `SurfaceHost` rasterizes and composites. The view
//! layer + theme live in [`view`] / [`theme`]; [`state`] holds the real
//! `hocket_model::Session` + `History` the views derive from (S2).

mod identity;
mod leaves;
mod project_io;
mod scenario;
mod state;
mod theme;
mod update;
mod view;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use accesskit::{Action, NodeId as AccessNodeId, Tree, TreeId, TreeUpdate};
use armillary::{ActorHandle, Wake};
use layout_dom_api::{DomMutation, LayoutDom as _, LayoutDomMut as _};
use netrender::{ColorLoad, ExternalTexturePlacement, NetrenderOptions};
use paint_list_api::{DeviceIntSize, PaintList as _};
use genet_layout::{IncrementalLayout, ScrollOffsets};
use genet_scripted_dom::{NodeId, ScriptedDom};
use genet_winit_host::{AccessKitBridge, BridgeStatus, SurfaceHost};
use winit::application::ApplicationHandler;
use winit::event::{ElementState, MouseButton, StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::{Window, WindowId};
use cambium::{GenetAppRunner, PointerClick, Propagation};

use identity::LocalIdentity;
use project_io::{ProjectCommand, ProjectUpdate, spawn_project_worker};
use state::AppState;
use view::{Child, root};

type Runner = GenetAppRunner<AppState, fn(&AppState) -> Child, Child>;

/// Engine tick cadence (~60 fps). Firewheel wants `update()` roughly per frame;
/// this drives `engine.tick()` (meter read-back, capture promotion, playback).
const TICK: Duration = Duration::from_millis(16);

#[derive(Clone, Copy)]
enum HostEvent {
    ProjectUpdate,
}

struct App {
    window: Option<Arc<Window>>,
    host: Option<SurfaceHost>,
    runner: Option<Runner>,
    /// Retained layout session (logical coords), hit-test target.
    layout: Option<IncrementalLayout<NodeId>>,
    layout_size: (f32, f32),
    sheet: String,
    /// Cursor in logical coordinates.
    cursor: (f32, f32),
    /// Host-owned chisel leaves (waveforms + meters), keyed by leaf key, plus
    /// their rendered Path-A command cache. Reconciled from `AppState` each
    /// frame; the retention gate keeps an unchanged leaf from repainting.
    leaves: sprigging::LeafRegistry<u64>,
    waveform_cache: leaves::WaveformCache,
    rendered: sprigging::RenderedLeaves,
    /// OS accessibility bridge: the same laid-out DOM the frame renders is
    /// projected to an AccessKit tree and pushed here, so a screen reader reads
    /// Hocket's controls. `None` until the window exists.
    a11y: Option<AccessKitBridge>,
    /// Maps an actionable node's AccessKit id back to its DOM node, so a screen
    /// reader's `Click` routes to the same `dispatch_click` path a mouse takes.
    /// Rebuilt each frame the tree changes.
    a11y_route: HashMap<AccessNodeId, NodeId>,
    project_worker: Option<ActorHandle<ProjectCommand>>,
    project_updates: Receiver<ProjectUpdate>,
    /// The update actor, handed to `AppState` at window creation so the
    /// status chip can act, and the honest statuses it reports.
    update_worker: Option<ActorHandle<update::worker::UpdateCommand>>,
    update_statuses: Receiver<update::UpdateStatus>,
    /// The self-drive scenario (activated by `HOCKET_SCENARIO`), pumped one step
    /// per timer tick. `None` for a normal interactive launch. Taken out of
    /// `self` during a tick, so capture-dir state lives separately below.
    scenario: Option<scenario::Run>,
    /// Where captures and the receipt land. Held apart from `scenario` so
    /// `Driveable::capture` can resolve a path while the scenario is taken out.
    capture_dir: Option<PathBuf>,
    /// A capture the next rendered frame fulfills, set by `Driveable::capture`.
    pending_capture: Option<PathBuf>,
}

impl App {
    fn drain_project_updates(&mut self) {
        let mut updated = false;
        while let Ok(update) = self.project_updates.try_recv() {
            if let Some(runner) = self.runner.as_mut() {
                runner.update(|state| state.apply_project_update(update));
                updated = true;
            }
        }
        while let Ok(status) = self.update_statuses.try_recv() {
            if let Some(runner) = self.runner.as_mut() {
                runner.update(|state| state.apply_update_status(status));
                updated = true;
            }
        }
        if updated {
            if let Some(window) = self.window.as_ref() {
                window.request_redraw();
            }
        }
    }

    /// Apply any screen-reader actions the OS queued since the last frame, routing
    /// a `Click` to the same `dispatch_click` path a mouse press takes. The route
    /// map is from the previous frame's tree, which is what the OS acted against.
    fn pump_a11y_actions(&mut self) {
        let requests = match self.a11y.as_mut() {
            Some(bridge) => bridge.drain_actions(),
            None => return,
        };
        if requests.is_empty() {
            return;
        }
        let Some(runner) = self.runner.as_mut() else {
            return;
        };
        let mut acted = false;
        for req in requests {
            if req.action == Action::Click {
                if let Some(&node) = self.a11y_route.get(&req.target_node) {
                    runner.dispatch_click(
                        node,
                        PointerClick {
                            local: (0.0, 0.0),
                            prop: Propagation::new(),
                        },
                    );
                    acted = true;
                }
            }
        }
        if acted {
            if let Some(window) = self.window.as_ref() {
                window.request_redraw();
            }
        }
    }

    fn redraw(&mut self) {
        self.pump_a11y_actions();
        let (Some(window), Some(host), Some(runner)) = (
            self.window.as_ref(),
            self.host.as_ref(),
            self.runner.as_ref(),
        ) else {
            return;
        };
        let size = window.inner_size();
        let (pw, ph) = (size.width.max(1), size.height.max(1));
        let scale = window.scale_factor() as f32;
        let (lw, lh) = (pw as f32 / scale, ph as f32 / scale);

        let scene = {
            let dom = runner.dom();
            let mut muts: Vec<DomMutation<NodeId>> = Vec::new();
            dom.borrow_mut().drain_mutations(&mut muts);
            let dom_ref = dom.borrow();
            let sheets: Vec<&str> = vec![self.sheet.as_str()];
            let structural = muts
                .iter()
                .any(|m| !matches!(m, DomMutation::AttributeChanged { .. }));
            let size_changed = self.layout_size != (lw, lh);
            match self.layout.as_mut() {
                Some(layout) if !structural && !size_changed => {
                    if !muts.is_empty() {
                        let _ = layout.apply(&*dom_ref, &sheets, &muts);
                    }
                }
                _ => {
                    self.layout = Some(IncrementalLayout::new(&*dom_ref, &sheets, lw, lh));
                    self.layout_size = (lw, lh);
                }
            }
            let layout = self.layout.as_ref().expect("layout just ensured");

            // Chisel leaves: reconcile from the session, size each leaf from the
            // laid-out `<chisel-leaf>` boxes, render the dirty ones, and splice
            // their Path-A commands at their boxes.
            leaves::reconcile(&mut self.leaves, &mut self.waveform_cache, runner.state());
            let boxes = layout.custom_leaf_boxes();
            let size_map: std::collections::HashMap<u64, sprigging::Size> = boxes
                .iter()
                .map(|(k, (w, h))| {
                    (
                        *k,
                        sprigging::Size {
                            width: *w,
                            height: *h,
                        },
                    )
                })
                .collect();
            self.leaves
                .render_into(|k| size_map.get(&k).copied(), &mut self.rendered);
            self.rendered.retain_keys(|k| size_map.contains_key(&k));

            let source = leaves::LeafSource(&self.rendered);
            let list = layout.emit_paint_list_with_leaves(
                &*dom_ref,
                &ScrollOffsets::default(),
                DeviceIntSize::new(lw as i32, lh as i32),
                &source,
            );
            let translated = paint_list_render::translate_paint_cmd_stream(
                list.viewport(),
                list.commands(),
                list.fonts(),
                list.images(),
            );

            // Accessibility: project the same laid-out DOM this frame rendered into
            // an AccessKit tree and push it to the OS bridge, rebuilding only when
            // the DOM or size changed (or the adapter isn't installed yet). Hocket
            // is a single genet surface, so it skips nothing and salts nothing —
            // the engine's opaque ids are the AccessKit ids. `build_subtree` hands
            // back the actionable nodes; we remember them so a screen reader's
            // request routes back to the view's click path.
            if let Some(bridge) = self.a11y.as_mut() {
                let needs_tree = structural
                    || size_changed
                    || !muts.is_empty()
                    || bridge.status() == BridgeStatus::Unavailable;
                if needs_tree {
                    // `_with_leaves`: the output meters are `<chisel-leaf>`s, whose
                    // interiors are invisible to the DOM. The source lets each leaf
                    // announce itself (a meter reports its level) instead of
                    // projecting as an opaque, unlabeled box.
                    let (nodes, root_id, actionable) = genet_layout::build_subtree_with_leaves(
                        &*dom_ref,
                        layout.fragments(),
                        dom_ref.document(),
                        &|d: &ScriptedDom, n: NodeId| AccessNodeId(d.opaque_id(n)),
                        &|_d: &ScriptedDom, _n: NodeId| false,
                        &mut leaves::LeafA11y(&mut self.leaves),
                    );
                    self.a11y_route = actionable
                        .iter()
                        .map(|&n| (AccessNodeId(dom_ref.opaque_id(n)), n))
                        .collect();
                    let tree = TreeUpdate {
                        nodes,
                        tree: Some(Tree::new(root_id)),
                        tree_id: TreeId::ROOT,
                        focus: root_id,
                    };
                    match bridge.status() {
                        BridgeStatus::Installed => bridge.update(tree),
                        // Best-effort: a platform with no adapter just goes without.
                        BridgeStatus::Unavailable => {
                            let _ = bridge.install(window, tree);
                        }
                    }
                }
            }

            translated.scene
        };

        let (_tex, view) = host.core().rasterize_scaled(
            &scene,
            pw,
            ph,
            ColorLoad::Clear(wgpu::Color::BLACK),
            scale,
        );
        let Some(frame) = host.acquire() else { return };
        let target = frame
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());
        host.renderer().compose_external_texture(
            &view,
            &target,
            host.format(),
            pw,
            ph,
            ExternalTexturePlacement::new([0.0, 0.0, pw as f32, ph as f32]),
        );
        // wgpu 30 moved presentation from SurfaceTexture to Queue.
        host.queue().present(frame);

        // Scenario self-capture: the receipt is the frame just presented, read
        // back from the same rasterized scene (not a re-render).
        if let Some(path) = self.pending_capture.take() {
            scenario::capture_frame(host, &view, pw, ph, &path);
        }
    }

    fn click(&mut self) {
        let (Some(runner), Some(layout)) = (self.runner.as_mut(), self.layout.as_ref()) else {
            return;
        };
        let (x, y) = self.cursor;
        let hit = {
            let dom = runner.dom();
            let dom_ref = dom.borrow();
            layout.hit_test(&*dom_ref, x, y, &ScrollOffsets::default())
        };
        let Some(node) = hit else { return };
        runner.dispatch_click(
            node,
            PointerClick {
                local: (0.0, 0.0),
                prop: Propagation::new(),
            },
        );
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
    }
}

/// Drive Hocket through genet-probe's shared harness: implementing this small
/// surface grants the scenario loop its `click` / `assert text` / `assert snap`
/// verbs over Hocket's one cambium surface. `with_surfaces` hands the retained
/// DOM to a visitor (the borrow guard lives only for the callback, since the DOM
/// is behind `RefCell`); a synthetic press routes through the same
/// `hit_test` + `dispatch_click` path a mouse takes.
impl genet_probe::Automatable for App {
    fn with_surfaces<R>(&self, f: impl FnOnce(&[genet_probe::ProbeSurface<'_>]) -> R) -> R {
        let Some(runner) = self.runner.as_ref() else {
            return f(&[]);
        };
        let dom = runner.dom();
        let dom_ref = dom.borrow();
        let (w, h) = self.layout_size;
        let surfaces = [genet_probe::ProbeSurface {
            name: "hocket",
            dom: &dom_ref,
            rect: [0.0, 0.0, w, h],
            sheet: &self.sheet,
        }];
        f(&surfaces)
    }

    fn snapshot(&self) -> genet_probe::ProbeSnapshot {
        let status = self
            .runner
            .as_ref()
            .map(|runner| runner.state().project_status_label())
            .unwrap_or_default();
        genet_probe::ProbeSnapshot::default().with_field("status", status)
    }

    fn drain_events(&mut self) -> Vec<String> {
        Vec::new()
    }

    fn act(&mut self, _label: &str) -> bool {
        false
    }

    fn press(&mut self, x: f32, y: f32) {
        self.cursor = (x, y);
        self.click();
    }

    fn moved(&mut self, x: f32, y: f32) {
        self.cursor = (x, y);
    }

    fn release(&mut self, _x: f32, _y: f32) {}
}

impl genet_probe::Driveable for App {
    fn capture(&mut self, name: &str) -> bool {
        let Some(dir) = self.capture_dir.as_ref() else {
            return false;
        };
        self.pending_capture = Some(dir.join(format!("{name}.png")));
        if let Some(window) = self.window.as_ref() {
            window.request_redraw();
        }
        true
    }
}

impl ApplicationHandler<HostEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let window = Arc::new(
            event_loop
                .create_window(
                    Window::default_attributes()
                        .with_title("Hocket")
                        // Top-anchored + short enough to clear the taskbar on a
                        // 720-logical laptop screen.
                        .with_position(winit::dpi::LogicalPosition::new(40.0, 8.0))
                        .with_inner_size(winit::dpi::LogicalSize::new(1180.0, 700.0))
                        .with_visible(false),
                )
                .expect("create window"),
        );
        // Keep the native window hidden while the initial AccessKit tree and
        // its native adapter are installed below.
        let wake_window = window.clone();
        let mut a11y = AccessKitBridge::new(move || wake_window.request_redraw());
        let size = window.inner_size();
        let host = SurfaceHost::boot(
            window.clone(),
            size.width.max(1),
            size.height.max(1),
            NetrenderOptions {
                tile_cache_size: Some(1024),
                enable_vello: true,
                ..Default::default()
            },
        )
        .expect("boot genet host");
        let dom = Rc::new(RefCell::new(ScriptedDom::new()));
        let worker = self
            .project_worker
            .take()
            .expect("project worker initialized");
        let update_worker = self
            .update_worker
            .take()
            .expect("update worker initialized");
        let identity = LocalIdentity::open_default().map_err(|error| error.to_string());
        let update_settings = update::UpdateSettingsProvider::load_or_default(
            update::settings_path(),
        )
        .settings();
        let runner = Runner::new(
            dom,
            root as fn(&AppState) -> Child,
            AppState::new(worker, update_worker, update_settings, identity),
        );

        // Bootstrap the adapter from the real initial view before Windows sees
        // the native window. Hidden windows do not reliably receive redraws, so
        // deferring installation to the first frame creates a startup cycle.
        leaves::reconcile(&mut self.leaves, &mut self.waveform_cache, runner.state());
        let scale = window.scale_factor() as f32;
        let (lw, lh) = (size.width as f32 / scale, size.height as f32 / scale);
        let (layout, tree, actionable) = {
            let dom = runner.dom();
            let dom_ref = dom.borrow();
            let sheets = [self.sheet.as_str()];
            let layout = IncrementalLayout::new(&*dom_ref, &sheets, lw, lh);
            let (nodes, root_id, actionable) = genet_layout::build_subtree_with_leaves(
                &*dom_ref,
                layout.fragments(),
                dom_ref.document(),
                &|d: &ScriptedDom, n: NodeId| AccessNodeId(d.opaque_id(n)),
                &|_d: &ScriptedDom, _n: NodeId| false,
                &mut leaves::LeafA11y(&mut self.leaves),
            );
            let tree = TreeUpdate {
                nodes,
                tree: Some(Tree::new(root_id)),
                tree_id: TreeId::ROOT,
                focus: root_id,
            };
            (layout, tree, actionable)
        };
        self.a11y_route = {
            let dom = runner.dom();
            let dom_ref = dom.borrow();
            actionable
                .into_iter()
                .map(|node| (AccessNodeId(dom_ref.opaque_id(node)), node))
                .collect()
        };
        a11y.install(&window, tree)
            .expect("install initial accessibility tree");
        self.layout = Some(layout);
        self.layout_size = (lw, lh);
        self.a11y = Some(a11y);
        self.window = Some(window);
        self.host = Some(host);
        self.runner = Some(runner);
        self.window
            .as_ref()
            .expect("window just installed")
            .set_visible(true);
        // Kick off the engine-tick timer.
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + TICK));
    }

    fn new_events(&mut self, event_loop: &ActiveEventLoop, cause: StartCause) {
        // ~60fps engine tick: advance the audio engine (meter, capture
        // promotion, playback) and repaint. `update` mutates the owned state
        // and re-diffs the view, so a completed capture's new layer appears.
        if matches!(cause, StartCause::ResumeTimeReached { .. }) {
            self.drain_project_updates();
            if let Some(runner) = self.runner.as_mut() {
                runner.update(|s| s.tick());
            }
            if let Some(window) = self.window.as_ref() {
                window.request_redraw();
            }
            // Self-drive: advance one scenario step per tick, after the frame the
            // previous tick requested. On completion, write the receipt and exit.
            if let Some(mut run) = self.scenario.take() {
                match run.scenario.tick(self) {
                    genet_probe::Progress::Done => {
                        scenario::write_done(&run.dir, &run.scenario.finish());
                        event_loop.exit();
                        return;
                    }
                    genet_probe::Progress::Running => self.scenario = Some(run),
                }
            }
            event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + TICK));
        }
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, event: HostEvent) {
        match event {
            HostEvent::ProjectUpdate => self.drain_project_updates(),
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::Resized(size) => {
                if let Some(host) = self.host.as_mut() {
                    host.resize(size.width.max(1), size.height.max(1));
                }
                if let Some(window) = self.window.as_ref() {
                    window.request_redraw();
                }
            }
            WindowEvent::CursorMoved { position, .. } => {
                let scale = self.window.as_ref().map_or(1.0, |w| w.scale_factor());
                self.cursor = ((position.x / scale) as f32, (position.y / scale) as f32);
            }
            WindowEvent::MouseInput {
                state: ElementState::Pressed,
                button: MouseButton::Left,
                ..
            } => self.click(),
            WindowEvent::RedrawRequested => self.redraw(),
            _ => {}
        }
    }
}

/// The update transport this run uses.
///
/// Luggage (the family's Rust-native pipeline) is the default;
/// `HOCKET_UPDATE_TRANSPORT=velopack` keeps the A/B alternative selectable
/// until one of them retires.
fn build_transport() -> Box<dyn update::UpdateTransport> {
    match std::env::var("HOCKET_UPDATE_TRANSPORT").as_deref() {
        Ok("velopack") => Box::new(update::velopack_transport::VelopackTransport::new()),
        _ => Box::new(update::luggage_transport::LuggageTransport::new()),
    }
}

fn main() {
    // FIRST, before anything else: Velopack hooks install/update/uninstall
    // lifecycle events here and may restart or exit the process. Opening a
    // window or an audio device ahead of it would leak both.
    velopack::VelopackApp::build().run();

    // `--update-now` runs the update flow in the terminal and exits, so an
    // update cycle can be proven (and scripted) without clicking through a
    // GUI. Same policy the app uses.
    if std::env::args().any(|arg| arg == "--update-now") {
        let settings = update::UpdateSettingsProvider::load_or_default(update::settings_path())
            .settings();
        let code = update::cli::run_update_now(build_transport(), settings);
        std::process::exit(code);
    }

    let event_loop = EventLoop::<HostEvent>::with_user_event()
        .build()
        .expect("event loop");
    event_loop.set_control_flow(ControlFlow::Wait);
    let proxy = event_loop.create_proxy();
    let wake: Wake = Arc::new(move || {
        let _ = proxy.send_event(HostEvent::ProjectUpdate);
    });
    let (project_worker, project_updates) = spawn_project_worker(wake.clone());

    // The updater is I/O, so it lives off the UI thread like project work.
    let (update_worker, update_statuses) =
        update::worker::spawn_update_worker(wake, build_transport());
    let update_settings = update::UpdateSettingsProvider::load_or_default(update::settings_path())
        .settings();
    if update_settings.policy.checks() {
        update_worker.command(update::worker::UpdateCommand::Check {
            settings: update_settings,
            user_asked: false,
        });
    }
    let scenario_run = scenario::load();
    let capture_dir = scenario_run.as_ref().map(|run| run.dir.clone());
    let mut app = App {
        window: None,
        host: None,
        runner: None,
        layout: None,
        layout_size: (0.0, 0.0),
        sheet: theme::sheet(),
        cursor: (0.0, 0.0),
        leaves: sprigging::LeafRegistry::new(),
        waveform_cache: leaves::WaveformCache::new(),
        rendered: sprigging::RenderedLeaves::new(),
        a11y: None,
        a11y_route: HashMap::new(),
        project_worker: Some(project_worker),
        project_updates,
        update_worker: Some(update_worker),
        update_statuses,
        scenario: scenario_run,
        capture_dir,
        pending_capture: None,
    };
    event_loop.run_app(&mut app).expect("run app");
}
