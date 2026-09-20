// Copyright © SixtyFPS GmbH <info@slint.dev>
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0

// cSpell:ignore Eisu Endcall Hankaku Headsethook Henkan Muhenkan Numpad Pictsymbols Sysrq teriary Thumbl Thumbr Zenkaku

use super::*;
// graffito patch (2026-09-19): this file is now loaded from inside
// `android_impl` (see lib.rs) rather than directly from the crate root, so
// `javahelper` is a sibling reached via `super::`, not `crate::`.
use super::javahelper::{JavaHelper, print_jni_error};
use android_activity::input::{
    ButtonState, InputEvent, KeyAction, KeyCharacterMap, KeyMapChar, Keycode, MotionAction,
    MotionEvent,
};
use android_activity::{InputStatus, MainEvent, PollEvent};
use i_slint_core::SharedString;
use i_slint_core::api::{
    LogicalPosition, LogicalSize, PhysicalPosition, PhysicalSize, PlatformError, Window,
};
use i_slint_core::input::{
    FocusReason, InternalKeyEvent, KeyEvent, KeyEventResult, KeyEventType, TouchPhase,
};
use i_slint_core::lengths::PhysicalEdges;
use i_slint_core::platform::{
    Key, PointerEventButton, WindowAdapter, WindowEvent, WindowProperties,
};
use i_slint_core::timers::{Timer, TimerMode};
use i_slint_core::window::{InputMethodRequest, WindowInner};
use i_slint_renderer_skia::{SkiaRenderer, SkiaSharedContext};
use std::cell::Cell;
use std::collections::HashMap;
use i_slint_core::item_tree::ItemRc;
use std::rc::Rc;
use std::sync::Arc;

struct LongPressDetection {
    _timer: Timer,
    position: LogicalPosition,
}

pub struct AndroidWindowAdapter {
    app: AndroidApp,
    pub(crate) window: Window,
    pub(crate) renderer: i_slint_renderer_skia::SkiaRenderer,
    requested_graphics_api: RefCell<Option<i_slint_core::graphics::RequestedGraphicsAPI>>,
    pub(crate) event_queue: EventQueue,
    pub(crate) pending_redraw: Cell<bool>,
    pub(super) java_helper: JavaHelper,
    pub(crate) fullscreen: Cell<bool>,
    /// The offset at which the Slint view is drawn in the native window (account for status bar)
    pub offset: Cell<PhysicalPosition>,

    /// Whether the cursor handle should be shown.
    /// They are shown when taping, but hidden whenever keys are pressed
    pub(crate) show_cursor_handles: Cell<bool>,

    long_press: RefCell<Option<LongPressDetection>>,
    last_pressed_state: Cell<ButtonState>,

    // graffito patch (2026-09-19): (a) per-input-device `KeyCharacterMap`
    // cache -- `AndroidApp::device_key_character_map` is a JNI round trip
    // (it walks `InputDevice.getDevice()` + `getKeyCharacterMap()`), so
    // avoid repeating it on every keystroke from the same keyboard.
    key_char_maps: RefCell<HashMap<i32, KeyCharacterMap>>,
    // graffito patch (2026-09-19): (c) pointer-down positions for open taps
    // (not yet Up), keyed by Android pointer id -- used to tell a genuine
    // tap (small movement) from a drag, which must never dismiss focus.
    // `LogicalPoint` (not the api `LogicalPosition`) to match what
    // `touch_pos()` in `process_inputs` already produces.
    tap_down_positions: RefCell<HashMap<i32, (i_slint_core::lengths::LogicalPoint, Option<ItemRc>)>>,
}

impl WindowAdapter for AndroidWindowAdapter {
    fn window(&self) -> &Window {
        &self.window
    }
    fn size(&self) -> PhysicalSize {
        self.app.native_window().map_or_else(Default::default, |w| PhysicalSize {
            width: w.width() as u32,
            height: w.height() as u32,
        })
    }
    fn renderer(&self) -> &dyn i_slint_core::platform::Renderer {
        &self.renderer
    }

    fn request_redraw(&self) {
        self.pending_redraw.set(true);
    }

    fn update_window_properties(&self, properties: WindowProperties<'_>) {
        let f = properties.is_fullscreen();
        if self.fullscreen.replace(f) != f {
            self.resize().unwrap();
        }
    }

    fn internal(
        &self,
        _: i_slint_core::InternalToken,
    ) -> Option<&dyn i_slint_core::window::WindowAdapterInternal> {
        Some(self)
    }
}

impl i_slint_core::window::WindowAdapterInternal for AndroidWindowAdapter {
    #[cfg(feature = "native-activity")]
    fn input_method_request(&self, request: InputMethodRequest) {
        match request {
            InputMethodRequest::Enable(props) => {
                self.java_helper
                    .set_imm_data(
                        &props,
                        self.window.scale_factor(),
                        self.show_cursor_handles.get(),
                    )
                    .unwrap_or_else(|e| print_jni_error(&self.app, e));
                self.java_helper
                    .show_or_hide_soft_input(true)
                    .unwrap_or_else(|e| print_jni_error(&self.app, e));

                if let Some(focus_item) =
                    WindowInner::from_pub(&self.window).focus_item.borrow().upgrade()
                {
                    if let Some(text_input) =
                        focus_item.downcast::<i_slint_core::items::TextInput>()
                    {
                        let color = text_input.as_pin_ref().selection_background_color();
                        self.java_helper
                            .set_handle_color(color.with_alpha(1.))
                            .unwrap_or_else(|e| print_jni_error(&self.app, e));
                    }
                }
            }
            InputMethodRequest::Update(props) => {
                self.java_helper
                    .set_imm_data(
                        &props,
                        self.window.scale_factor(),
                        self.show_cursor_handles.get(),
                    )
                    .unwrap_or_else(|e| print_jni_error(&self.app, e));
            }
            InputMethodRequest::Disable => {
                self.java_helper
                    .show_or_hide_soft_input(false)
                    .unwrap_or_else(|e| print_jni_error(&self.app, e));
            }
            _ => (),
        };
    }

    #[cfg(not(feature = "native-activity"))]
    fn input_method_request(&self, request: InputMethodRequest) {
        use android_activity::input::{TextInputState, TextSpan};

        let props = match request {
            InputMethodRequest::Enable(props) => {
                self.app.show_soft_input(true);
                props
            }
            InputMethodRequest::Update(props) => props,
            InputMethodRequest::Disable => {
                self.app.hide_soft_input(true);
                return;
            }
            _ => return,
        };
        let mut text = props.text.to_string();
        if !props.preedit_text.is_empty() {
            text.insert_str(props.preedit_offset, props.preedit_text.as_str());
        }
        self.app.set_text_input_state(TextInputState {
            text,
            selection: TextSpan {
                start: props.anchor_position.unwrap_or(props.cursor_position),
                end: props.cursor_position,
            },
            compose_region: (!props.preedit_text.is_empty()).then_some(TextSpan {
                start: props.preedit_offset,
                end: props.preedit_offset + props.preedit_text.len(),
            }),
        });
    }

    fn safe_area_inset(&self) -> PhysicalEdges {
        if self.fullscreen.get() {
            Default::default()
        } else {
            self.java_helper.get_safe_area().unwrap_or_else(|e| print_jni_error(&self.app, e))
        }
    }
}

impl AndroidWindowAdapter {
    pub fn new(app: AndroidApp) -> Rc<Self> {
        let java_helper = JavaHelper::new(&app).unwrap_or_else(|e| print_jni_error(&app, e));
        Rc::<Self>::new_cyclic(|w| Self {
            app,
            window: Window::new(w.clone()),
            #[cfg(not(any(feature = "unstable-wgpu-28", feature = "unstable-wgpu-29")))]
            renderer: SkiaRenderer::default(&SkiaSharedContext::default()),
            #[cfg(all(feature = "unstable-wgpu-28", not(feature = "unstable-wgpu-29")))]
            renderer: SkiaRenderer::default_wgpu_28(&SkiaSharedContext::default()),
            #[cfg(feature = "unstable-wgpu-29")]
            renderer: SkiaRenderer::default_wgpu_29(&SkiaSharedContext::default()),
            requested_graphics_api: RefCell::new(None),
            event_queue: Default::default(),
            pending_redraw: Default::default(),
            java_helper,
            fullscreen: Cell::new(false),
            offset: Default::default(),
            show_cursor_handles: Cell::new(false),
            long_press: RefCell::default(),
            last_pressed_state: Cell::new(ButtonState(0)),
            key_char_maps: RefCell::default(),
            tap_down_positions: RefCell::default(),
        })
    }

    pub fn process_event(&self, event: &PollEvent<'_>) -> Result<ControlFlow<()>, PlatformError> {
        let queue = std::mem::take(&mut *self.event_queue.lock().unwrap());
        for e in queue {
            match e {
                Event::Quit => return Ok(ControlFlow::Break(())),
                Event::Other(o) => o(),
            }
        }
        #[cfg_attr(slint_nightly_test, allow(non_exhaustive_omitted_patterns))]
        match event {
            PollEvent::Main(MainEvent::InputAvailable) => self.process_inputs()?,
            PollEvent::Main(MainEvent::InitWindow { .. }) => {
                if let Some(w) = self.app.native_window() {
                    let size = PhysicalSize { width: w.width() as u32, height: w.height() as u32 };

                    let scale_factor =
                        self.app.config().density().map(|dpi| dpi as f32 / 160.0).unwrap_or(1.0);

                    if (scale_factor - self.window.scale_factor()).abs() > f32::EPSILON {
                        self.window
                            .try_dispatch_event(WindowEvent::ScaleFactorChanged { scale_factor })?;
                    }

                    self.renderer.set_window_handle(
                        Arc::new(w),
                        Arc::new(DummyDisplayHandle),
                        size,
                        self.requested_graphics_api.borrow().clone(),
                    )?;
                    self.resize()?;

                    // Fixes a problem for old Android versions: the soft input always prompt out on startup.
                    #[cfg(feature = "native-activity")]
                    self.java_helper
                        .show_or_hide_soft_input(false)
                        .unwrap_or_else(|e| print_jni_error(&self.app, e));
                }
            }
            PollEvent::Main(
                MainEvent::WindowResized { .. } | MainEvent::ContentRectChanged { .. },
            ) => self.resize()?,
            PollEvent::Main(MainEvent::RedrawNeeded { .. }) => {
                self.pending_redraw.set(false);
                self.do_render()?;
            }
            PollEvent::Main(MainEvent::GainedFocus) => {
                self.window.try_dispatch_event(WindowEvent::WindowActiveChanged(true))?;
            }
            PollEvent::Main(MainEvent::LostFocus) => {
                self.window.try_dispatch_event(WindowEvent::WindowActiveChanged(false))?;
            }
            PollEvent::Main(MainEvent::ConfigChanged { .. }) => {
                let scale_factor =
                    self.app.config().density().map(|dpi| dpi as f32 / 160.0).unwrap_or(1.0);

                if (scale_factor - self.window.scale_factor()).abs() > f32::EPSILON {
                    self.window
                        .try_dispatch_event(WindowEvent::ScaleFactorChanged { scale_factor })?;
                    self.window.try_dispatch_event(WindowEvent::Resized {
                        size: self.size().to_logical(scale_factor),
                    })?;
                    WindowInner::from_pub(&self.window).set_window_item_safe_area(
                        self.internal(i_slint_core::InternalToken)
                            .map(|internal| internal.safe_area_inset().to_logical(scale_factor))
                            .unwrap_or_default(),
                    );
                }
            }
            PollEvent::Main(MainEvent::Destroy) => {
                return Ok(ControlFlow::Break(()));
            }
            _ => (),
        }
        Ok(ControlFlow::Continue(()))
    }

    fn try_dispatch_key_event(&self, ev: WindowEvent) -> KeyEventResult {
        #[cfg_attr(slint_nightly_test, allow(non_exhaustive_omitted_patterns))]
        match ev {
            WindowEvent::KeyPressed { text } => WindowInner::from_pub(&self.window)
                .process_key_input(InternalKeyEvent {
                    event_type: KeyEventType::KeyPressed,
                    key_event: {
                        let mut key_event = KeyEvent::default();
                        key_event.text = text;
                        key_event
                    },
                    ..Default::default()
                }),
            WindowEvent::KeyPressRepeated { text } => WindowInner::from_pub(&self.window)
                .process_key_input(InternalKeyEvent {
                    event_type: KeyEventType::KeyPressed,
                    key_event: {
                        let mut key_event = KeyEvent::default();
                        key_event.text = text;
                        key_event.repeat = true;
                        key_event
                    },
                    ..Default::default()
                }),
            WindowEvent::KeyReleased { text } => WindowInner::from_pub(&self.window)
                .process_key_input(InternalKeyEvent {
                    key_event: {
                        let mut key_event = KeyEvent::default();
                        key_event.text = text;
                        key_event
                    },
                    event_type: KeyEventType::KeyReleased,
                    ..Default::default()
                }),
            _ => KeyEventResult::EventIgnored,
        }
    }

    /// graffito patch (2026-09-19): (a) resolve a key event's text through
    /// the device's `KeyCharacterMap` (honors Shift/AltGr/meta state) before
    /// falling back to the static `map_key_code` table. The pure fallback
    /// decision lives in `crate::keymap::key_text_from_unicode` so it stays
    /// unit-testable on the host; this method does only the android-only
    /// JNI plumbing (the cached `KeyCharacterMap` lookup + the
    /// `KeyMapChar` -> `Option<char>` normalization) around it.
    fn resolve_key_text(
        &self,
        key_event: &android_activity::input::KeyEvent,
    ) -> Option<SharedString> {
        let unicode = self
            .key_char_map(key_event.device_id())
            .and_then(|kcm| kcm.get(key_event.key_code(), key_event.meta_state()).ok())
            .and_then(|kmc| match kmc {
                KeyMapChar::Unicode(c) => Some(c),
                KeyMapChar::CombiningAccent(_) | KeyMapChar::None => None,
            });
        match crate::keymap::key_text_from_unicode(unicode) {
            Some(c) => Some(SharedString::from(c)),
            None => map_key_code(key_event.key_code()),
        }
    }

    /// graffito patch (2026-09-19): per-device-id `KeyCharacterMap` cache
    /// backing `resolve_key_text` above. `device_id == 0` (the "no physical
    /// device" synthetic id -- e.g. events synthesized by
    /// `adb shell input text`) is rejected by
    /// `AndroidApp::device_key_character_map` itself, so it's simply never
    /// cached and every call falls back to the static keycode table, same
    /// as before this patch.
    fn key_char_map(&self, device_id: i32) -> Option<KeyCharacterMap> {
        if let Some(map) = self.key_char_maps.borrow().get(&device_id) {
            return Some(map.clone());
        }
        let map = self.app.device_key_character_map(device_id).ok()?;
        self.key_char_maps.borrow_mut().insert(device_id, map.clone());
        Some(map)
    }

    /// graffito patch (2026-09-19): (c) tap-outside-dismisses-keyboard.
    /// Sal's rule: a tap anywhere that is NOT a text field blurs the
    /// focused field (so the IME hides); a tap ON a text field must keep
    /// working exactly as today. `tap` is in the same logical-window space
    /// as the pointer positions computed a few lines above in
    /// `process_inputs` (display offset + scale factor already applied).
    /// The geometry decision itself is `crate::geom::tap_outside`, kept
    /// pure and unit-tested on the host; this method does only the
    /// android/Slint-specific lookups around it (mirrors the existing
    /// `long_press_timeout` function's geometry computation below).
    fn dismiss_keyboard_if_tap_outside_focus(&self, tap: i_slint_core::lengths::LogicalPoint) {
        let runtime_window = WindowInner::from_pub(&self.window);
        if !runtime_window.text_input_focused() {
            return;
        }
        let Some(focus_item) = runtime_window.focus_item.borrow().upgrade() else { return };
        let geometry = focus_item
            .geometry()
            .translate(focus_item.map_to_window(Default::default()).to_vector());
        let rect = (
            geometry.origin.x as f32,
            geometry.origin.y as f32,
            geometry.size.width as f32,
            geometry.size.height as f32,
        );
        if crate::geom::tap_outside(rect, (tap.x as f32, tap.y as f32)) {
            // set_focus=false clears focus (sends FocusOut) rather than
            // moving it elsewhere; a later tap on the field then produces a
            // fresh FocusIn, which is what shows the IME again.
            runtime_window.set_focus_item(&focus_item, false, FocusReason::PointerClick);
        }
    }

    fn process_inputs(&self) -> Result<(), PlatformError> {
        // graffito patch (2026-09-19): (b) stale IME focus. The focused
        // `TextInput`'s item tree can be dropped (a screen switch) without a
        // `FocusOut` ever reaching it -- Slint only hides the soft keyboard
        // via `WindowInner::set_text_input_focused(false)`, which normally
        // runs from the item's own focus-out handling. Detect + correct the
        // mismatch once per pass, before handling any new input, rather than
        // per-event (`focus_item.borrow().upgrade()` is cheap, but there is
        // no reason to repeat it per event in a batch).
        {
            let runtime_window = WindowInner::from_pub(&self.window);
            if runtime_window.text_input_focused()
                && runtime_window.focus_item.borrow().upgrade().is_none()
            {
                runtime_window.set_text_input_focused(false);
            }
        }

        let mut iter =
            self.app.input_events_iter().map_err(|e| PlatformError::Other(e.to_string()))?;
        loop {
            let mut result = Ok(());
            let read_input = iter.next(|event| match event {
                // graffito patch (2026-09-19): (a) resolve the key's text
                // through the device's KeyCharacterMap (honors Shift/AltGr/
                // meta state) before falling back to the static keycode
                // table -- see `resolve_key_text` and `crate::keymap`.
                InputEvent::KeyEvent(key_event) => match self.resolve_key_text(key_event) {
                    Some(text) => match map_key_event(text, key_event) {
                        Some(ev) => {
                            if self.try_dispatch_key_event(ev) == KeyEventResult::EventAccepted {
                                InputStatus::Handled
                            } else {
                                InputStatus::Unhandled
                            }
                        }
                        None => InputStatus::Unhandled,
                    },
                    None => InputStatus::Unhandled,
                },
                InputEvent::MotionEvent(motion_event) => {
                    let offset = self.offset.get();
                    let scale = self.window.scale_factor();
                    let touch_pos = |p: &android_activity::input::Pointer<'_>| {
                        i_slint_core::lengths::logical_point_from_api(pointer_logical_position(
                            p.x(),
                            p.y(),
                            offset,
                            scale,
                        ))
                    };
                    match motion_event.action() {
                        MotionAction::ButtonPress => {
                            result = self.window.try_dispatch_event(WindowEvent::PointerPressed {
                                position: position_for_event(motion_event, offset, scale),
                                button: button_for_event(motion_event, &self.last_pressed_state),
                            });
                            InputStatus::Handled
                        }
                        MotionAction::ButtonRelease => {
                            result = self.window.try_dispatch_event(WindowEvent::PointerReleased {
                                position: position_for_event(motion_event, offset, scale),
                                button: button_for_event(motion_event, &self.last_pressed_state),
                            });
                            InputStatus::Handled
                        }
                        MotionAction::Down => {
                            let position = position_for_event(motion_event, offset, scale);

                            self.show_cursor_handles.set(true);
                            let _timer = Timer::default();
                            _timer.start(
                                TimerMode::SingleShot,
                                self.java_helper
                                    .long_press_timeout()
                                    .unwrap_or_else(|e| print_jni_error(&self.app, e)),
                                long_press_timeout,
                            );
                            self.long_press.replace(Some(LongPressDetection { position, _timer }));
                            if let Some(p) = motion_event.pointers().next() {
                                let pos = touch_pos(&p);
                                // graffito patch (2026-09-19): (c) remember
                                // this pointer's down position so Up can
                                // tell a genuine tap from a drag.
                                {
                                    // graffito patch (2026-09-19): remember which item had focus
                                    // when the finger went down, so a tap that MOVES focus (onto a
                                    // field, or onto a field's padding whose TouchArea focuses it)
                                    // is never mistaken for a tap outside the field.
                                    let focus_before = WindowInner::from_pub(&self.window).focus_item.borrow().upgrade();
                                    self.tap_down_positions.borrow_mut().insert(p.pointer_id(), (pos, focus_before));
                                }
                                WindowInner::from_pub(&self.window).process_touch_input(
                                    p.pointer_id(),
                                    pos,
                                    TouchPhase::Started,
                                );
                            }
                            InputStatus::Handled
                        }
                        MotionAction::Up => {
                            self.long_press.take();
                            if let Some(p) = motion_event.pointers().next() {
                                let pid = p.pointer_id();
                                let pos = touch_pos(&p);
                                WindowInner::from_pub(&self.window).process_touch_input(
                                    pid,
                                    pos,
                                    TouchPhase::Ended,
                                );
                                // graffito patch (2026-09-19): (c) tap
                                // outside the focused text field dismisses
                                // the keyboard. Only for a genuine TAP (down
                                // and up close together) -- a drag/swipe
                                // must never blur the field. Runs AFTER the
                                // event above was dispatched to Slint as
                                // usual (never intercepts/consumes it): if
                                // the tap landed on another focusable item,
                                // Slint has already moved focus there by
                                // this point and the outside-check below is
                                // then comparing against the NEW focus item,
                                // which is exactly the desired "tap on a
                                // text field keeps working" behavior.
                                const TAP_SLOP: f32 = 8.0;
                                if let Some((down, focus_before)) = self.tap_down_positions.borrow_mut().remove(&pid) {
                                    let dx = pos.x as f32 - down.x as f32;
                                    let dy = pos.y as f32 - down.y as f32;
                                    let focus_now = WindowInner::from_pub(&self.window).focus_item.borrow().upgrade();
                                    let focus_unchanged = match (&focus_before, &focus_now) {
                                        (Some(a), Some(b)) => a == b,
                                        (None, None) => true,
                                        _ => false,
                                    };
                                    if focus_unchanged && dx * dx + dy * dy <= TAP_SLOP * TAP_SLOP {
                                        self.dismiss_keyboard_if_tap_outside_focus(pos);
                                    }
                                }
                            }
                            InputStatus::Handled
                        }
                        MotionAction::Move => {
                            let position = position_for_event(motion_event, offset, scale);

                            let mut lp = self.long_press.borrow_mut();
                            let sq = |x| x * x;
                            if lp.as_ref().map_or(false, |lp| {
                                sq(lp.position.x - position.x) + sq(lp.position.y - position.y)
                                    > 100.
                            }) {
                                *lp = None;
                            }
                            drop(lp);

                            let runtime_window = WindowInner::from_pub(&self.window);
                            for p in motion_event.pointers() {
                                runtime_window.process_touch_input(
                                    p.pointer_id(),
                                    touch_pos(&p),
                                    TouchPhase::Moved,
                                );
                            }
                            InputStatus::Handled
                        }
                        MotionAction::PointerDown => {
                            // A second finger means no long-press.
                            self.long_press.take();
                            let idx = motion_event.pointer_index();
                            if let Some(p) = motion_event.pointers().nth(idx) {
                                WindowInner::from_pub(&self.window).process_touch_input(
                                    p.pointer_id(),
                                    touch_pos(&p),
                                    TouchPhase::Started,
                                );
                            }
                            InputStatus::Handled
                        }
                        MotionAction::PointerUp => {
                            let idx = motion_event.pointer_index();
                            if let Some(p) = motion_event.pointers().nth(idx) {
                                WindowInner::from_pub(&self.window).process_touch_input(
                                    p.pointer_id(),
                                    touch_pos(&p),
                                    TouchPhase::Ended,
                                );
                            }
                            InputStatus::Handled
                        }
                        MotionAction::HoverMove => {
                            let position = position_for_event(motion_event, offset, scale);
                            let window_event = WindowEvent::PointerMoved { position };
                            result = self.window.try_dispatch_event(window_event);
                            InputStatus::Handled
                        }
                        MotionAction::Cancel | MotionAction::Outside => {
                            self.long_press.take();
                            let runtime_window = WindowInner::from_pub(&self.window);
                            for p in motion_event.pointers() {
                                // graffito patch (2026-09-19): (c) a
                                // cancelled gesture is never a tap -- drop
                                // its down position so it can't be mistaken
                                // for one by a later, unrelated Up.
                                self.tap_down_positions.borrow_mut().remove(&p.pointer_id());
                                runtime_window.process_touch_input(
                                    p.pointer_id(),
                                    touch_pos(&p),
                                    TouchPhase::Cancelled,
                                );
                            }
                            InputStatus::Handled
                        }
                        MotionAction::Scroll => todo!(),
                        MotionAction::HoverEnter | MotionAction::HoverExit => {
                            InputStatus::Unhandled
                        }
                        _ => InputStatus::Unhandled,
                    }
                }
                InputEvent::TextEvent(state) => {
                    self.show_cursor_handles.set(false);
                    let runtime_window = WindowInner::from_pub(&self.window);
                    // remove the pre_edit
                    let event = if let Some(r) = state.compose_region {
                        let adjust =
                            |pos| if pos > r.start { pos - r.start + r.end } else { pos } as i32;
                        let mut key_event = KeyEvent::default();
                        key_event.text = i_slint_core::format!(
                            "{}{}",
                            &state.text[..r.start],
                            &state.text[r.end..]
                        );

                        InternalKeyEvent {
                            event_type: KeyEventType::UpdateComposition,
                            preedit_text: state.text[r.start..r.end].into(),
                            preedit_selection: Some(0..(r.end - r.start) as i32),
                            replacement_range: Some(i32::MIN..i32::MAX),
                            cursor_position: Some(adjust(state.selection.end)),
                            anchor_position: Some(adjust(state.selection.start)),
                            key_event,
                            ..Default::default()
                        }
                    } else {
                        let mut key_event = KeyEvent::default();
                        key_event.text = state.text.as_str().into();
                        InternalKeyEvent {
                            event_type: KeyEventType::CommitComposition,
                            replacement_range: Some(i32::MIN..i32::MAX),
                            cursor_position: Some(state.selection.end as _),
                            anchor_position: Some(state.selection.start as _),
                            key_event,
                            ..Default::default()
                        }
                    };
                    runtime_window.process_key_input(event);
                    InputStatus::Handled
                }
                _ => InputStatus::Unhandled,
            });

            result?;

            if !read_input {
                return Ok(());
            }
        }
    }

    fn resize(&self) -> Result<(), PlatformError> {
        let Some(win) = self.app.native_window() else { return Ok(()) };
        let size = PhysicalSize { width: win.width() as u32, height: win.height() as u32 };

        let scale_factor = self.window.scale_factor();
        self.window
            .try_dispatch_event(WindowEvent::Resized { size: size.to_logical(scale_factor) })?;
        WindowInner::from_pub(&self.window).set_window_item_safe_area(
            self.internal(i_slint_core::InternalToken)
                .map(|internal| internal.safe_area_inset().to_logical(scale_factor))
                .unwrap_or_default(),
        );
        self.offset.set(Default::default());
        Ok(())
    }

    pub fn do_render(&self) -> Result<(), PlatformError> {
        if let Some(win) = self.app.native_window() {
            let o = self.offset.get();
            let _ = self.renderer.render_transformed_with_post_callback(
                0.,
                (o.x as f32, o.y as f32),
                PhysicalSize { width: win.width() as _, height: win.height() as _ },
                None,
            )?;
        }
        Ok(())
    }

    pub fn set_requested_graphics_api(
        &self,
        requested_graphics_api: Option<i_slint_core::graphics::RequestedGraphicsAPI>,
    ) {
        *self.requested_graphics_api.borrow_mut() = requested_graphics_api;
    }

    pub(super) fn update_window_insets(
        &self,
        window_origin: PhysicalPosition,
        window_size: PhysicalSize,
        safe_area: PhysicalEdges,
        keyboard: PhysicalEdges,
    ) {
        let scale_factor = self.window.scale_factor();
        WindowInner::from_pub(&self.window)
            .set_window_item_safe_area(safe_area.to_logical(scale_factor));

        let window_origin = window_origin.to_logical(scale_factor);
        let window_size = window_size.to_logical(scale_factor);
        let keyboard = keyboard.to_logical(scale_factor);

        // Assume that the keyboard is only on one side.
        let rect = if keyboard.bottom > (0 as i_slint_core::Coord) {
            (
                LogicalPosition::new(
                    window_origin.x,
                    window_origin.y + window_size.height - keyboard.bottom as i_slint_core::Coord,
                ),
                LogicalSize::new(window_size.width, keyboard.bottom as _),
            )
        } else if keyboard.top > (0 as i_slint_core::Coord) {
            (
                LogicalPosition::new(window_origin.x, window_origin.y),
                LogicalSize::new(window_size.width, keyboard.top as _),
            )
        } else if keyboard.left > (0 as i_slint_core::Coord) {
            (
                LogicalPosition::new(window_origin.x, window_origin.y),
                LogicalSize::new(keyboard.left as _, window_size.height),
            )
        } else if keyboard.right > (0 as i_slint_core::Coord) {
            (
                LogicalPosition::new(
                    window_origin.x + window_size.width - keyboard.right as i_slint_core::Coord,
                    window_origin.y,
                ),
                LogicalSize::new(keyboard.right as _, window_size.height),
            )
        } else {
            Default::default()
        };

        self.window.set_virtual_keyboard(rect.0, rect.1, i_slint_core::InternalToken);
    }
}

fn long_press_timeout() {
    let Some(adaptor) = CURRENT_WINDOW.with_borrow(|x| x.upgrade()) else { return };
    let Some(current) = adaptor.long_press.take() else { return };
    if let Some(focus_item) =
        i_slint_core::window::WindowInner::from_pub(&adaptor.window).focus_item.borrow().upgrade()
    {
        if let Some(text_input) = focus_item.downcast::<i_slint_core::items::TextInput>() {
            let text_input = text_input.as_pin_ref();
            let geometry = focus_item
                .geometry()
                .translate(focus_item.map_to_window(Default::default()).to_vector());
            if !geometry.contains(i_slint_core::lengths::logical_point_from_api(current.position)) {
                return;
            };
            let (cursor, anchor) = text_input.selection_anchor_and_cursor();
            if cursor == anchor {
                let text = text_input.text();
                if text.len() > cursor && text.as_bytes()[cursor] != b'\n' {
                    let adaptor = adaptor.clone() as Rc<dyn WindowAdapter>;
                    text_input.select_word(&adaptor, &focus_item);
                }
            }
            adaptor
                .java_helper
                .show_action_menu()
                .unwrap_or_else(|e| print_jni_error(&adaptor.app, e))
        }
    };
}

/// Convert raw pointer coordinates to a LogicalPosition, applying the
/// display offset and scale factor.
fn pointer_logical_position(
    x: f32,
    y: f32,
    offset: PhysicalPosition,
    scale_factor: f32,
) -> LogicalPosition {
    PhysicalPosition::new(x as i32 - offset.x, y as i32 - offset.y).to_logical(scale_factor)
}

fn position_for_event(
    motion_event: &MotionEvent,
    offset: PhysicalPosition,
    scale: f32,
) -> LogicalPosition {
    motion_event
        .pointers()
        .next()
        .map_or_else(Default::default, |p| pointer_logical_position(p.x(), p.y(), offset, scale))
}

fn button_for_event(
    motion_event: &MotionEvent,
    last_pressed_cell: &Cell<ButtonState>,
) -> PointerEventButton {
    //
    // The motion_event API has a method called action_button() which can be used to directly
    // determine the button associated with the event. However, the disadvantage of using the
    // action_button() API is that it relies on NDK 33 or higher, which implies that the output
    // application will only run on Android 13 or higher.
    //
    // This functionally equivalent method of computing the action button relies on the
    // button_state() call from the motion event, rather than action_button(). It is a bit more
    // complex than using action_button() directly, since the previous button state must be
    // tracked and used in the calculation for computing which button was toggled. However, this
    // will run on Android 12 (and possibly lower).
    //
    // See here for further discussion:
    //
    // https://stackoverflow.com/questions/75718566/amotionevent-getbuttonstate-returns-0-for-every-button-during-mouse-button-relea
    //
    let cur_pressed_state = motion_event.button_state();
    let last_pressed_state = last_pressed_cell.get();
    #[cfg_attr(slint_nightly_test, allow(non_exhaustive_omitted_patterns))]
    let toggled = match motion_event.action() {
        MotionAction::ButtonPress => {
            last_pressed_cell.set(cur_pressed_state);
            ButtonState((last_pressed_state.0 ^ cur_pressed_state.0) & cur_pressed_state.0)
        }
        MotionAction::ButtonRelease => {
            last_pressed_cell.set(cur_pressed_state);
            ButtonState((last_pressed_state.0 ^ cur_pressed_state.0) & last_pressed_state.0)
        }
        _ => ButtonState(0),
    };

    // if multiple buttons toggled, primary takes precedence, then secondary, etc.
    if toggled.primary() {
        return PointerEventButton::Left;
    }
    if toggled.secondary() {
        return PointerEventButton::Right;
    }
    if toggled.teriary() {
        return PointerEventButton::Middle;
    }
    if toggled.back() {
        return PointerEventButton::Back;
    }
    if toggled.forward() {
        return PointerEventButton::Forward;
    }
    return PointerEventButton::Other;
}

// graffito patch (2026-09-19): (a) `text` is now resolved by the caller
// (`AndroidWindowAdapter::resolve_key_text`, via the device's
// `KeyCharacterMap`, falling back to `map_key_code`) rather than looked up
// here directly from the static table -- the Down/Up/Repeat action logic
// below is otherwise unchanged.
fn map_key_event(
    text: SharedString,
    key_event: &android_activity::input::KeyEvent,
) -> Option<WindowEvent> {
    let repeat = key_event.repeat_count() > 0;
    match key_event.action() {
        KeyAction::Down if repeat => Some(WindowEvent::KeyPressRepeated { text }),
        KeyAction::Down => Some(WindowEvent::KeyPressed { text }),
        KeyAction::Up => Some(WindowEvent::KeyReleased { text }),
        KeyAction::Multiple if repeat => Some(WindowEvent::KeyPressRepeated { text }),
        KeyAction::Multiple => Some(WindowEvent::KeyPressed { text }),
        _ => None,
    }
}

fn map_key_code(code: android_activity::input::Keycode) -> Option<SharedString> {
    match code {
        Keycode::Unknown => None,
        Keycode::SoftLeft => None,
        Keycode::SoftRight => None,
        Keycode::Home => None,
        Keycode::Back => Some(Key::Back.into()),
        Keycode::Call => None,
        Keycode::Endcall => None,
        Keycode::Keycode0 => Some("0".into()),
        Keycode::Keycode1 => Some("1".into()),
        Keycode::Keycode2 => Some("2".into()),
        Keycode::Keycode3 => Some("3".into()),
        Keycode::Keycode4 => Some("4".into()),
        Keycode::Keycode5 => Some("5".into()),
        Keycode::Keycode6 => Some("6".into()),
        Keycode::Keycode7 => Some("7".into()),
        Keycode::Keycode8 => Some("8".into()),
        Keycode::Keycode9 => Some("9".into()),
        Keycode::Star => Some("*".into()),
        Keycode::Pound => Some("#".into()),
        Keycode::DpadUp => Some(Key::UpArrow.into()),
        Keycode::DpadDown => Some(Key::DownArrow.into()),
        Keycode::DpadLeft => Some(Key::LeftArrow.into()),
        Keycode::DpadRight => Some(Key::RightArrow.into()),
        Keycode::DpadCenter => Some(Key::Return.into()),
        Keycode::VolumeUp => None,
        Keycode::VolumeDown => None,
        Keycode::Power => None,
        Keycode::Camera => None,
        Keycode::Clear => None,
        Keycode::A => Some("a".into()),
        Keycode::B => Some("b".into()),
        Keycode::C => Some("c".into()),
        Keycode::D => Some("d".into()),
        Keycode::E => Some("e".into()),
        Keycode::F => Some("f".into()),
        Keycode::G => Some("g".into()),
        Keycode::H => Some("h".into()),
        Keycode::I => Some("i".into()),
        Keycode::J => Some("j".into()),
        Keycode::K => Some("k".into()),
        Keycode::L => Some("l".into()),
        Keycode::M => Some("m".into()),
        Keycode::N => Some("n".into()),
        Keycode::O => Some("o".into()),
        Keycode::P => Some("p".into()),
        Keycode::Q => Some("q".into()),
        Keycode::R => Some("r".into()),
        Keycode::S => Some("s".into()),
        Keycode::T => Some("t".into()),
        Keycode::U => Some("u".into()),
        Keycode::V => Some("v".into()),
        Keycode::W => Some("w".into()),
        Keycode::X => Some("x".into()),
        Keycode::Y => Some("y".into()),
        Keycode::Z => Some("z".into()),
        Keycode::Comma => Some(",".into()),
        Keycode::Period => Some(".".into()),
        Keycode::AltLeft => Some(Key::Alt.into()),
        Keycode::AltRight => Some(Key::AltGr.into()),
        Keycode::ShiftLeft => Some(Key::Shift.into()),
        Keycode::ShiftRight => Some(Key::ShiftR.into()),
        Keycode::Tab => Some("\t".into()),
        Keycode::Space => Some(" ".into()),
        Keycode::Sym => None,
        Keycode::Explorer => None,
        Keycode::Envelope => None,
        Keycode::Enter => Some(Key::Return.into()),
        Keycode::Del => Some(Key::Backspace.into()),
        Keycode::Grave => Some("`".into()),
        Keycode::Minus => Some("-".into()),
        Keycode::Equals => Some("=".into()),
        Keycode::LeftBracket => Some("[".into()),
        Keycode::RightBracket => Some("]".into()),
        Keycode::Backslash => Some("\\".into()),
        Keycode::Semicolon => Some(";".into()),
        Keycode::Apostrophe => Some("'".into()),
        Keycode::Slash => Some("/".into()),
        Keycode::At => Some("@".into()),
        Keycode::Num => None,
        Keycode::Headsethook => None,
        Keycode::Focus => None,
        Keycode::Plus => Some("+".into()),
        Keycode::Menu => Some(Key::Menu.into()),
        Keycode::Notification => None,
        Keycode::Search => None,
        Keycode::MediaPlayPause => None,
        Keycode::MediaStop => None,
        Keycode::MediaNext => None,
        Keycode::MediaPrevious => None,
        Keycode::MediaRewind => None,
        Keycode::MediaFastForward => None,
        Keycode::Mute => None,
        Keycode::PageUp => Some(Key::PageUp.into()),
        Keycode::PageDown => Some(Key::PageDown.into()),
        Keycode::Pictsymbols => None,
        Keycode::SwitchCharset => None,
        Keycode::ButtonA => None,
        Keycode::ButtonB => None,
        Keycode::ButtonC => None,
        Keycode::ButtonX => None,
        Keycode::ButtonY => None,
        Keycode::ButtonZ => None,
        Keycode::ButtonL1 => None,
        Keycode::ButtonR1 => None,
        Keycode::ButtonL2 => None,
        Keycode::ButtonR2 => None,
        Keycode::ButtonThumbl => None,
        Keycode::ButtonThumbr => None,
        Keycode::ButtonStart => None,
        Keycode::ButtonSelect => None,
        Keycode::ButtonMode => None,
        Keycode::Escape => Some(Key::Escape.into()),
        Keycode::ForwardDel => Some(Key::Delete.into()),
        Keycode::CtrlLeft => Some(Key::Control.into()),
        Keycode::CtrlRight => Some(Key::ControlR.into()),
        Keycode::CapsLock => None,
        Keycode::ScrollLock => Some(Key::ScrollLock.into()),
        Keycode::MetaLeft => Some(Key::Meta.into()),
        Keycode::MetaRight => Some(Key::MetaR.into()),
        Keycode::Function => None,
        Keycode::Sysrq => Some(Key::SysReq.into()),
        Keycode::Break => None,
        Keycode::MoveHome => Some(Key::Home.into()),
        Keycode::MoveEnd => Some(Key::End.into()),
        Keycode::Insert => Some(Key::Insert.into()),
        Keycode::Forward => None,
        Keycode::MediaPlay => None,
        Keycode::MediaPause => None,
        Keycode::MediaClose => None,
        Keycode::MediaEject => None,
        Keycode::MediaRecord => None,
        Keycode::F1 => Some(Key::F1.into()),
        Keycode::F2 => Some(Key::F2.into()),
        Keycode::F3 => Some(Key::F3.into()),
        Keycode::F4 => Some(Key::F4.into()),
        Keycode::F5 => Some(Key::F5.into()),
        Keycode::F6 => Some(Key::F6.into()),
        Keycode::F7 => Some(Key::F7.into()),
        Keycode::F8 => Some(Key::F8.into()),
        Keycode::F9 => Some(Key::F9.into()),
        Keycode::F10 => Some(Key::F10.into()),
        Keycode::F11 => Some(Key::F11.into()),
        Keycode::F12 => Some(Key::F12.into()),
        Keycode::NumLock => None,
        Keycode::Numpad0 => Some("0".into()),
        Keycode::Numpad1 => Some("1".into()),
        Keycode::Numpad2 => Some("2".into()),
        Keycode::Numpad3 => Some("3".into()),
        Keycode::Numpad4 => Some("4".into()),
        Keycode::Numpad5 => Some("5".into()),
        Keycode::Numpad6 => Some("6".into()),
        Keycode::Numpad7 => Some("7".into()),
        Keycode::Numpad8 => Some("8".into()),
        Keycode::Numpad9 => Some("9".into()),
        Keycode::NumpadDivide => Some("/".into()),
        Keycode::NumpadMultiply => Some("*".into()),
        Keycode::NumpadSubtract => Some("-".into()),
        Keycode::NumpadAdd => Some("+".into()),
        Keycode::NumpadDot => Some(".".into()),
        Keycode::NumpadComma => Some(",".into()),
        Keycode::NumpadEnter => Some("\n".into()),
        Keycode::NumpadEquals => Some("=".into()),
        Keycode::NumpadLeftParen => Some("(".into()),
        Keycode::NumpadRightParen => Some(")".into()),
        Keycode::VolumeMute => None,
        Keycode::Info => None,
        Keycode::ChannelUp => None,
        Keycode::ChannelDown => None,
        Keycode::ZoomIn => None,
        Keycode::ZoomOut => None,
        Keycode::Tv => None,
        Keycode::Window => None,
        Keycode::Guide => None,
        Keycode::Dvr => None,
        Keycode::Bookmark => None,
        Keycode::Captions => None,
        Keycode::Settings => None,
        Keycode::TvPower => None,
        Keycode::TvInput => None,
        Keycode::StbPower => None,
        Keycode::StbInput => None,
        Keycode::AvrPower => None,
        Keycode::AvrInput => None,
        Keycode::ProgRed => None,
        Keycode::ProgGreen => None,
        Keycode::ProgYellow => None,
        Keycode::ProgBlue => None,
        Keycode::AppSwitch => None,
        Keycode::Button1 => None,
        Keycode::Button2 => None,
        Keycode::Button3 => None,
        Keycode::Button4 => None,
        Keycode::Button5 => None,
        Keycode::Button6 => None,
        Keycode::Button7 => None,
        Keycode::Button8 => None,
        Keycode::Button9 => None,
        Keycode::Button10 => None,
        Keycode::Button11 => None,
        Keycode::Button12 => None,
        Keycode::Button13 => None,
        Keycode::Button14 => None,
        Keycode::Button15 => None,
        Keycode::Button16 => None,
        Keycode::LanguageSwitch => None,
        Keycode::MannerMode => None,
        Keycode::Keycode3dMode => None,
        Keycode::Contacts => None,
        Keycode::Calendar => None,
        Keycode::Music => None,
        Keycode::Calculator => None,
        Keycode::ZenkakuHankaku => None,
        Keycode::Eisu => None,
        Keycode::Muhenkan => None,
        Keycode::Henkan => None,
        Keycode::KatakanaHiragana => None,
        Keycode::Yen => None,
        Keycode::Ro => None,
        Keycode::Kana => None,
        Keycode::Assist => None,
        Keycode::BrightnessDown => None,
        Keycode::BrightnessUp => None,
        Keycode::MediaAudioTrack => None,
        Keycode::Sleep => None,
        Keycode::Wakeup => None,
        Keycode::Pairing => None,
        Keycode::MediaTopMenu => None,
        Keycode::Keycode11 => None,
        Keycode::Keycode12 => None,
        Keycode::LastChannel => None,
        Keycode::TvDataService => None,
        Keycode::VoiceAssist => None,
        Keycode::TvRadioService => None,
        Keycode::TvTeletext => None,
        Keycode::TvNumberEntry => None,
        Keycode::TvTerrestrialAnalog => None,
        Keycode::TvTerrestrialDigital => None,
        Keycode::TvSatellite => None,
        Keycode::TvSatelliteBs => None,
        Keycode::TvSatelliteCs => None,
        Keycode::TvSatelliteService => None,
        Keycode::TvNetwork => None,
        Keycode::TvAntennaCable => None,
        Keycode::TvInputHdmi1 => None,
        Keycode::TvInputHdmi2 => None,
        Keycode::TvInputHdmi3 => None,
        Keycode::TvInputHdmi4 => None,
        Keycode::TvInputComposite1 => None,
        Keycode::TvInputComposite2 => None,
        Keycode::TvInputComponent1 => None,
        Keycode::TvInputComponent2 => None,
        Keycode::TvInputVga1 => None,
        Keycode::TvAudioDescription => None,
        Keycode::TvAudioDescriptionMixUp => None,
        Keycode::TvAudioDescriptionMixDown => None,
        Keycode::TvZoomMode => None,
        Keycode::TvContentsMenu => None,
        Keycode::TvMediaContextMenu => None,
        Keycode::TvTimerProgramming => None,
        Keycode::Help => None,
        Keycode::NavigatePrevious => None,
        Keycode::NavigateNext => None,
        Keycode::NavigateIn => None,
        Keycode::NavigateOut => None,
        Keycode::StemPrimary => None,
        Keycode::Stem1 => None,
        Keycode::Stem2 => None,
        Keycode::Stem3 => None,
        Keycode::DpadUpLeft => None,
        Keycode::DpadDownLeft => None,
        Keycode::DpadUpRight => None,
        Keycode::DpadDownRight => None,
        Keycode::MediaSkipForward => None,
        Keycode::MediaSkipBackward => None,
        Keycode::MediaStepForward => None,
        Keycode::MediaStepBackward => None,
        Keycode::SoftSleep => None,
        Keycode::Cut => None,
        Keycode::Copy => None,
        Keycode::Paste => None,
        Keycode::SystemNavigationUp => None,
        Keycode::SystemNavigationDown => None,
        Keycode::SystemNavigationLeft => None,
        Keycode::SystemNavigationRight => None,
        Keycode::AllApps => None,
        Keycode::Refresh => None,
        Keycode::ThumbsUp => None,
        Keycode::ThumbsDown => None,
        Keycode::ProfileSwitch => None,
        _ => None,
    }
}

/// A dummy display handle that's Send + Sync. Required by wgpu, but harmless as
/// raw_window_handel::AndroidDisplayHandle is an empty struct.
struct DummyDisplayHandle;
impl raw_window_handle::HasDisplayHandle for DummyDisplayHandle {
    fn display_handle(
        &self,
    ) -> Result<raw_window_handle::DisplayHandle<'_>, raw_window_handle::HandleError> {
        Ok(raw_window_handle::DisplayHandle::android())
    }
}
