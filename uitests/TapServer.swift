// TapServer.swift
//
// A "tap server": a long-lived XCUITest that runs ON the device, polls a
// Mac-side HTTP server (ui-automation/ios-tap-server.py) for one queued
// command at a time, executes it against the running `graffito` app, and
// posts the result back. This is the only route to driving a physical,
// wirelessly-connected iPhone: idb needs the legacy AMDevice/USB path and
// cannot see CoreDevice-managed iOS 17+ devices, and `devicectl` (install /
// process launch / terminate) has no UI-interaction verb of its own.
//
// Slint renders the whole app to a single Metal surface, so the
// accessibility tree is EMPTY — element-based XCUIElement queries
// (`app.buttons["..."]`, `app.otherElements[...]`, etc.) find nothing and
// hang until their default timeout. Every interaction below is therefore
// COORDINATE-based, via `XCUICoordinate`. Do not "simplify" this back to
// element queries.
//
// Wire protocol (all bodies JSON unless noted):
//   GET  <base>/next               -> 204 (nothing queued) or 200 + one
//                                      command object, e.g.
//                                      {"op":"tap","x":120,"y":480}
//   POST <base>/result             <- {"op":"<op>","ok":true|false,
//                                       "error":"..." (only when !ok)}
//   POST <base>/screenshot         <- raw PNG bytes (Content-Type: image/png)
//
// Commands (coordinates are iOS POINTS, matching the harness's existing
// coordinate tables):
//   {"op":"tap","x":N,"y":N}
//   {"op":"swipe","x":N,"y":N,"dx":N,"dy":N,"duration":F}
//   {"op":"type","text":"..."}          types into whatever has focus
//   {"op":"pasteboard","text":"..."}    sets UIPasteboard.general.string
//   {"op":"screenshot"}                 captures + POSTs PNG to /screenshot
//   {"op":"quit"}                       ends the loop and the test cleanly
//
// `{"op":"pasteboard"}` is load-bearing, not a convenience: the harness
// must inject a ~1200-2200 byte ML-KEM armor containing literal
// `-----BEGIN ...-----` markers, and typing it is known-broken — the iOS
// keyboard's smart-dashes feature rewrites a run of 5 hyphens into two
// em-dashes plus a hyphen, and the app's parser hard-requires those
// markers verbatim. Setting UIPasteboard from the test process bypasses
// the on-screen keyboard entirely, so never replace this with a `type`.

import XCTest
import UIKit

final class TapServer: XCTestCase {

    /// Overall wall-clock deadline for the whole command loop, so a lost
    /// or unreachable Mac never wedges a test run forever. Overridable via
    /// `TEST_RUNNER_TAPSERVER_DEADLINE_MINUTES`; generous default because a
    /// real e2e suite can run long.
    private static let defaultDeadlineMinutes: Double = 60

    /// How long to sleep between empty (204) polls of /next.
    private static let pollInterval: TimeInterval = 0.25

    /// Named in refusal messages so a reader knows WHICH app had to be
    /// frontmost for the input to be allowed.
    private let XD_BUNDLE_DESC = "the app under test"

    func testTapServer() throws {
        // WITHOUT THIS, ONE BAD TAP ENDS THE RUN. A tap resolves the app's
        // coordinate space, so XCUITest snapshots the app first, and that
        // fails transiently with "Failed to get matching snapshot: Error
        // getting main window" when something is briefly over the app — an
        // incoming NOTIFICATION BANNER does exactly it. XCTest's default is
        // to stop the test at the first failure, so the runner exits and
        // every later leg then times out against a server nobody is polling.
        // That cost a cross-device run 15 minutes in on 2026-09-12.
        //
        // Note a wrapper around the tap CANNOT catch this: coordinate.tap()
        // records an XCTest failure rather than throwing, so a `for attempt
        // in 1...3` retry around it is dead code. Continuing past the
        // failure is the only lever, and the command loop then reports the
        // op as done and carries on — the leg's own `cb:` assertion is what
        // catches a tap that truly did not land.
        // UNBUFFER STDOUT. Swift block-buffers stdout when it is a pipe rather
        // than a TTY, and xcodebuild captures it through a pipe — so the
        // runner's own trace of what it is doing sits in a buffer instead of
        // reaching the log. That cost hours: the log showed a healthy
        // "attached ... entering command loop" (flushed early) and then ZERO
        // "executing" lines, while the server's access log proved 18 commands
        // had been handed out. The runner looked inert and was not.
        setvbuf(stdout, nil, _IONBF, 0)

        continueAfterFailure = true

        let env = ProcessInfo.processInfo.environment

        // xcodebuild forwards variables prefixed TEST_RUNNER_ from the host
        // environment into the on-device test runner process. Accept BOTH
        // spellings: depending on the Xcode version the runner sees the
        // variable still prefixed, or with TEST_RUNNER_ stripped. Reading
        // only one name makes a mismatch look like a network fault (every
        // poll fails against the sentinel host) rather than a config one,
        // which is an expensive thing to debug over a wireless device.
        // Fall back to a sentinel that is obviously wrong rather than to
        // something that might silently "work" against the wrong host.
        let baseURLString = env["TEST_RUNNER_TAPSERVER_URL"]
            ?? env["TAPSERVER_URL"]
            ?? "http://tapserver-url-not-set.invalid:0"
        guard let baseURL = URL(string: baseURLString) else {
            XCTFail("TapServer: TAPSERVER_URL is not a valid URL: \(baseURLString)")
            return
        }
        print("TapServer: base URL = \(baseURL.absoluteString)")

        let deadlineMinutes = (env["TEST_RUNNER_TAPSERVER_DEADLINE_MINUTES"]
            ?? env["TAPSERVER_DEADLINE_MINUTES"])
            .flatMap(Double.init) ?? Self.defaultDeadlineMinutes
        let deadline = Date().addingTimeInterval(deadlineMinutes * 60)
        print("TapServer: deadline = \(deadlineMinutes) minutes from now")

        let nextURL = baseURL.appendingPathComponent("next")
        let resultURL = baseURL.appendingPathComponent("result")
        let screenshotURL = baseURL.appendingPathComponent("screenshot")

        // launch() vs activate(): this decides whether the app's `cb:` log
        // lines are reachable AT ALL, so it is not a style choice.
        //
        // launch() always starts a FRESH process, and an app started by
        // XCUITest has nowhere to send stdout — the harness gets a driveable
        // UI and NO log, while every assertion in the cross-device suite is
        // `dev_logha ios "cb: ..."`. The physical-device equivalent of the
        // simulator's `simctl launch --console` is
        // `devicectl device process launch --console`, which streams stdout
        // for the life of the process — but only for the process IT started.
        //
        // So for a real run the harness starts the app under devicectl (that
        // console stream is the log channel), then runs this test with
        // TAPSERVER_ATTACH=1, and activate() simply brings that ALREADY
        // RUNNING process to the front instead of replacing it. Both channels
        // then point at one process: devicectl for output, this server for
        // input. Without it the two race, and the log side silently loses.
        let env2 = ProcessInfo.processInfo.environment
        let attach = (env2["TEST_RUNNER_TAPSERVER_ATTACH"] ?? env2["TAPSERVER_ATTACH"] ?? "") == "1"
        let app = XCUIApplication()
        if attach {
            app.activate()
            print("TapServer: attached to the running app (activate), entering command loop")
        } else {
            app.launch()
            print("TapServer: app launched (fresh process, NO console stream), entering command loop")
        }

        var running = true
        while running {
            if Date() > deadline {
                print("TapServer: overall deadline of \(deadlineMinutes) minutes reached; ending loop")
                XCTFail("TapServer: overall deadline reached without a quit command")
                break
            }

            guard let (status, data) = synchronousRequest(get: nextURL) else {
                print("TapServer: GET /next failed (network error); retrying in \(Self.pollInterval)s")
                Thread.sleep(forTimeInterval: 1.0)
                continue
            }

            if status == 204 {
                Thread.sleep(forTimeInterval: Self.pollInterval)
                continue
            }

            guard status == 200, let data = data else {
                print("TapServer: GET /next returned unexpected status \(status)")
                Thread.sleep(forTimeInterval: 1.0)
                continue
            }

            guard
                let json = try? JSONSerialization.jsonObject(with: data),
                let command = json as? [String: Any],
                let op = command["op"] as? String
            else {
                print("TapServer: could not parse command JSON: \(String(data: data, encoding: .utf8) ?? "<binary>")")
                continue
            }

            // REFUSE TO TOUCH ANYTHING UNLESS GRAFFITO IS FRONTMOST.
            //
            // A notification banner can switch apps mid-run, and a harness
            // driving blind COORDINATES then types and taps into whatever
            // came forward. On 2026-09-13 that put this automation into the
            // user's BANKING app, and he stopped the run himself. A test
            // harness must not be able to do that, and "keep notifications
            // off" is a precaution, not a guarantee.
            //
            // So every input op is gated on the app under test actually being
            // in the foreground. A refusal is reported as a normal command
            // failure, which the harness surfaces and retries — cheap, and
            // it fails safe rather than tapping somewhere unknown.
            let inputOps: Set<String> = ["tap", "swipe", "type", "pasteboard"]
            if inputOps.contains(op) && app.state != .runningForeground {
                print("TapServer: REFUSING op=\(op) — \(XD_BUNDLE_DESC) is not frontmost (state=\(app.state.rawValue)); something else is on screen")
                // Bring our app back, so the run can recover instead of
                // needing a human. NOTE THE LIMIT HONESTLY: this cannot stop
                // the FIRST tap, because when a banner is on screen the app
                // under test is still frontmost and the tap lands on the
                // banner. What it does stop is everything AFTER — the rest of
                // a leg's taps and typed text going into whatever the banner
                // opened. That is the difference between one stray tap and a
                // whole compose sequence entered into someone's bank.
                // ONLY re-activate an app that is actually RUNNING. activate()
                // on a .notRunning app LAUNCHES it — and an app launched by
                // XCUITest is not the process `devicectl ... --console` is
                // attached to, so the `cb:` log channel the whole suite
                // asserts on would silently go dead while everything looked
                // fine. The harness owns launching (dev_launch, under
                // devicectl); this guard must never take that over.
                var recovered = false
                if app.state == .runningBackground || app.state == .runningBackgroundSuspended {
                    app.activate()
                    Thread.sleep(forTimeInterval: 1.5)
                    recovered = app.state == .runningForeground
                    print("TapServer: re-activated \(XD_BUNDLE_DESC); frontmost now = \(recovered)")
                } else {
                    print("TapServer: \(XD_BUNDLE_DESC) is NOT RUNNING (state=\(app.state.rawValue)) — not launching it from here, because an XCUITest-launched process loses the devicectl console stream the suite reads. The harness must relaunch it.")
                }
                postResult(to: resultURL, op: op, ok: false,
                           error: "app under test was not frontmost (state \(app.state.rawValue)) — refused to send input somewhere unknown; re-activated=\(recovered)")
                continue
            }

            print("TapServer: executing op=\(op) command=\(command)")
            var ok = true
            var errorMessage: String?

            switch op {
            case "tap":
                let x = doubleValue(command["x"])
                let y = doubleValue(command["y"])
                tap(in: app, x: x, y: y)

            case "swipe":
                let x = doubleValue(command["x"])
                let y = doubleValue(command["y"])
                let dx = doubleValue(command["dx"])
                let dy = doubleValue(command["dy"])
                let duration = doubleValue(command["duration"], default: 0.3)
                swipe(in: app, x: x, y: y, dx: dx, dy: dy, duration: duration)

            case "type":
                let text = command["text"] as? String ?? ""
                app.typeText(text)

            case "pasteboard":
                let text = command["text"] as? String ?? ""
                UIPasteboard.general.string = text

            case "screenshot":
                let shot = app.screenshot()
                if !postScreenshot(to: screenshotURL, pngData: shot.pngRepresentation) {
                    ok = false
                    errorMessage = "screenshot POST failed"
                    print("TapServer: error: \(errorMessage!)")
                }

            case "quit":
                postResult(to: resultURL, op: op, ok: true, error: nil)
                print("TapServer: quit command received; ending loop")
                running = false
                continue

            default:
                ok = false
                errorMessage = "unknown op \(op)"
                print("TapServer: error: \(errorMessage!)")
            }

            postResult(to: resultURL, op: op, ok: ok, error: errorMessage)
        }

        print("TapServer: command loop ended")
    }

    // MARK: - Command execution
    //
    // Coordinate-based only — see the file-level comment on why element
    // queries are unusable against this app.

    // A tap resolves the app's coordinate space, which makes XCUITest take a
    // snapshot of the app first — and that can fail transiently with
    // "Failed to get matching snapshot: Error getting main window" when
    // something is momentarily over the app. An incoming NOTIFICATION BANNER
    // does exactly this, and on 2026-09-12 one killed a cross-device run 15
    // minutes in: the whole XCTest fails, the runner exits, and every later
    // leg then times out against a dead tap server.
    //
    // Retry rather than die. Bringing the app back to the front between
    // attempts clears the common causes (a banner that has since gone, the
    // app briefly not frontmost). Silencing notifications on the device is
    // still worth doing for a long run; this just stops one banner from
    // costing the run.
    private func tap(in app: XCUIApplication, x: Double, y: Double) {
        let coordinate = app
            .coordinate(withNormalizedOffset: CGVector(dx: 0, dy: 0))
            .withOffset(CGVector(dx: x, dy: y))
        coordinate.tap()
    }

    private func swipe(in app: XCUIApplication, x: Double, y: Double, dx: Double, dy: Double, duration: TimeInterval) {
        let origin = app.coordinate(withNormalizedOffset: CGVector(dx: 0, dy: 0))
        let start = origin.withOffset(CGVector(dx: x, dy: y))
        let end = origin.withOffset(CGVector(dx: x + dx, dy: y + dy))
        start.press(forDuration: duration, thenDragTo: end)
    }

    private func doubleValue(_ any: Any?, default def: Double = 0) -> Double {
        if let d = any as? Double { return d }
        if let i = any as? Int { return Double(i) }
        if let n = any as? NSNumber { return n.doubleValue }
        return def
    }

    // MARK: - HTTP
    //
    // This test method runs on its own thread (not the main thread), so
    // blocking it on a semaphore while URLSession's delegate queue
    // completes is safe and keeps the command loop's control flow simple.

    private func synchronousRequest(get url: URL, timeout: TimeInterval = 10) -> (Int, Data?)? {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = timeout
        return synchronousRequest(request)
    }

    private func postResult(to url: URL, op: String, ok: Bool, error: String?) {
        var payload: [String: Any] = ["op": op, "ok": ok]
        if let error = error {
            payload["error"] = error
        }
        guard let body = try? JSONSerialization.data(withJSONObject: payload) else {
            print("TapServer: failed to serialize result payload \(payload)")
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 10
        if synchronousRequest(request) == nil {
            print("TapServer: POST /result failed (network error) for op=\(op)")
        }
    }

    /// Returns true on a successful (2xx-ish, i.e. non-nil) response.
    private func postScreenshot(to url: URL, pngData: Data) -> Bool {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = pngData
        request.setValue("image/png", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 30
        return synchronousRequest(request) != nil
    }

    private func synchronousRequest(_ request: URLRequest) -> (Int, Data?)? {
        let semaphore = DispatchSemaphore(value: 0)
        var result: (Int, Data?)?
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("TapServer: request error for \(request.url?.absoluteString ?? "?"): \(error)")
            } else if let http = response as? HTTPURLResponse {
                result = (http.statusCode, data)
            } else {
                print("TapServer: no HTTPURLResponse for \(request.url?.absoluteString ?? "?")")
            }
            semaphore.signal()
        }
        task.resume()
        _ = semaphore.wait(timeout: .now() + request.timeoutInterval + 5)
        return result
    }
}
