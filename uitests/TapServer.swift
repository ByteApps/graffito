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

    func testTapServer() throws {
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
