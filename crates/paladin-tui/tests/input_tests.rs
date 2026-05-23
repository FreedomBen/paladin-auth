// SPDX-License-Identifier: AGPL-3.0-or-later

//! Input thread tests for `paladin-tui`.
//!
//! Tracks `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//! *"Input thread — `crossterm::event::read()` in a loop, maps to
//! `AppEvent::Input(KeyEvent | ResizeEvent | …)`."* The producer is a
//! long-lived thread; the reducer drives it off by dropping the
//! receiver. These tests pin the event-to-`AppEvent` mapping, the
//! `at` sampling order (after the blocking read returns), and the
//! two shutdown paths — receiver hangup and `read()` `Err`.
//!
//! `crossterm::event::read()` requires a real terminal, so production
//! callers invoke [`paladin_tui::app::input::spawn`] which threads the
//! real reader in. The tests drive
//! [`paladin_tui::app::input::spawn_with`] with a fake reader fed off
//! an in-process `mpsc` so the loop can be exercised without a TTY.
//!
//! The fake reader's `recv` is itself a blocking call. The tests put
//! a `Mutex<Receiver<_>>` behind the closure so the fake reader can be
//! cloned into the spawned thread and the test driver controls when
//! the next event flows in — that's the seam that lets us prove the
//! loop terminates *before* the next read.

use std::io;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

use paladin_tui::app::event::AppEvent;
use paladin_tui::app::input;

/// Generous slack for scheduler jitter on busy CI hosts.
const RECV_SLACK: Duration = Duration::from_secs(2);

/// Build a fake reader closure backed by an `mpsc` channel.
///
/// Returns the closure plus a `Sender` the test driver uses to push
/// fake results in. Each `recv` on the channel blocks until a result
/// is delivered or the sender is dropped (the latter surfaces as
/// `io::ErrorKind::BrokenPipe`, simulating a closed terminal).
fn fake_reader() -> (
    impl FnMut() -> io::Result<Event> + Send + 'static,
    mpsc::Sender<io::Result<Event>>,
) {
    let (tx, rx) = mpsc::channel::<io::Result<Event>>();
    let rx = Arc::new(Mutex::new(rx));
    let reader = move || -> io::Result<Event> {
        match rx.lock().expect("fake-reader receiver poisoned").recv() {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fake reader: driver dropped sender",
            )),
        }
    };
    (reader, tx)
}

fn key_event(code: KeyCode) -> Event {
    Event::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    })
}

fn unwrap_input(evt: AppEvent) -> (Event, Instant) {
    match evt {
        AppEvent::Input { event, at } => (event, at),
        other => panic!("expected AppEvent::Input, got {other:?}"),
    }
}

/// Watchdog `join`: hand the handle to a helper thread that signals
/// on a bounded channel so the test cannot hang the suite if the
/// input thread never notices the shutdown signal.
fn watchdog_join(handle: std::thread::JoinHandle<()>) -> Receiver<()> {
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = handle.join();
        let _ = done_tx.send(());
    });
    done_rx
}

// ---------------------------------------------------------------------------
// Input thread (docs/IMPLEMENTATION_PLAN_03_TUI.md > Event loop > Input thread)
// ---------------------------------------------------------------------------

#[test]
fn spawn_with_emits_app_event_input_for_each_crossterm_event() {
    // Each value the reader returns must arrive on the channel as an
    // `AppEvent::Input` (not `Tick` / `EffectResult` / `ClipboardClear`)
    // carrying the byte-identical `crossterm::event::Event` and an
    // `at` instant sampled *after* the read returned. Pin the
    // ordering by reading the test's pre-spawn `Instant::now()` as
    // a floor: every `at` from the loop must be `>=` that floor, and
    // the second `at` must strictly advance past the first because
    // `Instant::now()` is monotonically non-decreasing and the two
    // reads are separated by the channel-send hand-off.
    let (reader, tx) = fake_reader();
    let (event_tx, event_rx) = mpsc::channel();

    let pre_spawn = Instant::now();
    let _handle = input::spawn_with(event_tx, reader);

    let evt_a = key_event(KeyCode::Char('a'));
    let evt_b = Event::Resize(80, 24);
    tx.send(Ok(evt_a.clone()))
        .expect("driver hands first event to fake reader");
    tx.send(Ok(evt_b.clone()))
        .expect("driver hands second event to fake reader");

    let first = event_rx
        .recv_timeout(RECV_SLACK)
        .expect("input loop emits first AppEvent::Input within slack");
    let second = event_rx
        .recv_timeout(RECV_SLACK)
        .expect("input loop emits second AppEvent::Input within slack");

    let (event1, at1) = unwrap_input(first);
    let (event2, at2) = unwrap_input(second);

    assert_eq!(event1, evt_a, "first event must round-trip byte-identical");
    assert_eq!(event2, evt_b, "second event must round-trip byte-identical");
    assert!(
        at1 >= pre_spawn,
        "at1 ({at1:?}) must be >= pre-spawn floor ({pre_spawn:?})",
    );
    assert!(
        at2 > at1,
        "at2 ({at2:?}) must strictly advance past at1 ({at1:?}) — sampling order is read → now → send",
    );
}

#[test]
fn spawn_with_thread_exits_when_receiver_is_dropped() {
    // The reducer brings the input thread down by dropping the
    // receiver (channel hangup); the next `Sender::send` fails and
    // the loop returns. Mirror the ticker's shutdown contract so the
    // production event loop can rely on a single shutdown idiom
    // across producers.
    let (reader, tx) = fake_reader();
    let (event_tx, event_rx) = mpsc::channel();
    let handle = input::spawn_with(event_tx, reader);

    // Drive one event through so the thread is observably running.
    tx.send(Ok(key_event(KeyCode::Char('q'))))
        .expect("driver hands first event to fake reader");
    let _ = event_rx
        .recv_timeout(RECV_SLACK)
        .expect("input loop emits first event before we drop the receiver");

    // Drop the receiver, then unblock the reader by sending one more
    // event. The loop reads it, calls `Sender::send`, observes the
    // hangup error, and returns.
    drop(event_rx);
    tx.send(Ok(key_event(KeyCode::Char('Q'))))
        .expect("driver unblocks the reader for one final read");

    let done_rx = watchdog_join(handle);
    done_rx
        .recv_timeout(RECV_SLACK)
        .expect("input thread terminates after Sender::send observes receiver hangup");
}

#[test]
fn spawn_with_thread_exits_when_read_returns_error() {
    // The other shutdown path: a closed terminal surfaces as
    // `crossterm::event::read()` returning `Err`. The input loop
    // treats that as terminal disconnect and exits cleanly without
    // panicking. Drive it with an explicit `io::ErrorKind::BrokenPipe`
    // so a regression that ever swallows the error and keeps looping
    // (busy-spinning on a dead terminal) surfaces as a `recv_timeout`.
    let (reader, tx) = fake_reader();
    let (event_tx, event_rx) = mpsc::channel::<AppEvent>();
    let handle = input::spawn_with(event_tx, reader);

    tx.send(Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "test: terminal disconnected",
    )))
    .expect("driver hands a read-error to the fake reader");

    let done_rx = watchdog_join(handle);
    done_rx
        .recv_timeout(RECV_SLACK)
        .expect("input thread terminates after read() returns Err");

    // Ensure no spurious `AppEvent::Input` was sent before the exit
    // by polling the channel briefly. The receiver is deliberately
    // kept alive past the join so we can observe what — if anything
    // — the loop emitted on its way out.
    let err = event_rx
        .recv_timeout(Duration::from_millis(50))
        .expect_err("read-error path must not emit a spurious AppEvent::Input");
    assert!(
        matches!(
            err,
            RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected
        ),
        "expected Timeout or Disconnected, got {err:?}",
    );
}
