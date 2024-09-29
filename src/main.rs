use {
    linux_input::{Bus, Device, DeviceId, EventBit, Key, RelativeAxis},
    parking_lot::{Condvar, Mutex},
    std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
};

struct DeviceInfo {
    name: String,
    id: DeviceId,
    key_bits: Vec<Key>,
    relative_axis_bits: Vec<RelativeAxis>,
}

impl DeviceInfo {
    fn get(device: &mut Device) -> Option<Self> {
        let name = device.name().ok()?;
        let id = device.id().ok()?;
        let key_bits: Vec<_> = device.event_bits_of_kind::<Key>().ok()?.collect();
        let relative_axis_bits: Vec<_> =
            device.event_bits_of_kind::<RelativeAxis>().ok()?.collect();

        Some(DeviceInfo {
            name,
            id,
            key_bits,
            relative_axis_bits,
        })
    }

    fn is_mouse(&self) -> bool {
        self.relative_axis_bits.len() >= 2 && self.key_bits.contains(&Key::MouseLeft)
    }
}

fn list_devices() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir("/dev/input").unwrap() {
        let entry = entry.unwrap();
        if !entry.file_name().to_str().unwrap().starts_with("event") {
            continue;
        }
        paths.push(entry.path());
    }
    paths.sort();
    paths.sort_by_key(|path| {
        let path = path.to_str().unwrap();
        let digits = path
            .bytes()
            .rev()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        let nth: u32 = path[path.len() - digits..].parse().unwrap();
        nth
    });
    paths
}

static RUNNING: AtomicBool = AtomicBool::new(true);

struct VirtualDevice {
    path: PathBuf,
    device: linux_input::VirtualDevice,
}

// Not that it really matters, but the defaults come from here:
// https://github.com/obdev/v-usb/blob/master/usbdrv/USB-IDs-for-free.txt
const VIRTUAL_DEVICE_ID: DeviceId = DeviceId {
    bus: Bus::USB,
    vendor: 0x16c0,
    product: 0x27da,
    version: 0x0111,
};

fn create_virtual_device(name: &str, args: Args) -> VirtualDevice {
    let mut event_bits = Vec::new();
    event_bits.push(EventBit::Key(Key::MouseLeft));
    event_bits.push(EventBit::Key(Key::MouseRight));
    event_bits.push(EventBit::Key(Key::MouseMiddle));
    event_bits.push(EventBit::Key(Key::MouseExtra1));
    event_bits.push(EventBit::Key(Key::MouseExtra2));
    event_bits.push(EventBit::Key(Key::MouseExtra3));
    event_bits.push(EventBit::Key(Key::MouseExtra4));
    event_bits.push(EventBit::Key(Key::MouseExtra5));
    event_bits.push(EventBit::RelativeAxis(RelativeAxis::X));
    event_bits.push(EventBit::RelativeAxis(RelativeAxis::Y));
    event_bits.push(EventBit::RelativeAxis(RelativeAxis::Wheel));

    if args.scrollwheel_is_p {
        event_bits.push(EventBit::Key(Key::P));
    }

    let device = linux_input::VirtualDevice::create(VIRTUAL_DEVICE_ID, name, event_bits)
        .expect("failed to create a virtual device");

    let path = device.path().unwrap();

    log::info!("Created new virtual device at {path:?}: '{name}'");
    VirtualDevice { device, path }
}

struct ArcFlag(Arc<AtomicBool>);
struct ArcFlagLifetime(Arc<AtomicBool>);

impl ArcFlag {
    fn new() -> (Self, ArcFlagLifetime) {
        let arc = Arc::new(AtomicBool::new(true));
        (ArcFlag(arc.clone()), ArcFlagLifetime(arc))
    }

    fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl Drop for ArcFlagLifetime {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

fn run_for_device(hardware_device_path: PathBuf, args: Args) {
    let mut hardware_device = match Device::open(&hardware_device_path) {
        Ok(device) => device,
        Err(error) => {
            log::error!("Failed to open device {hardware_device_path:?}: {error}");
            return;
        }
    };

    let hardware_device_info = match DeviceInfo::get(&mut hardware_device) {
        Some(info) => info,
        None => {
            log::error!("Failed to get info for device {hardware_device_path:?}");
            return;
        }
    };

    if hardware_device_info.id == VIRTUAL_DEVICE_ID {
        return;
    }

    log::info!(
        "Found a new device in {:?}: '{}'",
        hardware_device_path,
        hardware_device_info.name
    );
    if !hardware_device_info.is_mouse() || hardware_device_info.name.contains("Keyboard") {
        return;
    }

    log::info!(
        "  Hooking to {:?} '{}'...",
        hardware_device_path,
        hardware_device_info.name
    );
    if let Err(error) = hardware_device.grab() {
        log::error!(
            "  Failed to turn on the exclusive mode for '{}': {}",
            hardware_device_info.name,
            error
        );
        return;
    }

    log::info!("  Device opened: '{}'", hardware_device_info.name);

    let virtual_device = create_virtual_device(
        &format!("{} (high-hz-mouse-fix)", hardware_device_info.name),
        args,
    );

    let target_hz_threshold = (1000000.0 / args.target_hz as f64) as u64;

    let condvar = Arc::new(Condvar::new());
    let (is_reader_running, reader_lifetime) = ArcFlag::new();
    let (is_writer_running, writer_lifetime) = ArcFlag::new();
    let pipe = Arc::new(Mutex::new(Vec::new()));
    {
        let pipe = pipe.clone();
        let condvar = condvar.clone();
        std::thread::spawn(move || {
            let mut buffer: Vec<linux_input::InputEvent> = Vec::new();
            let mut axis_list = Vec::new();
            let mut delta_for_axis = Vec::new();
            delta_for_axis.resize(u16::MAX as usize, 0_i32);

            let mut source = pipe.lock();
            let mut queued_movement = false;
            let mut last_movement_flush = Instant::now();
            while is_reader_running.get() && RUNNING.load(Ordering::Relaxed) {
                if source.is_empty() {
                    condvar.wait_for(
                        &mut source,
                        Duration::from_micros(if queued_movement { 100 } else { 10000 }),
                    );
                } else {
                    std::mem::swap(&mut buffer, &mut source);
                }

                std::mem::drop(source);

                fn emit_movement_events(
                    virtual_device: &VirtualDevice,
                    axis_list: &[u16],
                    delta_for_axis: &mut [i32],
                ) -> bool {
                    let mut emitted = false;
                    let timestamp = linux_input::Timestamp::get().unwrap();
                    for &axis in axis_list {
                        let delta = delta_for_axis[axis as usize];
                        if delta == 0 {
                            continue;
                        }

                        let event = linux_input::InputEvent {
                            timestamp,
                            body: linux_input::InputEventBody::RelativeMove {
                                axis: linux_input::RelativeAxis::Other(axis),
                                delta,
                            },
                        };

                        if let Err(error) = virtual_device.device.emit(event) {
                            log::error!(
                                "Failed to send an event to '{:?}': {}",
                                virtual_device.path,
                                error
                            );
                        }

                        delta_for_axis[axis as usize] = 0;
                        emitted = true;
                    }

                    emitted
                }

                let mut queued_flush = false;
                for mut event in buffer.drain(..) {
                    log::trace!("<< {:?}: {:?}", virtual_device.path, event);
                    match event.body {
                        linux_input::InputEventBody::RelativeMove {
                            axis: linux_input::RelativeAxis::WheelHiRes,
                            ..
                        } if args.scrollwheel_is_p => continue,
                        linux_input::InputEventBody::RelativeMove {
                            axis: linux_input::RelativeAxis::Wheel,
                            ..
                        } => {
                            if queued_movement {
                                queued_movement = false;
                                queued_flush |= emit_movement_events(
                                    &virtual_device,
                                    &axis_list,
                                    &mut delta_for_axis,
                                );
                                last_movement_flush = Instant::now();
                            }

                            if args.scrollwheel_is_p {
                                event.body =
                                    linux_input::InputEventBody::KeyPress(linux_input::Key::P);
                                if let Err(error) = virtual_device.device.emit(event.clone()) {
                                    log::error!(
                                        "Failed to send an event to '{:?}': {}",
                                        virtual_device.path,
                                        error
                                    );
                                }

                                event.body =
                                    linux_input::InputEventBody::KeyRelease(linux_input::Key::P);
                            }

                            if let Err(error) = virtual_device.device.emit(event) {
                                log::error!(
                                    "Failed to send an event to '{:?}': {}",
                                    virtual_device.path,
                                    error
                                );
                            }
                        }
                        linux_input::InputEventBody::RelativeMove { axis, delta }
                            if !matches!(
                                axis,
                                linux_input::RelativeAxis::Wheel
                                    | linux_input::RelativeAxis::WheelHiRes
                            ) =>
                        {
                            delta_for_axis[axis.raw() as usize] += delta;
                            if !axis_list.contains(&axis.raw()) {
                                // Should be faster than a hash set for small number of axes.
                                axis_list.push(axis.raw());
                            }

                            queued_movement = true;
                            continue;
                        }
                        linux_input::InputEventBody::Flush => {
                            queued_flush = true;
                            continue;
                        }
                        _ => {
                            if queued_movement {
                                queued_movement = false;
                                queued_flush |= emit_movement_events(
                                    &virtual_device,
                                    &axis_list,
                                    &mut delta_for_axis,
                                );
                                last_movement_flush = Instant::now();
                            }

                            if let Err(error) = virtual_device.device.emit(event) {
                                log::error!(
                                    "Failed to send an event to '{:?}': {}",
                                    virtual_device.path,
                                    error
                                );
                            }
                        }
                    }
                }

                if queued_movement {
                    let now = Instant::now();
                    if (now - last_movement_flush) >= Duration::from_micros(target_hz_threshold) {
                        queued_movement = false;
                        queued_flush |=
                            emit_movement_events(&virtual_device, &axis_list, &mut delta_for_axis);
                        last_movement_flush = now;
                    }
                }

                if queued_flush {
                    let event = linux_input::InputEvent {
                        timestamp: linux_input::Timestamp::get().unwrap(),
                        body: linux_input::InputEventBody::Flush,
                    };

                    if let Err(error) = virtual_device.device.emit(event) {
                        log::error!(
                            "Failed to send an event to '{:?}': {}",
                            virtual_device.path,
                            error
                        );
                    }
                }

                source = pipe.lock();
            }

            core::mem::drop(writer_lifetime);
        });
    };

    std::thread::spawn(move || {
        while is_writer_running.get() && RUNNING.load(Ordering::Relaxed) {
            let event = hardware_device.read(None);
            let event = match event {
                Ok(Some(event)) => event,
                Ok(None) => continue,
                Err(error) => {
                    if error.raw_os_error() == Some(libc::ENODEV) {
                        log::info!("Device disconnected: '{}'", hardware_device_info.name);
                    } else {
                        log::warn!(
                            "Failed to read from device '{}' ({:?}): {}",
                            hardware_device_info.name,
                            hardware_device_path,
                            error
                        );
                    }
                    break;
                }
            };

            match event.body {
                linux_input::InputEventBody::Dropped => {
                    log::warn!(
                        "Buffer overflow on device '{}' ({:?})",
                        hardware_device_info.name,
                        hardware_device_path
                    );
                    // TODO: Actually handle there: https://www.freedesktop.org/software/libevdev/doc/latest/syn_dropped.html
                }
                _ => {}
            }

            pipe.lock().push(event);
            condvar.notify_all();
        }

        condvar.notify_all();
        core::mem::drop(reader_lifetime);
    });
}

fn run(args: Args) {
    for path in list_devices() {
        run_for_device(path, args);
    }

    let monitor = udev::MonitorBuilder::new()
        .unwrap()
        .match_subsystem("input")
        .unwrap()
        .listen()
        .unwrap();

    use std::os::unix::io::AsRawFd;
    while RUNNING.load(Ordering::Relaxed) {
        if linux_input::poll_read(monitor.as_raw_fd(), None).unwrap() {
            let event = monitor.iter().next().unwrap();
            let devnode = event.devnode();
            log::debug!(
                "Device event: type={:?}, devpath={:?}, devnode={:?}",
                event.event_type(),
                event.devpath(),
                devnode
            );

            let Some(devnode) = devnode else { continue };

            if !devnode.starts_with("/dev/input")
                || devnode.components().count() != 4
                || !devnode
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("event")
            {
                continue;
            }

            if event.event_type() == udev::EventType::Add {
                run_for_device(devnode.to_owned(), args);
            }
        }
    }
}

#[derive(Copy, Clone, clap::Parser, Debug)]
struct Args {
    #[clap(short, long, default_value_t = 500)]
    target_hz: u64,

    #[clap(long, default_value_t = false)]
    scrollwheel_is_p: bool,
}

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    env_logger::init();

    use clap::Parser;
    let args = Args::parse();

    unsafe {
        fn signal_handler(_: libc::c_int) {
            RUNNING.store(false, Ordering::SeqCst);
        }

        for &signal in &[libc::SIGINT, libc::SIGTERM] {
            if libc::signal(signal, signal_handler as libc::size_t) == libc::SIG_ERR {
                panic!("signal failed: {}", std::io::Error::last_os_error());
            }
        }
    }

    run(args);
}
