use adw::prelude::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use gtk::{gio, glib};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    env,
    ffi::{OsStr, OsString},
    io::Write,
    os::unix::fs::FileTypeExt,
    path::PathBuf,
    rc::Rc,
};
use zeroize::Zeroizing;

const APP_ID: &str = "me.nexryai.keyvisor";
const AGENT_DBUS_NAME: &str = "me.nexryai.keyvisor.Agent";
const AGENT_DBUS_PATH: &str = "/me/nexryai/keyvisor/Agent";
const AGENT_DBUS_INTERFACE: &str = "me.nexryai.keyvisor.Agent1";
const MAX_PIN_BYTES: usize = 64;
const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DisplayPolicy {
    NoPin,
    TpmPin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DisplayKey {
    id: String,
    name: String,
    policy: DisplayPolicy,
    public_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DisplayHistoryEntry {
    timestamp_seconds: u64,
    key_name: String,
    policy: DisplayPolicy,
    succeeded: bool,
}

fn main() -> glib::ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if let [flag, key_name] = arguments.as_slice()
        && flag == "--authorize"
    {
        return run_pin_prompt(key_name);
    }

    let application = adw::Application::builder().application_id(APP_ID).build();

    application.connect_startup(setup_application_actions);
    application.connect_activate(build_ui);
    application.run()
}

fn setup_application_actions(application: &adw::Application) {
    let about = gio::SimpleAction::new("about", None);
    about.connect_activate(|_, _| {
        let Some(parent) = active_application_window() else {
            return;
        };
        adw::AboutDialog::builder()
            .application_name("Keyvisor")
            .application_icon(APP_ID)
            .developer_name("Nexryai")
            .version(env!("CARGO_PKG_VERSION"))
            .comments("Create and use hardware-bound SSH keys with the TPM.")
            .build()
            .present(Some(&parent));
    });
    application.add_action(&about);

    let shortcuts = gio::SimpleAction::new("shortcuts", None);
    shortcuts.connect_activate(|_, _| {
        let Some(parent) = active_application_window() else {
            return;
        };
        let general = adw::ShortcutsSection::new(Some("General"));
        general.add(adw::ShortcutsItem::new("Create a Key", "<Control>n"));
        general.add(adw::ShortcutsItem::new("Refresh Keys", "<Control>r"));
        general.add(adw::ShortcutsItem::new(
            "Keyboard Shortcuts",
            "<Control>question",
        ));
        general.add(adw::ShortcutsItem::new("Close Window", "<Control>w"));
        let dialog = adw::ShortcutsDialog::new();
        dialog.add(general);
        dialog.present(Some(&parent));
    });
    application.add_action(&shortcuts);
    application.set_accels_for_action("app.shortcuts", &["<Control>question"]);
}

fn active_application_window() -> Option<adw::ApplicationWindow> {
    gio::Application::default()
        .and_downcast::<adw::Application>()
        .and_then(|application| application.active_window())
        .and_downcast()
}

fn run_pin_prompt(key_name: &str) -> glib::ExitCode {
    let application = adw::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();
    let result = Rc::new(RefCell::new(None::<Zeroizing<Vec<u8>>>));
    let result_for_activate = Rc::clone(&result);
    let key_name = key_name.to_owned();

    application.connect_activate(move |application| {
        let pin_entry = adw::PasswordEntryRow::builder()
            .title("TPM PIN")
            .activates_default(true)
            .input_purpose(gtk::InputPurpose::Password)
            .build();
        let group = adw::PreferencesGroup::builder()
            .title("Authorize SSH Signature")
            .description(format!(
                "Enter the TPM-protected PIN for “{key_name}”. The PIN is used once and is not saved."
            ))
            .margin_top(24)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .build();
        group.add(&pin_entry);

        let cancel_button = gtk::Button::builder().label("Cancel").build();
        let authorize_button = gtk::Button::builder()
            .label("Authorize")
            .sensitive(false)
            .build();
        authorize_button.add_css_class("suggested-action");

        let header = adw::HeaderBar::new();
        header.pack_start(&cancel_button);
        header.pack_end(&authorize_button);
        let page = adw::PreferencesPage::new();
        page.add(&group);
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header);
        toolbar.set_content(Some(&page));

        let window = adw::ApplicationWindow::builder()
            .application(application)
            .title("TPM Authorization")
            .content(&toolbar)
            .default_width(460)
            .default_height(300)
            .default_widget(&authorize_button)
            .build();
        window.set_size_request(320, 260);

        pin_entry.connect_changed(glib::clone!(
            #[weak]
            pin_entry,
            #[weak]
            authorize_button,
            move |_| {
                authorize_button
                    .set_sensitive((6..=MAX_PIN_BYTES).contains(&pin_entry.text().len()));
            }
        ));
        cancel_button.connect_clicked(glib::clone!(
            #[weak]
            window,
            move |_| window.close()
        ));
        let result = Rc::clone(&result_for_activate);
        authorize_button.connect_clicked(glib::clone!(
            #[weak]
            window,
            #[weak]
            pin_entry,
            move |_| {
                let pin = Zeroizing::new(pin_entry.text().as_bytes().to_vec());
                pin_entry.set_text("");
                result.replace(Some(pin));
                window.close();
            }
        ));
        window.present();
    });
    application.run();

    let Some(pin) = result.borrow_mut().take() else {
        return glib::ExitCode::FAILURE;
    };
    // Standard output is a private pipe owned by the agent process. Keeping
    // authorization out of argv avoids exposure through process inspection.
    if std::io::stdout().lock().write_all(&pin).is_err() {
        return glib::ExitCode::FAILURE;
    }
    glib::ExitCode::SUCCESS
}

fn build_ui(application: &adw::Application) {
    let split_view = adw::NavigationSplitView::new();
    split_view.set_min_sidebar_width(200.0);
    split_view.set_max_sidebar_width(300.0);

    let toast_overlay = adw::ToastOverlay::new();
    toast_overlay.set_child(Some(&split_view));

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .content(&toast_overlay)
        .default_width(960)
        .default_height(640)
        .title("Keyvisor")
        .build();
    window.set_size_request(360, 480);
    // NavigationSplitView supplies GNOME's native back button, gestures, and
    // keyboard navigation when the two-pane layout no longer fits.
    let narrow_condition =
        adw::BreakpointCondition::parse("max-width: 700sp").expect("constant breakpoint is valid");
    let narrow_breakpoint = adw::Breakpoint::new(narrow_condition);
    narrow_breakpoint.add_setter(&split_view, "collapsed", Some(&true.to_value()));
    window.add_breakpoint(narrow_breakpoint);

    let create_action = gio::SimpleAction::new("create-key", None);
    let parent = window.clone();
    let overlay = toast_overlay.clone();
    create_action.connect_activate(move |_, _| {
        show_create_key_dialog(&parent, &overlay);
    });
    window.add_action(&create_action);
    application.set_accels_for_action("win.create-key", &["<Control>n"]);

    let refresh_action = gio::SimpleAction::new("refresh-keys", None);
    refresh_action.connect_activate(glib::clone!(
        #[weak]
        split_view,
        #[weak]
        toast_overlay,
        move |_, _| refresh_keys(&split_view, &toast_overlay)
    ));
    window.add_action(&refresh_action);
    application.set_accels_for_action("win.refresh-keys", &["<Control>r"]);

    let close_action = gio::SimpleAction::new("close", None);
    close_action.connect_activate(glib::clone!(
        #[weak]
        window,
        move |_, _| window.close()
    ));
    window.add_action(&close_action);
    application.set_accels_for_action("win.close", &["<Control>w"]);

    let management_proxy = Rc::new(RefCell::new(None::<gio::DBusProxy>));
    let activity_action = gio::SimpleAction::new("show-activity", None);
    let proxy_for_activity = Rc::clone(&management_proxy);
    activity_action.connect_activate(glib::clone!(
        #[weak]
        split_view,
        #[weak]
        toast_overlay,
        move |_, _| {
            let proxy = proxy_for_activity.borrow().clone();
            match proxy {
                Some(proxy) => show_activity_page(&split_view, &toast_overlay, &proxy),
                None => toast_overlay.add_toast(adw::Toast::new(
                    "The agent management service is unavailable",
                )),
            }
        }
    ));
    window.add_action(&activity_action);

    connect_management_proxy(application, Rc::clone(&management_proxy));
    let proxy_for_shutdown = Rc::clone(&management_proxy);
    application.connect_shutdown(move |_| {
        proxy_for_shutdown.replace(None);
    });

    split_view.set_sidebar(Some(&build_sidebar(
        &split_view,
        &toast_overlay,
        &[],
        Some("Loading TPM keys…"),
    )));
    split_view.set_content(Some(&build_empty_state()));

    window.present();
    refresh_keys(&split_view, &toast_overlay);
}

fn connect_management_proxy(
    _application: &adw::Application,
    holder: Rc<RefCell<Option<gio::DBusProxy>>>,
) {
    gio::DBusProxy::for_bus(
        gio::BusType::Session,
        gio::DBusProxyFlags::NONE,
        None,
        AGENT_DBUS_NAME,
        AGENT_DBUS_PATH,
        AGENT_DBUS_INTERFACE,
        None::<&gio::Cancellable>,
        move |result| {
            let Ok(proxy) = result else {
                return;
            };
            proxy.connect_g_signal(move |_, _, signal, parameters| match signal {
                "HistoryChanged" => {
                    let Some((timestamp, _, key_name, _, outcome)) =
                        parameters.get::<(u64, String, String, String, String)>()
                    else {
                        return;
                    };
                    // GDBus signal handlers satisfy Send + Sync and are not a
                    // safe place to touch GTK objects directly. Re-enter the
                    // GTK main context with owned, display-safe metadata.
                    glib::MainContext::default().invoke(move || {
                        let Some(application) =
                            gio::Application::default().and_downcast::<adw::Application>()
                        else {
                            return;
                        };
                        let notification = gio::Notification::new(if outcome == "succeeded" {
                            "SSH Signature Completed"
                        } else {
                            "SSH Signature Failed"
                        });
                        notification.set_body(Some(&format!(
                            "Keyvisor used “{key_name}” at {}.",
                            format_history_time(timestamp)
                        )));
                        application.send_notification(Some("signature-event"), &notification);
                    });
                }
                "KeysChanged" => {
                    glib::MainContext::default().invoke(move || {
                        let window = gio::Application::default()
                            .and_downcast::<adw::Application>()
                            .and_then(|application| application.active_window())
                            .and_downcast::<adw::ApplicationWindow>();
                        if let Some(window) = window {
                            gio::prelude::ActionGroupExt::activate_action(
                                &window,
                                "refresh-keys",
                                None,
                            );
                        }
                    });
                }
                _ => {}
            });
            holder.replace(Some(proxy));
        },
    );
}

fn show_activity_page(
    split_view: &adw::NavigationSplitView,
    toast_overlay: &adw::ToastOverlay,
    proxy: &gio::DBusProxy,
) {
    // Activity is navigable application content, not a decision that blocks
    // the user, so the HIG favors an in-window page over a modal dialog.
    let spinner = gtk::Spinner::new();
    spinner.start();
    let loading = adw::StatusPage::builder()
        .title("Loading Activity")
        .description("Reading privacy-preserving signing records from the agent")
        .child(&spinner)
        .build();
    let header = adw::HeaderBar::new();
    let refresh = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .action_name("win.show-activity")
        .tooltip_text("Refresh Signing Activity")
        .build();
    refresh.update_property(&[gtk::accessible::Property::Label("Refresh Signing Activity")]);
    header.pack_end(&refresh);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&loading));
    let page = adw::NavigationPage::new(&toolbar, "Signing Activity");
    page.set_tag(Some("activity"));
    split_view.set_content(Some(&page));
    split_view.set_show_content(true);

    proxy.call(
        "GetHistory",
        None,
        gio::DBusCallFlags::NONE,
        5_000,
        None::<&gio::Cancellable>,
        glib::clone!(
            #[weak]
            toolbar,
            #[weak]
            toast_overlay,
            move |result| {
                let entries = result
                    .map_err(|error| format!("Could not load signing activity: {error}"))
                    .and_then(|value| parse_history(&value));
                match entries {
                    Ok(entries) => toolbar.set_content(Some(&build_activity_content(&entries))),
                    Err(error) => {
                        toast_overlay.add_toast(adw::Toast::new(&error));
                        toolbar.set_content(Some(&build_activity_error_state()));
                    }
                }
            }
        ),
    );
}

fn parse_history(value: &glib::Variant) -> Result<Vec<DisplayHistoryEntry>, String> {
    let (entries,) = value
        .get::<(Vec<(u64, String, String, String, String)>,)>()
        .ok_or_else(|| String::from("The agent returned malformed signing activity"))?;
    entries
        .into_iter()
        .map(|(timestamp_seconds, _, key_name, policy, outcome)| {
            let policy = match policy.as_str() {
                "none" => DisplayPolicy::NoPin,
                "pin" => DisplayPolicy::TpmPin,
                _ => return Err(String::from("The agent returned an unknown key policy")),
            };
            let succeeded = match outcome.as_str() {
                "succeeded" => true,
                "failed" => false,
                _ => {
                    return Err(String::from(
                        "The agent returned an unknown activity result",
                    ));
                }
            };
            if key_name.is_empty() {
                return Err(String::from(
                    "The agent returned incomplete signing activity",
                ));
            }
            Ok(DisplayHistoryEntry {
                timestamp_seconds,
                key_name,
                policy,
                succeeded,
            })
        })
        .collect()
}

fn build_activity_content(entries: &[DisplayHistoryEntry]) -> gtk::Widget {
    if entries.is_empty() {
        return adw::StatusPage::builder()
            .icon_name("document-open-recent-symbolic")
            .title("No Signing Activity")
            .description(
                "Successful and failed signing requests will appear here. \
                 Request contents are never recorded.",
            )
            .build()
            .upcast();
    }

    let group = adw::PreferencesGroup::builder()
        .title("Recent Requests")
        .description(
            "Newest first. Keyvisor records the key and result, but never the signed content.",
        )
        .build();
    for entry in entries.iter().rev() {
        let row = adw::ActionRow::builder()
            .title(if entry.succeeded {
                format!("Signed with “{}”", entry.key_name)
            } else {
                format!("Signing failed for “{}”", entry.key_name)
            })
            .subtitle(format!(
                "{} · {}",
                format_history_time(entry.timestamp_seconds),
                policy_label(entry.policy)
            ))
            .build();
        let icon = gtk::Image::from_icon_name(if entry.succeeded {
            "emblem-ok-symbolic"
        } else {
            "dialog-error-symbolic"
        });
        icon.add_css_class(if entry.succeeded { "success" } else { "error" });
        row.add_prefix(&icon);
        group.add(&row);
    }
    let page = adw::PreferencesPage::new();
    page.add(&group);
    page.upcast()
}

fn build_activity_error_state() -> gtk::Widget {
    let retry = gtk::Button::builder()
        .label("Try Again")
        .action_name("win.show-activity")
        .halign(gtk::Align::Center)
        .build();
    retry.add_css_class("pill");
    adw::StatusPage::builder()
        .icon_name("dialog-error-symbolic")
        .title("Activity Could Not Be Loaded")
        .description("Check that the Keyvisor agent is running and try again.")
        .child(&retry)
        .build()
        .upcast()
}

fn format_history_time(timestamp_seconds: u64) -> String {
    i64::try_from(timestamp_seconds)
        .ok()
        .and_then(|timestamp| glib::DateTime::from_unix_local(timestamp).ok())
        .and_then(|date| date.format("%x %H:%M").ok())
        .map_or_else(|| String::from("Unknown time"), |value| value.to_string())
}

fn refresh_keys(split_view: &adw::NavigationSplitView, toast_overlay: &adw::ToastOverlay) {
    split_view.set_sidebar(Some(&build_sidebar(
        split_view,
        toast_overlay,
        &[],
        Some("Loading TPM keys…"),
    )));
    if let Err(error) = start_key_listing(glib::clone!(
        #[weak]
        split_view,
        #[weak]
        toast_overlay,
        move |result| match result {
            Ok(keys) => {
                split_view.set_sidebar(Some(&build_sidebar(
                    &split_view,
                    &toast_overlay,
                    &keys,
                    None,
                )));
                if keys.is_empty() {
                    split_view.set_content(Some(&build_empty_state()));
                    split_view.set_show_content(true);
                } else if split_view.is_collapsed()
                    && split_view
                        .content()
                        .and_then(|page| page.tag())
                        .is_none_or(|tag| tag == "empty" || tag == "error")
                {
                    // On the initial narrow view, present the collection before
                    // choosing a detail. Existing detail/activity pages remain
                    // visible during background refreshes.
                    split_view.set_show_content(false);
                }
            }
            Err(message) => {
                split_view.set_sidebar(Some(&build_sidebar(
                    &split_view,
                    &toast_overlay,
                    &[],
                    Some("Could not load keys"),
                )));
                split_view.set_content(Some(&build_error_state()));
                split_view.set_show_content(true);
                toast_overlay.add_toast(adw::Toast::new(&message));
            }
        }
    )) {
        split_view.set_sidebar(Some(&build_sidebar(
            split_view,
            toast_overlay,
            &[],
            Some("Could not load keys"),
        )));
        split_view.set_content(Some(&build_error_state()));
        split_view.set_show_content(true);
        toast_overlay.add_toast(adw::Toast::new(&error));
    }
}

fn start_key_listing(
    callback: impl FnOnce(Result<Vec<DisplayKey>, String>) + 'static,
) -> Result<(), String> {
    let launcher = gio::SubprocessLauncher::new(
        gio::SubprocessFlags::STDOUT_PIPE | gio::SubprocessFlags::STDERR_PIPE,
    );
    let agent = agent_path();
    let process = launcher
        .spawn(&[agent.as_os_str(), OsStr::new("list")])
        .map_err(|error| format!("Could not start the Keyvisor agent: {error}"))?;
    let process_for_callback = process.clone();
    process.communicate_async(
        None::<&glib::Bytes>,
        None::<&gio::Cancellable>,
        move |communication| {
            let result = communication
                .map_err(|error| format!("Could not read the key list: {error}"))
                .and_then(|(stdout, stderr)| {
                    if process_for_callback.is_successful() {
                        stdout
                            .as_deref()
                            .ok_or_else(|| String::from("The agent returned no key list"))
                            .and_then(parse_key_list)
                    } else {
                        Err(process_error(
                            stderr.as_deref(),
                            "The agent could not list keys",
                        ))
                    }
                });
            callback(result);
        },
    );
    Ok(())
}

fn parse_key_list(bytes: &[u8]) -> Result<Vec<DisplayKey>, String> {
    if bytes.len() > MAX_LIST_BYTES {
        return Err(String::from("The agent key list exceeds its size limit"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| String::from("The agent key list is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some("KEYVISOR-LIST-1") {
        return Err(String::from("The agent key list version is unsupported"));
    }

    let mut keys = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        let [id, policy, name, public_key] = fields.as_slice() else {
            return Err(String::from("The agent returned malformed key metadata"));
        };
        if id.is_empty() || id.len() > 4 * 1024 {
            return Err(String::from("The agent returned an invalid key identifier"));
        }
        let policy = match *policy {
            "none" => DisplayPolicy::NoPin,
            "pin" => DisplayPolicy::TpmPin,
            _ => return Err(String::from("The agent returned an unknown key policy")),
        };
        let name = String::from_utf8(hex_decode(name)?)
            .map_err(|_| String::from("The agent returned an invalid key name"))?;
        let public_key = hex_decode(public_key)?;
        if name.is_empty() || public_key.is_empty() {
            return Err(String::from("The agent returned incomplete key metadata"));
        }
        keys.push(DisplayKey {
            id: (*id).to_owned(),
            name,
            policy,
            public_key,
        });
    }
    Ok(keys)
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(String::from(
            "The agent returned malformed hexadecimal data",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])
                .ok_or_else(|| String::from("The agent returned malformed hexadecimal data"))?;
            let low = hex_nibble(pair[1])
                .ok_or_else(|| String::from("The agent returned malformed hexadecimal data"))?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn process_error(stderr: Option<&[u8]>, fallback: &str) -> String {
    stderr
        .map(|bytes| String::from_utf8_lossy(bytes).trim().to_owned())
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

fn agent_path() -> OsString {
    env::var_os("KEYVISOR_AGENT_PATH").unwrap_or_else(|| OsString::from("keyvisor-agent"))
}

// Keeping the programmatic widget tree and its signal wiring together makes
// ownership and weak-reference lifetimes visible in one place.
#[allow(clippy::too_many_lines)]
fn show_create_key_dialog(parent: &adw::ApplicationWindow, toast_overlay: &adw::ToastOverlay) {
    let name_row = adw::EntryRow::builder()
        .title("Name")
        .activates_default(true)
        .build();

    let identity_group = adw::PreferencesGroup::builder()
        .title("Key")
        .description("The key will use ECDSA P-256 and remain bound to this TPM.")
        .build();
    identity_group.add(&name_row);

    let algorithm_row = adw::ActionRow::builder()
        .title("Algorithm")
        .subtitle("ECDSA with the NIST P-256 curve")
        .build();
    let algorithm_icon = gtk::Image::from_icon_name("channel-secure-symbolic");
    algorithm_row.add_prefix(&algorithm_icon);
    identity_group.add(&algorithm_row);

    let no_pin_button = gtk::CheckButton::new();
    let no_pin_row = adw::ActionRow::builder()
        .title("No Authentication")
        .subtitle("Allow signing without prompting after a client reaches the agent")
        .activatable_widget(&no_pin_button)
        .build();
    no_pin_row.add_prefix(&no_pin_button);

    let pin_button = gtk::CheckButton::new();
    pin_button.set_group(Some(&no_pin_button));
    pin_button.set_active(true);
    let pin_row = adw::ActionRow::builder()
        .title("TPM Rate-limited PIN")
        .subtitle("Require a PIN for every signature and use the TPM lockout policy")
        .activatable_widget(&pin_button)
        .build();
    pin_row.add_prefix(&pin_button);

    let authorization_group = adw::PreferencesGroup::builder()
        .title("Authentication")
        .description("Choose how SSH clients authorize each signature.")
        .build();
    authorization_group.add(&no_pin_row);
    authorization_group.add(&pin_row);

    let pin_entry = adw::PasswordEntryRow::builder()
        .title("PIN")
        .activates_default(true)
        .input_purpose(gtk::InputPurpose::Password)
        .build();
    let pin_confirmation = adw::PasswordEntryRow::builder()
        .title("Confirm PIN")
        .activates_default(true)
        .input_purpose(gtk::InputPurpose::Password)
        .build();
    let pin_group = adw::PreferencesGroup::builder()
        .title("PIN")
        .description(
            "Use 6–64 UTF-8 bytes. The PIN is never stored, and Keyvisor never changes TPM lockout settings.",
        )
        .build();
    pin_group.add(&pin_entry);
    pin_group.add(&pin_confirmation);

    let page = adw::PreferencesPage::new();
    page.add(&identity_group);
    page.add(&authorization_group);
    page.add(&pin_group);

    let cancel_button = gtk::Button::builder().label("Cancel").build();
    let create_button = gtk::Button::builder()
        .label("Create")
        .sensitive(false)
        .build();
    create_button.add_css_class("suggested-action");

    let header = adw::HeaderBar::new();
    header.pack_start(&cancel_button);
    header.pack_end(&create_button);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    let pin_warning = adw::Banner::builder()
        .title("PIN failures count toward the TPM-wide lockout limit")
        .revealed(true)
        .build();
    toolbar.add_top_bar(&pin_warning);
    toolbar.set_content(Some(&page));

    let dialog = adw::Dialog::builder()
        .title("Create a Key")
        .content_width(580)
        .content_height(640)
        .default_widget(&create_button)
        .focus_widget(&name_row)
        .child(&toolbar)
        .build();

    cancel_button.connect_clicked(glib::clone!(
        #[weak]
        dialog,
        move |_| {
            dialog.close();
        }
    ));

    pin_button.connect_toggled(glib::clone!(
        #[weak]
        pin_group,
        #[weak]
        pin_warning,
        #[weak]
        name_row,
        #[weak]
        pin_button,
        #[weak]
        pin_entry,
        #[weak]
        pin_confirmation,
        #[weak]
        create_button,
        move |_| {
            pin_group.set_visible(pin_button.is_active());
            pin_warning.set_revealed(pin_button.is_active());
            update_create_button(
                &create_button,
                &name_row,
                &pin_button,
                &pin_entry,
                &pin_confirmation,
            );
        }
    ));
    name_row.connect_changed(glib::clone!(
        #[weak]
        name_row,
        #[weak]
        pin_button,
        #[weak]
        pin_entry,
        #[weak]
        pin_confirmation,
        #[weak]
        create_button,
        move |_| update_create_button(
            &create_button,
            &name_row,
            &pin_button,
            &pin_entry,
            &pin_confirmation,
        )
    ));
    pin_entry.connect_changed(glib::clone!(
        #[weak]
        name_row,
        #[weak]
        pin_button,
        #[weak]
        pin_entry,
        #[weak]
        pin_confirmation,
        #[weak]
        create_button,
        move |_| update_create_button(
            &create_button,
            &name_row,
            &pin_button,
            &pin_entry,
            &pin_confirmation,
        )
    ));
    pin_confirmation.connect_changed(glib::clone!(
        #[weak]
        name_row,
        #[weak]
        pin_button,
        #[weak]
        pin_entry,
        #[weak]
        pin_confirmation,
        #[weak]
        create_button,
        move |_| update_create_button(
            &create_button,
            &name_row,
            &pin_button,
            &pin_entry,
            &pin_confirmation,
        )
    ));

    let parent_window = parent.clone();
    create_button.connect_clicked(glib::clone!(
        #[weak]
        dialog,
        #[weak]
        toast_overlay,
        #[weak]
        name_row,
        #[weak]
        pin_button,
        #[weak]
        pin_entry,
        #[weak]
        pin_confirmation,
        #[weak]
        create_button,
        move |_| {
            let name = name_row.text().trim().to_owned();
            let requires_pin = pin_button.is_active();
            let pin = requires_pin.then(|| pin_entry.text().to_string());

            pin_entry.set_text("");
            pin_confirmation.set_text("");
            dialog.set_can_close(false);
            create_button.set_sensitive(false);
            create_button.set_label("Creating…");

            let display_name = name.clone();
            if let Err(error) = start_key_generation(
                &name,
                requires_pin,
                pin,
                glib::clone!(
                    #[weak]
                    dialog,
                    #[weak]
                    toast_overlay,
                    #[weak]
                    name_row,
                    #[weak]
                    pin_button,
                    #[weak]
                    pin_entry,
                    #[weak]
                    pin_confirmation,
                    #[weak]
                    create_button,
                    #[weak]
                    parent_window,
                    move |result| {
                        dialog.set_can_close(true);
                        create_button.set_label("Create");
                        match result {
                            Ok(()) => {
                                dialog.close();
                                gio::prelude::ActionGroupExt::activate_action(
                                    &parent_window,
                                    "refresh-keys",
                                    None,
                                );
                                toast_overlay.add_toast(adw::Toast::new(&format!(
                                    "“{display_name}” was created in the TPM"
                                )));
                            }
                            Err(message) => {
                                update_create_button(
                                    &create_button,
                                    &name_row,
                                    &pin_button,
                                    &pin_entry,
                                    &pin_confirmation,
                                );
                                toast_overlay.add_toast(adw::Toast::new(&message));
                            }
                        }
                    }
                ),
            ) {
                dialog.set_can_close(true);
                create_button.set_label("Create");
                update_create_button(
                    &create_button,
                    &name_row,
                    &pin_button,
                    &pin_entry,
                    &pin_confirmation,
                );
                toast_overlay.add_toast(adw::Toast::new(&error));
            }
        }
    ));

    dialog.present(Some(parent));
}

fn update_create_button(
    button: &gtk::Button,
    name: &adw::EntryRow,
    pin_mode: &gtk::CheckButton,
    pin: &adw::PasswordEntryRow,
    confirmation: &adw::PasswordEntryRow,
) {
    let name_is_valid = !name.text().trim().is_empty();
    let pin_text = pin.text();
    let pin_length = pin_text.len();
    let pin_is_valid = !pin_mode.is_active()
        || ((6..=MAX_PIN_BYTES).contains(&pin_length) && pin_text == confirmation.text());
    button.set_sensitive(name_is_valid && pin_is_valid);
}

fn start_key_generation(
    name: &str,
    requires_pin: bool,
    pin: Option<String>,
    callback: impl FnOnce(Result<(), String>) + 'static,
) -> Result<(), String> {
    let agent = agent_path();
    let authorization = if requires_pin { "pin" } else { "none" };
    let launcher = gio::SubprocessLauncher::new(
        gio::SubprocessFlags::STDIN_PIPE
            | gio::SubprocessFlags::STDOUT_PIPE
            | gio::SubprocessFlags::STDERR_PIPE,
    );
    let process = launcher
        .spawn(&[
            agent.as_os_str(),
            OsStr::new("generate"),
            OsStr::new("--name"),
            OsStr::new(name),
            OsStr::new("--authorization"),
            OsStr::new(authorization),
        ])
        .map_err(|error| format!("Could not start the Keyvisor agent: {error}"))?;

    let process_for_callback = process.clone();
    // PIN bytes use the subprocess stdin pipe and a zeroizing owner. Only the
    // non-sensitive authorization mode is included in the command line.
    let input = glib::Bytes::from_owned(Zeroizing::new(pin.unwrap_or_default().into_bytes()));
    process.communicate_async(
        Some(&input),
        None::<&gio::Cancellable>,
        move |communication| {
            let result = communication
                .map_err(|error| format!("Could not communicate with the agent: {error}"))
                .and_then(|(_, stderr)| {
                    if process_for_callback.is_successful() {
                        Ok(())
                    } else {
                        Err(process_error(
                            stderr.as_deref(),
                            "The agent could not create the key",
                        ))
                    }
                });
            callback(result);
        },
    );
    Ok(())
}

fn build_sidebar(
    split_view: &adw::NavigationSplitView,
    toast_overlay: &adw::ToastOverlay,
    keys: &[DisplayKey],
    message: Option<&str>,
) -> adw::NavigationPage {
    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&adw::WindowTitle::new("Keyvisor", "")));

    let add_button = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .action_name("win.create-key")
        .tooltip_text("Create a Key")
        .build();
    add_button.update_property(&[gtk::accessible::Property::Label("Create a Key")]);
    header.pack_start(&add_button);

    let menu_button = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(&build_main_menu())
        .primary(true)
        .tooltip_text("Main Menu")
        .build();
    menu_button.update_property(&[gtk::accessible::Property::Label("Main Menu")]);
    header.pack_end(&menu_button);

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.add_css_class("background");

    let keys_label = gtk::Label::builder()
        .label("TPM KEYS")
        .halign(gtk::Align::Start)
        .margin_top(18)
        .margin_start(18)
        .margin_bottom(6)
        .build();
    keys_label.add_css_class("caption");
    keys_label.add_css_class("dim-label");
    content.append(&keys_label);

    let key_list = build_key_list(split_view, toast_overlay, keys, message);
    content.append(&key_list);

    let spacer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    spacer.set_vexpand(true);
    content.append(&spacer);

    let destinations = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .margin_start(6)
        .margin_end(6)
        .margin_bottom(12)
        .build();
    destinations.add_css_class("navigation-sidebar");
    let activity = adw::ActionRow::builder()
        .title("Signing Activity")
        .subtitle("Recent SSH signature requests")
        .action_name("win.show-activity")
        .activatable(true)
        .build();
    activity.add_prefix(&gtk::Image::from_icon_name("document-open-recent-symbolic"));
    activity.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    destinations.append(&activity);
    content.append(&destinations);

    let status = build_agent_status();
    content.append(&status);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&content));

    let page = adw::NavigationPage::new(&toolbar, "Keys");
    page.set_tag(Some("keys"));
    page
}

fn build_main_menu() -> gio::Menu {
    let menu = gio::Menu::new();
    let actions = gio::Menu::new();
    actions.append(Some("Signing Activity"), Some("win.show-activity"));
    actions.append(Some("Refresh Keys"), Some("win.refresh-keys"));
    menu.append_section(None, &actions);

    let standard = gio::Menu::new();
    standard.append(Some("Keyboard Shortcuts"), Some("app.shortcuts"));
    standard.append(Some("About Keyvisor"), Some("app.about"));
    menu.append_section(None, &standard);
    menu
}

fn build_key_list(
    split_view: &adw::NavigationSplitView,
    toast_overlay: &adw::ToastOverlay,
    keys: &[DisplayKey],
    message: Option<&str>,
) -> gtk::ListBox {
    let key_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::Single)
        .margin_start(6)
        .margin_end(6)
        .build();
    key_list.add_css_class("navigation-sidebar");

    let display_keys = Rc::new(keys.to_vec());
    if display_keys.is_empty() {
        key_list.set_selection_mode(gtk::SelectionMode::None);
        let empty_icon: gtk::Widget = if message == Some("Loading TPM keys…") {
            let spinner = gtk::Spinner::new();
            spinner.start();
            spinner.upcast()
        } else {
            gtk::Image::from_icon_name("key-symbolic").upcast()
        };
        let empty_row = adw::ActionRow::builder()
            .title(message.unwrap_or("No keys yet"))
            .subtitle(if message == Some("Loading TPM keys…") {
                "Reading public metadata"
            } else if message.is_some() {
                "Use Refresh to try again"
            } else {
                "Create a key protected by this TPM"
            })
            .build();
        empty_row.add_prefix(&empty_icon);
        key_list.append(&empty_row);
        return key_list;
    }

    for key in display_keys.iter() {
        let icon = gtk::Image::from_icon_name("key-symbolic");
        let row = adw::ActionRow::builder()
            .title(&key.name)
            .subtitle(policy_label(key.policy))
            .activatable(true)
            .build();
        row.add_prefix(&icon);
        key_list.append(&row);
    }
    key_list.connect_row_selected(glib::clone!(
        #[weak]
        split_view,
        #[weak]
        toast_overlay,
        #[strong]
        display_keys,
        move |_, row| {
            let Some(row) = row else {
                return;
            };
            let Ok(index) = usize::try_from(row.index()) else {
                return;
            };
            let Some(key) = display_keys.get(index) else {
                return;
            };
            split_view.set_content(Some(&build_key_details(key, &toast_overlay, &split_view)));
            split_view.set_show_content(true);
        }
    ));
    let should_select_first = split_view
        .content()
        .and_then(|page| page.tag())
        .is_none_or(|tag| tag == "empty" || tag == "error");
    // Auto-selection is useful in the wide master-detail layout, but would
    // skip the collection and unexpectedly navigate on a narrow window.
    if !split_view.is_collapsed()
        && should_select_first
        && let Some(first) = key_list.row_at_index(0)
    {
        key_list.select_row(Some(&first));
    }
    key_list
}

fn build_agent_status() -> gtk::ListBox {
    let status = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .build();
    status.add_css_class("boxed-list");

    let socket_available = agent_socket_path()
        .and_then(|path| std::fs::symlink_metadata(path).ok())
        .is_some_and(|metadata| metadata.file_type().is_socket());
    let status_icon = gtk::Image::from_icon_name(if socket_available {
        "emblem-ok-symbolic"
    } else {
        "dialog-warning-symbolic"
    });
    status_icon.add_css_class(if socket_available {
        "success"
    } else {
        "warning"
    });
    let status_row = adw::ActionRow::builder()
        .title(if socket_available {
            "SSH Agent Available"
        } else {
            "SSH Agent Not Running"
        })
        .subtitle(if socket_available {
            "The Unix socket is ready for SSH clients"
        } else {
            "Start the Keyvisor user service to use SSH"
        })
        .build();
    status_row.add_prefix(&status_icon);
    status.append(&status_row);
    status
}

fn build_key_details(
    key: &DisplayKey,
    toast_overlay: &adw::ToastOverlay,
    split_view: &adw::NavigationSplitView,
) -> adw::NavigationPage {
    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&adw::WindowTitle::new(
        &key.name,
        "TPM-backed SSH key",
    )));

    let overview = adw::PreferencesGroup::builder().title("Overview").build();
    let algorithm = adw::ActionRow::builder()
        .title("Algorithm")
        .subtitle("ECDSA NIST P-256")
        .build();
    overview.add(&algorithm);
    let authorization = adw::ActionRow::builder()
        .title("Authentication")
        .subtitle(policy_label(key.policy))
        .build();
    overview.add(&authorization);
    let identifier = adw::ActionRow::builder()
        .title("Key Identifier")
        .subtitle(&key.id)
        .subtitle_selectable(true)
        .build();
    overview.add(&identifier);

    let fingerprint = format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(&key.public_key))
    );
    let fingerprint_row = adw::ActionRow::builder()
        .title("SHA-256 Fingerprint")
        .subtitle(&fingerprint)
        .subtitle_selectable(true)
        .build();
    let fingerprint_copy = copy_button("Copy Fingerprint");
    connect_copy(
        &fingerprint_copy,
        fingerprint,
        "Fingerprint copied",
        toast_overlay,
    );
    fingerprint_row.add_suffix(&fingerprint_copy);

    let public_key = format!(
        "ecdsa-sha2-nistp256 {} {}",
        STANDARD.encode(&key.public_key),
        key.name
    );
    let public_key_row = adw::ActionRow::builder()
        .title("OpenSSH Public Key")
        .subtitle(&public_key)
        .subtitle_selectable(true)
        .build();
    let public_key_copy = copy_button("Copy Public Key");
    connect_copy(
        &public_key_copy,
        public_key,
        "Public key copied",
        toast_overlay,
    );
    public_key_row.add_suffix(&public_key_copy);

    let public_group = adw::PreferencesGroup::builder()
        .title("Public Material")
        .description("Safe to copy and share. Private parameters remain in the TPM.")
        .build();
    public_group.add(&fingerprint_row);
    public_group.add(&public_key_row);

    let delete_button = gtk::Button::builder()
        .label("Delete…")
        .valign(gtk::Align::Center)
        .build();
    delete_button.add_css_class("destructive-action");
    let delete_row = adw::ActionRow::builder()
        .title("Delete Key")
        .subtitle("Remove the wrapped TPM object from this account")
        .build();
    delete_row.add_suffix(&delete_button);
    let destructive_group = adw::PreferencesGroup::builder()
        .title("Danger Zone")
        .build();
    destructive_group.add(&delete_row);

    let key_for_delete = key.clone();
    delete_button.connect_clicked(glib::clone!(
        #[weak]
        delete_button,
        #[weak]
        toast_overlay,
        #[weak]
        split_view,
        move |_| {
            confirm_key_deletion(&delete_button, &key_for_delete, &split_view, &toast_overlay);
        }
    ));

    let page = adw::PreferencesPage::new();
    page.add(&overview);
    page.add(&public_group);
    page.add(&destructive_group);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&page));
    let page = adw::NavigationPage::new(&toolbar, &key.name);
    page.set_tag(Some("key-details"));
    page
}

fn confirm_key_deletion(
    parent: &impl IsA<gtk::Widget>,
    key: &DisplayKey,
    split_view: &adw::NavigationSplitView,
    toast_overlay: &adw::ToastOverlay,
) {
    let dialog = adw::AlertDialog::builder()
        .heading(format!("Delete “{}”?", key.name))
        .body(
            "The TPM-wrapped key record will be permanently removed. \
             Existing servers will still trust its public key, but Keyvisor \
             will no longer be able to sign with it.",
        )
        .close_response("cancel")
        .default_response("cancel")
        .build();
    dialog.add_responses(&[("cancel", "Cancel"), ("delete", "Delete")]);
    dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);

    let id = key.id.clone();
    let name = key.name.clone();
    let split_view = split_view.clone();
    let toast_overlay = toast_overlay.clone();
    dialog.choose(Some(parent), None::<&gio::Cancellable>, move |response| {
        if response != "delete" {
            return;
        }
        if let Err(error) = start_key_deletion(
            &id,
            glib::clone!(
                #[weak]
                split_view,
                #[weak]
                toast_overlay,
                move |result| match result {
                    Ok(()) => {
                        split_view.set_content(Some(&build_empty_state()));
                        refresh_keys(&split_view, &toast_overlay);
                        toast_overlay.add_toast(adw::Toast::new(&format!("“{name}” was deleted")));
                    }
                    Err(message) => {
                        toast_overlay.add_toast(adw::Toast::new(&message));
                    }
                }
            ),
        ) {
            toast_overlay.add_toast(adw::Toast::new(&error));
        }
    });
}

fn start_key_deletion(
    id: &str,
    callback: impl FnOnce(Result<(), String>) + 'static,
) -> Result<(), String> {
    let launcher = gio::SubprocessLauncher::new(
        gio::SubprocessFlags::STDOUT_PIPE | gio::SubprocessFlags::STDERR_PIPE,
    );
    let agent = agent_path();
    let process = launcher
        .spawn(&[agent.as_os_str(), OsStr::new("delete"), OsStr::new(id)])
        .map_err(|error| format!("Could not start the Keyvisor agent: {error}"))?;
    let process_for_callback = process.clone();
    process.communicate_async(
        None::<&glib::Bytes>,
        None::<&gio::Cancellable>,
        move |communication| {
            let result = communication
                .map_err(|error| format!("Could not communicate with the agent: {error}"))
                .and_then(|(_, stderr)| {
                    if process_for_callback.is_successful() {
                        Ok(())
                    } else {
                        Err(process_error(
                            stderr.as_deref(),
                            "The agent could not delete the key",
                        ))
                    }
                });
            callback(result);
        },
    );
    Ok(())
}

fn copy_button(tooltip: &str) -> gtk::Button {
    let button = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text(tooltip)
        .valign(gtk::Align::Center)
        .build();
    button.update_property(&[gtk::accessible::Property::Label(tooltip)]);
    button
}

fn connect_copy(
    button: &gtk::Button,
    value: String,
    confirmation: &'static str,
    toast_overlay: &adw::ToastOverlay,
) {
    button.connect_clicked(glib::clone!(
        #[weak]
        toast_overlay,
        move |_| {
            if let Some(display) = gtk::gdk::Display::default() {
                display.clipboard().set_text(&value);
                toast_overlay.add_toast(adw::Toast::new(confirmation));
            }
        }
    ));
}

const fn policy_label(policy: DisplayPolicy) -> &'static str {
    match policy {
        DisplayPolicy::NoPin => "No Authentication",
        DisplayPolicy::TpmPin => "TPM Rate-limited PIN",
    }
}

fn agent_socket_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("KEYVISOR_AGENT_SOCKET").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(path));
    }
    env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .map(|path| path.join("keyvisor/agent.sock"))
}

fn build_error_state() -> adw::NavigationPage {
    let header = adw::HeaderBar::new();
    header.set_show_title(false);
    let retry = gtk::Button::builder()
        .label("Try Again")
        .action_name("win.refresh-keys")
        .halign(gtk::Align::Center)
        .build();
    retry.add_css_class("pill");
    let status = adw::StatusPage::builder()
        .icon_name("dialog-error-symbolic")
        .title("Keys Could Not Be Loaded")
        .description("Check that the Keyvisor agent helper is installed and try again.")
        .child(&retry)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&status));
    let page = adw::NavigationPage::new(&toolbar, "Error");
    page.set_tag(Some("error"));
    page
}

fn build_empty_state() -> adw::NavigationPage {
    let header = adw::HeaderBar::new();
    header.set_show_title(false);

    let create_button = gtk::Button::builder()
        .label("Create a Key")
        .action_name("win.create-key")
        .halign(gtk::Align::Center)
        .build();
    create_button.add_css_class("suggested-action");
    create_button.add_css_class("pill");

    let status_page = adw::StatusPage::builder()
        .icon_name("key-symbolic")
        .title("Protect Your SSH Keys")
        .description(
            "Create a hardware-bound key. Signing happens in the TPM, \
             so private key material is never exported.",
        )
        .child(&create_button)
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&status_page));

    let page = adw::NavigationPage::new(&toolbar, "Key Details");
    page.set_tag(Some("empty"));
    page
}

#[cfg(test)]
mod tests {
    use gtk::glib::prelude::ToVariant;

    use super::{
        DisplayHistoryEntry, DisplayKey, DisplayPolicy, hex_decode, parse_history, parse_key_list,
    };

    #[test]
    fn parses_public_agent_key_listing() {
        let listing = b"KEYVISOR-LIST-1\n\
            abcd\tpin\t576f726b\t010203\n";
        assert_eq!(
            parse_key_list(listing),
            Ok(vec![DisplayKey {
                id: "abcd".to_owned(),
                name: "Work".to_owned(),
                policy: DisplayPolicy::TpmPin,
                public_key: vec![1, 2, 3],
            }])
        );
    }

    #[test]
    fn rejects_malformed_hexadecimal_metadata() {
        assert!(hex_decode("0").is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn parses_privacy_preserving_history() {
        let value = (vec![(
            42_u64,
            String::from("object-id"),
            String::from("Work"),
            String::from("pin"),
            String::from("succeeded"),
        )],)
            .to_variant();
        assert_eq!(
            parse_history(&value),
            Ok(vec![DisplayHistoryEntry {
                timestamp_seconds: 42,
                key_name: String::from("Work"),
                policy: DisplayPolicy::TpmPin,
                succeeded: true,
            }])
        );
    }
}
