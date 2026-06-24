use oc_oxide_daemon::DaemonCore;
use oc_oxide_ipc::{
    decode_command_line, encode_response_line, AuthPrompt, AuthPromptField, AuthPromptFieldKind,
    AuthSubmission, AuthSubmittedField, DaemonState, DisconnectReason, IpcCommand, IpcEvent,
    IpcResponse, NetworkApplied,
};

#[test]
fn m6_daemon_handles_ipc_lifecycle_without_network_or_system_changes() {
    let mut daemon = DaemonCore::new();
    let connect = decode_command_line("{\"type\":\"connect\",\"profile\":\"office\"}\n").unwrap();

    assert_eq!(daemon.handle_command(connect), IpcResponse::Accepted);
    assert_eq!(daemon.status().state, DaemonState::Connecting);
    assert_eq!(daemon.status().active_profile.as_deref(), Some("office"));

    daemon.emit_auth_prompt(AuthPrompt {
        form_id: "form-1".to_owned(),
        title: "Login".to_owned(),
        message: None,
        error: None,
        fields: vec![AuthPromptField {
            id: "password".to_owned(),
            label: "Password".to_owned(),
            kind: AuthPromptFieldKind::Password,
            required: true,
        }],
    });
    assert_eq!(daemon.status().state, DaemonState::AwaitingAuth);
    assert_eq!(daemon.pending_auth_form_id(), Some("form-1"));

    let auth_response = AuthSubmission::new(
        "form-1",
        vec![AuthSubmittedField::new("password", "do-not-log", true).unwrap()],
    )
    .unwrap();
    assert_eq!(
        daemon.handle_command(IpcCommand::SubmitAuth(auth_response)),
        IpcResponse::Accepted
    );
    assert_eq!(daemon.status().state, DaemonState::Connecting);

    daemon.mark_network_applied(NetworkApplied {
        route_commands: 5,
        dns_commands: 2,
    });
    daemon.mark_connected("tun0");
    assert_eq!(daemon.status().state, DaemonState::Connected);
    assert_eq!(daemon.status().interface.as_deref(), Some("tun0"));

    let events = daemon.drain_events();
    assert!(events.contains(&IpcEvent::AuthPrompt(AuthPrompt {
        form_id: "form-1".to_owned(),
        title: "Login".to_owned(),
        message: None,
        error: None,
        fields: vec![AuthPromptField {
            id: "password".to_owned(),
            label: "Password".to_owned(),
            kind: AuthPromptFieldKind::Password,
            required: true,
        }],
    })));
    assert!(events.contains(&IpcEvent::NetworkApplied(NetworkApplied {
        route_commands: 5,
        dns_commands: 2,
    })));
    assert!(events.contains(&IpcEvent::Connected {
        interface: "tun0".to_owned(),
    }));

    let diagnostics = daemon.handle_command(IpcCommand::Diagnostics);
    let encoded = encode_response_line(&diagnostics).unwrap();
    assert!(encoded.contains("\"type\":\"diagnostics\""));
    assert!(encoded.contains("managed on tun0"));
    assert!(!encoded.contains("do-not-log"));

    assert_eq!(
        daemon.handle_command(IpcCommand::Disconnect),
        IpcResponse::Accepted
    );
    assert_eq!(daemon.status().state, DaemonState::Disconnected);
    assert_eq!(daemon.status().active_profile, None);
    assert!(daemon.drain_events().contains(&IpcEvent::Disconnected {
        reason: DisconnectReason::UserRequested,
    }));
}
