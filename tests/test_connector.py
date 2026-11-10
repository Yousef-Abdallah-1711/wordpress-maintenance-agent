from pathlib import Path


def test_connector_has_explicit_read_only_route_and_capability_check():
    source = (Path(__file__).parents[1] / "wordpress-connector/wp-maintenance-connector.php").read_text(encoding="utf-8")
    assert "WP_REST_Server::READABLE" in source
    assert "permission_callback" in source
    assert "current_user_can( 'view_wp_maintenance_inventory' )" in source
    assert "register_activation_hook" in source
    assert "update_plugins" in source
    for dangerous in ("eval(", "shell_exec(", "exec(", "wp_update_plugin", "wp_update_core"):
        assert dangerous not in source
