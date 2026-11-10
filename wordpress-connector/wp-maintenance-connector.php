<?php
/**
 * Plugin Name: WP Maintenance Connector
 * Description: Read-only authenticated inventory endpoint for WordPress Maintenance Agent.
 * Version: 0.1.0
 * Requires at least: 5.6
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 * Text Domain: wp-maintenance-connector
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

register_activation_hook( __FILE__, function () {
	$administrator = get_role( 'administrator' );
	if ( $administrator ) {
		$administrator->add_cap( 'view_wp_maintenance_inventory' );
	}
} );

register_deactivation_hook( __FILE__, function () {
	$administrator = get_role( 'administrator' );
	if ( $administrator ) {
		$administrator->remove_cap( 'view_wp_maintenance_inventory' );
	}
} );

add_action( 'rest_api_init', function () {
	register_rest_route(
		'wp-maintenance/v1',
		'/inventory',
		array(
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => 'wpmc_inventory_response',
				'permission_callback' => 'wpmc_inventory_permission',
			),
		)
	);
} );

/** Restrict all inventory data to authenticated site administrators. */
function wpmc_inventory_permission() {
	if ( ! is_user_logged_in() || ! current_user_can( 'view_wp_maintenance_inventory' ) ) {
		return new WP_Error( 'wpmc_forbidden', 'The view_wp_maintenance_inventory capability is required.', array( 'status' => 403 ) );
	}
	return true;
}

/** Return a read-only inventory; do not expose credentials, paths, or user data. */
function wpmc_inventory_response() {
	if ( ! function_exists( 'get_plugins' ) ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	$plugins       = get_plugins();
	$must_use      = get_mu_plugins();
	$active        = (array) get_option( 'active_plugins', array() );
	$network_active = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
	$updates       = get_site_transient( 'update_plugins' );
	$plugin_data   = array();

	foreach ( $plugins as $file => $headers ) {
		$update = isset( $updates->response[ $file ] ) ? $updates->response[ $file ] : null;
		$plugin_data[] = array(
			'name'              => sanitize_text_field( $headers['Name'] ),
			'slug'              => sanitize_text_field( dirname( $file ) === '.' ? basename( $file, '.php' ) : dirname( $file ) ),
			'version'           => sanitize_text_field( $headers['Version'] ),
			'file_id'           => sanitize_text_field( $file ),
			'status'            => in_array( $file, $active, true ) ? 'active' : ( in_array( $file, $network_active, true ) ? 'network-active' : 'inactive' ),
			'update_available'  => (bool) $update,
			'update_version'    => $update && isset( $update->new_version ) ? sanitize_text_field( $update->new_version ) : null,
			'requires_php'      => sanitize_text_field( $headers['RequiresPHP'] ),
			'requires_wordpress' => sanitize_text_field( $headers['RequiresWP'] ),
		);
	}
	foreach ( $must_use as $file => $headers ) {
		$plugin_data[] = array(
			'name' => sanitize_text_field( $headers['Name'] ),
			'slug' => sanitize_text_field( basename( $file, '.php' ) ),
			'version' => sanitize_text_field( $headers['Version'] ),
			'file_id' => sanitize_text_field( $file ),
			'status' => 'must-use',
			'update_available' => false,
			'update_version' => null,
			'requires_php' => sanitize_text_field( $headers['RequiresPHP'] ),
			'requires_wordpress' => sanitize_text_field( $headers['RequiresWP'] ),
		);
	}

	$core_updates = get_site_transient( 'update_core' );
	$core_version = null;
	if ( is_object( $core_updates ) && ! empty( $core_updates->updates ) ) {
		foreach ( $core_updates->updates as $offer ) {
			if ( isset( $offer->response, $offer->version ) && 'upgrade' === $offer->response ) {
				$core_version = sanitize_text_field( $offer->version );
				break;
			}
		}
	}

	return rest_ensure_response(
		array(
			'wordpress_version' => get_bloginfo( 'version' ),
			'wordpress_update_version' => $core_version,
			'php_version'       => PHP_VERSION,
			'plugins'           => $plugin_data,
			'read_only'         => true,
			'generated_at'      => gmdate( 'c' ),
		)
	);
}
