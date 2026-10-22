#!/usr/local/bin/php-cgi -f
<?php
require_once("config.inc");
require_once("functions.inc");
require_once("filter.inc");

// 1. Config flag was turned off (GUI, console menu, or config edit)
if (!isset($config['system']['ssh']['enable'])) {
	init_config_arr(array('system', 'ssh'));
	$config['system']['ssh']['enable'] = "enabled";
	write_config("Watchdog: re-enabled SSHD");
	send_event("service reload sshd");
	filter_configure();
	exit;
}

// 2. Config says enabled, but the daemon isn't running (killed)
exec("pgrep -x sshd", $out, $rc);
if ($rc !== 0) {
	send_event("service reload sshd");
}